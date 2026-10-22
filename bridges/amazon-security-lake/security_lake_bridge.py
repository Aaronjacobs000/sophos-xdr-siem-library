#!/usr/bin/env python3
"""Read Amazon Security Lake records (OCSF) through Amazon Athena and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Security Lake keeps its records as Apache Parquet objects in S3, which Sophos NG-SIEM can't read, so
this script has Athena write each new window of a Security Lake table out as JSON, then reads what
Athena wrote and sends it. It needs query access to the tables (in the Security Lake account, or as a
query subscriber through AWS Lake Formation) and an S3 location Athena can write to:

  POST https://athena.<region>.amazonaws.com/   StartQueryExecution: UNLOAD (SELECT * FROM <table>
                                                WHERE time_dt in the window) TO 's3://...' WITH (format = 'JSON')
  POST https://athena.<region>.amazonaws.com/   GetQueryExecution, until the query ends
  GET  https://<bucket>.s3.<region>.amazonaws.com/<key>   the query's data manifest, then each gzip
                                                          JSON file it lists, in parts

Requests are signed with AWS Signature Version 4. Each record goes out with "security_lake_record":
"ocsf" and "security_lake_table" first, then the record as Athena wrote it, so the library parsers in
parsers/amazon-web-services/amazon-security-lake can recognize and normalize it.

Each run reads each table from the end of its last window, less an overlap, to a delay before now,
and drops records it already sent, known by a hash of the whole record. The request and response
shapes follow the Athena API reference, the Athena UNLOAD and Security Lake query docs, and the S3 API
reference. Configuration comes from environment variables (see README.md). A window's end only moves
after HTTP Ingest accepted every record in it. --dry-run prints what would be sent and changes no
state, though Athena still runs the queries and writes their files.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import http.client
import json
import logging
import os
import random
import re
import secrets
import socket
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("security_lake_bridge")
USER_AGENT = f"sophos-xdr-siem-library-security-lake-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
RECORD_KEY = "security_lake_record"
RECORD = "ocsf"
TABLE_KEY = "security_lake_table"
# Security Lake's tables for the AWS log sources, in source version 2 (OCSF 1.1.0).
DEFAULT_SOURCES = "cloud_trail_mgmt,route53,vpc_flow,sh_findings"
SOURCES = ("cloud_trail_mgmt", "lambda_execution", "s3_data", "route53", "vpc_flow", "sh_findings",
           "eks_audit", "waf")
SOURCE_VERSION = "2_0"
# Each data file is read this many bytes at a time, and a record longer than MAX_LINE_BYTES once
# unpacked stops the run, so a broken or hostile file can't use up memory.
PART_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024 * 1024
UNPACK_STEP = 4 * 1024 * 1024
# Records are sent, and their hashes saved, this many at a time.
SEND_RECORDS = 5000
MAX_FILES = 100000
MAX_PAGES = 10000
SEEN_LIMIT = 200000
# Athena answers a throttled request with HTTP 400 and one of these error types.
THROTTLED = {"TooManyRequestsException", "ThrottlingException", "ThrottledException", "RequestLimitExceeded"}
# AWS answers credentials it can't use with these, at HTTP 400 or 403. Their messages can quote the
# signed request, session token included, so they are never passed on.
CREDENTIAL_ERRORS = {"UnrecognizedClientException", "InvalidSignatureException", "SignatureDoesNotMatch",
                     "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "InvalidToken",
                     "InvalidAccessKeyId", "IncompleteSignature", "MissingAuthenticationToken",
                     "RequestExpired", "RequestTimeTooSkewed", "TokenRefreshRequired"}
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$")
TABLE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,254}$")
WORKGROUP = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
# Characters an S3 key prefix may hold here: the ones S3 calls safe. A quote can't reach the query.
PREFIX = re.compile(r"^[A-Za-z0-9!_.*()/=-]*$")
QUERY_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")

class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""

class NetworkError(BridgeError):
    """The API or HTTP Ingest couldn't be reached, even after the retries. With --interval the
    bridge logs it and tries again at the next interval."""

class HostNotFound(NetworkError):
    """A host name in a URL setting didn't resolve, even after the retries. Until a run has worked,
    it stops the bridge even with --interval, since it is most likely a mistyped URL."""


# ---------------------------------------------------------------- configuration

def _env(env: dict, name: str, default: str | None = None) -> str | None:
    value = env.get(name)
    if not (value and value.strip()) and name.startswith("BRIDGE_"):
        # Bridges were called collectors, so the old COLLECTOR_ names still work.
        value = env.get("COLLECTOR_" + name[len("BRIDGE_"):])
    return value.strip() if value and value.strip() else default

def _flag(env: dict, name: str, default: bool) -> bool:
    value = _env(env, name)
    if value is None:
        return default
    return value.lower() not in ("0", "false", "no", "off")

def _number(env: dict, name: str, default: str, cast=int, low: float = 0, high: int = 10 ** 9):
    """A numeric setting: a bad value stops the bridge with one plain error, not a traceback."""
    value = _env(env, name, default)
    try:
        number = cast(value)
    except ValueError:
        raise BridgeError(f"{name} must be a number") from None
    # NaN fails every comparison, so it lands here too.
    if not low <= number <= high:
        raise BridgeError(f"{name} must be between {low:,} and {high:,}")
    return number

def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")

def _refuse_user_info(url: str, what: str) -> None:
    """urllib sends no user name or password from a URL, and the host isn't found with them in
    it, so a URL setting that has them can never work."""
    if "@" in urllib.parse.urlsplit(url).netloc:
        raise BridgeError(f"{what} has a user name or password before the host (user:pass@), which the bridge "
                          "can't use; remove it")


def _list(env: dict, name: str, default: str = "") -> list[str]:
    return list(dict.fromkeys(x.strip() for x in (_env(env, name, default) or "").split(",") if x.strip()))


def _s3_location(value: str, name: str) -> tuple[str, str]:
    """An s3://bucket/prefix/ setting, as (bucket, prefix), with the prefix ending in a slash."""
    if not value.startswith("s3://"):
        raise BridgeError(f"{name} must be an S3 location such as s3://example-bucket/security-lake-bridge/")
    bucket, _, prefix = value[len("s3://"):].partition("/")
    if not BUCKET.match(bucket) or ".." in bucket:
        raise BridgeError(f"{name} names a bucket that isn't a valid S3 bucket name")
    if not PREFIX.match(prefix) or "//" in prefix:
        raise BridgeError(f"{name} may hold only letters, digits and !_.*()/=- after the bucket name")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return bucket, prefix


def _endpoint(env: dict, name: str) -> str | None:
    """An endpoint override, such as a VPC endpoint: the scheme, host and port only."""
    url = (_env(env, name) or "").rstrip("/")
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    if parts.path or parts.query or parts.fragment:
        raise BridgeError(f"{name} takes the scheme, host and port only, such as https://athena.ap-southeast-2.amazonaws.com")
    _refuse_user_info(url, name)
    _require_https(url, name)
    return url


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    region = _env(env, "AWS_REGION") or _env(env, "AWS_DEFAULT_REGION")
    if not region or not REGION.match(region):
        raise BridgeError("AWS_REGION is required: the Region of your Security Lake tables and Athena, such as ap-southeast-2")
    under = region.replace("-", "_")
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "region": region,
        "key_id": _env(env, "AWS_ACCESS_KEY_ID"),
        "secret": _env(env, "AWS_SECRET_ACCESS_KEY"),
        "token": _env(env, "AWS_SESSION_TOKEN"),
        "database": _env(env, "SECURITY_LAKE_DATABASE", f"amazon_security_lake_glue_db_{under}"),
        "workgroup": _env(env, "ATHENA_WORKGROUP", "primary"),
        "output": _env(env, "ATHENA_OUTPUT_LOCATION"),
        "query_timeout": _number(env, "ATHENA_QUERY_TIMEOUT", "900", low=30, high=86400),
        "athena_url": _endpoint(env, "AWS_ENDPOINT_URL_ATHENA") or f"https://athena.{region}.amazonaws.com",
        "s3_url": _endpoint(env, "AWS_ENDPOINT_URL_S3"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "security_lake_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "delay_seconds": _number(env, "BRIDGE_DELAY_SECONDS", "900", high=86400),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "2700"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["key_id"] or not cfg["secret"]:
        raise BridgeError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required: the access key of an IAM "
                          "principal with the permissions in the README (and AWS_SESSION_TOKEN with temporary keys)")
    if not TABLE.match(cfg["database"]):
        raise BridgeError("SECURITY_LAKE_DATABASE may hold only letters, digits, _ and -")
    if not WORKGROUP.match(cfg["workgroup"]):
        raise BridgeError("ATHENA_WORKGROUP may hold only letters, digits and ._-")
    tables = _list(env, "SECURITY_LAKE_TABLES")
    if not tables:
        sources = [x.lower() for x in _list(env, "SECURITY_LAKE_SOURCES", DEFAULT_SOURCES)]
        unknown = [x for x in sources if x not in SOURCES]
        if unknown or not sources:
            raise BridgeError(f"SECURITY_LAKE_SOURCES takes {', '.join(SOURCES)}, separated by commas")
        tables = [f"amazon_security_lake_table_{under}_{x}_{SOURCE_VERSION}" for x in sources]
    if any(not TABLE.match(t) for t in tables):
        raise BridgeError("SECURITY_LAKE_TABLES takes table names of letters, digits, _ and -, separated by commas")
    cfg["tables"] = tables
    unload = _env(env, "ATHENA_UNLOAD_LOCATION")
    if not unload:
        raise BridgeError("ATHENA_UNLOAD_LOCATION is required: an S3 location in AWS_REGION where Athena writes the "
                          "JSON files, such as s3://example-bucket/security-lake-bridge/")
    cfg["unload_bucket"], cfg["unload_prefix"] = _s3_location(unload, "ATHENA_UNLOAD_LOCATION")
    if cfg["output"]:
        _s3_location(cfg["output"], "ATHENA_OUTPUT_LOCATION")
        if not cfg["output"].endswith("/"):
            cfg["output"] += "/"
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    if cfg["ingest_url"]:
        _refuse_user_info(cfg["ingest_url"], "NGSIEM_INGEST_URL")
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    """The host and port, for log lines and errors. A user name or password in the URL is a
    credential, so it shows as [redacted]."""
    _, at, host = urllib.parse.urlsplit(url).netloc.rpartition("@")
    return f"[redacted]@{host}" if at else host

def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            # Honor the server's wait for up to five minutes, so a bad value can't stall the bridge.
            return min(300.0, max(0.0, float(retry_after)))
        except ValueError:
            pass
    return min(60.0, 2 ** attempt) + random.uniform(0, 1)

class HttpStatus(BridgeError):
    def __init__(self, what: str, url: str, code: int, body: bytes = b""):
        if code in REDIRECT_STATUS:
            message = (f"{what} to {_host(url)} answered with a redirect (HTTP {code}), which the bridge refuses "
                       "so the key or token never goes to another URL; check the URL setting")
        elif code in UNSUPPORTED_STATUS:
            message = (f"{what} to {_host(url)} failed with HTTP {code}: {UNSUPPORTED_STATUS[code]}, and a retry "
                       "won't change that; check the URL setting")
        else:
            message = f"{what} to {_host(url)} failed with HTTP {code}"
        super().__init__(message)
        self.code = code
        self.body = body

class RetriedStatus(HttpStatus, NetworkError):
    """A 408, 429, 500, 502, 503 or 504 that outlasted the retries. It is a NetworkError too, so with --interval
    the bridge logs it and tries again at the next interval."""

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None

_OPENER = urllib.request.build_opener(_NoRedirect)

def _read(resp, what: str, url: str, limit: int | None = None) -> bytes:
    """Reads a response body, but no more than the limit, so a broken or hostile endpoint can't
    use up memory. It reads 1 MB at a time: before Python 3.10, read(n) set aside all n bytes first.
    A body that ends short of its Content-Length raises IncompleteRead, like a cut-off chunked one."""
    limit = limit or MAX_RESPONSE_BYTES
    chunks, size = [], 0
    while True:
        chunk = resp.read(min(1048576, limit + 1 - size))
        if not chunk:
            # read(n) returns nothing, with no error, when the connection closes before the
            # Content-Length is reached. http.client still counts the bytes it was promised.
            owed = getattr(resp, "length", None)
            if owed:
                raise http.client.IncompleteRead(b"", owed)
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise BridgeError(f"{what} to {_host(url)} sent more than {limit // 1048576} MB, which the bridge "
                              "refuses so a bad response can't use up memory")

# Retried, then a NetworkError. On Python 3.9 a read timeout is socket.timeout, which isn't a
# TimeoutError yet, and IncompleteRead means the connection closed partway through an answer.
_NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError, http.client.IncompleteRead)

def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, headers, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers, _read(resp, what, url)
        except urllib.error.HTTPError as e:
            # Read the body, then close the error response so its socket is released now, not
            # when the error is garbage collected. A status that is retried is retried whatever
            # its body, so a body over the limit only stops the run for the other statuses.
            try:
                error_body = _read(e, what, url)
            except BridgeError:
                if e.code not in RETRY_STATUS:
                    raise
                error_body = b""
            except _NETWORK_ERRORS:
                # The body was cut short or timed out: the status still decides what happens.
                error_body = b""
            finally:
                e.close()
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None)
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS:
                raise RetriedStatus(what, url, e.code, error_body) from None
            raise HttpStatus(what, url, e.code, error_body) from None
        except _NETWORK_ERRORS as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            if isinstance(e, urllib.error.URLError) and isinstance(e.reason, socket.gaierror):
                raise HostNotFound(f"{what} to {_host(url)} failed: the host name wasn't found; "
                                   "check the URL setting") from None
            raise NetworkError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
        except ValueError:
            # http.client puts a header value it refuses, such as a key with a line break in it,
            # in its error, so that error isn't passed on.
            raise BridgeError(f"{what} to {_host(url)} couldn't be sent: a key or token has a line break or "
                              "another character a request header can't carry") from None
        except http.client.HTTPException as e:
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise BridgeError(f"{what} to {_host(url)} failed")

def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise BridgeError(f"{what} returned a body that is not JSON") from None


# ---------------------------------------------------------------- AWS signing (Signature Version 4)

def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def _uri(text: str) -> str:
    return urllib.parse.quote(text, safe="-_.~")


def sigv4(method: str, url: str, headers: dict, body: bytes | None, region: str, service: str, key_id: str,
          secret: str, token: str | None, now: float | None = None) -> dict:
    """The request's headers signed with AWS Signature Version 4, as AWS's guide to signing API
    requests lays it out. The URL's path must already be URI-encoded once."""
    parts = urllib.parse.urlsplit(url)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time() if now is None else now))
    payload = hashlib.sha256(body or b"").hexdigest()
    out = dict(headers)
    out["X-Amz-Date"] = stamp
    if service == "s3":
        out["X-Amz-Content-Sha256"] = payload
    if token:
        out["X-Amz-Security-Token"] = token
    signed = {k.lower(): " ".join(str(v).split()) for k, v in out.items()}
    signed["host"] = parts.netloc
    names = sorted(signed)
    query = "&".join(f"{_uri(k)}={_uri(v)}" for k, v in sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True)))
    canonical = "\n".join([method, parts.path or "/", query, "".join(f"{k}:{signed[k]}\n" for k in names),
                           ";".join(names), payload])
    scope = f"{stamp[:8]}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret).encode("utf-8"), stamp[:8]), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={';'.join(names)}, "
                            f"Signature={signature}")
    return out


def _aws_error(body: bytes) -> tuple[str, str]:
    """AWS's error type and message, from Athena's JSON ({"__type": ..., "Message": ...}) or S3's XML
    (<Error><Code>...</Code><Message>...</Message></Error>)."""
    text = body[:65536].decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        kind = str(data.get("__type") or data.get("code") or "")
        message = str(data.get("Message") or data.get("message") or "")
    else:
        code = re.search(r"<Code>([^<]{1,200})</Code>", text)
        msg = re.search(r"<Message>([^<]{1,500})</Message>", text)
        kind, message = (code.group(1) if code else ""), (msg.group(1) if msg else "")
    # Types can come as "com.amazonaws.athena#InvalidRequestException" or "Type:http://...".
    kind = kind.rsplit("#", 1)[-1].split(":", 1)[0].strip()
    return kind, " ".join(message.split())[:300]


# ---------------------------------------------------------------- Athena and S3

# The clock for a query's time limit.
_clock = time.monotonic


class Aws:
    """Calls Athena's JSON API and reads S3 objects, signing each request with the configured keys."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _clean(self, message: str) -> str:
        for secret in (self.cfg["key_id"], self.cfg["secret"], self.cfg["token"]):
            if secret:
                message = message.replace(secret, "[redacted]")
        return message

    def _signed(self, method: str, url: str, headers: dict, body: bytes | None, service: str) -> dict:
        return sigv4(method, url, headers, body, self.cfg["region"], service, self.cfg["key_id"], self.cfg["secret"],
                     self.cfg["token"])

    def _refused(self, code: int, kind: str, message: str, what: str, needs: str) -> BridgeError | None:
        if kind in CREDENTIAL_ERRORS:
            return BridgeError(f"AWS refused the credentials for the {what} (HTTP {code}, {kind}); check "
                               "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN, and that this "
                               "machine's clock is right")
        if code == 403 or kind in ("AccessDeniedException", "AccessDenied"):
            return BridgeError(f"AWS refused the {what} (HTTP {code}{f', {kind}' if kind else ''}: "
                               f"{self._clean(message) or 'no message'}); {needs}")
        return None

    def athena(self, action: str, payload: dict, what: str) -> dict:
        """One Athena API call. A throttled call (HTTP 400 TooManyRequestsException) is retried like a 429."""
        url = self.cfg["athena_url"] + "/"
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        for attempt in range(MAX_ATTEMPTS):
            headers = self._signed("POST", url, {"Content-Type": "application/x-amz-json-1.1",
                                                 "X-Amz-Target": f"AmazonAthena.{action}"}, body, "athena")
            try:
                _, _, raw = _request("POST", url, headers, body, self.cfg["timeout"], what)
            except HttpStatus as e:
                kind, message = _aws_error(e.body)
                if e.code == 400 and kind in THROTTLED:
                    if attempt < MAX_ATTEMPTS - 1:
                        delay = _retry_delay(attempt, None)
                        LOG.warning("%s to %s was throttled; retrying in %.1fs", what, _host(url), delay)
                        time.sleep(delay)
                        continue
                    raise NetworkError(f"{what} to {_host(url)} was still throttled after {MAX_ATTEMPTS} tries") from None
                refused = self._refused(e.code, kind, message, what, "the bridge's IAM policy needs the Athena, Glue, "
                                        "Lake Formation and S3 permissions in the README")
                if refused:
                    raise refused from None
                if e.code == 400:
                    raise BridgeError(f"Athena rejected the {what} (HTTP 400{f', {kind}' if kind else ''}: "
                                      f"{self._clean(message) or 'no message'})") from None
                raise
            data = _json(raw, what)
            if not isinstance(data, dict):
                raise BridgeError(f"{what} returned JSON that is not an object")
            return data
        raise BridgeError(f"{what} to {_host(url)} failed")

    def query(self, sql: str, label: str, kind: str = "query") -> dict:
        """Starts the query, checks it until it ends, and returns its QueryExecution. A query that
        runs past ATHENA_QUERY_TIMEOUT is stopped."""
        label = f"{label} {kind}"
        payload = {"QueryString": sql, "ClientRequestToken": secrets.token_hex(16), "WorkGroup": self.cfg["workgroup"],
                   "QueryExecutionContext": {"Catalog": "AwsDataCatalog", "Database": self.cfg["database"]}}
        if self.cfg["output"]:
            payload["ResultConfiguration"] = {"OutputLocation": self.cfg["output"]}
        started = self.athena("StartQueryExecution", payload, f"{label} start")
        qid = started.get("QueryExecutionId")
        if not isinstance(qid, str) or not QUERY_ID.match(qid):
            raise BridgeError(f"{label} start returned no QueryExecutionId")
        deadline = _clock() + self.cfg["query_timeout"]
        wait = 1.0
        while True:
            data = self.athena("GetQueryExecution", {"QueryExecutionId": qid}, f"{label} status")
            q = data.get("QueryExecution") if isinstance(data.get("QueryExecution"), dict) else {}
            status = q.get("Status") if isinstance(q.get("Status"), dict) else {}
            state = status.get("State")
            if state == "SUCCEEDED":
                return q
            if state in ("FAILED", "CANCELLED"):
                error = status.get("AthenaError") if isinstance(status.get("AthenaError"), dict) else {}
                reason = " ".join(str(status.get("StateChangeReason") or error.get("ErrorMessage") or "no reason given").split())
                kind = NetworkError if error.get("Retryable") is True else BridgeError
                raise kind(f"Athena reports the {label} {state}: {self._clean(reason)[:300]}")
            if state not in ("QUEUED", "RUNNING"):
                raise BridgeError(f"{label} status returned an unknown state")
            if _clock() >= deadline:
                try:
                    self.athena("StopQueryExecution", {"QueryExecutionId": qid}, f"{label} stop")
                except BridgeError as e:
                    LOG.warning("%s", e)
                raise NetworkError(f"the {label} ran past ATHENA_QUERY_TIMEOUT and was stopped; the next run "
                                   "reads the same window again")
            time.sleep(wait)
            wait = min(wait * 2, 10.0)

    def rows(self, q: dict, label: str) -> list[list[str]]:
        """Every row of a finished query's results, page by page, as lists of text."""
        out, token = [], None
        for _ in range(MAX_PAGES):
            payload = {"QueryExecutionId": q.get("QueryExecutionId"), "MaxResults": 1000}
            if token:
                payload["NextToken"] = token
            data = self.athena("GetQueryResults", payload, f"{label} results")
            result = data.get("ResultSet") if isinstance(data.get("ResultSet"), dict) else {}
            for row in result.get("Rows") or []:
                cells = row.get("Data") if isinstance(row, dict) and isinstance(row.get("Data"), list) else []
                out.append([c.get("VarCharValue") if isinstance(c, dict) else None for c in cells])
            token = data.get("NextToken")
            if not isinstance(token, str) or not token:
                return out
        raise BridgeError(f"{label} results had more than {MAX_PAGES} pages")

    def columns(self, table: str) -> list[tuple[str, str]]:
        """The table's columns and their types, in order, from Athena's information_schema."""
        sql = ("SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = "
               f"'{self.cfg['database'].lower()}' AND table_name = '{table.lower()}' ORDER BY ordinal_position")
        q = self.query(sql, table, "column list query")
        rows = self.rows(q, f"{table} column list query")
        # The first row of a SELECT's results is its header.
        if rows and [x.lower() if isinstance(x, str) else x for x in rows[0]] == ["column_name", "data_type"]:
            rows = rows[1:]
        cols = [(r[0], r[1]) for r in rows if len(r) == 2 and isinstance(r[0], str) and r[0] and isinstance(r[1], str) and r[1]]
        if not cols:
            raise BridgeError(f"Athena lists no columns for {self.cfg['database']}.{table}: check SECURITY_LAKE_DATABASE "
                              "and the table names, and that Lake Formation lets the bridge describe and select the table")
        return cols

    def s3_url(self, bucket: str, key: str) -> str:
        path = "/".join(_uri(p) for p in key.split("/"))
        if self.cfg["s3_url"]:
            return f"{self.cfg['s3_url']}/{bucket}/{path}"
        if "." in bucket:
            # A bucket name with a dot doesn't match S3's certificate as a host name, so it goes in the path.
            return f"https://s3.{self.cfg['region']}.amazonaws.com/{bucket}/{path}"
        return f"https://{bucket}.s3.{self.cfg['region']}.amazonaws.com/{path}"

    def get(self, bucket: str, key: str, what: str, first: int | None = None):
        """GETs an object, or the PART_BYTES of it from first. Returns (status, headers, body)."""
        url = self.s3_url(bucket, key)
        headers = {} if first is None else {"Range": f"bytes={first}-{first + PART_BYTES - 1}"}
        try:
            return _request("GET", url, self._signed("GET", url, headers, None, "s3"), None, self.cfg["timeout"], what)
        except HttpStatus as e:
            kind, message = _aws_error(e.body)
            if e.code == 416 and first == 0:
                return 206, {"Content-Range": "bytes */0"}, b""
            if kind in ("PermanentRedirect", "AuthorizationHeaderMalformed", "IllegalLocationConstraintException"):
                raise BridgeError(f"S3 answered the {what} for bucket {bucket} with HTTP {e.code} ({kind}): the bucket "
                                  f"isn't in {self.cfg['region']}, and the bridge doesn't follow redirects; use a bucket "
                                  "in AWS_REGION") from None
            refused = self._refused(e.code, kind, message, what, f"the bridge's IAM policy needs s3:GetObject on "
                                    f"s3://{bucket}/{key.rsplit('/', 1)[0]}/, and kms:Decrypt if a KMS key encrypts it")
            if refused:
                raise refused from None
            if e.code == 404:
                raise BridgeError(f"S3 has no object for the {what} (HTTP 404{f', {kind}' if kind else ''})") from None
            raise

    def manifest(self, q: dict, label: str) -> list[str]:
        """The data files the query wrote, from its data manifest: one s3:// URI a line."""
        stats = q.get("Statistics") if isinstance(q.get("Statistics"), dict) else {}
        where = stats.get("DataManifestLocation")
        if not isinstance(where, str) or not where.startswith("s3://"):
            raise BridgeError(f"Athena gave no data manifest for the {label} query; use a workgroup that keeps query "
                              "results in S3, not managed query results")
        bucket, _, key = where[len("s3://"):].partition("/")
        _, _, raw = self.get(bucket, key, f"{label} manifest read")
        return [line.strip().strip('"') for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]

    def records(self, bucket: str, key: str, label: str):
        """Yields each record of one gzip JSON Lines file, read PART_BYTES at a time and unpacked a
        step at a time, so neither a large file nor a record that unpacks to a lot fills memory."""
        what = f"{label} file read"
        unpack = zlib.decompressobj(wbits=31)
        pending = b""
        first, total = 0, None
        while total is None or first < total:
            status, headers, raw = self.get(bucket, key, what, first)
            if status == 200:
                total = len(raw)
            else:
                m = re.match(r"bytes (?:\d+-\d+|\*)/(\d+)$", (headers.get("Content-Range") or "").strip())
                if not m:
                    raise BridgeError(f"{what} for s3://{bucket}/{key} answered a part without a Content-Range")
                total = int(m.group(1))
            if not raw:
                break
            first += len(raw)
            data = raw
            while True:
                if unpack.eof:
                    # A file can hold several gzip members one after another. What followed the
                    # last one is in unused_data, and data holds only what was read since.
                    data = unpack.unused_data + data
                    if not data.strip(b"\0"):
                        break
                    unpack = zlib.decompressobj(wbits=31)
                try:
                    out = unpack.decompress(data, UNPACK_STEP)
                except zlib.error:
                    raise BridgeError(f"{what} for s3://{bucket}/{key} isn't gzip, or is damaged") from None
                # At the end of a member, unconsumed_tail can still hold what is now in unused_data.
                data = b"" if unpack.eof else unpack.unconsumed_tail
                pending += out
                *lines, pending = pending.split(b"\n")
                for line in lines:
                    if line.strip():
                        yield _record(line, what)
                if len(pending) > MAX_LINE_BYTES:
                    raise BridgeError(f"{what} for s3://{bucket}/{key} has a record over {MAX_LINE_BYTES // 1048576} MB, "
                                      "which the bridge refuses")
                # A full step may leave more to unpack from what was already read.
                if not data and len(out) < UNPACK_STEP and not (unpack.eof and unpack.unused_data):
                    break
        if total and not unpack.eof:
            raise BridgeError(f"{what} for s3://{bucket}/{key} ended partway through its gzip data")
        if pending.strip():
            yield _record(pending, what)


def _record(line: bytes, what: str) -> dict:
    try:
        rec = json.loads(line)
    except ValueError:
        raise BridgeError(f"{what} found a line that is not JSON") from None
    if not isinstance(rec, dict):
        raise BridgeError(f"{what} found a line that is not a JSON object")
    return rec


# ---------------------------------------------------------------- HTTP Ingest

class Sink:
    """Batches records as NDJSON and posts them to HTTP Ingest, or prints them in dry-run."""

    def __init__(self, cfg: dict, dry_run: bool, out=None):
        self.cfg, self.dry_run = cfg, dry_run
        self.out = out or sys.stdout
        self.sent = 0
        self.batches = 0
        if not dry_run and not (cfg["ingest_url"] and cfg["ingest_key"]):
            raise BridgeError("NGSIEM_INGEST_URL and NGSIEM_INGEST_KEY are required unless --dry-run is set")

    def send(self, records: list[dict]) -> None:
        batch, size = [], 0
        for rec in records:
            line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
            n = len(line.encode("utf-8")) + 1
            if batch and size + n > self.cfg["batch_bytes"]:
                self._post(batch)
                batch, size = [], 0
            batch.append(line)
            size += n
        if batch:
            self._post(batch)

    def _post(self, lines: list[str]) -> None:
        body = ("\n".join(lines) + "\n").encode("utf-8")
        if self.dry_run:
            self.out.write(body.decode("utf-8"))
            self.out.flush()
        else:
            headers = {"Authorization": f"Bearer {self.cfg['ingest_key']}", "Content-Type": "application/json"}
            if self.cfg["gzip"]:
                body = gzip.compress(body)
                headers["Content-Encoding"] = "gzip"
            _request("POST", self.cfg["ingest_url"], headers, body, self.cfg["timeout"], "HTTP Ingest POST")
        self.sent += len(lines)
        self.batches += 1


# ---------------------------------------------------------------- collection

def _key(record: dict) -> str:
    """A record is known by the hash of all of it: a finding keeps its uid when it changes, so the uid
    alone would drop the update."""
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()[:32]


def _record_time(record: dict, now: float) -> float:
    """OCSF's time is milliseconds since the epoch."""
    t = record.get("time")
    return t / 1000.0 if isinstance(t, (int, float)) and not isinstance(t, bool) and t > 0 else now


def _timestamp(epoch: float) -> str:
    """A timestamp literal for Athena, in UTC to the millisecond, as time_dt holds it."""
    dt = datetime.fromtimestamp(epoch, timezone.utc)
    return "TIMESTAMP '" + dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}'"


_TYPE_TOKEN = re.compile(r'\s*(?:"((?:[^"]|"")*)"|([A-Za-z_][A-Za-z0-9_]*)|(\d+)|([(),]))')


def _type_tokens(text: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TYPE_TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise BridgeError("Athena gave a column type the bridge can't read")
        quoted, word, number, mark = m.groups()
        out.append(("name", quoted.replace('""', '"')) if quoted is not None else ("word", word) if word
                   else ("num", number) if number else ("mark", mark))
        pos = m.end()
    return out


def parse_type(text: str):
    """A Trino type as Athena's information_schema writes it, such as
    row(uid varchar, created_time_dt timestamp(3) with time zone), as a tree: ("row", [(name, type)]),
    ("array", type), ("map", key, value) or ("type", text)."""
    tokens = _type_tokens(text)
    pos = 0

    def peek(n=0):
        return tokens[pos + n] if pos + n < len(tokens) else ("end", "")

    def take(kind=None, value=None):
        nonlocal pos
        tok = peek()
        if (kind and tok[0] != kind) or (value and tok[1].lower() != value):
            raise BridgeError("Athena gave a column type the bridge can't read")
        pos += 1
        return tok

    def one():
        word = take("word")[1].lower()
        if word in ("row", "array", "map") and peek() == ("mark", "("):
            take("mark", "(")
            if word == "array":
                inner = one()
                take("mark", ")")
                return ("array", inner)
            if word == "map":
                key = one()
                take("mark", ",")
                value = one()
                take("mark", ")")
                return ("map", key, value)
            fields = []
            while True:
                name = take()
                if name[0] not in ("name", "word"):
                    raise BridgeError("Athena gave a column type the bridge can't read")
                fields.append((name[1], one()))
                if take("mark")[1] == ")":
                    return ("row", fields)
        text = word
        if peek() == ("mark", "("):
            take("mark", "(")
            args = []
            while peek() != ("mark", ")"):
                args.append(take()[1])
            take("mark", ")")
            text += "(" + "".join(args).replace(",", ", ") + ")"
        if peek()[0] == "word" and peek()[1].lower() in ("with", "without") and peek(1)[1].lower() == "time" \
                and peek(2)[1].lower() == "zone":
            text += f" {take()[1].lower()} time zone"
            take("word", "time")
            take("word", "zone")
        return ("type", text)

    tree = one()
    if pos != len(tokens):
        raise BridgeError("Athena gave a column type the bridge can't read")
    return tree


def _has_time(tree) -> bool:
    if tree[0] == "type":
        return tree[1].startswith(("timestamp", "time"))
    if tree[0] == "array":
        return _has_time(tree[1])
    if tree[0] == "map":
        return _has_time(tree[1]) or _has_time(tree[2])
    return any(_has_time(t) for _, t in tree[1])


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _as_text(tree) -> str:
    """The type with every timestamp and time made varchar, which UNLOAD's JSON writer can write."""
    if tree[0] == "type":
        return "varchar" if tree[1].startswith(("timestamp", "time")) else tree[1]
    if tree[0] == "array":
        return f"array({_as_text(tree[1])})"
    if tree[0] == "map":
        return f"map({_as_text(tree[1])}, {_as_text(tree[2])})"
    return "row(" + ", ".join(f"{_quote(n)} {_as_text(t)}" for n, t in tree[1]) + ")"


def select_list(columns: list[tuple[str, str]]) -> str:
    """Every column. A column that holds a timestamp, at any depth, is cast to the same type with the
    timestamps as text: Athena's JSON writer can't write a timestamp with a time zone, and Security
    Lake's *_dt columns hold one."""
    out = []
    for name, dtype in columns:
        tree = parse_type(dtype)
        out.append(f"CAST({_quote(name)} AS {_as_text(tree)}) AS {_quote(name)}" if _has_time(tree) else _quote(name))
    return ", ".join(out)


def unload_sql(cfg: dict, table: str, columns: list[tuple[str, str]], start: float, end: float, prefix: str) -> str:
    """The table's rows in [start, end), written as gzip JSON Lines. Source version 2 tables are
    partitioned on time_dt, so a time_dt filter reads only those days; a table without it (source
    version 1 or a custom source) is read by time, in milliseconds, within its eventday partitions."""
    names = {n.lower() for n, _ in columns}
    if "time_dt" in names:
        where = f"time_dt >= {_timestamp(start)} AND time_dt < {_timestamp(end)}"
    elif "time" in names:
        where = f'"time" >= {int(start * 1000)} AND "time" < {int(end * 1000)}'
        if "eventday" in names:
            where = (f"eventday >= '{time.strftime('%Y%m%d', time.gmtime(start))}' AND eventday <= "
                     f"'{time.strftime('%Y%m%d', time.gmtime(end))}' AND " + where)
    else:
        raise BridgeError(f"{table} has neither a time_dt nor a time column, so the bridge can't read it by time")
    return (f'UNLOAD (SELECT {select_list(columns)} FROM "{cfg["database"]}"."{table}" WHERE {where}) '
            f"TO 's3://{cfg['unload_bucket']}/{prefix}' WITH (format = 'JSON')")


def collect(table: str, cfg: dict, state: dict, sink: Sink, save, aws: Aws, now: float) -> int:
    """Reads one table from the end of its last window, less the overlap, to BRIDGE_DELAY_SECONDS
    before now, and sends the records not sent before. The window's end is saved only after every
    file the query wrote was sent."""
    cur = state.setdefault("tables", {}).setdefault(table, {})
    since = cur.get("until")
    end = now - cfg["delay_seconds"]
    # A saved end later than the window's end (the clock went back) counts as the end.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) and not isinstance(since, bool) \
        else (now - cfg["lookback_hours"] * 3600)
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    # UNLOAD only writes to an empty location, so each query gets its own.
    prefix = f"{cfg['unload_prefix']}{time.strftime('%Y%m%d', time.gmtime(now))}/{secrets.token_hex(8)}/"
    label = table
    columns = aws.columns(table)
    q = aws.query(unload_sql(cfg, table, columns, start, end, prefix), label)
    files = aws.manifest(q, label)
    if len(files) > MAX_FILES:
        raise BridgeError(f"the {label} query wrote more than {MAX_FILES} files; lower BRIDGE_LOOKBACK_HOURS")
    sent = 0
    fresh = {}

    def flush():
        nonlocal sent, seen
        if not fresh:
            return
        sink.send([{RECORD_KEY: RECORD, TABLE_KEY: table, **{f: v for f, v in r.items() if f not in (RECORD_KEY, TABLE_KEY)}}
                   for _, r in fresh.values()])
        # Only now that HTTP Ingest took them do they count as sent.
        seen.update({k: t for k, (t, _) in fresh.items()})
        if len(seen) > SEEN_LIMIT:
            cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
        sent += len(fresh)
        fresh.clear()
        save()

    keys = []
    for uri in files:
        bucket, _, key = uri[len("s3://"):].partition("/") if uri.startswith("s3://") else ("", "", "")
        # Only files under the location this query was given are read.
        if bucket != cfg["unload_bucket"] or not key.startswith(prefix) or ".." in key.split("/"):
            raise BridgeError(f"the {label} query's manifest lists a file outside its UNLOAD location")
        keys.append(key)
    for key in keys:
        for rec in aws.records(cfg["unload_bucket"], key, label):
            k = _key(rec)
            if k not in seen and k not in fresh:
                fresh[k] = (_record_time(rec, now), rec)
                if len(fresh) >= SEND_RECORDS:
                    flush()
        flush()
    cur["until"] = end
    save()
    LOG.info("%s: %d sent from %d files", label, sent, len(files))
    return sent


def run_once(cfg: dict, dry_run: bool = False, out=None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    aws = Aws(cfg)
    now = time.time()
    count = 0
    for table in cfg["tables"]:
        count += collect(table, cfg, state, sink, save, aws, now)
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


# ---------------------------------------------------------------- state and main

def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}

def save_state(path: str, state: dict) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=folder)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh, separators=(",", ":"))
    os.replace(tmp, path)

def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Amazon Security Lake records to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=_env(dict(os.environ), "BRIDGE_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    if args.interval < 0:
        ap.error("--interval must be 0 or more")
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "BRIDGE_DRY_RUN", False)
    try:
        cfg = load_config()
        worked = False
        while True:
            try:
                run_once(cfg, dry_run)
                worked = True
            except NetworkError as e:
                # A host name that doesn't resolve before any run has worked is most likely a
                # mistyped URL, so it stops the bridge.
                if not args.interval or (isinstance(e, HostNotFound) and not worked):
                    raise
                LOG.error("%s; trying again in %d seconds", e, args.interval)
            except BridgeError:
                raise
            except Exception as e:
                if not args.interval:
                    raise
                LOG.error("the run failed with an unexpected %s at %s; trying again in %d seconds",
                          type(e).__name__, _where(e), args.interval)
            if not args.interval:
                return 0
            time.sleep(args.interval)
    except BridgeError as e:
        LOG.error("%s", e)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
