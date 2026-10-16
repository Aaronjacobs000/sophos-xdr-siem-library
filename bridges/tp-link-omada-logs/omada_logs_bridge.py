#!/usr/bin/env python3
"""Pull TP-Link Omada event, alert and audit logs from the Omada Open API and send them to a Sophos
NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

An Omada controller (software, hardware or cloud-based) keeps its logs for the controller, the MSP
view and each site, and offers them through its Open API, which is pull only. The controller's
syslog output has no published format, and its webhook can't set the Authorization header HTTP
Ingest needs, so this script reads the logs with an Open API application in client credentials mode:

  POST <interface access address>/openapi/authorize/token?grant_type=client_credentials
  GET  /openapi/v1/<omadacId>/sites/<siteId>/logs/events, /logs/alerts and /audit-logs   (each site)
  GET  /openapi/v1/<omadacId>/logs/events, /logs/alerts and /audit-logs                  (the controller)
  GET  /openapi/v1/msp/<mspId>/logs/events, /logs/alerts and /audit-logs                 (MSP mode)

Each record goes out with "omada_record" first (event, alert or audit), then where it came from
(omada_scope, omada_id, and the site and customer for site records), then the record as Omada
returns it, so the library parsers in parsers/tp-link/omada can recognize and normalize it.

Each run reads each log from the end of its last window, less an overlap, to a minute before now,
page by page, and drops records it already sent: events and alerts by their id, audit logs by a
hash of the whole record. The request and response shapes follow TP-Link's Omada Open API reference
and Open API Access Guide. Configuration comes from environment variables (see README.md). A
window's end only moves after HTTP Ingest accepted every record in it. --dry-run prints what would
be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import logging
import os
import random
import re
import socket
import ssl
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
LOG = logging.getLogger("omada_logs_bridge")
USER_AGENT = f"sophos-xdr-siem-library-omada-logs-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 10000
RECORD_KEY = "omada_record"
TOKEN_PATH = "/openapi/authorize/token"
LOGS = ("events", "alerts", "audit")
# A window ends this long before now, so a clock a little ahead of the controller's never asks for
# the future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000
# TP-Link gives each controller and organization a budget of 10 Open API requests a second, so the
# bridge spaces its requests to stay under it.
PACE_SECONDS = 0.15
# A token is renewed this long before Omada says it expires.
TOKEN_MARGIN_SECONDS = 60
# Omada answers an expired or unknown access token with these error codes.
TOKEN_ERRORS = {-44112, -44113}
OMADA_ID = re.compile(r"^[A-Za-z0-9]{1,64}$")


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


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "OMADA_URL") or "").rstrip("/"),
        "omada_id": _env(env, "OMADA_ID"),
        "client_id": _env(env, "OMADA_CLIENT_ID"),
        "client_secret": _env(env, "OMADA_CLIENT_SECRET"),
        "msp": _flag(env, "OMADA_MSP", False),
        "logs": [x.lower() for x in _list(env, "OMADA_LOGS", "events,alerts,audit")],
        "page_size": _number(env, "OMADA_PAGE_SIZE", "1000", low=1, high=1000),
        "ca_file": _env(env, "OMADA_CA_FILE"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "omada_logs_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["api_url"]:
        raise BridgeError("OMADA_URL is required: the Interface Access Address of the Open API application, such as "
                          "https://aps1-omada-northbound.tplinkcloud.com or https://omada.example.com:8043")
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment:
        raise BridgeError("OMADA_URL takes the scheme, host and port only, such as https://omada.example.com:8043")
    _refuse_user_info(cfg["api_url"], "OMADA_URL")
    _require_https(cfg["api_url"], "OMADA_URL")
    if not cfg["omada_id"] or not OMADA_ID.match(cfg["omada_id"]):
        raise BridgeError("OMADA_ID is required: the Omada ID (or, with OMADA_MSP=1, the MSP ID) shown with the "
                          "Open API application")
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise BridgeError("OMADA_CLIENT_ID and OMADA_CLIENT_SECRET are required: the Client ID and Client Secret "
                          "of an Open API application in client mode")
    if not cfg["logs"] or any(x not in LOGS for x in cfg["logs"]):
        raise BridgeError("OMADA_LOGS takes events, alerts and audit, separated by commas")
    if cfg["ca_file"] and not os.path.isfile(cfg["ca_file"]):
        raise BridgeError("OMADA_CA_FILE must be the path of a PEM file that holds the certificate to trust")
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


def tls_opener(ca_file: str | None):
    """The opener for the Omada controller. A software or hardware controller serves the Open API with
    a self-signed certificate unless you install another, so OMADA_CA_FILE can name the certificate (or
    the CA that issued it) to trust. Certificates are always checked, and so is the host name."""
    if not ca_file:
        return _OPENER
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError, ValueError):
        raise BridgeError("OMADA_CA_FILE couldn't be read as a PEM certificate") from None
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))


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


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str, opener=None):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body)."""
    opener = opener or _OPENER
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, _read(resp, what, url)
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
            # A certificate that fails the check is refused at once: a retry gets the same certificate.
            reason = getattr(e, "reason", None)
            if isinstance(e, ssl.SSLCertVerificationError) or isinstance(reason, ssl.SSLCertVerificationError):
                raise BridgeError(f"{what} to {_host(url)} failed: the server's certificate isn't trusted or doesn't "
                                  "name this host; for a software or hardware controller, set OMADA_CA_FILE to its "
                                  "certificate and use the host name it gives") from None
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


def _error_code(body: bytes):
    """Omada answers with {"errorCode": <n>, "msg": "..."}, on errors too. Returns (code, message)."""
    try:
        data = json.loads(body)
    except ValueError:
        return None, "no message"
    if not isinstance(data, dict):
        return None, "no message"
    code = data.get("errorCode")
    return (code if isinstance(code, int) else None), (str(data.get("msg") or "")[:200] or "no message")


# ---------------------------------------------------------------- Omada Open API

class Omada:
    """Calls the Open API with an access token from the client credentials grant, sent as
    'Authorization: AccessToken=<token>'. The token is renewed before it expires, and once more when
    Omada answers that it expired or isn't valid."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.opener = tls_opener(cfg["ca_file"])
        self._token = None
        self._expires = 0.0
        self._last = 0.0

    def _pace(self) -> None:
        wait = self._last + PACE_SECONDS - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _new_token(self) -> str:
        url = f"{self.cfg['api_url']}{TOKEN_PATH}?grant_type=client_credentials"
        body = json.dumps({"omadacId": self.cfg["omada_id"], "client_id": self.cfg["client_id"],
                           "client_secret": self.cfg["client_secret"]}, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self._pace()
        try:
            _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "access token request", self.opener)
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                code, message = _error_code(e.body)
                raise BridgeError(f"Omada refused the access token request (HTTP {e.code}{f', error {code}' if code else ''}: "
                                  f"{message}); check OMADA_ID, OMADA_CLIENT_ID and OMADA_CLIENT_SECRET, and that the "
                                  "application is in client mode") from None
            raise
        data = _json(raw, "access token request")
        if not isinstance(data, dict):
            raise BridgeError("access token request returned JSON that is not an object")
        if data.get("errorCode") != 0:
            code, message = _error_code(raw)
            raise BridgeError(f"Omada refused the access token request (error {code}: {message}); check OMADA_ID, "
                              "OMADA_CLIENT_ID and OMADA_CLIENT_SECRET, and that the application is in client mode")
        result = data.get("result") if isinstance(data.get("result"), dict) else {}
        token = result.get("accessToken")
        if not isinstance(token, str) or not token:
            raise BridgeError("access token request returned no accessToken")
        expires_in = result.get("expiresIn")
        life = float(expires_in) if isinstance(expires_in, (int, float)) and expires_in > 0 else 3600.0
        self._token = token
        self._expires = time.time() + max(0.0, life - TOKEN_MARGIN_SECONDS)
        return token

    def _token_now(self) -> str:
        if self._token and time.time() < self._expires:
            return self._token
        return self._new_token()

    def get(self, path: str, query: dict, what: str):
        """One GET with the access token. Returns the 'result' of the answer. An expired or unknown
        token is renewed and the request sent once more."""
        url = f"{self.cfg['api_url']}{path}?{urllib.parse.urlencode(query)}"
        for attempt in range(2):
            headers = {"Authorization": f"AccessToken={self._token_now()}", "Accept": "application/json"}
            self._pace()
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what, self.opener)
            except HttpStatus as e:
                code, message = _error_code(e.body)
                if e.code == 401 and attempt == 0:
                    self._token = None
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"Omada refused the {what} (HTTP {e.code}{f', error {code}' if code else ''}: "
                                      f"{message}); the application needs read access to the sites, customers or MSP "
                                      "view it reads") from None
                if e.code == 400:
                    raise BridgeError(f"Omada rejected the {what} (HTTP 400{f', error {code}' if code else ''}: "
                                      f"{message})") from None
                if e.code == 404:
                    raise BridgeError(f"Omada answered the {what} with HTTP 404; check OMADA_URL and OMADA_ID, and that "
                                      "the controller's version offers this request in its Open API") from None
                raise
            data = _json(raw, what)
            if not isinstance(data, dict):
                raise BridgeError(f"{what} returned JSON that is not an object")
            code = data.get("errorCode")
            if code in TOKEN_ERRORS and attempt == 0:
                self._token = None
                continue
            if code != 0:
                _, message = _error_code(raw)
                if code in TOKEN_ERRORS:
                    raise BridgeError(f"Omada refused the {what}: it refused a new access token too (error {code}: "
                                      f"{message})") from None
                if code == -1505 or code == -1005:
                    raise BridgeError(f"Omada refused the {what} (error {code}: {message}); give the application access "
                                      "to every site and customer it reads") from None
                raise BridgeError(f"Omada answered the {what} with error {code}: {message}") from None
            return data.get("result")
        # Not reached: the second answer above always returns or raises.
        raise BridgeError(f"Omada refused the {what}")

    def pages(self, path: str, query: dict, what: str):
        """Yields each page's list of rows, from page 1, until the rows read reach totalRows or a page
        is empty. The rows are counted, so a server that sends fewer per page than asked is read to
        the end too."""
        size = self.cfg["page_size"]
        got = 0
        for page in range(1, MAX_PAGES + 1):
            result = self.get(path, {"page": page, "pageSize": size, **query}, what)
            if not isinstance(result, dict):
                raise BridgeError(f"{what} returned a result that is not an object")
            rows = result.get("data")
            if rows is None:
                rows = []
            if not isinstance(rows, list):
                raise BridgeError(f"{what} returned data that is not a list")
            yield rows
            got += len(rows)
            total = result.get("totalRows")
            if not rows or (isinstance(total, int) and got >= total):
                return
        raise BridgeError(f"{what} had more than {MAX_PAGES} pages; the next run reads the same window again")


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
    """Events and alerts have a unique id. An audit log has none, so it is known by the hash of the
    whole record."""
    rid = record.get("id")
    if isinstance(rid, str) and rid:
        return "id:" + rid
    return "sha:" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _record_time(record: dict, now: float) -> float:
    """time is milliseconds since the epoch."""
    t = record.get("time")
    return t / 1000.0 if isinstance(t, (int, float)) and not isinstance(t, bool) and t > 0 else now


def scopes(cfg: dict, client: Omada) -> list[dict]:
    """Where to read: the controller (or, in MSP mode, the MSP view and each customer) and every site
    the application can read. Sites are listed again on every run, so new ones are picked up."""
    oid = cfg["omada_id"]
    out = []
    if cfg["msp"]:
        out.append({"scope": "msp", "id": oid, "base": f"/openapi/v1/msp/{oid}", "audit": "/audit-logs"})
        customers = {}
        for rows in client.pages(f"/openapi/v1/msp/{oid}/customers", {}, "customer list request"):
            for c in rows:
                if isinstance(c, dict) and isinstance(c.get("customerId"), str) and OMADA_ID.match(c["customerId"]):
                    customers[c["customerId"]] = str(c.get("customerName") or "")
        sites = []
        for rows in client.pages(f"/openapi/v1/msp/{oid}/sites", {}, "MSP site list request"):
            for s in rows:
                if isinstance(s, dict) and isinstance(s.get("siteId"), str) and OMADA_ID.match(s["siteId"]) \
                        and isinstance(s.get("customerId"), str) and OMADA_ID.match(s["customerId"]):
                    customers.setdefault(s["customerId"], str(s.get("customerName") or ""))
                    sites.append((s["customerId"], customers[s["customerId"]], s["siteId"], str(s.get("siteName") or "")))
        for cid, cname in customers.items():
            out.append({"scope": "customer", "id": cid, "customer_id": cid, "customer_name": cname,
                        "base": f"/openapi/v1/{cid}", "audit": "/audit-logs"})
        for cid, cname, sid, sname in sites:
            out.append({"scope": "site", "id": cid, "customer_id": cid, "customer_name": cname, "site_id": sid,
                        "site_name": sname, "base": f"/openapi/v1/{cid}/sites/{sid}", "audit": "/audit-logs"})
        return out
    out.append({"scope": "global", "id": oid, "base": f"/openapi/v1/{oid}", "audit": "/audit-logs"})
    for rows in client.pages(f"/openapi/v1/{oid}/sites", {}, "site list request"):
        for s in rows:
            if isinstance(s, dict) and isinstance(s.get("siteId"), str) and OMADA_ID.match(s["siteId"]):
                out.append({"scope": "site", "id": oid, "site_id": s["siteId"], "site_name": str(s.get("name") or ""),
                            "base": f"/openapi/v1/{oid}/sites/{s['siteId']}", "audit": "/audit-logs"})
    return out


def _label(where: dict, log: str) -> str:
    if where["scope"] == "site":
        return f"site {where['site_id']} {log}"
    return f"{where['scope']} {where['id']} {log}"


def _context(where: dict, log: str) -> dict:
    """The fields each record goes out with, in front of the record itself."""
    ctx = {RECORD_KEY: {"events": "event", "alerts": "alert", "audit": "audit"}[log],
           "omada_scope": where["scope"], "omada_id": where["id"]}
    if "customer_id" in where:
        ctx["omada_customer_id"] = where["customer_id"]
        ctx["omada_customer_name"] = where["customer_name"]
    if "site_id" in where:
        ctx["omada_site_id"] = where["site_id"]
        ctx["omada_site_name"] = where["site_name"]
    return ctx


def collect(where: dict, log: str, cfg: dict, state: dict, sink: Sink, save, client: Omada, now: float) -> int:
    """Reads one log of one scope from the end of its last window, less the overlap, to a minute
    before now, page by page, and sends the records not sent before. The window's end is saved only
    after every page of it was sent."""
    key = f"{where['scope']}/{where['id']}/{where.get('site_id', '-')}/{log}"
    cur = state.setdefault("logs", {}).setdefault(key, {})
    since = cur.get("until")
    end = now - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) \
        else (now - cfg["lookback_hours"] * 3600)
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    lo, hi = int(start * 1000), int(end * 1000)
    if log == "audit":
        path = where["base"] + where["audit"]
        query = {"sorts.time": "asc", "filters.times": json.dumps([{"timeStart": lo, "timeEnd": hi}], separators=(",", ":"))}
    else:
        path = f"{where['base']}/logs/{log}"
        query = {"filters.timeStart": lo, "filters.timeEnd": hi}
    label = _label(where, log)
    ctx = _context(where, log)
    sent = 0
    for rows in client.pages(path, query, f"{label} request"):
        fresh = {}
        for r in rows:
            if not isinstance(r, dict):
                continue
            k = _key(r)
            if k not in seen and k not in fresh:
                fresh[k] = (_record_time(r, now), r)
        if fresh:
            sink.send([{**ctx, **{f: v for f, v in r.items() if f not in ctx}} for _, r in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            if len(seen) > SEEN_LIMIT:
                cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
            sent += len(fresh)
            save()
    cur["until"] = end
    save()
    LOG.info("%s: %d sent", label, sent)
    return sent


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


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Omada | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or Omada(cfg)
    now = time.time()
    count = 0
    for where in scopes(cfg, client):
        for log in cfg["logs"]:
            count += collect(where, log, cfg, state, sink, save, client, now)
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send TP-Link Omada event, alert and audit logs to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for every run, so the certificate is read once and the token kept until it expires.
        client = Omada(cfg)
        worked = False
        while True:
            try:
                run_once(cfg, dry_run, client=client)
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
