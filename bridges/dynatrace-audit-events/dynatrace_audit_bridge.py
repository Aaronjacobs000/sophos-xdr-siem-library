#!/usr/bin/env python3
"""Pull Dynatrace audit events from Grail with the Grail Query API and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Dynatrace stores audit events (settings changes, and requests through the API gateway, including
sign-ins) as dt.system.events with event.kind "AUDIT_EVENT", for a year. The classic audit logs API
(/api/v2/auditlogs) isn't available in the latest Dynatrace environments, and OpenPipeline doesn't
forward these events, so this script runs a DQL query for each new window:

  POST https://{environment}.apps.dynatrace.com/platform/storage/query/v1/query:execute
  GET  https://{environment}.apps.dynatrace.com/platform/storage/query/v1/query:poll?request-token=...

with a platform token, or an OAuth client's access token from https://sso.dynatrace.com/sso/oauth2/token,
that can read only audit events (storage:system:read and storage:buckets:read, limited by policy
to event.kind "AUDIT_EVENT" and the dt_system_events bucket).

Each record goes on as Dynatrace returns it, with "dynatrace_record" first ("audit") and the
environment ID, so the library parser in parsers/dynatrace/dynatrace-audit-events can normalize it.

The request and response shapes follow Dynatrace's Platform API reference. Configuration comes from
environment variables (see README.md). A window's end only moves after HTTP Ingest accepted every
record in it. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import calendar
import gzip
import http.client
import json
import logging
import os
import random
import re
import socket
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("dynatrace_audit_bridge")
USER_AGENT = f"parser-studio-dynatrace-audit-bridge/{__version__}"
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
# The most records one query asks for: DYNATRACE_PAGE_SIZE's limit, and how far a page grows to
# get past records that share one time.
MAX_PAGE_SIZE = 100000
RECORD_KEY = "dynatrace_record"
ENV_KEY = "dynatrace_environment"
QUERY_PATH = "/platform/storage/query/v1/query"
# Dynatrace keeps audit events in Grail for a year.
RETENTION_DAYS = 365
NS = 1_000_000_000
# Each poll asks Dynatrace to hold the answer this long while the query runs.
POLL_WAIT_MS = 10000
# Only the scopes that read audit events. Policy statements on the client's service user narrow
# them to event.kind "AUDIT_EVENT" and the dt_system_events bucket.
SCOPES = "storage:system:read storage:buckets:read"


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """Dynatrace or HTTP Ingest couldn't be reached, even after the retries, or a query didn't
    finish in time. With --interval the bridge logs it and tries again at the next interval."""


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


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "env_url": (_env(env, "DYNATRACE_ENV_URL") or "").rstrip("/"),
        "platform_token": _env(env, "DYNATRACE_PLATFORM_TOKEN"),
        "client_id": _env(env, "DYNATRACE_CLIENT_ID"),
        "client_secret": _env(env, "DYNATRACE_CLIENT_SECRET"),
        "account_urn": _env(env, "DYNATRACE_ACCOUNT_URN"),
        "token_url": _env(env, "DYNATRACE_TOKEN_URL", "https://sso.dynatrace.com/sso/oauth2/token"),
        "page_size": _number(env, "DYNATRACE_PAGE_SIZE", "1000", low=1, high=MAX_PAGE_SIZE),
        "query_timeout": _number(env, "DYNATRACE_QUERY_TIMEOUT", "300", float, low=1, high=3600),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "dynatrace_audit_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=RETENTION_DAYS * 24),
        "delay_seconds": _number(env, "BRIDGE_DELAY_SECONDS", "300", high=86400),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["env_url"]:
        raise BridgeError("DYNATRACE_ENV_URL is required: the environment's platform URL, such as "
                          "https://abc12345.apps.dynatrace.com")
    _refuse_user_info(cfg["env_url"], "DYNATRACE_ENV_URL")
    _require_https(cfg["env_url"], "DYNATRACE_ENV_URL")
    parts = urllib.parse.urlsplit(cfg["env_url"])
    if parts.path or parts.query or parts.fragment or not parts.hostname:
        raise BridgeError("DYNATRACE_ENV_URL must be the environment's address with no path, such as "
                          "https://abc12345.apps.dynatrace.com")
    # The environment ID is the first label of the host name, as in abc12345.apps.dynatrace.com.
    cfg["environment"] = parts.hostname.split(".")[0]
    oauth = [cfg["client_id"], cfg["client_secret"], cfg["account_urn"]]
    if cfg["platform_token"] and any(oauth):
        raise BridgeError("set DYNATRACE_PLATFORM_TOKEN, or DYNATRACE_CLIENT_ID, DYNATRACE_CLIENT_SECRET and "
                          "DYNATRACE_ACCOUNT_URN, not both")
    if not cfg["platform_token"] and not all(oauth):
        raise BridgeError("DYNATRACE_PLATFORM_TOKEN is required, or DYNATRACE_CLIENT_ID, DYNATRACE_CLIENT_SECRET "
                          "and DYNATRACE_ACCOUNT_URN for an OAuth client")
    if cfg["account_urn"] and not re.fullmatch(r"urn:dtaccount:[0-9A-Fa-f-]{8,64}", cfg["account_urn"]):
        raise BridgeError("DYNATRACE_ACCOUNT_URN must look like urn:dtaccount:<account UUID>")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["token_url"], "DYNATRACE_TOKEN_URL")
    _require_https(cfg["token_url"], "DYNATRACE_TOKEN_URL")
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
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
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


def _dt_error(body: bytes) -> str:
    """Dynatrace's platform APIs answer {"error": {"code", "message", "details": {"errorType",
    "missingScopes", "missingPermissions"}}}, and the token endpoint {"error", "error_description"}.
    Returns a short message."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    err = data.get("error")
    if isinstance(err, dict):
        text = str(err.get("message") or "")
        details = err.get("details") if isinstance(err.get("details"), dict) else {}
        missing = [str(x) for key in ("missingScopes", "missingPermissions") for x in (details.get(key) or [])
                   if isinstance(details.get(key), list)]
        if missing:
            text = f"{text} (missing: {', '.join(missing)})" if text else "missing: " + ", ".join(missing)
    else:
        text = str(data.get("error_description") or err or data.get("message") or "")
    return text[:200] or "no message"


# ---------------------------------------------------------------- Dynatrace

class Dynatrace:
    """Runs DQL queries with the Grail Query API. With a platform token, every request carries it
    as 'Authorization: Bearer'. With an OAuth client, an access token comes from the client
    credentials grant, is renewed a minute before it expires, and once more if Dynatrace refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        # The credentials go in the form body, not the URL, so no proxy or server log keeps them.
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.cfg["client_id"],
                                       "client_secret": self.cfg["client_secret"], "scope": SCOPES,
                                       "resource": self.cfg["account_urn"]}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        try:
            _, raw = _request("POST", self.cfg["token_url"], headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"Dynatrace refused the OAuth client credentials (HTTP {e.code}): {_dt_error(e.body)}; "
                                  "check DYNATRACE_CLIENT_ID, DYNATRACE_CLIENT_SECRET and DYNATRACE_ACCOUNT_URN, and that "
                                  "the client has the storage:system:read and storage:buckets:read scopes") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 300)
        except (TypeError, ValueError):
            lifetime = 300.0
        self._token = token
        self._expires = time.monotonic() + max(30.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if self.cfg["platform_token"]:
            return self.cfg["platform_token"]
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def _call(self, method: str, url: str, body: bytes | None, what: str) -> bytes:
        renewable = not self.cfg["platform_token"]
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json"}
            if body:
                headers["Content-Type"] = "application/json"
            try:
                _, raw = _request(method, url, headers, body, self.cfg["timeout"], what)
                return raw
            except HttpStatus as e:
                if e.code == 401 and renewable and not renew:
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"Dynatrace refused the {what} (HTTP {e.code}): {_dt_error(e.body)}; check the token, "
                                      "its scopes (storage:system:read and storage:buckets:read) and the policy statements "
                                      "on its user") from None
                if e.code == 400:
                    raise BridgeError(f"Dynatrace refused the {what} (HTTP 400): {_dt_error(e.body)}") from None
                raise
        raise BridgeError(f"{what} failed")

    def _answer(self, raw: bytes, what: str) -> dict:
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
        return data

    def _cancel(self, request_token: str) -> None:
        url = f"{self.cfg['env_url']}{QUERY_PATH}:cancel?{urllib.parse.urlencode({'request-token': request_token})}"
        try:
            self._call("POST", url, b"", "query cancel")
        except BridgeError as e:
            LOG.warning("couldn't cancel the query: %s", e)

    def query(self, dql: str, start_ns: int, end_ns: int, limit: int) -> list[dict]:
        """Runs one query and returns its records. A query that is still running after the first
        answer is polled until it finishes, for up to DYNATRACE_QUERY_TIMEOUT seconds; past that it is
        cancelled and the run ends with a NetworkError, so the window stays where it was."""
        # The DQL filter sets the exact window. The query's timeframe is a second wider on each
        # side, since the docs don't say whether its bounds are inclusive.
        body = json.dumps({"query": dql, "defaultTimeframeStart": _iso(start_ns - NS),
                           "defaultTimeframeEnd": _iso(end_ns + NS), "timezone": "UTC",
                           "maxResultRecords": limit,
                           "requestTimeoutMilliseconds": POLL_WAIT_MS}).encode("utf-8")
        data = self._answer(self._call("POST", f"{self.cfg['env_url']}{QUERY_PATH}:execute", body, "query request"),
                            "query request")
        request_token = data.get("requestToken")
        deadline = time.monotonic() + self.cfg["query_timeout"]
        while True:
            state = data.get("state")
            if state == "SUCCEEDED":
                result = data.get("result")
                records = result.get("records") if isinstance(result, dict) else None
                if not isinstance(records, list):
                    raise BridgeError("the query succeeded but its answer has no records list")
                return [r for r in records if isinstance(r, dict)]
            if state in ("NOT_STARTED", "RUNNING"):
                if not isinstance(request_token, str) or not request_token:
                    raise BridgeError("the query is still running but the answer has no requestToken to poll with")
                if time.monotonic() >= deadline:
                    self._cancel(request_token)
                    raise NetworkError(f"the query didn't finish within {self.cfg['query_timeout']:g} seconds, so it was "
                                       "cancelled; the next run tries the same window again")
                params = urllib.parse.urlencode({"request-token": request_token, "request-timeout-milliseconds": POLL_WAIT_MS})
                try:
                    raw = self._call("GET", f"{self.cfg['env_url']}{QUERY_PATH}:poll?{params}", None, "query poll")
                except HttpStatus as e:
                    if e.code in (404, 410):
                        raise NetworkError("the query's result was gone before the bridge read it; the next run tries "
                                           "the same window again") from None
                    raise
                data = self._answer(raw, "query poll")
                continue
            if state == "RESULT_GONE":
                raise NetworkError("the query's result was gone before the bridge read it; the next run tries the same "
                                   "window again")
            raise BridgeError(f"the query ended in state {state if isinstance(state, str) and state else 'unknown'}")


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

_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9})\d*)?(Z|z|[+-]\d{2}:?\d{2})?")


def _ns(value) -> int | None:
    """A record's timestamp in nanoseconds since the epoch. Grail gives ISO 8601 in UTC with nine
    fraction digits, such as 2026-10-15T01:25:23.987000000Z, or epoch nanoseconds as a number.
    Parsed by hand, so it reads the same on Python 3.9 to 3.13 and keeps every digit."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    m = _TIME.fullmatch(str(value or "").strip())
    if not m:
        return None
    year, month, day, hour, minute, second, fraction, zone = m.groups()
    try:
        moment = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc)
    except ValueError:
        return None
    seconds = calendar.timegm(moment.utctimetuple())
    if zone and zone not in ("Z", "z"):
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        seconds -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    return seconds * NS + int((fraction or "").ljust(9, "0"))


def _iso(ns: int) -> str:
    seconds, fraction = divmod(ns, NS)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def dql(start_ns: int, end_ns: int, page_size: int) -> str:
    """Audit events from start (inclusive) to end (exclusive), oldest first. event.id breaks ties,
    so pages always come in the same order. toTimestamp takes nanoseconds since the epoch as a long,
    so the bounds keep every digit."""
    return ("fetch dt.system.events\n"
            "| filter event.kind == \"AUDIT_EVENT\"\n"
            f"| filter timestamp >= toTimestamp({int(start_ns)}) and timestamp < toTimestamp({int(end_ns)})\n"
            "| sort timestamp asc, event.id asc\n"
            f"| limit {page_size}")


def _id(rec: dict) -> str:
    eid = rec.get("event.id")
    if isinstance(eid, str) and eid:
        return eid
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tag(rec: dict, cfg: dict) -> dict:
    out = {RECORD_KEY: "audit", ENV_KEY: cfg["environment"]}
    out.update({k: v for k, v in rec.items() if k not in (RECORD_KEY, ENV_KEY)})
    return out


def collect(cfg: dict, state: dict, sink: Sink, save, client: Dynatrace, now_ns: int) -> int:
    """Reads the audit events from where the last window ended to BRIDGE_DELAY_SECONDS before now,
    a page at a time. A full page means there may be more, so the next page starts at the time of
    the page's last record and skips the records at that time it already sent. The saved position
    only moves after HTTP Ingest accepted a page."""
    cur = state.setdefault(cfg["environment"], {})
    end = now_ns - cfg["delay_seconds"] * NS
    cursor = cur.get("cursor_ns")
    if isinstance(cursor, int) and not isinstance(cursor, bool):
        # A saved position later than the window's end (the clock went back) counts as the end.
        start = min(cursor, end)
        boundary = {x for x in (cur.get("boundary_ids") or []) if isinstance(x, str)}
    else:
        start = now_ns - int(cfg["lookback_hours"] * 3600) * NS
        boundary = set()
    floor = now_ns - RETENTION_DAYS * 86400 * NS
    if start < floor:
        start, boundary = floor, set()
    if start >= end:
        LOG.info("audit events: no new window yet")
        return 0
    sent = 0
    limit = cfg["page_size"]
    for _ in range(MAX_PAGES):
        records = client.query(dql(start, end, limit), start, end, limit)
        page = []
        for rec in records:
            ts = _ns(rec.get("timestamp"))
            if ts is None:
                raise BridgeError("a record has no timestamp the bridge can read, so the window can't move past it")
            page.append((ts, rec))
        fresh = [tag(rec, cfg) for ts, rec in page if not (ts == start and _id(rec) in boundary)]
        if fresh:
            sink.send(fresh)
            sent += len(fresh)
        if len(page) < limit:
            cur.update({"cursor_ns": end, "boundary_ids": []})
            save()
            break
        last = max(ts for ts, _ in page)
        at_last = {_id(rec) for ts, rec in page if ts == last}
        if last == start:
            # Every record of a full page has the window's start time, so a page of the same size
            # would come back the same. The next one is twice as large, until it gets past them.
            boundary |= at_last
            cur.update({"cursor_ns": start, "boundary_ids": sorted(boundary)})
            save()
            if limit >= MAX_PAGE_SIZE:
                raise BridgeError(f"more than {MAX_PAGE_SIZE:,} audit events share the time {_iso(start)}, so the "
                                  "bridge can't page past them")
            limit = min(limit * 2, MAX_PAGE_SIZE)
            continue
        boundary, start, limit = at_last, last, cfg["page_size"]
        cur.update({"cursor_ns": start, "boundary_ids": sorted(boundary)})
        save()
    else:
        LOG.warning("audit events: stopped after %d pages; the next run goes on from there", MAX_PAGES)
    LOG.info("audit events: %d sent", sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = Dynatrace(cfg)
    count = collect(cfg, state, sink, save, client, time.time_ns())
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
    ap = argparse.ArgumentParser(description="Send Dynatrace audit events to Sophos NG-SIEM HTTP Ingest.")
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
