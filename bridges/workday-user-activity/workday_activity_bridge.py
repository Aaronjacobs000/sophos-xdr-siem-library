#!/usr/bin/env python3
"""Pull Workday user activity logs from the Workday REST API and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Workday logs who ran which task or report, read, changed or downloaded which data, from where,
when User Activity Logging is turned on for the tenant. It offers the log through the Privacy
service of its REST API, which is pull only, so this script reads it with an API client for
integrations and the refresh token of an integration system user:

  POST https://<host>/ccx/oauth2/<tenant>/token                       (refresh_token grant)
  GET  https://<host>/ccx/api/privacy/v1/<tenant>/activityLogging     (from, to, limit, offset)

Each entry goes out with "workday_record" first ("user_activity") and "workday_tenant", so the
library parser in parsers/workday/workday-user-activity can recognize and normalize it.

Each run reads from the end of its last window, less an overlap, to three minutes before now, in
windows of BRIDGE_WINDOW_MINUTES, paging with offset until it reaches total. Entries carry no ID,
so repeats are dropped by a hash of the whole entry. The request and response shapes follow
Workday's Privacy API reference. Configuration comes from environment variables (see README.md).
A window's end only moves after HTTP Ingest accepted every entry in it. --dry-run prints what
would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
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
LOG = logging.getLogger("workday_activity_bridge")
USER_AGENT = f"sophos-xdr-siem-library-workday-activity-bridge/{__version__}"
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
RECORD_KEY = "workday_record"
RECORD = "user_activity"
TENANT_KEY = "workday_tenant"
# Workday keeps user activity for 30 days.
RETENTION_DAYS = 30
# Workday writes the log about every 2 minutes, so a window ends 3 minutes before now.
END_MARGIN_SECONDS = 180
# instancesReturned times this is the most entries one query returns.
INSTANCES = 10000
MAX_INSTANCES_RETURNED = 25
# A window this short that still reaches the cap is read with instancesReturned at its maximum.
MIN_WINDOW_SECONDS = 60
SEEN_LIMIT = 200000
TENANT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


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


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "host_url": (_env(env, "WORKDAY_HOST_URL") or "").rstrip("/"),
        "tenant": _env(env, "WORKDAY_TENANT"),
        "client_id": _env(env, "WORKDAY_CLIENT_ID"),
        "client_secret": _env(env, "WORKDAY_CLIENT_SECRET"),
        "refresh_token": _env(env, "WORKDAY_REFRESH_TOKEN"),
        "page_limit": _number(env, "WORKDAY_PAGE_LIMIT", "1000", low=1, high=1000),
        "instances": _number(env, "WORKDAY_INSTANCES_RETURNED", "1", low=1, high=MAX_INSTANCES_RETURNED),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "workday_activity_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=RETENTION_DAYS * 24),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "window_minutes": _number(env, "BRIDGE_WINDOW_MINUTES", "60", low=1, high=1440),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "180", float, low=0.001),
    }
    missing = [name for name, key in (("WORKDAY_HOST_URL", "host_url"), ("WORKDAY_TENANT", "tenant"),
                                      ("WORKDAY_CLIENT_ID", "client_id"), ("WORKDAY_CLIENT_SECRET", "client_secret"),
                                      ("WORKDAY_REFRESH_TOKEN", "refresh_token")) if not cfg[key]]
    if missing:
        raise BridgeError(f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} required: the services host, the "
                          "tenant name, and the API client and refresh token from Register API Client for Integrations")
    if not TENANT.match(cfg["tenant"]):
        raise BridgeError("WORKDAY_TENANT takes the tenant name, as in the token endpoint /ccx/oauth2/<tenant>/token")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["host_url"], "WORKDAY_HOST_URL")
    _require_https(cfg["host_url"], "WORKDAY_HOST_URL")
    parts = urllib.parse.urlsplit(cfg["host_url"])
    if parts.path or parts.query or parts.fragment or not parts.hostname:
        raise BridgeError("WORKDAY_HOST_URL takes the scheme and host only, such as https://wd2-impl-services1.workday.com, "
                          "from the Workday REST API Endpoint on View API Clients")
    cfg["token_url"] = f"{cfg['host_url']}/ccx/oauth2/{cfg['tenant']}/token"
    cfg["activity_url"] = f"{cfg['host_url']}/ccx/api/privacy/v1/{cfg['tenant']}/activityLogging"
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


def _workday_error(body: bytes) -> str:
    """Workday answers API errors with {"error": ..., "errors": [{"error": ...}]}, and the token
    endpoint with OAuth's {"error": ..., "error_description": ...}. Returns a short message."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    message = data.get("error_description") or data.get("error") or ""
    details = data.get("errors")
    if isinstance(details, list) and details and isinstance(details[0], dict) and details[0].get("error"):
        detail = str(details[0]["error"])
        message = f"{message}: {detail}" if message and detail != message else detail
    return str(message)[:200] or "no message"


# ---------------------------------------------------------------- Workday REST API

class Workday:
    """Gets an access token with the refresh token grant, the API client's ID and secret in HTTP
    Basic, and reads the activityLogging resource with 'Authorization: Bearer <token>'. A token is
    renewed a minute before Workday says it expires (after an hour when it doesn't say), and once
    more if Workday refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        basic = base64.b64encode(f"{self.cfg['client_id']}:{self.cfg['client_secret']}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        body = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": self.cfg["refresh_token"]}).encode()
        try:
            _, _, raw = _request("POST", self.cfg["token_url"], headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"Workday refused the token request (HTTP {e.code}): {_workday_error(e.body)}; check "
                                  "WORKDAY_CLIENT_ID, WORKDAY_CLIENT_SECRET, WORKDAY_REFRESH_TOKEN (generating a new one "
                                  "revokes the old one) and WORKDAY_TENANT, and that OAuth 2.0 clients are enabled in Edit "
                                  "Tenant Setup - Security") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 0)
        except (TypeError, ValueError):
            lifetime = 0.0
        # Without enforced 60 minute expiry, Workday gives expires_in as -1 or leaves it out.
        if not 0 < lifetime < 10 ** 7:
            lifetime = 3600.0
        self._token = token
        self._expires = time.monotonic() + max(60.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def activity(self, params: dict) -> dict:
        """One page of user activity entries, with total, the number of entries the query matched."""
        url = f"{self.cfg['activity_url']}?{urllib.parse.urlencode(params)}"
        what = "activityLogging request"
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json"}
            try:
                _, _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
                break
            except HttpStatus as e:
                if e.code == 401 and not renew:
                    LOG.info("Workday refused the access token; getting a new one")
                    continue
                if e.code == 401:
                    raise BridgeError(f"Workday refused the access token (HTTP 401): {_workday_error(e.body)}") from None
                if e.code == 403:
                    raise BridgeError(f"Workday refused the {what} (HTTP 403): {_workday_error(e.body)}; the API client "
                                      "needs the System scope, and the integration system user's security group needs Get "
                                      "and View on the System Auditing domain") from None
                if e.code == 404:
                    raise BridgeError(f"Workday couldn't find the {what} (HTTP 404): {_workday_error(e.body)}; check "
                                      "WORKDAY_HOST_URL (the services host) and WORKDAY_TENANT") from None
                if e.code == 400:
                    raise BridgeError(f"Workday rejected the {what} (HTTP 400): {_workday_error(e.body)}; the reference "
                                      "gives 100 as the most per page in one place and 1000 in another, so if the limit is "
                                      "refused, set WORKDAY_PAGE_LIMIT to 100") from None
                raise
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
        return data


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

def _fromisoformat(text: str) -> datetime:
    """datetime.fromisoformat, the same on Python 3.9 to 3.13. Before 3.11 it takes no Z, only 3 or 6
    fraction digits and only +HH:MM offsets (no version takes z), so the text is rewritten first."""
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, rest = text.split(".", 1)
        # The fraction is the digits right after the point. An offset after them keeps its place.
        tail = rest.lstrip("0123456789")
        text = head + "." + (rest[:len(rest) - len(tail)] + "000000")[:6] + tail
    if text[-5:-4] in ("+", "-") and text[-4:].isdigit():
        text = text[:-2] + ":" + text[-2:]  # +1000 becomes +10:00
    return datetime.fromisoformat(text)


def _parse_time(value) -> float | None:
    """requestTime is ISO 8601, in UTC with milliseconds such as 2026-10-03T07:00:00.000Z. A time
    with no zone is read as UTC."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _wd_time(epoch: float) -> str:
    """from and to take {yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z, in UTC."""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key(entry: dict) -> str:
    """Entries have no ID, so each is known by the hash of the whole entry."""
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _total(data: dict) -> int | None:
    value = data.get("total")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


class _Split(Exception):
    """A window matched as many entries as one query can return, so it is read in halves."""


def read_window(cfg: dict, seen: dict, sink: Sink, save, client: Workday, start: int, end: int, instances: int,
                now: float) -> int:
    """Reads one window, a second before start to end, paging with offset until offset reaches
    total, and sends the entries not sent before. One query returns at most instances times 10,000
    entries, so a window that matches that many raises _Split before anything is sent, unless it
    is already the shortest window, which is read with instancesReturned at its maximum."""
    cap = instances * INSTANCES
    # The window starts a second early, so an entry on the boundary second is never missed,
    # whichever ends Workday includes; the repeat is dropped.
    params = {"from": _wd_time(start - 1), "to": _wd_time(end), "limit": cfg["page_limit"], "offset": 0,
              "instancesReturned": instances}
    offset, sent = 0, 0
    for _ in range(MAX_PAGES):
        data = client.activity(dict(params, offset=offset))
        rows = data.get("data") or []
        if not isinstance(rows, list):
            raise BridgeError("activityLogging request returned data that is not a list")
        total = _total(data)
        if offset == 0 and total is not None and total >= cap:
            if end - start > MIN_WINDOW_SECONDS:
                raise _Split()
            if instances < MAX_INSTANCES_RETURNED:
                return read_window(cfg, seen, sink, save, client, start, end, MAX_INSTANCES_RETURNED, now)
            LOG.warning("%s to %s matched %d entries, and Workday returns at most %d for one query; the rest of that "
                        "minute can't be read", _wd_time(start), _wd_time(end), total, cap)
        fresh = {}
        for e in rows:
            if not isinstance(e, dict):
                continue
            k = _key(e)
            if k not in seen and k not in fresh:
                t = _parse_time(e.get("requestTime"))
                fresh[k] = (t if t is not None else now, e)
        if fresh:
            batch = sorted(fresh.values(), key=lambda te: te[0])
            sink.send([{RECORD_KEY: RECORD, TENANT_KEY: cfg["tenant"],
                        **{f: v for f, v in e.items() if f not in (RECORD_KEY, TENANT_KEY)}} for _, e in batch])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        offset += len(rows)
        # A page can hold fewer entries than the limit, so the end is an empty page or reaching total.
        if not rows or (total is not None and offset >= min(total, cap)):
            return sent
    raise BridgeError(f"activityLogging request still had more after {MAX_PAGES} pages; shorten BRIDGE_WINDOW_MINUTES")


def collect(cfg: dict, state: dict, sink: Sink, save, client: Workday, now: float) -> int:
    """Reads from the end of the last window, less the overlap, to three minutes before now, in
    windows of BRIDGE_WINDOW_MINUTES, oldest first. The end moves after each window was sent."""
    cur = state.setdefault("activity", {})
    since = cur.get("until")
    end = int(now) - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) else (now - cfg["lookback_hours"] * 3600)
    # Workday keeps user activity for 30 days, so a window never starts before that.
    start = int(min(max(start, now - RETENTION_DAYS * 86400), end))
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    step = cfg["window_minutes"] * 60
    windows = [(a, min(a + step, end)) for a in range(start, end, step)]
    sent = 0
    while windows:
        a, b = windows.pop(0)
        try:
            sent += read_window(cfg, seen, sink, save, client, a, b, cfg["instances"], now)
        except _Split:
            middle = (a + b) // 2
            LOG.info("%s to %s matched too many entries for one query; reading it in halves", _wd_time(a), _wd_time(b))
            windows[:0] = [(a, middle), (middle, b)]
            continue
        if len(seen) > SEEN_LIMIT:
            cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
        cur["until"] = b
        save()
    LOG.info("%d sent", sent)
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
    count = collect(cfg, state, sink, save, Workday(cfg), time.time())
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
    ap = argparse.ArgumentParser(description="Send Workday user activity logs to Sophos NG-SIEM HTTP Ingest.")
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
