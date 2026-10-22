#!/usr/bin/env python3
"""Pull Citrix Cloud and Citrix DaaS logs from the Citrix Cloud APIs and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Citrix offers these logs through REST APIs, which are pull only. This script reads them with a
Citrix Cloud service principal, in client credentials mode:

  POST https://api.cloud.com/cctrustoauth2/<customerId>/tokens/clients                 (the token)
  GET  https://api.cloud.com/systemlog/records                 Citrix Cloud System Log: platform admin events
  GET  https://api.cloud.com/cvad/manage/me                    the DaaS sites, unless CITRIX_SITE_IDS names them
  GET  https://api.cloud.com/cvad/manage/ConfigLog/Operations  DaaS Configuration Logging: each site's admin changes
  GET  https://api.cloud.com/monitorodata/Connections          DaaS Monitor: each session connection, with its
                                                               session, user and machine

Each record goes out with "citrix_record" first (systemlog, configlog or connection) and
"citrix_customer_id", plus "citrix_site_id" for Configuration Logging, then the record as Citrix
returns it, so the library parsers in parsers/citrix/citrix-daas-and-citrix-cloud can recognize and
normalize it. Citrix's System Log API reference spells record keys in camelCase and its examples in
PascalCase, so the bridge writes each System Log record's keys with a capital first letter.

Each run reads each log from the end of its last window, less an overlap, to a minute before now,
and drops records it already sent: connections by their Id, the others by a hash of the whole
record. The request and response shapes follow Citrix's System Log, DaaS REST API and Monitor OData
API references. Configuration comes from environment variables (see README.md). A window's end only
moves after HTTP Ingest accepted every record in it. --dry-run prints what would be sent and changes
nothing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import logging
import math
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
LOG = logging.getLogger("citrix_cloud_logs_bridge")
USER_AGENT = f"sophos-xdr-siem-library-citrix-cloud-logs-bridge/{__version__}"
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
RECORD_KEY = "citrix_record"
CUSTOMER_KEY = "citrix_customer_id"
SITE_KEY = "citrix_site_id"
LOGS = ("systemlog", "configlog", "connections")
RECORD = {"systemlog": "systemlog", "configlog": "configlog", "connections": "connection"}
# System Log takes at most 200 records a page; Configuration Logging defaults to 250.
SYSTEMLOG_LIMIT = 200
CONFIGLOG_LIMIT = 250
# Configuration Logging is read by whole days back from now, up to the 180 days DaaS keeps.
CONFIGLOG_MAX_DAYS = 180
# A window ends this long before now, so a clock a little ahead of Citrix's never asks for the future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000
# A token is renewed this long before Citrix says it expires.
TOKEN_MARGIN_SECONDS = 60
CUSTOMER_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SITE_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")

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
        "api_url": (_env(env, "CITRIX_API_URL", "https://api.cloud.com") or "").rstrip("/"),
        "customer_id": _env(env, "CITRIX_CUSTOMER_ID"),
        "client_id": _env(env, "CITRIX_CLIENT_ID"),
        "client_secret": _env(env, "CITRIX_CLIENT_SECRET"),
        "logs": [x.lower() for x in _list(env, "CITRIX_LOGS", ",".join(LOGS))],
        "site_ids": _list(env, "CITRIX_SITE_IDS"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "citrix_cloud_logs_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=2160),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment:
        raise BridgeError("CITRIX_API_URL takes the scheme, host and port only, such as https://api.cloud.com")
    _refuse_user_info(cfg["api_url"], "CITRIX_API_URL")
    _require_https(cfg["api_url"], "CITRIX_API_URL")
    if not cfg["customer_id"] or not CUSTOMER_ID.match(cfg["customer_id"]):
        raise BridgeError("CITRIX_CUSTOMER_ID is required: the Customer ID shown on the API access page of Citrix Cloud")
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise BridgeError("CITRIX_CLIENT_ID and CITRIX_CLIENT_SECRET are required: the client ID and secret of a Citrix Cloud "
                          "service principal")
    if not cfg["logs"] or any(x not in LOGS for x in cfg["logs"]):
        raise BridgeError("CITRIX_LOGS takes systemlog, configlog and connections, separated by commas")
    if any(not SITE_ID.match(x) for x in cfg["site_ids"]):
        raise BridgeError("CITRIX_SITE_IDS takes DaaS site IDs, separated by commas")
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
    """timestamp is RFC 3339 in UTC, such as 2026-10-14T00:12:44.123Z."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _cc_time(epoch: float) -> str:
    """System Log and OData take times in UTC, sent here to the whole second."""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _configlog_time(op: dict) -> float | None:
    """FormattedStartTime is RFC 3339. StartTime is a local-format text such as 12/21/2020 : 3:21:12 PM,
    in UTC since the bridge asks with X-TimeZone: UTC; it is read only when FormattedStartTime is missing."""
    t = _parse_time(op.get("FormattedStartTime"))
    if t is not None:
        return t
    try:
        return datetime.strptime(str(op.get("StartTime") or "").strip(), "%m/%d/%Y : %I:%M:%S %p") \
            .replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _get(data: dict, name: str):
    """A key read alike in PascalCase and camelCase: Citrix's docs and API references differ."""
    if name in data:
        return data[name]
    return data.get(name[:1].lower() + name[1:])


def _message(body: bytes) -> str:
    """Citrix answers errors with {"Error": {"Message": ...}}, {"detail": ...} or {"error_description": ...}."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    err = data.get("Error") if isinstance(data.get("Error"), dict) else {}
    text = err.get("Message") or data.get("ErrorMessage") or data.get("detail") or data.get("error_description") \
        or data.get("message") or data.get("Message") or data.get("error")
    return " ".join(str(text or "").split())[:200] or "no message"


# ---------------------------------------------------------------- Citrix Cloud APIs

class Citrix:
    """Calls the Citrix Cloud APIs with a bearer token from the client credentials grant, sent as
    'Authorization: CwsAuth Bearer=<token>' with Citrix-CustomerId. A token lasts an hour; it is
    renewed before it expires, and once more when Citrix refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        url = f"{self.cfg['api_url']}/cctrustoauth2/{urllib.parse.quote(self.cfg['customer_id'], safe='')}/tokens/clients"
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.cfg["client_id"],
                                       "client_secret": self.cfg["client_secret"]}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        try:
            _, _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"Citrix Cloud refused the token request (HTTP {e.code}: {_message(e.body)}); check "
                                  "CITRIX_CUSTOMER_ID, CITRIX_CLIENT_ID and CITRIX_CLIENT_SECRET, and CITRIX_API_URL for "
                                  "your region") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise BridgeError("token request returned no access_token")
        # Citrix gives expires_in as text, such as "3600".
        try:
            life = float(data.get("expires_in"))
        except (TypeError, ValueError):
            life = 3600.0
        life = life if 0 < life < 10 ** 7 else 3600.0
        self._token = token
        self._expires = time.time() + max(0.0, life - TOKEN_MARGIN_SECONDS)
        return token

    def _token_now(self) -> str:
        if self._token and time.time() < self._expires:
            return self._token
        return self._new_token()

    def get(self, url: str, what: str, extra: dict | None = None) -> dict:
        """One GET. An expired or refused token is renewed and the request sent once more."""
        for attempt in range(2):
            headers = {"Authorization": f"CwsAuth Bearer={self._token_now()}", "Citrix-CustomerId": self.cfg["customer_id"],
                       "Accept": "application/json", **(extra or {})}
            try:
                _, _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
            except HttpStatus as e:
                if e.code == 401 and attempt == 0:
                    self._token = None
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"Citrix Cloud refused the {what} (HTTP {e.code}: {_message(e.body)}); the service principal "
                                      "needs a role that can read it") from None
                if e.code == 404:
                    raise BridgeError(f"Citrix Cloud answered the {what} with HTTP 404 ({_message(e.body)}); check "
                                      "CITRIX_API_URL, CITRIX_CUSTOMER_ID and CITRIX_SITE_IDS, and that the service is "
                                      "in your Citrix Cloud") from None
                if e.code == 400:
                    raise BridgeError(f"Citrix Cloud rejected the {what} (HTTP 400: {_message(e.body)})") from None
                raise
            data = _json(raw, what)
            if not isinstance(data, dict):
                raise BridgeError(f"{what} returned JSON that is not an object")
            return data
        raise BridgeError(f"Citrix Cloud refused the {what}")

    def sites(self) -> list[str]:
        """The DaaS sites of the customer, from /cvad/manage/me."""
        data = self.get(f"{self.cfg['api_url']}/cvad/manage/me", "site list request")
        out = []
        for customer in data.get("Customers") or []:
            if isinstance(customer, dict) and str(customer.get("Id") or "").lower() == self.cfg["customer_id"].lower():
                for site in customer.get("Sites") or []:
                    sid = site.get("Id") if isinstance(site, dict) else None
                    if isinstance(sid, str) and SITE_ID.match(sid):
                        out.append(sid)
        return out


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

def _hash(record: dict) -> str:
    return "sha:" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                                   .encode("utf-8")).hexdigest()[:32]


def _key(log: str, record: dict) -> str:
    """A connection keeps its Id as it changes, so it is sent once. A System Log record can have no
    RecordId, and a configuration operation changes when it completes, so those are known by a hash."""
    if log == "connections" and isinstance(record.get("Id"), (int, str)) and not isinstance(record.get("Id"), bool):
        return f"id:{record['Id']}"
    return _hash(record)


def _query(params: dict) -> str:
    """OData's $ names and parentheses stay as they are; everything else is percent-encoded."""
    return "&".join(f"{k}={urllib.parse.quote(str(v), safe='(),;=:$')}" for k, v in params.items())


class Window:
    """One log's window: from the end of the last, less the overlap, to a minute before now, and the
    records already sent within it."""

    def __init__(self, cfg: dict, state: dict, key: str, now: float):
        self.cur = state.setdefault("logs", {}).setdefault(key, {})
        since = self.cur.get("until")
        self.end = now - END_MARGIN_SECONDS
        # A saved end later than now (the clock went back) counts as now.
        start = (min(since, self.end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) and not isinstance(since, bool) \
            else (now - cfg["lookback_hours"] * 3600)
        self.start = min(start, self.end - 1)
        self.seen = {k: t for k, t in (self.cur.get("seen") or {}).items()
                     if isinstance(t, (int, float)) and t >= self.start - 3600}
        self.cur["seen"] = self.seen
        self.sent = 0

    def send(self, sink: "Sink", save, items: list[tuple[str, float, dict]]) -> None:
        fresh = {}
        for k, t, rec in items:
            if k not in self.seen and k not in fresh:
                fresh[k] = (t, rec)
        if not fresh:
            return
        sink.send([rec for _, rec in fresh.values()])
        # Only now that HTTP Ingest took them do they count as sent.
        self.seen.update({k: t for k, (t, _) in fresh.items()})
        if len(self.seen) > SEEN_LIMIT:
            self.cur["seen"] = self.seen = dict(sorted(self.seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
        self.sent += len(fresh)
        save()

    def close(self, save) -> None:
        self.cur["until"] = self.end
        save()


def collect_systemlog(cfg: dict, state: dict, sink: Sink, save, client: Citrix, now: float) -> int:
    w = Window(cfg, state, "systemlog", now)
    base = {RECORD_KEY: "systemlog", CUSTOMER_KEY: cfg["customer_id"]}
    params = {"StartDateTime": _cc_time(w.start), "EndDateTime": _cc_time(w.end), "Limit": SYSTEMLOG_LIMIT}
    token, seen_tokens = None, set()
    for _ in range(MAX_PAGES):
        query = {**params, **({"ContinuationToken": token} if token else {})}
        data = client.get(f"{cfg['api_url']}/systemlog/records?{urllib.parse.urlencode(query)}", "System Log request")
        items = _get(data, "Items") or []
        if not isinstance(items, list):
            raise BridgeError("System Log request returned Items that are not a list")
        batch = []
        for rec in items:
            if isinstance(rec, dict):
                # Keys with a capital first letter, as Citrix's examples show them.
                rec = {(k[:1].upper() + k[1:]): v for k, v in rec.items()}
                out = {**base, **{k: v for k, v in rec.items() if k not in base}}
                t = _parse_time(rec.get("UtcTimestamp"))
                batch.append((_key("systemlog", out), t if t is not None else now, out))
        w.send(sink, save, batch)
        token = _get(data, "ContinuationToken")
        if not items or not isinstance(token, str) or not token:
            break
        if token in seen_tokens:
            raise BridgeError("System Log answered with the same ContinuationToken twice; the next run reads the same "
                              "window again")
        seen_tokens.add(token)
    else:
        raise BridgeError(f"System Log had more than {MAX_PAGES} pages; the next run reads the same window again")
    w.close(save)
    LOG.info("System Log: %d sent", w.sent)
    return w.sent


def collect_configlog(cfg: dict, state: dict, sink: Sink, save, client: Citrix, now: float, site: str) -> int:
    """Configuration Logging returns the most recent operations first, a number of whole days back,
    so the bridge asks for enough days to cover the window and reads until it passes the start."""
    w = Window(cfg, state, f"configlog/{site}", now)
    base = {RECORD_KEY: "configlog", CUSTOMER_KEY: cfg["customer_id"], SITE_KEY: site}
    days = min(CONFIGLOG_MAX_DAYS, max(1, math.ceil((now - w.start) / 86400)))
    extra = {"Citrix-InstanceId": site, "X-TimeZone": "UTC"}
    token, seen_tokens = None, set()
    for _ in range(MAX_PAGES):
        query = {"days": days, "limit": CONFIGLOG_LIMIT, **({"continuationToken": token} if token else {})}
        data = client.get(f"{cfg['api_url']}/cvad/manage/ConfigLog/Operations?{urllib.parse.urlencode(query)}",
                          f"site {site} Configuration Logging request", extra)
        items = _get(data, "Items") or []
        if not isinstance(items, list):
            raise BridgeError("Configuration Logging request returned Items that are not a list")
        batch, past = [], False
        for op in items:
            if not isinstance(op, dict):
                continue
            t = _configlog_time(op)
            if t is not None and t < w.start:
                past = True
                continue
            # An operation after the window's end is read by the next run.
            if t is not None and t > w.end:
                continue
            out = {**base, **{k: v for k, v in op.items() if k not in base}}
            batch.append((_key("configlog", out), t if t is not None else now, out))
        w.send(sink, save, batch)
        token = _get(data, "ContinuationToken")
        if past or not items or not isinstance(token, str) or not token:
            break
        if token in seen_tokens:
            raise BridgeError("Configuration Logging answered with the same ContinuationToken twice; the next run reads "
                              "the same window again")
        seen_tokens.add(token)
    else:
        raise BridgeError(f"Configuration Logging had more than {MAX_PAGES} pages; the next run reads the same window again")
    w.close(save)
    LOG.info("site %s Configuration Logging: %d sent", site, w.sent)
    return w.sent


def collect_connections(cfg: dict, state: dict, sink: Sink, save, client: Citrix, now: float) -> int:
    """Monitor's connections created in the window, oldest first, with each one's session, user and
    machine, following @odata.nextLink while it stays on CITRIX_API_URL's Monitor path."""
    w = Window(cfg, state, "connections", now)
    base = {RECORD_KEY: "connection", CUSTOMER_KEY: cfg["customer_id"]}
    params = {"$filter": f"CreatedDate ge {_cc_time(w.start)} and CreatedDate lt {_cc_time(w.end)}",
              "$orderby": "CreatedDate", "$expand": "Session($expand=User,Machine)"}
    url = f"{cfg['api_url']}/monitorodata/Connections?{_query(params)}"
    origin = urllib.parse.urlsplit(cfg["api_url"])
    for _ in range(MAX_PAGES):
        data = client.get(url, "Monitor connections request")
        items = data.get("value") or []
        if not isinstance(items, list):
            raise BridgeError("Monitor connections request returned a value that is not a list")
        batch = []
        for conn in items:
            if isinstance(conn, dict):
                out = {**base, **{k: v for k, v in conn.items() if k not in base}}
                t = _parse_time(conn.get("CreatedDate"))
                batch.append((_key("connections", out), t if t is not None else now, out))
        w.send(sink, save, batch)
        nxt = data.get("@odata.nextLink")
        if not isinstance(nxt, str) or not nxt:
            break
        parts = urllib.parse.urlsplit(nxt)
        # The token goes with the next request, so it only goes back to the same host.
        if (parts.scheme, parts.netloc) != (origin.scheme, origin.netloc) or not parts.path.startswith("/monitorodata/"):
            raise BridgeError("Monitor answered with a next page on another host or path, which the bridge refuses so the "
                              "token never goes to another URL")
        url = nxt
    else:
        raise BridgeError(f"Monitor connections had more than {MAX_PAGES} pages; the next run reads the same window again")
    w.close(save)
    LOG.info("Monitor connections: %d sent", w.sent)
    return w.sent


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Citrix | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or Citrix(cfg)
    now = time.time()
    count = 0
    for log in cfg["logs"]:
        if log == "systemlog":
            count += collect_systemlog(cfg, state, sink, save, client, now)
        elif log == "configlog":
            sites = cfg["site_ids"] or client.sites()
            if not sites:
                LOG.warning("Configuration Logging: Citrix Cloud lists no DaaS site for this customer; set CITRIX_SITE_IDS")
            for site in sites:
                count += collect_configlog(cfg, state, sink, save, client, now, site)
        else:
            count += collect_connections(cfg, state, sink, save, client, now)
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
    ap = argparse.ArgumentParser(description="Send Citrix Cloud System Log, DaaS Configuration Logging and Monitor connections to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for every run, so a token is kept until it expires.
        client = Citrix(cfg)
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
