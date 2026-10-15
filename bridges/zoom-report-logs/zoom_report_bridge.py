#!/usr/bin/env python3
"""Pull Zoom sign-in and sign-out activity and operation logs from the Zoom Reports API and send them
to a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Zoom's webhooks need an endpoint that answers Zoom's URL validation challenge within 3 seconds, and
the sign-in webhook carries no IP address, so this script polls the Reports API instead, with a
Server-to-Server OAuth app that has only the report read scopes:

  POST https://zoom.us/oauth/token                  (grant_type=account_credentials, account_id)
  GET  https://api.zoom.us/v2/report/activities     (from, to, page_size, next_page_token)
  GET  https://api.zoom.us/v2/report/operationlogs  (from, to, page_size, next_page_token, category_type)

Each record goes on with "zoom_record" first ("signin" or "operation") and the account ID, so the
library parsers in parsers/zoom/zoom-sign-in-and-operation-logs can normalize them.

The request and response shapes follow Zoom's API reference and OpenAPI document. Configuration
comes from environment variables (see README.md). A window's end only moves after HTTP Ingest
accepted every record in it. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
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
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("zoom_report_bridge")
USER_AGENT = f"parser-studio-zoom-report-bridge/{__version__}"
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
RECORD_KEY = "zoom_record"
# Zoom keeps these reports for six months and gives at most a month per request.
RETENTION_DAYS = 180
MAX_RANGE_DAYS = 30
# Each report: its path, its list key, the record name, the fields that identify a record, and the
# extra query parameters it takes.
REPORTS = {
    "activities": ("/report/activities", "activity_logs", "signin",
                   ("time", "email", "type", "ip_address", "client_type", "version")),
    "operationlogs": ("/report/operationlogs", "operation_logs", "operation",
                      ("time", "operator", "category_type", "action", "operation_detail")),
}
CATEGORIES = ("all", "user", "user_settings", "account", "billing", "im", "recording", "phone_contacts",
              "webinar", "sub_account", "role", "zoom_rooms")


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """The API or HTTP Ingest couldn't be reached, even after the retries. With --interval the
    bridge logs it and tries again at the next interval."""


class HostNotFound(NetworkError):
    """A host name in a URL setting didn't resolve, even after the retries. Until a run has worked,
    it stops the bridge even with --interval, since it is most likely a mistyped URL."""


class RateLimited(NetworkError):
    """Zoom's daily request limit is used up. With --interval the bridge logs it and tries again
    at the next interval."""


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
        "api_url": (_env(env, "ZOOM_API_URL", "https://api.zoom.us") or "").rstrip("/"),
        "token_url": _env(env, "ZOOM_TOKEN_URL", "https://zoom.us/oauth/token"),
        "account_id": _env(env, "ZOOM_ACCOUNT_ID"),
        "client_id": _env(env, "ZOOM_CLIENT_ID"),
        "client_secret": _env(env, "ZOOM_CLIENT_SECRET"),
        "reports": [r.strip() for r in (_env(env, "ZOOM_REPORTS", "activities,operationlogs") or "").split(",") if r.strip()],
        "category": _env(env, "ZOOM_OPERATION_CATEGORY", "all"),
        "page_size": _number(env, "ZOOM_PAGE_SIZE", "300", low=1, high=300),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "zoom_report_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not (cfg["account_id"] and cfg["client_id"] and cfg["client_secret"]):
        raise BridgeError("ZOOM_ACCOUNT_ID, ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET are required: the Server-to-Server "
                          "OAuth app's credentials")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", cfg["account_id"]):
        raise BridgeError("ZOOM_ACCOUNT_ID must be the account ID from the Server-to-Server OAuth app")
    # Basic auth joins the two with a colon, so a colon in the client ID would move the split.
    if ":" in cfg["client_id"]:
        raise BridgeError("ZOOM_CLIENT_ID can't contain a colon")
    if not cfg["reports"] or any(r not in REPORTS for r in cfg["reports"]):
        raise BridgeError("ZOOM_REPORTS takes activities, operationlogs or both, comma separated")
    cfg["reports"] = list(dict.fromkeys(cfg["reports"]))
    if cfg["category"] not in CATEGORIES:
        raise BridgeError("ZOOM_OPERATION_CATEGORY must be one of " + ", ".join(CATEGORIES))
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["api_url"], "ZOOM_API_URL")
    _require_https(cfg["api_url"], "ZOOM_API_URL")
    _refuse_user_info(cfg["token_url"], "ZOOM_TOKEN_URL")
    _require_https(cfg["token_url"], "ZOOM_TOKEN_URL")
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
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body). Zoom's daily
    rate limit isn't retried: it lasts until the next day."""
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
            if e.code == 429 and b"daily rate limit" in error_body.lower():
                raise RateLimited(f"{what} to {_host(url)}: Zoom's daily API rate limit is used up") from None
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


def _zoom_error(body: bytes) -> str:
    """Zoom answers {"code": 124, "message": "Invalid access token."}, and the token endpoint
    {"reason", "error"}. Returns a short message."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    code = data.get("code")
    message = data.get("message") or data.get("reason") or data.get("error_description") or data.get("error") or ""
    text = f"{message} (code {code})" if code is not None and message else str(message)
    return text[:200] or "no message"


# ---------------------------------------------------------------- Zoom API

class Zoom:
    """Gets an access token with the account credentials grant and reads the Reports API with
    'Authorization: Bearer <token>'. Tokens last an hour; one is renewed a minute before it
    expires, and once more if Zoom refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        basic = base64.b64encode(f"{self.cfg['client_id']}:{self.cfg['client_secret']}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        body = urllib.parse.urlencode({"grant_type": "account_credentials", "account_id": self.cfg["account_id"]}).encode()
        try:
            _, raw = _request("POST", self.cfg["token_url"], headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"Zoom refused the Server-to-Server OAuth credentials (HTTP {e.code}): {_zoom_error(e.body)}; "
                                  "check ZOOM_ACCOUNT_ID, ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET, and that the app is activated") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            lifetime = 3600.0
        self._token = token
        self._expires = time.monotonic() + max(60.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def report(self, name: str, start: str, end: str, page_token: str | None) -> dict:
        path = REPORTS[name][0]
        params = {"from": start, "to": end, "page_size": self.cfg["page_size"]}
        if name == "operationlogs":
            params["category_type"] = self.cfg["category"]
        if page_token:
            params["next_page_token"] = page_token
        url = f"{self.cfg['api_url']}/v2{path}?{urllib.parse.urlencode(params)}"
        what = f"{name} report request"
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json"}
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
                break
            except HttpStatus as e:
                if e.code == 401 and not renew:
                    continue
                if e.code in (400, 401, 403, 404):
                    raise BridgeError(f"Zoom refused the {what} (HTTP {e.code}): {_zoom_error(e.body)}; check that the "
                                      "app has the report read scopes and the account is on a Pro plan or higher") from None
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
    """time is ISO 8601 in UTC, such as 2026-10-13T01:10:04Z."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _day(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def ranges(start: float, now: float) -> list[tuple[str, str]]:
    """Zoom's from and to are dates with no time (UTC, as Zoom staff advise), and a request covers
    at most a month, so the window is read as whole days in ranges of up to 30 days, the oldest
    first."""
    first, last = _day(start), _day(now)
    out = []
    while first <= last:
        end = min(first + timedelta(days=MAX_RANGE_DAYS - 1), last)
        out.append((first.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")))
        first = end + timedelta(days=1)
    return out


def tag(name: str, row: dict, cfg: dict) -> dict:
    rec = {RECORD_KEY: REPORTS[name][2], "account_id": cfg["account_id"]}
    rec.update({k: v for k, v in row.items() if k not in (RECORD_KEY, "account_id")})
    return rec


def collect_report(cfg: dict, name: str, state: dict, sink: Sink, save, client: Zoom, now: float) -> int:
    """Reads one report from the start of the day the last window ended in, less the overlap, to
    today. Zoom's dates have no time, so whole days are read again each run, and records sent
    before are dropped by key: the fields that identify a record, and how many times the same
    fields came before it in the window, so two identical records in one second both go on. The
    window's end is saved only after every page of it was sent."""
    path, list_key, _, fields = REPORTS[name]
    cur = state.setdefault(name, {})
    since = cur.get("until")
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, now) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) else (now - cfg["lookback_hours"] * 3600)
    start = max(start, now - RETENTION_DAYS * 86400)
    floor = _day(start).timestamp()
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= floor - 60}
    cur["seen"] = seen
    counts: dict[str, int] = {}
    sent = 0
    for first, last in ranges(start, now):
        page_token = None
        for _ in range(MAX_PAGES):
            data = client.report(name, first, last, page_token)
            fresh = {}
            for row in data.get(list_key) or []:
                if not isinstance(row, dict):
                    continue
                base = json.dumps([row.get(f) for f in fields], separators=(",", ":"), ensure_ascii=False)
                n = counts.get(base, 0)
                counts[base] = n + 1
                key = f"{base}#{n}"
                if key not in seen:
                    t = _parse_time(row.get("time"))
                    fresh[key] = (t if t is not None else now, tag(name, row, cfg))
            if fresh:
                sink.send([rec for _, rec in fresh.values()])
                # Only now that HTTP Ingest took them do they count as sent.
                seen.update({key: t for key, (t, _) in fresh.items()})
                sent += len(fresh)
                save()
            page_token = data.get("next_page_token")
            if not page_token:
                break
        else:
            LOG.warning("%s: stopped after %d pages; the next run reads the same window again", name, MAX_PAGES)
            LOG.info("%s: %d sent", name, sent)
            return sent
    cur["until"] = now
    save()
    LOG.info("%s: %d sent", name, sent)
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
    client = Zoom(cfg)
    now = time.time()
    count = sum(collect_report(cfg, name, state, sink, save, client, now) for name in cfg["reports"])
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
    ap = argparse.ArgumentParser(description="Send Zoom sign-in and operation logs to Sophos NG-SIEM HTTP Ingest.")
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
