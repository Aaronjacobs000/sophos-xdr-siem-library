#!/usr/bin/env python3
"""Pull Menlo Security logs from the Menlo Log API and send them to a Sophos NG-SIEM HTTP Ingest
integration, one JSON record per line. Python 3 standard library only.

Menlo Security offers its cloud proxy and isolation logs (web requests and downloads, admin
audit, email, DLP and more) through its Log API, which is pull only, so this script reads them
with an API token that has the Log Export API permission:

  POST https://logs.menlosecurity.com/api/rep/v2/fetch/client_select?format=JSON&limit=&start=&end=
       {"token": ..., "log_type": ..., "pagingIdentifiers": ...}

Each event goes out with "menlo_record" first (its log type, such as "web"), so the library
parsers in parsers/menlo-security/menlo-security can recognize and normalize it.

Each run reads each log type from the end of its last window, less an overlap, to three minutes
before now, in windows of BRIDGE_WINDOW_MINUTES, sending pagingIdentifiers back until the last
page. Events carry no ID, so repeats are dropped by a hash of the whole event. Menlo's Log API
reference needs a sign-in, so the request and response shapes follow Menlo's own Microsoft
Sentinel connector and the Cortex XSOAR Menlo Security pack. Configuration comes from environment
variables (see README.md). A window's end only moves after HTTP Ingest accepted every event in it.
--dry-run prints what would be sent and changes nothing.
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
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("menlo_logs_bridge")
USER_AGENT = f"sophos-xdr-siem-library-menlo-logs-bridge/{__version__}"
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
FETCH_PATH = "/api/rep/v2/fetch/client_select"
RECORD_KEY = "menlo_record"
# Other connectors refuse a start more than 30 days back; Menlo doesn't publish its retention.
RETENTION_DAYS = 30
# Menlo's own connector reads up to three minutes before now, so a window ends there too.
END_MARGIN_SECONDS = 180
SEEN_LIMIT = 200000
LOG_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


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
        "api_url": (_env(env, "MENLO_API_URL", "https://logs.menlosecurity.com") or "").rstrip("/"),
        "token": _env(env, "MENLO_TOKEN"),
        "log_types": list(dict.fromkeys(t.lower() for t in _list(env, "MENLO_LOG_TYPES", "web,audit"))),
        "page_limit": _number(env, "MENLO_PAGE_LIMIT", "1000", low=1, high=10000),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "menlo_logs_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=RETENTION_DAYS * 24),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "window_minutes": _number(env, "BRIDGE_WINDOW_MINUTES", "5", low=1, high=1440),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "120", float, low=0.001),
    }
    if not cfg["token"]:
        raise BridgeError("MENLO_TOKEN is required: an API token from the Menlo Admin Portal with the Log Export API "
                          "permission")
    if not cfg["log_types"] or any(not LOG_TYPE.match(t) for t in cfg["log_types"]):
        raise BridgeError("MENLO_LOG_TYPES takes log types such as web, audit, email, dlp or smtp, separated by commas")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["api_url"], "MENLO_API_URL")
    _require_https(cfg["api_url"], "MENLO_API_URL")
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


def _menlo_error(body: bytes) -> str:
    """Menlo answers errors with {"reason": ...}. Returns it, kept short."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    message = (data.get("reason") or data.get("error") or "") if isinstance(data, dict) else ""
    return str(message)[:200] or "no message"


# ---------------------------------------------------------------- Menlo Log API

class Menlo:
    """Calls the Log API. The token goes in the JSON body, as the API takes it, so it is never in
    a URL or a header."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def fetch(self, log_type: str, start: int, end: int, paging: dict | None) -> list:
        """One page: the response's wrappers, or [] for the empty answer Menlo gives when there is
        no data."""
        query = urllib.parse.urlencode({"format": "JSON", "limit": self.cfg["page_limit"], "start": start, "end": end})
        url = f"{self.cfg['api_url']}{FETCH_PATH}?{query}"
        body = {"token": self.cfg["token"], "log_type": log_type}
        if paging:
            body["pagingIdentifiers"] = paging
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        what = f"{log_type} logs request"
        try:
            _, _, raw = _request("POST", url, headers, json.dumps(body, separators=(",", ":")).encode(), self.cfg["timeout"], what)
        except HttpStatus as e:
            if e.code in (401, 403):
                raise BridgeError(f"Menlo refused the {what} (HTTP {e.code}): {_menlo_error(e.body)}; check MENLO_TOKEN, "
                                  f"and that the token has the Log Export API permission and can read {log_type} logs") from None
            if e.code == 400:
                raise BridgeError(f"Menlo rejected the {what} (HTTP 400): {_menlo_error(e.body)}") from None
            if e.code in (404, 405):
                raise BridgeError(f"Menlo answered the {what} with HTTP {e.code}; check MENLO_API_URL") from None
            raise
        if not raw.strip():
            return []
        data = _json(raw, what)
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise BridgeError(f"{what} returned JSON that is not an object or a list")
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
    """event_time has no zone, such as 2026-10-21T21:02:11.218000, and is read as UTC, as Menlo's
    own connector does."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _key(event: dict) -> str:
    """Events have no ID, so each is known by the hash of the whole event."""
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _page(wrappers: list, what: str) -> tuple[list, dict | None, bool]:
    """The events in one answer, the pagingIdentifiers to send back, and whether it is the last
    page. An answer is a list of wrappers, each {"result": {"events": [{"event": {...}}],
    "pagingIdentifiers": {...}}}. Menlo's connector reads last_iteration in result, and other
    connectors in pagingIdentifiers, so either one ends the window."""
    events, paging, last = [], None, False
    for wrapper in wrappers:
        if not isinstance(wrapper, dict):
            continue
        result = wrapper.get("result") if isinstance(wrapper.get("result"), dict) else wrapper
        items = result.get("events") or []
        if not isinstance(items, list):
            raise BridgeError(f"{what} returned events that are not a list")
        events.extend(i["event"] for i in items if isinstance(i, dict) and isinstance(i.get("event"), dict))
        ident = result.get("pagingIdentifiers")
        if isinstance(ident, dict) and ident:
            paging = ident
        if result.get("last_iteration") is True or (isinstance(ident, dict) and ident.get("last_iteration") is True):
            last = True
    return events, paging, last


def read_window(cfg: dict, log_type: str, seen: dict, sink: Sink, save, client: Menlo, start: int, end: int,
                now: float) -> int:
    """Reads one window of one log type, a second before start to end, sending pagingIdentifiers
    back until the last page, and sends the events not sent before."""
    what = f"{log_type} logs request"
    paging, sent = None, 0
    for _ in range(MAX_PAGES):
        # The window starts a second early, so an event on the boundary second is never missed,
        # whichever ends Menlo includes; the repeat is dropped.
        events, following, last = _page(client.fetch(log_type, start - 1, end, paging), what)
        fresh = {}
        for e in events:
            k = _key(e)
            if k not in seen and k not in fresh:
                t = _parse_time(e.get("event_time"))
                fresh[k] = (t if t is not None else now, e)
        if fresh:
            batch = sorted(fresh.values(), key=lambda te: te[0])
            sink.send([{RECORD_KEY: log_type, **{f: v for f, v in e.items() if f != RECORD_KEY}} for _, e in batch])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        # An empty answer, a page with no events, the last page or no pagingIdentifiers ends it.
        if not events or last or not following:
            return sent
        # Menlo's own connector updates the identifiers it sent with the ones it got back.
        nxt = {**(paging or {}), **following}
        if nxt == paging:
            raise BridgeError(f"{what} returned the same pagingIdentifiers twice, so the next page can't be read")
        paging = nxt
    raise BridgeError(f"{what} still had more after {MAX_PAGES} pages; shorten BRIDGE_WINDOW_MINUTES")


def collect(cfg: dict, log_type: str, state: dict, sink: Sink, save, client: Menlo, now: float) -> int:
    """Reads one log type from the end of its last window, less the overlap, to three minutes
    before now, in windows of BRIDGE_WINDOW_MINUTES, oldest first. The end moves after each window
    was sent."""
    cur = state.setdefault("logs", {}).setdefault(log_type, {})
    since = cur.get("until")
    end = int(now) - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) else (now - cfg["lookback_hours"] * 3600)
    start = int(min(max(start, now - RETENTION_DAYS * 86400), end))
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    step = cfg["window_minutes"] * 60
    sent = 0
    for a in range(start, end, step):
        b = min(a + step, end)
        sent += read_window(cfg, log_type, seen, sink, save, client, a, b, now)
        if len(seen) > SEEN_LIMIT:
            cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
        cur["until"] = b
        save()
    LOG.info("%s: %d sent", log_type, sent)
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
    client = Menlo(cfg)
    now = time.time()
    count = sum(collect(cfg, t, state, sink, save, client, now) for t in cfg["log_types"])
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
    ap = argparse.ArgumentParser(description="Send Menlo Security logs to Sophos NG-SIEM HTTP Ingest.")
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
