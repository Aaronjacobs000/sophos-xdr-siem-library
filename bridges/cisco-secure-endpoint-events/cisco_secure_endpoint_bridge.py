#!/usr/bin/env python3
"""Pull Cisco Secure Endpoint events from the Secure Endpoint API v1 and send them to a Sophos
NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Cisco Secure Endpoint (formerly AMP for Endpoints) has no syslog output and no webhook to an
arbitrary HTTPS endpoint, and its event streams are AMQP queues, so this script polls the events
list with a read-only API credential:

  GET https://api.amp.cisco.com/v1/events   (start_date, limit, offset, event_type[], group_guid[])

It sends each event with "cisco_se_record": "event" first, and "event_id", the event's id as text:
the id is a 64-bit number, which a reader that keeps numbers as 64-bit floats would round. The
library parsers in parsers/cisco/cisco-secure-endpoint normalize them.

The request and response shapes follow Cisco's Secure Endpoint API v1 reference and OpenAPI files.
Configuration comes from environment variables (see README.md). A window's end only moves after
HTTP Ingest accepted every event in it. --dry-run prints what would be sent and changes nothing.
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
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("cisco_secure_endpoint_bridge")
USER_AGENT = f"parser-studio-cisco-secure-endpoint-bridge/{__version__}"
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
# Longest wait for Cisco's hourly rate limit to reset before the run stops and tries later.
MAX_RATE_WAIT = 300
RECORD_KEY = "cisco_se_record"
GUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """The API or HTTP Ingest couldn't be reached, even after the retries. With --interval the
    bridge logs it and tries again at the next interval."""


class HostNotFound(NetworkError):
    """A host name in a URL setting didn't resolve, even after the retries. Until a run has worked,
    it stops the bridge even with --interval, since it is most likely a mistyped URL."""


class RateLimited(NetworkError):
    """Cisco's hourly request limit is used up for longer than the bridge waits. With --interval
    the bridge logs it and tries again at the next interval."""


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


def _list(env: dict, name: str) -> list[str]:
    return [v.strip() for v in (_env(env, name) or "").split(",") if v.strip()]


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "CISCO_SE_API_URL", "https://api.amp.cisco.com") or "").rstrip("/"),
        "client_id": _env(env, "CISCO_SE_CLIENT_ID"),
        "api_key": _env(env, "CISCO_SE_API_KEY"),
        "event_types": _list(env, "CISCO_SE_EVENT_TYPES"),
        "group_guids": _list(env, "CISCO_SE_GROUP_GUIDS"),
        "page_size": _number(env, "CISCO_SE_PAGE_SIZE", "500", low=1, high=500),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "cisco_secure_endpoint_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["client_id"] or not cfg["api_key"]:
        raise BridgeError("CISCO_SE_CLIENT_ID and CISCO_SE_API_KEY are required: the API credential's 3rd party API "
                          "client ID and API key")
    # Basic auth joins the two with a colon, so a colon in the client ID would move the split.
    if ":" in cfg["client_id"]:
        raise BridgeError("CISCO_SE_CLIENT_ID can't contain a colon")
    if any(not re.fullmatch(r"\d{1,12}", t) for t in cfg["event_types"]):
        raise BridgeError("CISCO_SE_EVENT_TYPES takes event type IDs, such as 1090519054,553648143")
    if any(not GUID.match(g) for g in cfg["group_guids"]):
        raise BridgeError("CISCO_SE_GROUP_GUIDS takes group GUIDs, comma separated")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["api_url"], "CISCO_SE_API_URL")
    _require_https(cfg["api_url"], "CISCO_SE_API_URL")
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


def _rate_reset(headers) -> float | None:
    """Cisco sends X-RateLimit-Reset, the seconds until the hourly limit resets."""
    try:
        value = float((headers.get("X-RateLimit-Reset") or "").strip()) if headers else None
    except ValueError:
        return None
    return value if value is not None and 0 <= value < 10 ** 7 else None


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
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body). A 429 waits
    for Cisco's X-RateLimit-Reset when that is at most MAX_RATE_WAIT seconds away."""
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
            reset = _rate_reset(e.headers) if e.code == 429 else None
            if reset is not None and reset > MAX_RATE_WAIT:
                raise RateLimited(f"{what} to {_host(url)}: the hourly API rate limit is used up and resets in "
                                  f"{int(reset)} seconds") from None
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = reset + random.uniform(0, 1) if reset is not None else \
                    _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None)
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


def _cisco_error(body: bytes) -> str:
    """Cisco answers {"version", "data": {}, "errors": [{"error_code", "description", "details"}]},
    where details is a list of text or one text. Returns a short message."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    errors = data.get("errors") if isinstance(data, dict) else None
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        e = errors[0]
        details = e.get("details")
        details = "; ".join(str(d) for d in details) if isinstance(details, list) else str(details or "")
        text = ": ".join(t for t in (str(e.get("description") or ""), details) if t)
        return text[:200] or "no message"
    return "no message"


# ---------------------------------------------------------------- Cisco Secure Endpoint API

class SecureEndpoint:
    """Reads the API v1 with 'Authorization: Basic base64(client_id:api_key)'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        basic = base64.b64encode(f"{cfg['client_id']}:{cfg['api_key']}".encode("utf-8")).decode("ascii")
        self.headers = {"Authorization": f"Basic {basic}", "Accept": "application/json"}

    def events(self, start_date: str, offset: int) -> dict:
        params = [("start_date", start_date), ("limit", str(self.cfg["page_size"])), ("offset", str(offset))]
        params += [("event_type[]", t) for t in self.cfg["event_types"]]
        params += [("group_guid[]", g) for g in self.cfg["group_guids"]]
        url = f"{self.cfg['api_url']}/v1/events?{urllib.parse.urlencode(params)}"
        what = "events request"
        try:
            _, raw = _request("GET", url, self.headers, None, self.cfg["timeout"], what)
        except HttpStatus as e:
            message = _cisco_error(e.body)
            if e.code in (401, 403):
                raise BridgeError(f"Cisco refused the API credential for the {what} (HTTP {e.code}): {message}; check "
                                  "CISCO_SE_CLIENT_ID and CISCO_SE_API_KEY, and that CISCO_SE_API_URL is the region the "
                                  "credential was created in") from None
            if e.code in (400, 404):
                raise BridgeError(f"Cisco rejected the {what} (HTTP {e.code}): {message}") from None
            raise
        data = _json(raw, what)
        if not isinstance(data, dict) or not isinstance(data.get("data", []), list):
            raise BridgeError(f"{what} returned JSON that is not an events list")
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
    """date is ISO 8601 with an offset, such as 2026-10-13T01:10:04+00:00."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def event_time(event: dict) -> float | None:
    t = event.get("timestamp")
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        return float(t)
    return _parse_time(event.get("date"))


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def tag(event: dict) -> dict:
    rec = {RECORD_KEY: "event"}
    if event.get("id") is not None:
        rec["event_id"] = str(event["id"])
    rec.update({k: v for k, v in event.items() if k not in (RECORD_KEY, "event_id")})
    return rec


def collect_events(cfg: dict, state: dict, sink: Sink, save, client: SecureEndpoint, now: float) -> int:
    """Reads every page of events from the end of the last window, less the overlap. Cisco lists
    the newest first and pages by offset, so an event that arrives during the walk moves the rest
    along and shows up twice; repeats are dropped by event ID. The window's end is saved only after
    every page was sent."""
    cur = state.setdefault("events", {})
    since = cur.get("until")
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, now) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) else (now - cfg["lookback_hours"] * 3600)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    start_date = _iso(start)
    sent, offset = 0, 0
    for _ in range(MAX_PAGES):
        data = client.events(start_date, offset)
        items = [e for e in data.get("data") or [] if isinstance(e, dict)]
        fresh, no_id = {}, 0
        for e in items:
            if e.get("id") is None:
                no_id += 1
                continue
            key = str(e["id"])
            if key not in seen and key not in fresh:
                t = event_time(e)
                fresh[key] = (t if t is not None else now, tag(e))
        if no_id:
            LOG.warning("skipped %d events with no id, which can't be told apart from repeats", no_id)
        if fresh:
            sink.send([rec for _, rec in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({key: t for key, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        links = (data.get("metadata") or {}).get("links") or {}
        if not items or not links.get("next"):
            break
        # The next page's offset is worked out here rather than read from links.next, so the
        # credential only goes to CISCO_SE_API_URL.
        offset += len(items)
    else:
        LOG.warning("stopped after %d pages; the next run reads the same window again", MAX_PAGES)
        LOG.info("events: %d sent", sent)
        return sent
    cur["until"] = now
    save()
    LOG.info("events: %d sent", sent)
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
    count = collect_events(cfg, state, sink, save, SecureEndpoint(cfg), time.time())
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
    ap = argparse.ArgumentParser(description="Send Cisco Secure Endpoint events to Sophos NG-SIEM HTTP Ingest.")
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
