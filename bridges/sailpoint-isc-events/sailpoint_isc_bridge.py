#!/usr/bin/env python3
"""Pull SailPoint Identity Security Cloud audit events from the Search API and send them to a
Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

SailPoint Identity Security Cloud has no syslog or push stream for its audit events (sign-ins,
provisioning, access changes, source changes, admin rights), so this script reads the events index
of the Search API with a personal access token that has the sp:search:read scope:

  POST https://{tenant}.api.identitynow.com/oauth/token   (client_credentials)
  POST https://{tenant}.api.identitynow.com/v3/search     (indices ["events"], a range on created)

and posts each event with "sailpoint_record": "event" first, so the library parsers in
parsers/sailpoint/identity-security-cloud can recognize and normalize it.

Each run reads the window from the end of the last one, less an overlap for events that reach
search late, to now, paging with searchAfter on id as SailPoint's paging guide describes, and
drops events it already sent. The request and response shapes follow SailPoint's Search API
reference (v3 search-post, EventDocument), its authentication guide and its Searching Audit Events
guide. Configuration comes from environment variables (see README.md). A window's end only moves
after HTTP Ingest accepted every event in it. --dry-run prints what would be sent and changes
nothing.
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
LOG = logging.getLogger("sailpoint_isc_bridge")
USER_AGENT = f"parser-studio-sailpoint-isc-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 10000
RECORD_KEY = "sailpoint_record"
SEARCH_PATH = "/v3/search"
TOKEN_PATH = "/oauth/token"
# SailPoint keeps audit events in search for one year plus the current month.
RETENTION_SECONDS = 365 * 86400
# A window ends this long before now, so a clock a little ahead of SailPoint's never asks for the future.
END_MARGIN_SECONDS = 60
TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
EVENT_TYPE = re.compile(r"^[A-Z][A-Z_ ]{1,63}$")


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


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    tenant = _env(env, "SAILPOINT_TENANT")
    api_url = _env(env, "SAILPOINT_API_URL")
    if tenant and not TENANT.match(tenant):
        raise BridgeError("SAILPOINT_TENANT must be the tenant name from the tenant's URL, such as acme for acme.identitynow.com")
    if not api_url and tenant:
        api_url = f"https://{tenant.lower()}.api.identitynow.com"
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (api_url or "").rstrip("/"),
        "client_id": _env(env, "SAILPOINT_CLIENT_ID"),
        "client_secret": _env(env, "SAILPOINT_CLIENT_SECRET"),
        "event_types": [t.strip().upper() for t in (_env(env, "SAILPOINT_EVENT_TYPES") or "").split(",") if t.strip()],
        "page_size": _number(env, "SAILPOINT_PAGE_SIZE", "1000", low=1, high=10000),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "sailpoint_isc_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["api_url"]:
        raise BridgeError("SAILPOINT_TENANT (or SAILPOINT_API_URL) is required")
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise BridgeError("SAILPOINT_CLIENT_ID and SAILPOINT_CLIENT_SECRET are required")
    if any(not EVENT_TYPE.match(t) for t in cfg["event_types"]):
        raise BridgeError("SAILPOINT_EVENT_TYPES takes event types such as AUTH,SSO,PROVISIONING, separated by commas")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _require_https(cfg["api_url"], "SAILPOINT_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


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
        else:
            message = f"{what} to {_host(url)} failed with HTTP {code}"
        super().__init__(message)
        self.code = code
        self.body = body


class RetriedStatus(HttpStatus, NetworkError):
    """A 408, 429 or 5xx that outlasted the retries. It is a NetworkError too, so with --interval
    the bridge logs it and tries again at the next interval."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _read(resp, what: str, url: str, limit: int | None = None) -> bytes:
    """Reads a response body, but no more than the limit, so a broken or hostile endpoint can't
    use up memory. It reads 1 MB at a time: before Python 3.10, read(n) set aside all n bytes first."""
    limit = limit or MAX_RESPONSE_BYTES
    chunks, size = [], 0
    while True:
        chunk = resp.read(min(1048576, limit + 1 - size))
        if not chunk:
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
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, body)."""
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


def _error_message(body: bytes) -> str:
    """SailPoint's API errors are {"detailCode", "trackingId", "messages": [{"text"}]}; its token
    endpoint answers {"error", "error_description"}. Keep the message short."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    texts = [m.get("text") for m in data.get("messages") or [] if isinstance(m, dict) and m.get("text")]
    message = texts[0] if texts else (data.get("error_description") or data.get("detailCode") or data.get("error") or "")
    return str(message)[:200] or "no message"


# ---------------------------------------------------------------- SailPoint API

class SailPoint:
    """Gets an access token with the client credentials grant and calls the Search API with
    'Authorization: Bearer <token>'. A token is renewed a minute before it expires, and once more
    if SailPoint refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        url = f"{self.cfg['api_url']}{TOKEN_PATH}"
        # The credentials go in the form body, not the URL, so no proxy or server log keeps them.
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.cfg["client_id"],
                                       "client_secret": self.cfg["client_secret"]}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        try:
            _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"SailPoint refused the API credentials (HTTP {e.code}): {_error_message(e.body)}; "
                                  "check SAILPOINT_CLIENT_ID and SAILPOINT_CLIENT_SECRET and the tenant") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 600)
        except (TypeError, ValueError):
            lifetime = 600.0
        self._token = token
        self._expires = time.monotonic() + max(30.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def search(self, start: str, end: str, after: str | None) -> list:
        """One page of events created in [start, end], sorted by id, after the id given."""
        must = [{"range": {"created": {"gte": start, "lte": end}}}]
        if self.cfg["event_types"]:
            must.append({"bool": {"should": [{"match": {"type": t}} for t in self.cfg["event_types"]],
                                  "minimum_should_match": 1}})
        query = {"indices": ["events"], "queryType": "DSL", "queryDsl": {"bool": {"must": must}}, "sort": ["id"]}
        if after is not None:
            query["searchAfter"] = [after]
        url = f"{self.cfg['api_url']}{SEARCH_PATH}?{urllib.parse.urlencode({'limit': self.cfg['page_size']})}"
        body = json.dumps(query, separators=(",", ":")).encode()
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Content-Type": "application/json",
                       "Accept": "application/json"}
            try:
                _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "search request")
                break
            except HttpStatus as e:
                if e.code == 401 and not renew:
                    LOG.info("search request returned 401; renewing the access token")
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"SailPoint refused the search request (HTTP {e.code}): {_error_message(e.body)}; "
                                      "check that the personal access token has the sp:search:read scope "
                                      "and a user level that can search events, such as Report Admin") from None
                if e.code == 400:
                    raise BridgeError(f"SailPoint rejected the search request (HTTP 400): {_error_message(e.body)}") from None
                raise
        data = _json(raw, "search request")
        if not isinstance(data, list):
            raise BridgeError("search request returned JSON that is not a list")
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
    """created is ISO 8601 in UTC, such as 2026-10-14T02:10:05.412Z."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _key(event: dict) -> str:
    """An event is known by its id; one without an id by the hash of the whole event."""
    ident = event.get("id")
    if isinstance(ident, str) and ident:
        return ident
    return "sha256:" + hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def collect(cfg: dict, state: dict, sink: Sink, save, client: SailPoint, now: float) -> int:
    """Reads the window from the end of the last one, less the overlap, to now, page by page
    sorted by id, and sends the events not sent before. The window's end is saved only after
    every page of it was sent."""
    cur = state.setdefault("events", {})
    since = cur.get("until")
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, now - END_MARGIN_SECONDS) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) \
        else (now - cfg["lookback_hours"] * 3600)
    start = max(start, now - RETENTION_SECONDS + 600)
    end = now - END_MARGIN_SECONDS
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    start_s, end_s = _iso(start), _iso(end)
    sent, after = 0, None
    for _ in range(MAX_PAGES):
        events = [e for e in client.search(start_s, end_s, after) if isinstance(e, dict)]
        fresh = {}
        for e in events:
            k = _key(e)
            if k not in seen and k not in fresh:
                t = _parse_time(e.get("created"))
                fresh[k] = (t if t is not None else now, e)
        if fresh:
            rows = sorted(fresh.values(), key=lambda x: (x[0], str(x[1].get("id") or "")))
            sink.send([{RECORD_KEY: "event", **e} for _, e in rows])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        if len(events) < cfg["page_size"]:
            break
        last = events[-1].get("id")
        if not isinstance(last, str) or not last:
            LOG.warning("the last event of a full page has no id to page after; the next run reads the same window again")
            LOG.info("events: %d sent", sent)
            return sent
        after = last
    else:
        LOG.warning("stopped after %d pages; the next run reads the same window again", MAX_PAGES)
        LOG.info("events: %d sent", sent)
        return sent
    cur["until"] = end
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
    count = collect(cfg, state, sink, save, SailPoint(cfg), time.time())
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
    ap = argparse.ArgumentParser(description="Send SailPoint Identity Security Cloud audit events from the Search API to Sophos NG-SIEM HTTP Ingest.")
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
