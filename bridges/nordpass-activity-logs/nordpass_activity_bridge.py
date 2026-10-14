#!/usr/bin/env python3
"""Pull NordPass Enterprise activity logs from the NordPass Activity Logs API and send them to a
Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

NordPass offers its activity log to other tools only through the Activity Logs API, which is pull
only, so this script reads the activities by time window with the organization's events reporting
token and posts each one with "nordpass_record": "activity" first, so the library parsers in
parsers/nordpass/nordpass-activity-logs can normalize it:

  POST https://api-activities.<eu|us>.nordpass.com/activities/query
       {"timestamp_from", "timestamp_to", "per_page", "page"}   (Authorization: <token>)

The request and response shapes follow NordPass's Activity Logs API article. Configuration comes
from environment variables (see README.md). The cursor only moves after HTTP Ingest accepted the
records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import random
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
LOG = logging.getLogger("nordpass_activity_bridge")
USER_AGENT = f"parser-studio-nordpass-activity-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
MAX_REQUESTS = 20000
SEEN_LIMIT = 100000
RECORD_KEY = "nordpass_record"
URLS = {"eu": "https://api-activities.eu.nordpass.com", "us": "https://api-activities.us.nordpass.com"}
QUERY_PATH = "/activities/query"
# NordPass rejects a window longer than 90 days, and a query can only reach its 10,000 most
# recent results, so a busier window is split in two until each part fits.
MAX_WINDOW = 90 * 86400
MAX_RESULTS = 10000
# timestamp_to may not be in the future, so the window ends a little before now.
END_MARGIN = 5


class BridgeError(Exception):
    """A failure that stops the run without moving the cursor past unsent data."""


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


def _number(env: dict, name: str, default: str, cast=int):
    value = _env(env, name, default)
    try:
        return cast(value)
    except ValueError:
        raise BridgeError(f"{name} must be a number") from None


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    region = (_env(env, "NORDPASS_REGION", "eu") or "").lower()
    if region not in URLS:
        raise BridgeError("NORDPASS_REGION must be eu or us")
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "NORDPASS_API_URL") or URLS[region]).rstrip("/"),
        "token": _env(env, "NORDPASS_TOKEN"),
        "per_page": _number(env, "NORDPASS_PER_PAGE", "100"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "nordpass_activity_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float),
    }
    if not cfg["token"]:
        raise BridgeError("NORDPASS_TOKEN is required")
    if not 1 <= cfg["per_page"] <= 100:
        raise BridgeError("NORDPASS_PER_PAGE must be from 1 to 100")
    if cfg["overlap_seconds"] < 0 or cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_OVERLAP_SECONDS can't be negative and BRIDGE_LOOKBACK_HOURS must be above 0")
    _require_https(cfg["api_url"], "NORDPASS_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return max(0.0, float(retry_after))
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            # Read the body, then close the error response so its socket is released now, not
            # when the error is garbage collected.
            error_body = e.read()
            e.close()
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After"))
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            raise HttpStatus(what, url, e.code, error_body) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise BridgeError(f"{what} to {_host(url)} failed")


def _error_message(body: bytes) -> str:
    """NordPass answers errors as {"message": ...}. Keep the message short."""
    try:
        data = json.loads(body) or {}
        message = data.get("message") or data.get("error") or ""
    except (ValueError, AttributeError, TypeError):
        message = ""
    return str(message)[:200] or "no message"


# ---------------------------------------------------------------- NordPass Activity Logs API

class NordPass:
    """Posts queries to the Activity Logs API with 'Authorization: <token>', the raw token NordPass
    shows when it creates an events reporting token."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.requests = 0

    def query(self, start: int, end: int, page: int) -> dict:
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise BridgeError(f"stopped after {MAX_REQUESTS} requests; shorten BRIDGE_LOOKBACK_HOURS")
        url = f"{self.cfg['api_url']}{QUERY_PATH}"
        body = json.dumps({"timestamp_from": start, "timestamp_to": end, "per_page": self.cfg["per_page"], "page": page}).encode()
        headers = {"Authorization": self.cfg["token"], "Content-Type": "application/json", "Accept": "application/json"}
        try:
            _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "activities query")
        except HttpStatus as e:
            if e.code == 400:
                raise BridgeError(f"NordPass rejected the activities query (HTTP 400): {_error_message(e.body)}") from None
            if e.code in (401, 403):
                raise BridgeError(f"NordPass refused the token (HTTP {e.code}: {_error_message(e.body)}); check NORDPASS_TOKEN, "
                                     "that it hasn't expired or been revoked, and that NORDPASS_REGION is the organization's data center") from None
            raise
        try:
            data = json.loads(raw)
        except ValueError:
            raise BridgeError("activities query returned a body that is not JSON") from None
        if not isinstance(data, dict) or not isinstance(data.get("data") or [], list):
            raise BridgeError("activities query returned an unexpected shape")
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

def _key(activity: dict) -> str:
    """Activities carry no ID, so a repeat is found by the hash of the whole activity."""
    return hashlib.sha256(json.dumps(activity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _seconds(activity: dict) -> float:
    """timestamp is a Unix time in seconds."""
    try:
        return float(activity.get("timestamp"))
    except (TypeError, ValueError):
        return 0.0


def read_window(client: NordPass, start: int, end: int) -> list[dict]:
    """Every activity with a timestamp in [start, end]. A window over 90 days, or with more results
    than the API can page to, is read in two halves."""
    if end - start > MAX_WINDOW:
        mid = start + MAX_WINDOW
        return read_window(client, start, mid) + read_window(client, mid + 1, end)
    first = client.query(start, end, 1)
    meta = first.get("metadata") or {}
    total = int(meta.get("total") or 0)
    if total > MAX_RESULTS:
        if end <= start:
            raise BridgeError(f"more than {MAX_RESULTS} activities share one second ({start}); the API can't return them all")
        mid = (start + end) // 2
        LOG.info("%d activities in one window; reading it in two halves", total)
        return read_window(client, start, mid) + read_window(client, mid + 1, end)
    rows = [a for a in first.get("data") or [] if isinstance(a, dict)]
    pages = int(meta.get("total_pages") or 1)
    for page in range(2, pages + 1):
        data = client.query(start, end, page)
        rows.extend(a for a in data.get("data") or [] if isinstance(a, dict))
    return rows


def collect_activities(cfg: dict, state: dict, sink: Sink, save, client: NordPass) -> int:
    """Read [cursor minus the overlap, now], send the activities not sent before, oldest first,
    then move the cursor to the end of the window."""
    end = int(time.time()) - END_MARGIN
    cur = state.setdefault("activities", {"since": end - int(cfg["lookback_hours"] * 3600), "seen": []})
    start = int(cur["since"]) - cfg["overlap_seconds"]
    rows = read_window(client, start, end)
    seen = set(cur["seen"])
    fresh, keys = [], set()
    for a in rows:
        k = _key(a)
        if k in seen or k in keys:
            continue
        keys.add(k)
        fresh.append(a)
    fresh.sort(key=_seconds)
    if fresh:
        sink.send([{RECORD_KEY: "activity", **a} for a in fresh])
    # Keep the hashes of the activities that the next run's overlap reads again, so they aren't sent twice.
    cutoff = end - cfg["overlap_seconds"]
    recent = [_key(a) for a in rows if _seconds(a) >= cutoff]
    cur["seen"] = list(dict.fromkeys(recent))[-SEEN_LIMIT:]
    cur["since"] = end + 1
    save()
    LOG.info("activities: %d read, %d new", len(rows), len(fresh))
    return len(fresh)


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
        json.dump(state, fh, indent=1)
    os.replace(tmp, path)


def run_once(cfg: dict, dry_run: bool = False, out=None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    count = collect_activities(cfg, state, sink, save, NordPass(cfg))
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send NordPass Enterprise activity logs from the Activity Logs API to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=_env(dict(os.environ), "BRIDGE_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "BRIDGE_DRY_RUN", False)
    try:
        cfg = load_config()
        while True:
            run_once(cfg, dry_run)
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
