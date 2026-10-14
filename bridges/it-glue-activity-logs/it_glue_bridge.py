#!/usr/bin/env python3
"""Pull the IT Glue activity log and send it to a Sophos NG-SIEM HTTP Ingest integration, one
JSON record per line. Python 3 standard library only.

IT Glue keeps an activity log of creates, updates, deletes and level 1 records (actions that
change no data, such as viewing a record) across passwords, documents and configurations, but
it has no syslog or log push. This script reads GET /logs with an API key, keeps a cursor, and
posts each record unchanged so the library parser ITGLUE_ACTIVITY_JSON_STANDALONE_CLOUDAUDIT
(parsers/it-glue/activity-logs) can normalize it.

Configuration comes from environment variables (see README.md). The cursor only moves after
HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
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
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("it_glue_bridge")
USER_AGENT = f"parser-studio-it-glue-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
SEEN_LIMIT = 20000
MAX_REQUESTS = 10000
# IT Glue returns at most 5 pages per query and refuses ranges much longer than a week.
MAX_PAGE_NUMBER = 5
MAX_WINDOW = timedelta(days=7)


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


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "ITGLUE_API_URL", "https://api.itglue.com") or "").rstrip("/"),
        "api_key": _env(env, "ITGLUE_API_KEY"),
        "page_size": int(_env(env, "ITGLUE_PAGE_SIZE", "1000")),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "it_glue_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": int(_env(env, "BRIDGE_BATCH_BYTES", "100000")),
        "lookback_hours": float(_env(env, "BRIDGE_LOOKBACK_HOURS", "24")),
        "overlap_seconds": int(_env(env, "BRIDGE_OVERLAP_SECONDS", "300")),
        "settle_seconds": int(_env(env, "BRIDGE_SETTLE_SECONDS", "60")),
        "timeout": float(_env(env, "BRIDGE_HTTP_TIMEOUT", "60")),
    }
    if not cfg["api_key"]:
        raise BridgeError("ITGLUE_API_KEY is required")
    _require_https(cfg["api_url"], "ITGLUE_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    if not 1 <= cfg["page_size"] <= 1000:
        raise BridgeError("ITGLUE_PAGE_SIZE must be between 1 and 1000")
    if cfg["lookback_hours"] > 30 * 24:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS can be at most 720: GET /logs only covers the most recent 30 days")
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
    def __init__(self, what: str, url: str, code: int):
        if code in REDIRECT_STATUS:
            message = (f"{what} to {_host(url)} answered with a redirect (HTTP {code}), which the bridge refuses "
                       "so the key or token never goes to another URL; check the URL setting")
        else:
            message = f"{what} to {_host(url)} failed with HTTP {code}"
        super().__init__(message)
        self.code = code


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
            # Close the error response now so its socket is released, not when the error is
            # garbage collected. The code and headers stay readable.
            e.close()
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After"))
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            raise HttpStatus(what, url, e.code) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise BridgeError(f"{what} to {_host(url)} failed")


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise BridgeError(f"{what} returned a body that is not JSON") from None


# ---------------------------------------------------------------- IT Glue API

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: str) -> datetime:
    v = value.strip().replace("Z", "+00:00")
    if "." in v:  # fromisoformat before 3.11 takes 3 or 6 fraction digits only
        head, rest = v.split(".", 1)
        digits = "".join(ch for ch in rest if ch.isdigit())
        v = head + "." + (digits + "000000")[:6] + rest[len(digits):]
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class GlueClient:
    """Reads the activity log with the x-api-key header."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.headers = {"x-api-key": cfg["api_key"], "Accept": "application/vnd.api+json"}

    def logs(self, start: datetime, end: datetime, page: int) -> dict:
        params = {"filter[created_at]": f"{_iso(start)},{_iso(end)}", "sort": "created_at",
                  "page[size]": self.cfg["page_size"], "page[number]": page}
        url = f"{self.cfg['api_url']}/logs?{urllib.parse.urlencode(params)}"
        try:
            _, body = _request("GET", url, self.headers, None, self.cfg["timeout"], "activity log request")
        except HttpStatus as e:
            if e.code in (401, 403):
                raise BridgeError("IT Glue refused the API key (check ITGLUE_API_KEY; unused keys are revoked after 90 days)") from None
            raise
        return _json(body, "activity log request")


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

def _created(rec: dict) -> datetime:
    return _parse_time((rec.get("attributes") or {}).get("created-at") or "1970-01-01T00:00:00Z")


def collect(cfg: dict, state: dict, sink: Sink, save, client: GlueClient | None = None) -> int:
    """Read windows of at most a week from the cursor (minus the overlap) to now (minus the settle
    time), sorted by created_at, up to 5 pages each. When a window has more than 5 pages, the next
    query starts at the newest record received. Records already sent are dropped by ID."""
    client = client or GlueClient(cfg)
    now = datetime.now(timezone.utc)
    cur = state.setdefault("activity_logs", {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
    end_all = now - timedelta(seconds=cfg["settle_seconds"])
    start = _parse_time(cur["since"]) - timedelta(seconds=cfg["overlap_seconds"])
    seen = set(cur["seen"])
    window_ids, total, requests = [], 0, 0
    while start < end_all:
        end = min(end_all, start + MAX_WINDOW)
        newest = None
        more = False
        for page in range(1, MAX_PAGE_NUMBER + 1):
            requests += 1
            if requests > MAX_REQUESTS:
                raise BridgeError(f"stopped after {MAX_REQUESTS} requests; shorten BRIDGE_LOOKBACK_HOURS")
            body = client.logs(start, end, page)
            data = [r for r in (body.get("data") or []) if isinstance(r, dict)]
            data.sort(key=lambda r: (_created(r), r.get("id") or ""))
            fresh = [r for r in data if r.get("id") not in seen]
            if fresh:
                sink.send(fresh)
                total += len(fresh)
            for r in data:
                seen.add(r.get("id"))
                window_ids.append((r.get("id"), _created(r)))
            if data:
                newest = _created(data[-1])
            pages = int((body.get("meta") or {}).get("total-pages") or 1)
            if page >= pages or not data:
                break
            more = page == MAX_PAGE_NUMBER
        if more and newest and newest > start:
            # The window had more than 5 pages: continue from the newest record (its second may hold
            # more records, so it is read again and repeats are dropped by ID).
            start = newest
            continue
        if more:
            raise BridgeError("one second holds more records than 5 pages; raise ITGLUE_PAGE_SIZE")
        start = end
    cutoff = end_all - timedelta(seconds=cfg["overlap_seconds"])
    cur["seen"] = list(dict.fromkeys(i for i, ts in window_ids if i and ts >= cutoff))[-SEEN_LIMIT:]
    cur["since"] = _iso(end_all)
    save()
    LOG.info("activity logs: %d new records sent", total)
    return total


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
    count = collect(cfg, state, sink, save)
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send the IT Glue activity log to Sophos NG-SIEM HTTP Ingest.")
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
