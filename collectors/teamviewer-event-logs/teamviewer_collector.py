#!/usr/bin/env python3
"""Pull the TeamViewer event log (audit log) and send it to a Sophos NG-SIEM HTTP Ingest
integration, one JSON record per line. Python 3 standard library only.

TeamViewer Tensor and Business keep an event log of remote sessions (started, joined, ended,
files sent and received, recordings, black screen and remote input changes) and of user, role,
policy, script token, SSO, conditional access and device management changes. It has no syslog
or push export. This script reads POST /api/v2/EventLogging with a script token, keeps a
cursor, and posts each event unchanged so the library parser
TEAMVIEWER_EVENTLOG_JSON_STANDALONE_CLOUDAUDIT (parsers/teamviewer/event-log) can normalize it.

Configuration comes from environment variables (see README.md). The cursor only moves after
HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
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
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("teamviewer_collector")
USER_AGENT = f"parser-studio-teamviewer-collector/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 6
SEEN_LIMIT = 20000
MAX_REQUESTS = 10000


class CollectorError(Exception):
    """A failure that stops the run without moving the cursor past unsent data."""


# ---------------------------------------------------------------- configuration

def _env(env: dict, name: str, default: str | None = None) -> str | None:
    value = env.get(name)
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
    raise CollectorError(f"{what} must be an https URL")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "TEAMVIEWER_API_URL", "https://webapi.teamviewer.com") or "").rstrip("/"),
        "token": _env(env, "TEAMVIEWER_SCRIPT_TOKEN"),
        "event_types": [x.strip() for x in (_env(env, "TEAMVIEWER_EVENT_TYPES") or "").split(",") if x.strip()],
        "state_file": _env(env, "COLLECTOR_STATE_FILE", "teamviewer_state.json"),
        "gzip": _flag(env, "COLLECTOR_GZIP", True),
        "batch_bytes": int(_env(env, "COLLECTOR_BATCH_BYTES", "100000")),
        "lookback_hours": float(_env(env, "COLLECTOR_LOOKBACK_HOURS", "24")),
        "overlap_seconds": int(_env(env, "COLLECTOR_OVERLAP_SECONDS", "300")),
        "settle_seconds": int(_env(env, "COLLECTOR_SETTLE_SECONDS", "60")),
        "timeout": float(_env(env, "COLLECTOR_HTTP_TIMEOUT", "60")),
    }
    if not cfg["token"]:
        raise CollectorError("TEAMVIEWER_SCRIPT_TOKEN is required")
    _require_https(cfg["api_url"], "TEAMVIEWER_API_URL")
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


class HttpStatus(CollectorError):
    def __init__(self, what: str, url: str, code: int):
        super().__init__(f"{what} to {_host(url)} failed with HTTP {code}")
        self.code = code


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
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
            raise CollectorError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise CollectorError(f"{what} to {_host(url)} failed")


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise CollectorError(f"{what} returned a body that is not JSON") from None


# ---------------------------------------------------------------- TeamViewer API

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


class TeamViewerClient:
    """Reads the event log with the script token as a bearer token."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.headers = {"Authorization": f"Bearer {cfg['token']}", "Accept": "application/json",
                        "Content-Type": "application/json"}

    def events(self, start: datetime, end: datetime, token: str | None) -> dict:
        body = {"StartDate": _iso(start), "EndDate": _iso(end)}
        if self.cfg["event_types"]:
            body["EventTypes"] = self.cfg["event_types"]
        if token:
            body["PaginationToken"] = token
        try:
            _, raw = _request("POST", f"{self.cfg['api_url']}/api/v2/EventLogging", self.headers,
                              json.dumps(body).encode(), self.cfg["timeout"], "event log request")
        except HttpStatus as e:
            if e.code in (401, 403):
                raise CollectorError("TeamViewer refused the script token (it needs the event logging permission, "
                                     "and event logging must be turned on for the company)") from None
            raise
        return _json(raw, "event log request")


# ---------------------------------------------------------------- HTTP Ingest

class Sink:
    """Batches records as NDJSON and posts them to HTTP Ingest, or prints them in dry-run."""

    def __init__(self, cfg: dict, dry_run: bool, out=None):
        self.cfg, self.dry_run = cfg, dry_run
        self.out = out or sys.stdout
        self.sent = 0
        self.batches = 0
        if not dry_run and not (cfg["ingest_url"] and cfg["ingest_key"]):
            raise CollectorError("NGSIEM_INGEST_URL and NGSIEM_INGEST_KEY are required unless --dry-run is set")

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

def event_key(ev: dict) -> str:
    """Events carry no ID, so repeats are recognized by a hash of the whole event."""
    return hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _when(ev: dict) -> datetime:
    try:
        return _parse_time(ev.get("Timestamp") or "")
    except ValueError:
        return datetime.fromtimestamp(0, timezone.utc)


def collect(cfg: dict, state: dict, sink: Sink, save, client: TeamViewerClient | None = None) -> int:
    """Read the window from the cursor (minus the overlap) to now (minus the settle time), follow
    PaginationToken until it is empty, drop events already sent, send, then move the cursor."""
    client = client or TeamViewerClient(cfg)
    now = datetime.now(timezone.utc)
    cur = state.setdefault("event_log", {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
    end = now - timedelta(seconds=cfg["settle_seconds"])
    start = _parse_time(cur["since"]) - timedelta(seconds=cfg["overlap_seconds"])
    if end <= start:
        return 0
    seen = set(cur["seen"])
    window, token = [], None
    for _ in range(MAX_REQUESTS):
        page = client.events(start, end, token)
        if page.get("ParsingError"):
            raise CollectorError("TeamViewer could not read the event log request (ParsingError)")
        window.extend(ev for ev in (page.get("AuditEvents") or []) if isinstance(ev, dict))
        token = page.get("PaginationToken")
        if not token:
            break
    else:
        raise CollectorError(f"stopped after {MAX_REQUESTS} pages; shorten COLLECTOR_LOOKBACK_HOURS")
    keyed = [(event_key(ev), ev) for ev in window]
    fresh, sent_keys = [], set()
    for k, ev in sorted(keyed, key=lambda kv: _when(kv[1])):
        if k in seen or k in sent_keys:
            continue
        sent_keys.add(k)
        fresh.append(ev)
    if fresh:
        sink.send(fresh)
    cutoff = end - timedelta(seconds=cfg["overlap_seconds"])
    cur["seen"] = list(dict.fromkeys(k for k, ev in keyed if _when(ev) >= cutoff))[-SEEN_LIMIT:]
    cur["since"] = _iso(end)
    save()
    LOG.info("event log: %d read, %d new", len(window), len(fresh))
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
    count = collect(cfg, state, sink, save)
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send the TeamViewer event log to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=os.environ.get("COLLECTOR_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "COLLECTOR_DRY_RUN", False)
    try:
        cfg = load_config()
        while True:
            run_once(cfg, dry_run)
            if not args.interval:
                return 0
            time.sleep(args.interval)
    except CollectorError as e:
        LOG.error("%s", e)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
