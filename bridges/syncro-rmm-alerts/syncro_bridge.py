#!/usr/bin/env python3
"""Pull Syncro RMM alerts and send them to a Sophos NG-SIEM HTTP Ingest integration, one JSON
record per line. Python 3 standard library only.

Syncro raises RMM alerts from its monitors (antivirus, event log, services, scripts and the
rest). Its notification webhook payload isn't documented and it has no syslog export, so this
script reads GET /api/v1/rmm_alerts with an API token, keeps a cursor, and posts each alert
unchanged so the library parser SYNCRO_RMM_ALERT_JSON_STANDALONE_THIRDPARTYALERT
(parsers/syncro/rmm-alerts) can normalize it.

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
LOG = logging.getLogger("syncro_bridge")
USER_AGENT = f"parser-studio-syncro-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
SEEN_LIMIT = 20000
MAX_REQUESTS = 10000


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
        "api_url": (_env(env, "SYNCRO_API_URL") or "").rstrip("/"),
        "token": _env(env, "SYNCRO_API_TOKEN"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "syncro_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": int(_env(env, "BRIDGE_BATCH_BYTES", "100000")),
        "lookback_hours": float(_env(env, "BRIDGE_LOOKBACK_HOURS", "24")),
        "overlap_seconds": int(_env(env, "BRIDGE_OVERLAP_SECONDS", "300")),
        "timeout": float(_env(env, "BRIDGE_HTTP_TIMEOUT", "60")),
    }
    for name, key in (("SYNCRO_API_URL", "api_url"), ("SYNCRO_API_TOKEN", "token")):
        if not cfg[key]:
            raise BridgeError(f"{name} is required")
    _require_https(cfg["api_url"], "SYNCRO_API_URL")
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


# ---------------------------------------------------------------- Syncro API

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


class SyncroClient:
    """Reads RMM alerts with the API token as a bearer token."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.headers = {"Authorization": f"Bearer {cfg['token']}", "Accept": "application/json"}

    def alerts(self, created_after: datetime, page: int) -> dict:
        params = {"status": "all", "created_after": _iso(created_after), "page": page}
        url = f"{self.cfg['api_url']}/rmm_alerts?{urllib.parse.urlencode(params)}"
        try:
            _, body = _request("GET", url, self.headers, None, self.cfg["timeout"], "RMM alert request")
        except HttpStatus as e:
            if e.code in (401, 403):
                raise BridgeError("Syncro refused the API token (it needs the RMM Alerts - List permission)") from None
            raise
        return _json(body, "RMM alert request")


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
    try:
        return _parse_time(rec.get("created_at") or "")
    except ValueError:
        return datetime.fromtimestamp(0, timezone.utc)


def collect(cfg: dict, state: dict, sink: Sink, save, client: SyncroClient | None = None) -> int:
    """Read every page of alerts created after the cursor (minus the overlap), drop alerts already
    sent by ID, send them oldest first, then move the cursor to the newest created_at."""
    client = client or SyncroClient(cfg)
    now = datetime.now(timezone.utc)
    cur = state.setdefault("rmm_alerts", {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
    after = _parse_time(cur["since"]) - timedelta(seconds=cfg["overlap_seconds"])
    rows, page = [], 1
    for _ in range(MAX_REQUESTS):
        body = client.alerts(after, page)
        rows.extend(r for r in (body.get("rmm_alerts") or []) if isinstance(r, dict))
        pages = int((body.get("meta") or {}).get("total_pages") or 1)
        if page >= pages:
            break
        page += 1
    else:
        raise BridgeError(f"stopped after {MAX_REQUESTS} pages; shorten BRIDGE_LOOKBACK_HOURS")
    seen = set(cur["seen"])
    fresh = sorted((r for r in {r.get("id"): r for r in rows}.values() if r.get("id") not in seen),
                   key=lambda r: (_created(r), r.get("id") or 0))
    if fresh:
        sink.send(fresh)
    newest = max([_created(r) for r in rows] + [_parse_time(cur["since"])])
    cutoff = newest - timedelta(seconds=cfg["overlap_seconds"])
    cur["seen"] = list(dict.fromkeys(r.get("id") for r in rows if r.get("id") is not None and _created(r) >= cutoff))[-SEEN_LIMIT:]
    cur["since"] = _iso(newest)
    save()
    LOG.info("RMM alerts: %d read, %d new", len(rows), len(fresh))
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
    ap = argparse.ArgumentParser(description="Send Syncro RMM alerts to Sophos NG-SIEM HTTP Ingest.")
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
