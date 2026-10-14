#!/usr/bin/env python3
"""Pull 1Password Business sign-in attempts, item usage and audit events from the 1Password
Events API and send them to a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line.
Python 3 standard library only.

1Password offers these events only through the Events API (no syslog or webhook), so this script
reads each feature with a cursor and posts each event with a "onepassword_record" key naming its
feature, so the library parsers in parsers/1password/1password-business can normalize it:

  signin_attempt   POST /api/v2/signinattempts   (signinattempts feature)
  item_usage       POST /api/v2/itemusages       (itemusages feature)
  audit_event      POST /api/v2/auditevents      (auditevents feature)

The request and response shapes follow 1Password's Events API reference. Configuration comes
from environment variables (see README.md). A feature's cursor only moves after HTTP Ingest
accepted that page. --dry-run prints what would be sent and changes nothing.
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
LOG = logging.getLogger("onepassword_events_collector")
USER_AGENT = f"parser-studio-1password-events-collector/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
MAX_PAGES = 10000
INTROSPECT_PATH = "/api/v2/auth/introspect"
# feature: (path, record name)
FEATURES = {
    "signinattempts": ("/api/v2/signinattempts", "signin_attempt"),
    "itemusages": ("/api/v2/itemusages", "item_usage"),
    "auditevents": ("/api/v2/auditevents", "audit_event"),
}


class CollectorError(Exception):
    """A failure that stops the run without moving a cursor past unsent data."""


# ---------------------------------------------------------------- configuration

def _env(env: dict, name: str, default: str | None = None) -> str | None:
    value = env.get(name)
    return value.strip() if value and value.strip() else default


def _flag(env: dict, name: str, default: bool) -> bool:
    value = _env(env, name)
    if value is None:
        return default
    return value.lower() not in ("0", "false", "no", "off")


def _csv(value: str | None) -> list[str]:
    return [x.strip().lower() for x in (value or "").split(",") if x.strip()]


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
        "api_url": (_env(env, "ONEPASSWORD_EVENTS_URL", "https://events.1password.com") or "").rstrip("/"),
        "token": _env(env, "ONEPASSWORD_EVENTS_TOKEN"),
        "features": _csv(_env(env, "ONEPASSWORD_FEATURES", "signinattempts,itemusages,auditevents")),
        "state_file": _env(env, "COLLECTOR_STATE_FILE", "onepassword_events_state.json"),
        "gzip": _flag(env, "COLLECTOR_GZIP", True),
        "batch_bytes": int(_env(env, "COLLECTOR_BATCH_BYTES", "100000")),
        "page_limit": int(_env(env, "COLLECTOR_PAGE_LIMIT", "1000")),
        "lookback_hours": float(_env(env, "COLLECTOR_LOOKBACK_HOURS", "24")),
        "timeout": float(_env(env, "COLLECTOR_HTTP_TIMEOUT", "60")),
    }
    if not cfg["token"]:
        raise CollectorError("ONEPASSWORD_EVENTS_TOKEN is required")
    if not cfg["features"]:
        raise CollectorError("ONEPASSWORD_FEATURES names no feature")
    for f in cfg["features"]:
        if f not in FEATURES:
            raise CollectorError(f"unknown feature in ONEPASSWORD_FEATURES: {f} (use signinattempts, itemusages, auditevents)")
    if not 1 <= cfg["page_limit"] <= 1000:
        raise CollectorError("COLLECTOR_PAGE_LIMIT must be from 1 to 1000")
    _require_https(cfg["api_url"], "ONEPASSWORD_EVENTS_URL")
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
    def __init__(self, what: str, url: str, code: int, body: bytes = b""):
        if code in REDIRECT_STATUS:
            message = (f"{what} to {_host(url)} answered with a redirect (HTTP {code}), which the collector refuses "
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
            raise CollectorError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise CollectorError(f"{what} to {_host(url)} failed")


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise CollectorError(f"{what} returned a body that is not JSON") from None


# ---------------------------------------------------------------- 1Password Events API

class EventsClient:
    """Calls the Events API with 'Authorization: Bearer <token>'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _call(self, method: str, path: str, payload: dict | None, what: str) -> dict:
        url = f"{self.cfg['api_url']}{path}"
        headers = {"Authorization": f"Bearer {self.cfg['token']}", "Accept": "application/json"}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        try:
            _, raw = _request(method, url, headers, body, self.cfg["timeout"], what)
        except HttpStatus as e:
            if e.code == 401:
                raise CollectorError(f"1Password refused the token for {what} (HTTP 401); check ONEPASSWORD_EVENTS_TOKEN, "
                                     "and that ONEPASSWORD_EVENTS_URL is the events URL for the account's region") from None
            if e.code == 400:
                raise CollectorError(f"1Password rejected {what} (HTTP 400): {_error_message(e.body)}") from None
            raise
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise CollectorError(f"{what} returned JSON that is not an object")
        return data

    def features(self) -> list[str]:
        data = self._call("GET", INTROSPECT_PATH, None, "token introspection")
        return [str(f).lower() for f in data.get("features") or []]

    def page(self, feature: str, payload: dict) -> dict:
        return self._call("POST", FEATURES[feature][0], payload, f"{feature} request")


def _error_message(body: bytes) -> str:
    """The API reference shows the error body as {"status": ..., "message": ...} and the OpenAPI
    spec as {"Error": {"Message": ...}}, so read either. Keep the message short."""
    try:
        data = json.loads(body) or {}
        message = data.get("message") or (data.get("Error") or {}).get("Message") or ""
    except (ValueError, AttributeError, TypeError):
        message = ""
    return str(message)[:200] or "no message"


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

def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_feature(feature: str, cfg: dict, state: dict, sink: Sink, save, client: EventsClient) -> int:
    """Read pages from the saved cursor, or from the lookback on the first run, until has_more is
    false. Each page is sent, then its cursor saved."""
    record = FEATURES[feature][1]
    cursor = (state.get(feature) or {}).get("cursor")
    if cursor:
        payload = {"cursor": cursor}
    else:
        start = datetime.now(timezone.utc) - timedelta(hours=cfg["lookback_hours"])
        payload = {"limit": cfg["page_limit"], "start_time": _rfc3339(start)}
    sent = 0
    for _ in range(MAX_PAGES):
        data = client.page(feature, payload)
        items = data.get("items") or []
        if not isinstance(items, list):
            raise CollectorError(f"{feature} returned items that are not a list")
        cursor = data.get("cursor")
        if not cursor or not isinstance(cursor, str):
            raise CollectorError(f"{feature} returned no cursor")
        rows = [r for r in items if isinstance(r, dict)]
        if rows:
            sink.send([{"onepassword_record": record, **r} for r in rows])
        state[feature] = {"cursor": cursor}
        save()
        sent += len(rows)
        if not data.get("has_more"):
            break
        payload = {"cursor": cursor}
    else:
        LOG.warning("%s: stopped after %d pages; the next run continues from the saved cursor", feature, MAX_PAGES)
    LOG.info("%s: %d sent", feature, sent)
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
        json.dump(state, fh, indent=1)
    os.replace(tmp, path)


def run_once(cfg: dict, dry_run: bool = False, out=None) -> dict:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = EventsClient(cfg)
    allowed = client.features()
    missing = [f for f in cfg["features"] if f not in allowed]
    if missing:
        raise CollectorError(f"the token can't read {', '.join(missing)}; add the event types to the Events Reporting "
                             "integration's token, or leave them out of ONEPASSWORD_FEATURES")
    counts = {f: collect_feature(f, cfg, state, sink, save, client) for f in cfg["features"]}
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send 1Password Business events from the Events API to Sophos NG-SIEM HTTP Ingest.")
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
