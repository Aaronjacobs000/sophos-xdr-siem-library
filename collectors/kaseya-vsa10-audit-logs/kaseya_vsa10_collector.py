#!/usr/bin/env python3
"""Pull the Kaseya VSA 10 audit log and send it to a Sophos NG-SIEM HTTP Ingest integration,
one JSON record per line. Python 3 standard library only.

VSA 10 pushes notifications through webhooks but not its audit log: ad-hoc and automation
script runs, remote control, file transfers, API token and account changes. This script reads
GET /api/v3/auditlogs with a third-party API token, keeps the last AuditLogRecordId as its
cursor, and posts each record unchanged so the library parser
KASEYA_VSA10_AUDIT_JSON_STANDALONE_CLOUDAUDIT (parsers/kaseya/vsa-10) can normalize it.
Pulseway documents the same API, so the same script reads Pulseway with VSA10_API_URL set to
its API base.

Configuration comes from environment variables (see README.md). The cursor only moves after
HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
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
LOG = logging.getLogger("kaseya_vsa10_collector")
USER_AGENT = f"parser-studio-kaseya-vsa10-collector/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
MAX_PAGES = 10000


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
        "api_url": (_env(env, "VSA10_API_URL") or "").rstrip("/"),
        "token_id": _env(env, "VSA10_TOKEN_ID"),
        "token_secret": _env(env, "VSA10_TOKEN_SECRET"),
        "page_size": int(_env(env, "VSA10_PAGE_SIZE", "1000")),
        "start_id": _env(env, "VSA10_START_ID"),
        "state_file": _env(env, "COLLECTOR_STATE_FILE", "kaseya_vsa10_state.json"),
        "gzip": _flag(env, "COLLECTOR_GZIP", True),
        "batch_bytes": int(_env(env, "COLLECTOR_BATCH_BYTES", "100000")),
        "lookback_hours": float(_env(env, "COLLECTOR_LOOKBACK_HOURS", "24")),
        "timeout": float(_env(env, "COLLECTOR_HTTP_TIMEOUT", "60")),
    }
    for name, key in (("VSA10_API_URL", "api_url"), ("VSA10_TOKEN_ID", "token_id"), ("VSA10_TOKEN_SECRET", "token_secret")):
        if not cfg[key]:
            raise CollectorError(f"{name} is required")
    _require_https(cfg["api_url"], "VSA10_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    if not 1 <= cfg["page_size"] <= 5000:
        raise CollectorError("VSA10_PAGE_SIZE must be between 1 and 5000")
    if cfg["start_id"] is not None and not cfg["start_id"].isdigit():
        raise CollectorError("VSA10_START_ID must be a whole number")
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
        if code in REDIRECT_STATUS:
            message = (f"{what} to {_host(url)} answered with a redirect (HTTP {code}), which the collector refuses "
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
            raise CollectorError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise CollectorError(f"{what} to {_host(url)} failed")


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise CollectorError(f"{what} returned a body that is not JSON") from None


# ---------------------------------------------------------------- VSA 10 API

class VsaClient:
    """Reads the audit log with HTTP Basic authentication (token ID and secret)."""

    def __init__(self, cfg: dict):
        basic = base64.b64encode(f"{cfg['token_id']}:{cfg['token_secret']}".encode()).decode()
        self.headers = {"Authorization": f"Basic {basic}", "Accept": "application/json"}
        self.cfg = cfg

    def audit_logs(self, filter_expr: str) -> list[dict]:
        params = {"$filter": filter_expr, "$orderby": "AuditLogRecordId asc", "$top": self.cfg["page_size"]}
        url = f"{self.cfg['api_url']}/auditlogs?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"
        try:
            _, body = _request("GET", url, self.headers, None, self.cfg["timeout"], "audit log request")
        except HttpStatus as e:
            if e.code == 401:
                raise CollectorError("VSA 10 refused the API token (check VSA10_TOKEN_ID and VSA10_TOKEN_SECRET)") from None
            if e.code == 403:
                raise CollectorError("VSA 10 answered 403: the token lacks audit log permission or its IP allow-list blocks this address") from None
            raise
        page = _json(body, "audit log request")
        meta = page.get("Meta") or {}
        if meta.get("ResponseCode") not in (None, 200):
            raise CollectorError(f"VSA 10 reported response code {meta.get('ResponseCode')}")
        return page.get("Data") or []


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

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect(cfg: dict, state: dict, sink: Sink, save, client: VsaClient | None = None) -> int:
    """Keyset paging on AuditLogRecordId: each request asks for records after the cursor, oldest
    first, and the cursor moves to the last id of every page HTTP Ingest accepted."""
    client = client or VsaClient(cfg)
    cur = state.setdefault("audit_logs", {"last_id": None})
    if cur["last_id"] is None and cfg["start_id"] is not None:
        cur["last_id"] = int(cfg["start_id"])
    total = 0
    for _ in range(MAX_PAGES):
        if cur["last_id"] is None:
            since = datetime.now(timezone.utc) - timedelta(hours=cfg["lookback_hours"])
            records = client.audit_logs(f"AuditLogRecordDateTime ge {_iso(since)}")
        else:
            records = client.audit_logs(f"AuditLogRecordId gt {int(cur['last_id'])}")
        if not records:
            break
        records.sort(key=lambda r: r.get("AuditLogRecordId") or 0)
        sink.send(records)
        total += len(records)
        cur["last_id"] = max(int(r.get("AuditLogRecordId") or 0) for r in records)
        save()
        LOG.info("audit logs: %d records sent, cursor at id %s", len(records), cur["last_id"])
        if len(records) < cfg["page_size"]:
            break
    else:
        raise CollectorError(f"stopped after {MAX_PAGES} pages; run again to continue")
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
    ap = argparse.ArgumentParser(description="Send the Kaseya VSA 10 (or Pulseway) audit log to Sophos NG-SIEM HTTP Ingest.")
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
