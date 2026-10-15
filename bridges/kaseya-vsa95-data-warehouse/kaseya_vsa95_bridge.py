#!/usr/bin/env python3
"""Pull remote control, Live Connect and configuration change records from the Kaseya VSA 9.5
Data Warehouse API and send them to a Sophos NG-SIEM HTTP Ingest integration, one JSON record
per line. Python 3 standard library only.

VSA 9.5 has no syslog or webhook export for these logs. This script reads the Data Warehouse
API (GET /api/odata/1.0/<dataset>) with a user token, keeps a cursor per dataset, adds a
"Dataset" key at the front of each record, and posts it so the library parser
KASEYA_VSA95_DW_JSON_STANDALONE_CLOUDAUDIT (parsers/kaseya/vsa-9-5) can normalize it.

Configuration comes from environment variables (see README.md). Each cursor only moves after
HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.client
import json
import logging
import os
import random
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("kaseya_vsa95_bridge")
USER_AGENT = f"parser-studio-kaseya-vsa95-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
SEEN_LIMIT = 20000
MAX_REQUESTS = 10000
# The datasets this bridge reads, with the field that orders each one in time and the fields
# that identify a record. Names and fields come from the Data Warehouse API reference (R95).
DATASETS = {
    "RemoteControlSessions": ("SessionStartTime", ("SessionId",)),
    "RemoteControlFileTransferSessions": ("TransferTime", ("SessionId", "TransferTime", "TransferFileOrFolderName")),
    "AgentLiveConnectAuditLogs": ("EntryTimeStamp", ("AgentId", "EntryTimeStamp", "LogEntry")),
    "LiveConnectOnDemandAudit": ("CreationDateTime", ("EntryId",)),
    "ConfigurationChangeEvents": ("ChangeEventDateTime", ("AgentId", "EventId")),
}


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


def _number(env: dict, name: str, default: str, cast=int, high: int = 10 ** 9):
    """A numeric setting: a bad value stops the bridge with one plain error, not a traceback."""
    value = _env(env, name, default)
    try:
        number = cast(value)
    except ValueError:
        raise BridgeError(f"{name} must be a number") from None
    # NaN fails every comparison, so it lands here too.
    if not 0 <= number <= high:
        raise BridgeError(f"{name} must be between 0 and {high:,}")
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
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "VSA95_API_URL") or "").rstrip("/"),
        "username": _env(env, "VSA95_USERNAME"),
        "token": _env(env, "VSA95_USER_TOKEN"),
        "datasets": [x.strip() for x in (_env(env, "VSA95_DATASETS") or ",".join(DATASETS)).split(",") if x.strip()],
        "page_size": _number(env, "VSA95_PAGE_SIZE", "1000"),
        "quote_times": _flag(env, "VSA95_QUOTE_TIMES", False),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "kaseya_vsa95_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float),
    }
    for name, key in (("VSA95_API_URL", "api_url"), ("VSA95_USERNAME", "username"), ("VSA95_USER_TOKEN", "token")):
        if not cfg[key]:
            raise BridgeError(f"{name} is required")
    _require_https(cfg["api_url"], "VSA95_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    for d in cfg["datasets"]:
        if d not in DATASETS:
            raise BridgeError(f"unknown dataset in VSA95_DATASETS: {d}")
    if not 1 <= cfg["page_size"] <= 10000:
        raise BridgeError("VSA95_PAGE_SIZE must be between 1 and 10000")
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


def _read(resp, what: str, url: str, limit: int | None = None) -> bytes:
    """Reads a response body, but no more than the limit, so a broken or hostile endpoint can't
    use up memory."""
    limit = limit or MAX_RESPONSE_BYTES
    body = resp.read(limit + 1)
    if len(body) > limit:
        raise BridgeError(f"{what} to {_host(url)} sent more than {limit // 1048576} MB, which the bridge "
                          "refuses so a bad response can't use up memory")
    return body


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, _read(resp, what, url)
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


# ---------------------------------------------------------------- Data Warehouse API

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


class WarehouseClient:
    """Reads Data Warehouse datasets with HTTP Basic (user name and user token)."""

    def __init__(self, cfg: dict):
        basic = base64.b64encode(f"{cfg['username']}:{cfg['token']}".encode()).decode()
        self.headers = {"Authorization": f"Basic {basic}", "Accept": "application/json"}
        self.cfg = cfg

    def page(self, dataset: str, time_field: str, after: datetime, skip: int) -> list[dict]:
        literal = f"'{_iso(after)}'" if self.cfg["quote_times"] else _iso(after)
        params = {"$filter": f"{time_field} gt {literal}", "$orderby": f"{time_field} asc",
                  "$top": self.cfg["page_size"], "$skip": skip}
        url = f"{self.cfg['api_url']}/{dataset}?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"
        try:
            _, body = _request("GET", url, self.headers, None, self.cfg["timeout"], f"{dataset} request")
        except HttpStatus as e:
            if e.code in (401, 403):
                raise BridgeError("VSA refused the user token (it needs the Data Warehouse API scope)") from None
            if e.code == 400:
                raise BridgeError(f"VSA refused the {dataset} filter; try VSA95_QUOTE_TIMES=1") from None
            raise
        body = _json(body, f"{dataset} request")
        rows = body.get("value") if isinstance(body, dict) else body
        return [r for r in (rows or []) if isinstance(r, dict)]


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

def record_key(dataset: str, rec: dict) -> str:
    fields = DATASETS[dataset][1]
    raw = json.dumps([dataset] + [rec.get(f) for f in fields], separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _when(rec: dict, field: str) -> datetime:
    try:
        return _parse_time(rec.get(field) or "")
    except ValueError:
        return datetime.fromtimestamp(0, timezone.utc)


def collect(cfg: dict, state: dict, sink: Sink, save, client: WarehouseClient | None = None) -> int:
    """For each dataset, read records newer than its cursor (minus the overlap), oldest first, page
    with $skip, drop records already sent, send them with a Dataset key in front, then move the
    cursor to the newest time read."""
    client = client or WarehouseClient(cfg)
    now = datetime.now(timezone.utc)
    total = 0
    for dataset in cfg["datasets"]:
        time_field = DATASETS[dataset][0]
        cur = state.setdefault(dataset, {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
        after = min(_parse_time(cur["since"]), now) - timedelta(seconds=cfg["overlap_seconds"])
        rows, skip = [], 0
        for _ in range(MAX_REQUESTS):
            page = client.page(dataset, time_field, after, skip)
            rows.extend(page)
            if len(page) < cfg["page_size"]:
                break
            skip += len(page)
        else:
            raise BridgeError(f"stopped after {MAX_REQUESTS} pages of {dataset}; shorten BRIDGE_LOOKBACK_HOURS")
        seen = set(cur["seen"])
        keyed = [(record_key(dataset, r), r) for r in rows]
        fresh, sent = [], set()
        for k, r in sorted(keyed, key=lambda kr: _when(kr[1], time_field)):
            if k in seen or k in sent:
                continue
            sent.add(k)
            fresh.append({"Dataset": dataset, **r})
        if fresh:
            sink.send(fresh)
        # A record dated in the future, from a wrong clock, mustn't move the cursor past now: the
        # next run would ask only for records after it.
        newest = min(max([_when(r, time_field) for r in rows] + [_parse_time(cur["since"])]), now)
        cutoff = newest - timedelta(seconds=cfg["overlap_seconds"])
        cur["seen"] = list(dict.fromkeys(k for k, r in keyed if _when(r, time_field) >= cutoff))[-SEEN_LIMIT:]
        cur["since"] = _iso(newest)
        save()
        LOG.info("%s: %d read, %d new", dataset, len(rows), len(fresh))
        total += len(fresh)
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


def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Kaseya VSA 9.5 Data Warehouse logs to Sophos NG-SIEM HTTP Ingest.")
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
        while True:
            try:
                run_once(cfg, dry_run)
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
