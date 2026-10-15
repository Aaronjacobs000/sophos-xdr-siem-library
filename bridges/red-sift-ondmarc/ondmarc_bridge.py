#!/usr/bin/env python3
"""Pull Red Sift OnDMARC records from the OnDMARC API v2 and send them to a Sophos NG-SIEM HTTP
Ingest integration, one JSON record per line. Python 3 standard library only.

OnDMARC has no syslog export, and its Event Hub push format isn't publicly documented, so this
script reads the public API v2 with an API key, keeps a cursor per source, and posts each record
with an "ondmarc_record" key naming its source, so the library parsers in parsers/red-sift/ondmarc
can normalize it:

  guardian     GET /dmarc-guardian              DMARC Guardian issues (dangling DNS, SPF takeover)
  dns_history  GET /dns-history                 DNS record changes on the account's domains
  aggregate    GET /reports/aggregate/analyst   DMARC aggregate report rows, one day per request
               (needs OnDMARC's DMARC Analyst feature; off unless named in ONDMARC_SOURCES)

Configuration comes from environment variables (see README.md). Cursors only move after HTTP
Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
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
from datetime import date, datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("ondmarc_bridge")
USER_AGENT = f"parser-studio-ondmarc-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
SEEN_LIMIT = 50000
MAX_REQUESTS = 10000
SOURCES = ("guardian", "dns_history", "aggregate")
DEFAULT_API_URL = "https://rpc.redsift.cloud/api/ondmarc/v2"


class BridgeError(Exception):
    """A failure that stops the run without moving a cursor past unsent data."""


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


def _csv(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


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
        "api_url": (_env(env, "ONDMARC_API_URL") or DEFAULT_API_URL).rstrip("/"),
        "api_key": _env(env, "ONDMARC_API_KEY"),
        "sources": _csv(_env(env, "ONDMARC_SOURCES", "guardian,dns_history")),
        "aggregate_domains": _csv(_env(env, "ONDMARC_AGGREGATE_DOMAINS")),
        "aggregate_lookback_days": _number(env, "ONDMARC_AGGREGATE_LOOKBACK_DAYS", "7", high=36500),
        "aggregate_settle_days": _number(env, "ONDMARC_AGGREGATE_SETTLE_DAYS", "2", high=36500),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "ondmarc_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float),
    }
    if not cfg["api_key"]:
        raise BridgeError("ONDMARC_API_KEY is required")
    for s in cfg["sources"]:
        if s not in SOURCES:
            raise BridgeError(f"unknown source in ONDMARC_SOURCES: {s}")
    if not cfg["sources"]:
        raise BridgeError("ONDMARC_SOURCES names no source")
    _require_https(cfg["api_url"], "ONDMARC_API_URL")
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


# ---------------------------------------------------------------- OnDMARC API

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: str) -> datetime:
    v = (value or "").strip().replace("Z", "+00:00")
    if "." in v:  # fromisoformat before 3.11 takes 3 or 6 fraction digits only
        head, rest = v.split(".", 1)
        # The fraction is the digits right after the point. An offset after them keeps its place.
        tail = rest.lstrip("0123456789")
        v = head + "." + (rest[:len(rest) - len(tail)] + "000000")[:6] + tail
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class OnDmarcClient:
    """Reads the OnDMARC API v2 with "Authorization: Api-Key <key>"."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.headers = {"Authorization": f"Api-Key {cfg['api_key']}", "Accept": "application/json"}

    def get(self, path: str, params: dict, what: str) -> dict:
        url = f"{self.cfg['api_url']}{path}?{urllib.parse.urlencode(params)}"
        try:
            _, body = _request("GET", url, self.headers, None, self.cfg["timeout"], what)
        except HttpStatus as e:
            if e.code in (401, 403):
                raise BridgeError(f"OnDMARC refused the API key for {what} (HTTP {e.code}); check the key, its region and that API access is on for the account") from None
            if e.code == 402:
                raise BridgeError(f"{what} needs a feature that isn't enabled for this OnDMARC account (HTTP 402)") from None
            raise
        data = _json(body, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned an unexpected body")
        return data

    def paged(self, path: str, params: dict, what: str) -> list:
        """Follow page and pagination.page_count (pages count from 0)."""
        rows, page = [], 0
        for _ in range(MAX_REQUESTS):
            data = self.get(path, {**params, "page": page}, what)
            rows.extend(data.get("data") or [])
            pages = int((data.get("pagination") or {}).get("page_count") or 0)
            page += 1
            if page >= pages:
                return rows
        raise BridgeError(f"{what}: stopped after {MAX_REQUESTS} pages")


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


# ---------------------------------------------------------------- sources

def guardian_record(item: dict) -> dict:
    """Tag a Guardian issue. The bulky threat-intelligence list and the screenshot URL are left out."""
    rec = {"ondmarc_record": "dmarc_guardian_issue"}
    for k, v in item.items():
        if k == "imageUrl":
            continue
        if k == "emails" and isinstance(v, dict):
            v = {ek: ev for ek, ev in v.items() if ek != "list"}
        rec[k] = v
    return rec


def collect_guardian(cfg: dict, state: dict, sink: Sink, save, client: OnDmarcClient) -> int:
    """The Guardian list holds the account's active issues. An issue is sent when it first
    appears and again whenever its lastUpdated changes."""
    items = client.paged("/dmarc-guardian", {"page_size": 1000}, "DMARC Guardian request")
    known = state.setdefault("guardian", {"issues": {}})["issues"]
    fresh, current = [], {}
    for item in items:
        issue = item.get("issue") or {}
        iid = issue.get("issueId")
        if iid is None:
            continue
        key, updated = str(iid), str(issue.get("lastUpdated") or issue.get("createdOn") or "")
        current[key] = updated
        if known.get(key) != updated:
            fresh.append(guardian_record(item))
    if fresh:
        sink.send(fresh)
    state["guardian"]["issues"] = current
    save()
    LOG.info("DMARC Guardian: %d active issues, %d new or updated", len(items), len(fresh))
    return len(fresh)


def dns_record(row: dict) -> dict:
    rec = {"ondmarc_record": "dns_history"}
    rec.update({k: v for k, v in row.items() if k != "diffSegments"})
    return rec


def collect_dns_history(cfg: dict, state: dict, sink: Sink, save, client: OnDmarcClient) -> int:
    """Read changes from the day of the cursor (minus the overlap), oldest first, and drop the ones
    already sent by ID. The API filters by whole UTC days, so IDs from that day are remembered."""
    now = datetime.now(timezone.utc)
    cur = state.setdefault("dns_history", {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
    start = min(_parse_time(cur["since"]), now) - timedelta(seconds=cfg["overlap_seconds"])
    rows = client.paged("/dns-history", {"from_date": start.date().isoformat(), "sort": "observedAt::asc", "page_size": 1000},
                        "DNS history request")
    seen = set(cur["seen"])

    def observed(r):
        try:
            return _parse_time(r.get("observedAt") or "")
        except ValueError:
            return datetime.fromtimestamp(0, timezone.utc)

    rows = [r for r in rows if isinstance(r, dict) and r.get("id") is not None]
    fresh = sorted((r for r in {r["id"]: r for r in rows}.values() if r["id"] not in seen and observed(r) >= start),
                   key=lambda r: (observed(r), str(r["id"])))
    if fresh:
        sink.send([dns_record(r) for r in fresh])
    # A record dated in the future, from a wrong clock, mustn't move the cursor past now: the
    # next run would ask only for records after it.
    newest = min(max([observed(r) for r in rows] + [_parse_time(cur["since"])]), now)
    keep_from = datetime.combine((newest - timedelta(seconds=cfg["overlap_seconds"])).date(), datetime.min.time(), timezone.utc)
    cur["seen"] = list(dict.fromkeys(r["id"] for r in rows if observed(r) >= keep_from))[-SEEN_LIMIT:]
    cur["since"] = _iso(newest)
    save()
    LOG.info("DNS history: %d read, %d new", len(rows), len(fresh))
    return len(fresh)


def collect_aggregate(cfg: dict, state: dict, sink: Sink, save, client: OnDmarcClient) -> int:
    """Read each finished day once per domain. DMARC reporters send aggregate reports a day or two
    late, so a day is read when it is ONDMARC_AGGREGATE_SETTLE_DAYS old."""
    domains = cfg["aggregate_domains"] or [d for d in client.paged("/domains/flat", {"page_size": 1000}, "domain list request")
                                           if isinstance(d, str)]
    st = state.setdefault("aggregate", {"days": {}})["days"]
    last_day = datetime.now(timezone.utc).date() - timedelta(days=cfg["aggregate_settle_days"])
    total = 0
    for domain in domains:
        done = st.get(domain)
        day = date.fromisoformat(done) + timedelta(days=1) if done else last_day - timedelta(days=cfg["aggregate_lookback_days"] - 1)
        while day <= last_day:
            rows, page = [], 0
            for _ in range(MAX_REQUESTS):
                data = client.get("/reports/aggregate/analyst",
                                  {"from_date": day.isoformat(), "to_date": day.isoformat(), "domain": domain,
                                   "pagination_model": json.dumps({"page": page, "pageSize": 1000}, separators=(",", ":"))},
                                  "aggregate report request")
                batch = [r for r in (data.get("data") or []) if isinstance(r, dict)]
                rows.extend(batch)
                page += 1
                if not batch or len(rows) >= int(data.get("rowCount") or 0):
                    break
            else:
                raise BridgeError(f"aggregate report request: stopped after {MAX_REQUESTS} pages")
            records = [{"ondmarc_record": "aggregate_record", "ondmarc_domain": domain, **r} for r in rows]
            if records:
                sink.send(records)
            total += len(records)
            st[domain] = day.isoformat()
            save()
            LOG.info("aggregate reports: %s %s gave %d rows", domain, day.isoformat(), len(records))
            day += timedelta(days=1)
    return total


COLLECT_BY_SOURCE = {"guardian": collect_guardian, "dns_history": collect_dns_history, "aggregate": collect_aggregate}


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
    client = OnDmarcClient(cfg)
    counts = {name: COLLECT_BY_SOURCE[name](cfg, state, sink, save, client) for name in cfg["sources"]}
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return counts


def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Red Sift OnDMARC records to Sophos NG-SIEM HTTP Ingest.")
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
