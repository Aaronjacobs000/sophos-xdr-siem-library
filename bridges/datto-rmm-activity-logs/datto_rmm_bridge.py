#!/usr/bin/env python3
"""Pull the Datto RMM Activity Log and send it to a Sophos NG-SIEM HTTP Ingest integration,
one JSON record per line. Python 3 standard library only.

Datto RMM pushes monitor alerts (Global Webhooks) but not its Activity Log: logins, jobs and
components run, remote takeover and Web Remote sessions, file transfers, and device and user
changes. This script reads GET /api/v2/activity-logs with an API key pair, keeps a cursor, and
posts each record unchanged so the library parser DATTO_RMM_ACTIVITY_JSON_STANDALONE_CLOUDAUDIT
(parsers/datto/datto-rmm) can normalize it.

Configuration comes from environment variables (see README.md). The cursor only moves after
HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
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
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("datto_rmm_bridge")
USER_AGENT = f"parser-studio-datto-rmm-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
SEEN_LIMIT = 20000
MAX_PAGES = 10000
# Datto documents public-client / public as the OAuth client for API key pairs.
OAUTH_CLIENT = ("public-client", "public")


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
        "api_url": (_env(env, "DATTO_RMM_API_URL") or "").rstrip("/"),
        "api_key": _env(env, "DATTO_RMM_API_KEY"),
        "api_secret": _env(env, "DATTO_RMM_API_SECRET"),
        "entities": _env(env, "DATTO_RMM_ENTITIES", "device,user"),
        "page_size": _number(env, "DATTO_RMM_PAGE_SIZE", "250"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "datto_rmm_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "settle_seconds": _number(env, "BRIDGE_SETTLE_SECONDS", "60"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float),
    }
    for name, key in (("DATTO_RMM_API_URL", "api_url"), ("DATTO_RMM_API_KEY", "api_key"), ("DATTO_RMM_API_SECRET", "api_secret")):
        if not cfg[key]:
            raise BridgeError(f"{name} is required")
    _require_https(cfg["api_url"], "DATTO_RMM_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    if not 1 <= cfg["page_size"] <= 250:
        raise BridgeError("DATTO_RMM_PAGE_SIZE must be between 1 and 250")
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


# ---------------------------------------------------------------- Datto RMM API

class DattoClient:
    """Requests an OAuth access token with the API key pair and reads the Activity Log."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.token = None

    def _get_token(self) -> str:
        basic = base64.b64encode(f"{OAUTH_CLIENT[0]}:{OAUTH_CLIENT[1]}".encode()).decode()
        form = urllib.parse.urlencode({"grant_type": "password", "username": self.cfg["api_key"],
                                       "password": self.cfg["api_secret"]}).encode()
        try:
            _, body = _request("POST", f"{self.cfg['api_url']}/auth/oauth/token",
                               {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                                "Accept": "application/json"}, form, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401):
                raise BridgeError("Datto RMM refused the API key pair (check DATTO_RMM_API_KEY and DATTO_RMM_API_SECRET, and that API access is on)") from None
            raise
        token = _json(body, "token request").get("access_token")
        if not token:
            raise BridgeError("token response has no access_token")
        return token

    def get(self, url: str) -> dict:
        # Only ever send the token to the configured API scheme and host, including nextPageUrl
        # links, so a link can't send it somewhere else or over plain http.
        here, api = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.cfg["api_url"])
        if (here.scheme, here.netloc) != (api.scheme, api.netloc):
            raise BridgeError("a page link points at a different host or scheme; refusing to send the token there")
        for refreshed in (False, True):
            if not self.token:
                self.token = self._get_token()
            try:
                _, body = _request("GET", url, {"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
                                   None, self.cfg["timeout"], "activity log request")
                return _json(body, "activity log request")
            except HttpStatus as e:
                # Tokens last 100 hours; ask for a new one once if this one has expired.
                if e.code == 401 and not refreshed:
                    self.token = None
                    continue
                if e.code == 403:
                    raise BridgeError("Datto RMM answered 403: the API user lacks Activity Log permission, or the "
                                         "address was blocked after the rate limit; wait 5 minutes before retrying") from None
                raise
        raise BridgeError("activity log request failed")


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

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def collect(cfg: dict, state: dict, sink: Sink, save, client: DattoClient | None = None) -> int:
    """Read the window from the cursor (minus the overlap) to now (minus the settle time), oldest
    first, follow nextPageUrl, drop records already sent, send, then move the cursor."""
    client = client or DattoClient(cfg)
    now = datetime.now(timezone.utc)
    cur = state.setdefault("activity_logs", {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
    until = now - timedelta(seconds=cfg["settle_seconds"])
    since = _parse_iso(cur["since"]) - timedelta(seconds=cfg["overlap_seconds"])
    if until <= since:
        return 0
    params = {"from": _iso(since), "until": _iso(until), "order": "asc", "size": cfg["page_size"]}
    if cfg["entities"]:
        params["entities"] = cfg["entities"]
    url = f"{cfg['api_url']}/api/v2/activity-logs?{urllib.parse.urlencode(params)}"
    seen = set(cur["seen"])
    window, fresh = [], []
    for _ in range(MAX_PAGES):
        page = client.get(url)
        if page.get("error"):
            raise BridgeError("Datto RMM reported an Activity Log database error")
        acts = page.get("activities") or []
        window.extend(acts)
        fresh.extend(a for a in acts if a.get("id") not in seen)
        nxt = (page.get("pageDetails") or {}).get("nextPageUrl")
        if not nxt or not acts:
            break
        url = urllib.parse.urljoin(url, nxt)
    else:
        raise BridgeError(f"stopped after {MAX_PAGES} pages; shorten BRIDGE_LOOKBACK_HOURS")
    fresh.sort(key=lambda a: (a.get("date") or 0, a.get("id") or ""))
    if fresh:
        sink.send(fresh)
    # The next run re-reads the overlap before `until`; remember those ids to drop repeats.
    cutoff = (until - timedelta(seconds=cfg["overlap_seconds"])).timestamp()
    cur["seen"] = list(dict.fromkeys(a["id"] for a in window if a.get("id") and (a.get("date") or 0) >= cutoff))[-SEEN_LIMIT:]
    cur["since"] = _iso(until)
    save()
    LOG.info("activity logs: %d read, %d new", len(window), len(fresh))
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


def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send the Datto RMM Activity Log to Sophos NG-SIEM HTTP Ingest.")
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
