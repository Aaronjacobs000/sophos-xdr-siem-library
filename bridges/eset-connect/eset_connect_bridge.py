#!/usr/bin/env python3
"""Pull ESET PROTECT (cloud) detections from the ESET Connect API and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

ESET PROTECT cloud has no syslog export, so this script signs in to ESET Connect as an API user,
lists detections by time window from the Incident Management API, and posts each detection with an
"eset_connect_record" key, so the library parsers in parsers/eset/eset-protect-cloud can normalize it:

  POST https://<region>.business-account.iam.eset.systems/oauth/token          (password or refresh_token grant)
  GET  https://<region>.incident-management.eset.systems/v1/detections         (startTime, endTime, pageSize, pageToken)

The request and response shapes follow ESET's public ESET Connect API reference and OpenAPI
specifications. Configuration comes from environment variables (see README.md). The cursor only
moves after HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
import http.client
import json
import logging
import os
import random
import re
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("eset_connect_bridge")
USER_AGENT = f"parser-studio-eset-connect-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
REGIONS = ("eu", "de", "us", "ca", "jpn")
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# ESET answers 202 with a response-id header when a query takes over 30 seconds, and keeps the
# result for 10 minutes. The bridge asks again with that header this many times.
PENDING_ATTEMPTS = 20
SEEN_LIMIT = 50000
MAX_REQUESTS = 10000
RECORD_KEY = "eset_connect_record"


class BridgeError(Exception):
    """A failure that stops the run without moving the cursor past unsent data."""


class NetworkError(BridgeError):
    """The API or HTTP Ingest couldn't be reached, even after the retries. With --interval the
    bridge logs it and tries again at the next interval."""


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
    region = (_env(env, "ESET_CONNECT_REGION", "eu") or "").lower()
    if region not in REGIONS:
        raise BridgeError(f"ESET_CONNECT_REGION must be one of {', '.join(REGIONS)}")
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "region": region,
        "token_url": (_env(env, "ESET_CONNECT_TOKEN_URL") or f"https://{region}.business-account.iam.eset.systems").rstrip("/"),
        "api_url": (_env(env, "ESET_CONNECT_API_URL") or f"https://{region}.incident-management.eset.systems").rstrip("/"),
        "username": _env(env, "ESET_CONNECT_USERNAME"),
        "password": _env(env, "ESET_CONNECT_PASSWORD"),
        "device_uuid": _env(env, "ESET_CONNECT_DEVICE_UUID"),
        "page_size": _number(env, "ESET_CONNECT_PAGE_SIZE", "500"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "eset_connect_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "pending_wait": _number(env, "BRIDGE_PENDING_WAIT_SECONDS", "15", float),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "150", float),
    }
    for name, key in (("ESET_CONNECT_USERNAME", "username"), ("ESET_CONNECT_PASSWORD", "password")):
        if not cfg[key]:
            raise BridgeError(f"{name} is required")
    if not 1 <= cfg["page_size"] <= 1000:
        raise BridgeError("ESET_CONNECT_PAGE_SIZE must be between 1 and 1000")
    if cfg["overlap_seconds"] < 0 or cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_OVERLAP_SECONDS can't be negative and BRIDGE_LOOKBACK_HOURS must be above 0")
    _require_https(cfg["token_url"], "ESET_CONNECT_TOKEN_URL")
    _require_https(cfg["api_url"], "ESET_CONNECT_API_URL")
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
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, headers, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers, _read(resp, what, url)
        except urllib.error.HTTPError as e:
            # Read the body, then close the error response so its socket is released now, not
            # when the error is garbage collected.
            try:
                error_body = _read(e, what, url)
            finally:
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


# ---------------------------------------------------------------- ESET Connect

class EsetConnect:
    """Signs in with the API user's name and password, renews the access token with the refresh
    token before it expires, and reads the Incident Management API with 'Authorization: Bearer'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0.0

    def _token(self, form: dict, what: str) -> None:
        url = f"{self.cfg['token_url']}/oauth/token"
        body = urllib.parse.urlencode(form).encode()
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        try:
            _, _, raw = _request("POST", url, headers, body, self.cfg["timeout"], what)
        except HttpStatus as e:
            if e.code in REDIRECT_STATUS:
                raise
            raise BridgeError(f"{what} failed with HTTP {e.code}; check the API user's name and password, "
                                 "and that the user has Integrations access") from None
        data = _json(raw, what) or {}
        if not data.get("access_token"):
            raise BridgeError(f"{what} returned no access token")
        self.access_token = data["access_token"]
        self.refresh_token = data.get("refresh_token") or self.refresh_token
        try:
            lifetime = int(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            lifetime = 3600
        # Renew a minute early so a token never expires mid-request.
        self.expires_at = time.time() + max(60, lifetime - 60)

    def sign_in(self) -> None:
        self._token({"grant_type": "password", "username": self.cfg["username"], "password": self.cfg["password"]},
                    "ESET Connect sign-in")

    def renew(self) -> None:
        if self.refresh_token:
            try:
                self._token({"grant_type": "refresh_token", "refresh_token": self.refresh_token}, "ESET Connect token refresh")
                return
            except HttpStatus as e:
                if e.code in REDIRECT_STATUS:
                    raise
            except BridgeError:
                pass
            LOG.info("ESET Connect token refresh failed; signing in again")
        self.sign_in()

    def get(self, path: str, params: dict, what: str) -> dict:
        """GET with the bearer token. A 401 renews the token once. A 202 means ESET is still working
        on the query: ask again with the same query and the response-id header until it answers."""
        if not self.access_token:
            self.sign_in()
        elif time.time() >= self.expires_at:
            self.renew()
        url = f"{self.cfg['api_url']}{path}?{urllib.parse.urlencode(params)}"
        response_id = None
        renewed = False
        pending = 0
        while True:
            headers = {"Authorization": f"Bearer {self.access_token}", "Accept": "application/json"}
            if response_id:
                headers["response-id"] = response_id
            try:
                status, resp_headers, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
            except HttpStatus as e:
                if e.code == 401 and not renewed:
                    LOG.info("ESET Connect token was rejected; renewing it")
                    self.renew()
                    renewed = True
                    continue
                if e.code == 404 and response_id:
                    raise BridgeError(f"{what}: ESET dropped the pending result before it was collected; the next run reads the window again") from None
                if e.code in (401, 403):
                    raise BridgeError(f"ESET Connect refused {what} (HTTP {e.code}); the API user needs Integrations access and read access to detections") from None
                raise
            if status == 202:
                pending += 1
                if pending > PENDING_ATTEMPTS:
                    raise BridgeError(f"{what}: ESET was still preparing the result after {PENDING_ATTEMPTS} checks")
                response_id = resp_headers.get("response-id") or response_id
                if not response_id:
                    raise BridgeError(f"{what}: ESET answered 202 without a response-id header")
                LOG.info("%s is pending at ESET; asking again in %.0fs", what, self.cfg["pending_wait"])
                time.sleep(self.cfg["pending_wait"])
                continue
            return _json(raw, what) if raw else {}


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

_RFC3339 = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?$", re.I)


def _epoch(value) -> float | None:
    """occurTime is a protobuf Timestamp in RFC 3339, with or without fractional seconds."""
    m = _RFC3339.match(str(value or "").strip())
    if not m:
        return None
    date, hm, sec, frac, zone = m.groups()
    zone = (zone or "Z").upper()
    zone = "+00:00" if zone == "Z" else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
    try:
        dt = datetime.fromisoformat(f"{date}T{hm}:{sec or '00'}{zone}")
    except ValueError:
        return None
    return dt.timestamp() + (float(f"0.{frac}") if frac else 0.0)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_detections(cfg: dict, state: dict, sink: Sink, save, client: EsetConnect) -> int:
    """Read every page of [cursor minus the overlap, now), send the detections not sent before,
    oldest first, then move the cursor to now."""
    now = time.time()
    cur = state.setdefault("detections", {"since": now - cfg["lookback_hours"] * 3600, "seen": []})
    start = cur["since"] - cfg["overlap_seconds"]
    # One fixed end time per run, so a pending (202) query is repeated exactly.
    params = {"startTime": _iso(start), "endTime": _iso(now), "pageSize": cfg["page_size"]}
    if cfg["device_uuid"]:
        params["deviceUuid"] = cfg["device_uuid"]
    rows, token = [], ""
    for _ in range(MAX_REQUESTS):
        query = dict(params, pageToken=token) if token else params
        data = client.get("/v1/detections", query, "detections request")
        items = (data or {}).get("detections") or []
        rows.extend(d for d in items if isinstance(d, dict))
        token = (data or {}).get("nextPageToken") or ""
        if not token:
            break
    else:
        raise BridgeError(f"stopped after {MAX_REQUESTS} pages; shorten BRIDGE_LOOKBACK_HOURS")
    seen = set(cur["seen"])
    fresh, keys = [], set()
    for d in rows:
        key = str(d.get("uuid") or json.dumps(d, sort_keys=True))
        if key in seen or key in keys:
            continue
        keys.add(key)
        fresh.append(d)
    fresh.sort(key=lambda d: _epoch(d.get("occurTime")) or 0.0)
    if fresh:
        sink.send([{RECORD_KEY: "detection", **d} for d in fresh])
    # Keep the IDs that the next run's overlap reads again, so they aren't sent twice.
    cutoff = now - cfg["overlap_seconds"]
    recent = [str(d.get("uuid") or json.dumps(d, sort_keys=True)) for d in rows if (_epoch(d.get("occurTime")) or now) >= cutoff]
    cur["seen"] = list(dict.fromkeys(recent))[-SEEN_LIMIT:]
    cur["since"] = now
    save()
    LOG.info("detections: %d read, %d new", len(rows), len(fresh))
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


def run_once(cfg: dict, dry_run: bool = False, out=None, client: EsetConnect | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    count = collect_detections(cfg, state, sink, save, client or EsetConnect(cfg))
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
    ap = argparse.ArgumentParser(description="Send ESET PROTECT (cloud) detections from ESET Connect to Sophos NG-SIEM HTTP Ingest.")
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
        client = EsetConnect(cfg)
        while True:
            try:
                run_once(cfg, dry_run, client=client)
            except NetworkError as e:
                if not args.interval:
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
