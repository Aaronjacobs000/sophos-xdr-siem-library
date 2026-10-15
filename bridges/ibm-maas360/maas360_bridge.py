#!/usr/bin/env python3
"""Pull IBM MaaS360 portal administrator logins and administrator changes and send them to a
Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

MaaS360 has no syslog or webhook for portal audit data, so this script authenticates to the
MaaS360 web services with an access key, reads two reports by time window, and posts each record
with a "maas360_record" key naming its report, so the library parsers in parsers/ibm/maas360 can
normalize it:

  admin_login   GET .../administrator/1.0/getAdminLoginReports/customer/{billingId}   (loginEvent)
  admin_change  GET .../administrator/1.0/getAdminChangesAudit/customer/{billingId}   (adminChange)

IBM's per-endpoint reference is inside the MaaS360 Portal (Setup > Web Services API >
Documentation). The request and response shapes here follow IBM's public authentication page and
the MIT-licensed Cortex XSOAR IBM MaaS360 Security event collector.

Configuration comes from environment variables (see README.md). Cursors only move after HTTP
Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
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

__version__ = "0.1.0"
LOG = logging.getLogger("maas360_bridge")
USER_AGENT = f"parser-studio-maas360-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
SEEN_LIMIT = 50000
MAX_REQUESTS = 10000
PAGE_SIZE = 250
# report: (path, response key, list key, time field)
REPORTS = {
    "admin_login": ("/account-provisioning/administrator/1.0/getAdminLoginReports/customer/{billing}",
                    "loginEvents", "loginEvent", "loginAttemptTime"),
    "admin_change": ("/account-provisioning/administrator/1.0/getAdminChangesAudit/customer/{billing}",
                     "adminChanges", "adminChange", "updateDate"),
}


class BridgeError(Exception):
    """A failure that stops the run without moving a cursor past unsent data."""


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


def _number(env: dict, name: str, default: str, cast=int, low: float = 0, high: int = 10 ** 9):
    """A numeric setting: a bad value stops the bridge with one plain error, not a traceback."""
    value = _env(env, name, default)
    try:
        number = cast(value)
    except ValueError:
        raise BridgeError(f"{name} must be a number") from None
    # NaN fails every comparison, so it lands here too.
    if not low <= number <= high:
        raise BridgeError(f"{name} must be between {low:,} and {high:,}")
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
        "api_url": (_env(env, "MAAS360_API_URL") or "").rstrip("/"),
        "billing_id": _env(env, "MAAS360_BILLING_ID"),
        "platform_id": _env(env, "MAAS360_PLATFORM_ID", "3"),
        "app_id": _env(env, "MAAS360_APP_ID"),
        "app_version": _env(env, "MAAS360_APP_VERSION", "1.0"),
        "access_key": _env(env, "MAAS360_APP_ACCESS_KEY"),
        "username": _env(env, "MAAS360_USERNAME"),
        "password": _env(env, "MAAS360_PASSWORD"),
        "sources": _csv(_env(env, "MAAS360_SOURCES", "admin_login,admin_change")),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "maas360_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    for name, key in (("MAAS360_API_URL", "api_url"), ("MAAS360_BILLING_ID", "billing_id"), ("MAAS360_APP_ID", "app_id"),
                      ("MAAS360_APP_ACCESS_KEY", "access_key"), ("MAAS360_USERNAME", "username"), ("MAAS360_PASSWORD", "password")):
        if not cfg[key]:
            raise BridgeError(f"{name} is required")
    for s in cfg["sources"]:
        if s not in REPORTS:
            raise BridgeError(f"unknown source in MAAS360_SOURCES: {s}")
    if not cfg["sources"]:
        raise BridgeError("MAAS360_SOURCES names no source")
    _require_https(cfg["api_url"], "MAAS360_API_URL")
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
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, _read(resp, what, url)
        except urllib.error.HTTPError as e:
            # Read the body, then close the error response so its socket is released now, not
            # when the error is garbage collected. A status that is retried is retried whatever
            # its body, so a body over the limit only stops the run for the other statuses.
            try:
                error_body = _read(e, what, url)
            except BridgeError:
                if e.code not in RETRY_STATUS:
                    raise
                error_body = b""
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


# ---------------------------------------------------------------- MaaS360 web services

class TokenRejected(BridgeError):
    """The MaaS360 token was invalid or expired."""


class MaaS360Client:
    """Authenticates with the access key and reads the administrator reports with
    'Authorization: MaaS token="<token>"'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.token = None

    def authenticate(self) -> None:
        c = self.cfg
        body = json.dumps({"authRequest": {"maaS360AdminAuth": {
            "billingID": c["billing_id"], "platformID": c["platform_id"], "appID": c["app_id"], "appVersion": c["app_version"],
            "appAccessKey": c["access_key"], "userName": c["username"], "password": c["password"]}}}).encode()
        url = f"{c['api_url']}/auth-apis/auth/2.0/authenticate/customer/{urllib.parse.quote(c['billing_id'], safe='')}"
        try:
            _, raw = _request("POST", url, {"Accept": "application/json", "Content-Type": "application/json"}, body,
                              c["timeout"], "MaaS360 authentication")
        except HttpStatus as e:
            if e.code in REDIRECT_STATUS:
                raise
            raise BridgeError(f"MaaS360 authentication failed with HTTP {e.code}; check the access key and credentials") from None
        res = (_json(raw, "MaaS360 authentication") or {}).get("authResponse") or {}
        # Failed authentication can come back with HTTP 200 and an errorCode.
        if res.get("errorCode") or not res.get("authToken"):
            raise BridgeError(f"MaaS360 authentication failed (error code {res.get('errorCode') or 'none'}); check the access key and credentials")
        self.token = res["authToken"]

    def get(self, path: str, params: dict, what: str) -> dict:
        if not self.token:
            self.authenticate()
        for attempt in range(2):
            url = f"{self.cfg['api_url']}{path}?{urllib.parse.urlencode(params)}"
            headers = {"Authorization": f'MaaS token="{self.token}"', "Accept": "application/json"}
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
                return _json(raw, what)
            except HttpStatus as e:
                text = e.body.decode("utf-8", "replace") if e.body else ""
                if attempt == 0 and (e.code == 401 or "Token invalid" in text or "Token expired" in text):
                    LOG.info("MaaS360 token was rejected; authenticating again")
                    self.authenticate()
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"MaaS360 refused {what} (HTTP {e.code}); the administrator needs read access to administrator reports") from None
                raise
        raise BridgeError(f"{what} failed")


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

def _ms(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _fingerprint(rec: dict) -> str:
    """The reports carry no record ID, so a repeat inside the overlap is recognized by content."""
    return hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def collect_report(name: str, cfg: dict, state: dict, sink: Sink, save, client: MaaS360Client) -> int:
    """Read every page of the window from the cursor (minus the overlap) to now, oldest first."""
    path, resp_key, list_key, ts_field = REPORTS[name]
    path = path.format(billing=urllib.parse.quote(cfg["billing_id"], safe=""))
    now = int(time.time() * 1000)
    cur = state.setdefault(name, {"since": now - int(cfg["lookback_hours"] * 3600 * 1000), "seen": []})
    start = min(cur["since"], now) - cfg["overlap_seconds"] * 1000
    rows, page = [], 1
    for _ in range(MAX_REQUESTS):
        data = client.get(path, {"fromDate": start, "toDate": now, "pageSize": PAGE_SIZE, "pageNumber": page},
                          f"{name} report request")
        block = (data or {}).get(resp_key) or {}
        items = block.get(list_key) or []
        if isinstance(items, dict):  # a single record comes back as an object, not a list
            items = [items]
        rows.extend(r for r in items if isinstance(r, dict))
        if len(items) < PAGE_SIZE:
            break
        page += 1
    else:
        raise BridgeError(f"{name}: stopped after {MAX_REQUESTS} pages; shorten BRIDGE_LOOKBACK_HOURS")
    seen = set(cur["seen"])
    fresh = sorted((r for r in rows if _fingerprint(r) not in seen), key=lambda r: _ms(r.get(ts_field)))
    if fresh:
        sink.send([{"maas360_record": name, **r} for r in fresh])
    # A record dated in the future, from a wrong clock, mustn't move the cursor past now: the
    # next run would ask only for records after it.
    newest = min(max([_ms(r.get(ts_field)) for r in rows] + [cur["since"]]), now)
    cutoff = newest - cfg["overlap_seconds"] * 1000
    cur["seen"] = list(dict.fromkeys(_fingerprint(r) for r in rows if _ms(r.get(ts_field)) >= cutoff))[-SEEN_LIMIT:]
    cur["since"] = newest
    save()
    LOG.info("%s: %d read, %d new", name, len(rows), len(fresh))
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


def run_once(cfg: dict, dry_run: bool = False, out=None) -> dict:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = MaaS360Client(cfg)
    counts = {name: collect_report(name, cfg, state, sink, save, client) for name in cfg["sources"]}
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
    ap = argparse.ArgumentParser(description="Send IBM MaaS360 administrator logins and changes to Sophos NG-SIEM HTTP Ingest.")
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
