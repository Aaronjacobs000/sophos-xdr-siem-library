#!/usr/bin/env python3
"""Turn N-able N-sight RMM failing checks into events and send them to a Sophos NG-SIEM HTTP
Ingest integration, one JSON record per line. Python 3 standard library only.

N-sight RMM has no syslog, webhook or audit log export. Its Data Extraction API returns the
checks failing right now (service list_failing_checks, XML). This script polls that list,
compares it with the last poll, and sends one record when a check starts failing and one when
it clears, so the library parser NSIGHT_FAILING_CHECK_JSON_STANDALONE_THIRDPARTYALERT
(parsers/n-able/n-sight-rmm) can normalize them.

Configuration comes from environment variables (see README.md). The saved state only changes
after HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
import http.client
import json
import xml.etree.ElementTree as ET
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
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("n_sight_bridge")
USER_AGENT = f"parser-studio-n-sight-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
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
        "api_url": (_env(env, "NSIGHT_API_URL") or "").rstrip("/"),
        "api_key": _env(env, "NSIGHT_API_KEY"),
        "client_ids": [x.strip() for x in (_env(env, "NSIGHT_CLIENT_IDS") or "").split(",") if x.strip()],
        "check_type": _env(env, "NSIGHT_CHECK_TYPE", "random"),
        "send_existing": _flag(env, "NSIGHT_SEND_EXISTING", True),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "n_sight_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "120", float),
    }
    for name, key in (("NSIGHT_API_URL", "api_url"), ("NSIGHT_API_KEY", "api_key")):
        if not cfg[key]:
            raise BridgeError(f"{name} is required")
    _require_https(cfg["api_url"], "NSIGHT_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    if cfg["check_type"] not in ("checks", "tasks", "random"):
        raise BridgeError("NSIGHT_CHECK_TYPE must be checks, tasks or random")
    if any(not x.isdigit() for x in cfg["client_ids"]):
        raise BridgeError("NSIGHT_CLIENT_IDS must be client ID numbers")
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


# ---------------------------------------------------------------- Data Extraction API

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(node, tag: str) -> str:
    found = node.find(tag) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


class NsightClient:
    """Calls list_failing_checks. The API key travels in the query string, so URLs are never logged."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def failing_checks(self, client_id: str | None) -> bytes:
        params = {"apikey": self.cfg["api_key"], "service": "list_failing_checks", "check_type": self.cfg["check_type"]}
        if client_id:
            params["clientid"] = client_id
        url = f"{self.cfg['api_url']}/api/?{urllib.parse.urlencode(params)}"
        _, body = _request("GET", url, {"Accept": "application/xml"}, None, self.cfg["timeout"], "list_failing_checks request")
        return body


def parse_failing_checks(body: bytes) -> list[dict]:
    """Flatten the documented XML (items > client > site > workstations|servers > device >
    failed_checks > check) into one dict per failing check."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        raise BridgeError("list_failing_checks returned XML that could not be read") from None
    if (root.get("status") or "").upper() != "OK":
        raise BridgeError(f"list_failing_checks returned status {root.get('status') or 'unknown'}")
    out = []
    for client in root.iter("client"):
        for site in client.findall("site"):
            for group, kind in (("workstations", "workstation"), ("servers", "server")):
                for device in site.findall(f"{group}/{kind}"):
                    for check in device.findall("failed_checks/check"):
                        out.append({
                            "Source": "N-sight RMM", "ClientId": _text(client, "clientid"), "ClientName": _text(client, "name"),
                            "SiteId": _text(site, "siteid"), "SiteName": _text(site, "name"), "DeviceType": kind,
                            "DeviceId": _text(device, "id"), "DeviceName": _text(device, "name"),
                            "CheckId": _text(check, "checkid"), "CheckType": _text(check, "check_type"),
                            "Dsc247": _text(check, "dsc_247"), "Description": _text(check, "description"),
                            "CheckDate": _text(check, "date"), "CheckTime": _text(check, "time"),
                            "StartDate": _text(check, "startdate"), "StartTime": _text(check, "starttime"),
                            "FormattedOutput": _text(check, "formatted_output"), "CheckStatus": _text(check, "checkstatus"),
                        })
    return out


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

def _key(rec: dict) -> str:
    return f"{rec.get('DeviceType')}:{rec.get('DeviceId')}:{rec.get('CheckId')}"


def collect(cfg: dict, state: dict, sink: Sink, save, client: NsightClient | None = None) -> int:
    """Poll the failing checks (all clients, or each configured client), send a "failing" record
    for each check that wasn't failing at the last poll and a "cleared" record for each check
    that no longer is, then save the new list."""
    client = client or NsightClient(cfg)
    st = state.setdefault("failing_checks", {"initialized": False, "current": {}})
    now = _iso(datetime.now(timezone.utc))
    checks = []
    for cid in cfg["client_ids"] or [None]:
        checks.extend(parse_failing_checks(client.failing_checks(cid)))
    current = {_key(c): c for c in checks}
    before = st["current"]
    records = []
    if st["initialized"] or cfg["send_existing"]:
        records += [{"State": "failing", "ObservedAt": now, **c} for k, c in current.items() if k not in before]
    records += [{"State": "cleared", "ObservedAt": now, **c} for k, c in before.items() if k not in current]
    if records:
        sink.send(records)
    st["current"] = current
    st["initialized"] = True
    save()
    LOG.info("failing checks: %d now failing, %d records sent", len(current), len(records))
    return len(records)


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
    ap = argparse.ArgumentParser(description="Send N-sight RMM failing check changes to Sophos NG-SIEM HTTP Ingest.")
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
