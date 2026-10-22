#!/usr/bin/env python3
"""Pull Rapid7 InsightVM vulnerability findings with the InsightVM Cloud Integrations API (v4) and send
them to a Sophos NG-SIEM HTTP Ingest integration, one JSON record per finding. Python 3 standard
library only.

InsightVM has no push for findings, so each run asks the Insight Platform which findings are new on
each asset, and which were remediated, since the last run:

  POST https://{region}.api.insight.rapid7.com/vm/v4/integration/assets?comparisonTime=...&currentTime=...
  POST https://{region}.api.insight.rapid7.com/vm/v4/integration/vulnerabilities

with an Insight Platform API key (X-Api-Key) whose user can view the assets. The first run has no
earlier time to compare with, so it sends every current finding of the assets assessed in the
lookback ("same"). Each record carries the asset, the finding and the vulnerability's definition
(title, severity, CVSS scores, CVEs and the rest), with "rapid7_record" ("finding"), the region and
"rapid7_state" (new, remediated or same) first, so the library parser in
parsers/rapid7/insightvm can normalize it.

The request and response shapes follow Rapid7's InsightVM Cloud Integrations API reference.
Configuration comes from environment variables (see README.md). A window's end only moves after
HTTP Ingest accepted every record in it. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import calendar
import gzip
import http.client
import json
import logging
import os
import random
import re
import socket
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("rapid7_insightvm_bridge")
USER_AGENT = f"sophos-xdr-siem-library-rapid7-insightvm-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 10000
RECORD_KEY = "rapid7_record"
REGION_KEY = "rapid7_region"
STATE_KEY = "rapid7_state"
ASSETS_PATH = "/vm/v4/integration/assets"
VULNS_PATH = "/vm/v4/integration/vulnerabilities"
# The finding lists of an asset, in the order the records go out.
STATES = ("new", "remediated", "same")
# Vulnerability IDs per definitions request, and the IDs the bridge puts in a filter: Rapid7's are
# letters, digits and - . _ : only, such as 7-zip-cve-2016-2334.
VULN_BATCH = 100
VULN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
VULN_CACHE_MAX = 200000
# The definition fields each record carries. The description, links, references and PCI details
# are left out, so records stay small.
VULN_FIELDS = ("id", "title", "severity", "severity_score", "risk_score", "cvss_v2_score", "cvss_v2_vector",
               "cvss_v3_score", "cvss_v3_vector", "cves", "categories", "published", "modified", "added",
               "denial_of_service", "exploits", "malware_kits")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REGION = re.compile(r"[a-z]{2,4}[0-9]?")


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """Rapid7 or HTTP Ingest couldn't be reached, even after the retries. With --interval the bridge
    logs it and tries again at the next interval."""


class HostNotFound(NetworkError):
    """A host name in a URL setting didn't resolve, even after the retries. Until a run has worked,
    it stops the bridge even with --interval, since it is most likely a mistyped URL."""


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


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


def _refuse_user_info(url: str, what: str) -> None:
    """urllib sends no user name or password from a URL, and the host isn't found with them in
    it, so a URL setting that has them can never work."""
    if "@" in urllib.parse.urlsplit(url).netloc:
        raise BridgeError(f"{what} has a user name or password before the host (user:pass@), which the bridge "
                          "can't use; remove it")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "region": (_env(env, "RAPID7_REGION") or "").lower(),
        "api_url": (_env(env, "RAPID7_API_URL") or "").rstrip("/"),
        "api_key": _env(env, "RAPID7_API_KEY"),
        "page_size": _number(env, "RAPID7_PAGE_SIZE", "50", low=1, high=500),
        "include_same": _flag(env, "RAPID7_INCLUDE_SAME", False),
        "definitions": _flag(env, "RAPID7_DEFINITIONS", True),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "rapid7_insightvm_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=8760),
        "delay_seconds": _number(env, "BRIDGE_DELAY_SECONDS", "900", high=86400),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "120", float, low=0.001),
    }
    if not REGION.fullmatch(cfg["region"]):
        raise BridgeError("RAPID7_REGION is required: your Insight Platform region's code, such as us, us2, us3, eu, "
                          "ca, au, ap, aps2 or me1")
    if not cfg["api_url"]:
        cfg["api_url"] = f"https://{cfg['region']}.api.insight.rapid7.com"
    _refuse_user_info(cfg["api_url"], "RAPID7_API_URL")
    _require_https(cfg["api_url"], "RAPID7_API_URL")
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment or not parts.hostname:
        raise BridgeError("RAPID7_API_URL must be an address with no path, such as https://au.api.insight.rapid7.com")
    if not cfg["api_key"]:
        raise BridgeError("RAPID7_API_KEY is required: an Insight Platform user key")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    if cfg["ingest_url"]:
        _refuse_user_info(cfg["ingest_url"], "NGSIEM_INGEST_URL")
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    """The host and port, for log lines and errors. A user name or password in the URL is a
    credential, so it shows as [redacted]."""
    _, at, host = urllib.parse.urlsplit(url).netloc.rpartition("@")
    return f"[redacted]@{host}" if at else host


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
        elif code in UNSUPPORTED_STATUS:
            message = (f"{what} to {_host(url)} failed with HTTP {code}: {UNSUPPORTED_STATUS[code]}, and a retry "
                       "won't change that; check the URL setting")
        else:
            message = f"{what} to {_host(url)} failed with HTTP {code}"
        super().__init__(message)
        self.code = code
        self.body = body


class RetriedStatus(HttpStatus, NetworkError):
    """A 408, 429, 500, 502, 503 or 504 that outlasted the retries. It is a NetworkError too, so with --interval
    the bridge logs it and tries again at the next interval."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _read(resp, what: str, url: str, limit: int | None = None) -> bytes:
    """Reads a response body, but no more than the limit, so a broken or hostile endpoint can't
    use up memory. It reads 1 MB at a time: before Python 3.10, read(n) set aside all n bytes first.
    A body that ends short of its Content-Length raises IncompleteRead, like a cut-off chunked one."""
    limit = limit or MAX_RESPONSE_BYTES
    chunks, size = [], 0
    while True:
        chunk = resp.read(min(1048576, limit + 1 - size))
        if not chunk:
            # read(n) returns nothing, with no error, when the connection closes before the
            # Content-Length is reached. http.client still counts the bytes it was promised.
            owed = getattr(resp, "length", None)
            if owed:
                raise http.client.IncompleteRead(b"", owed)
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise BridgeError(f"{what} to {_host(url)} sent more than {limit // 1048576} MB, which the bridge "
                              "refuses so a bad response can't use up memory")


# Retried, then a NetworkError. On Python 3.9 a read timeout is socket.timeout, which isn't a
# TimeoutError yet, and IncompleteRead means the connection closed partway through an answer.
_NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError, http.client.IncompleteRead)


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body)."""
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
            except _NETWORK_ERRORS:
                # The body was cut short or timed out: the status still decides what happens.
                error_body = b""
            finally:
                e.close()
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None)
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS:
                raise RetriedStatus(what, url, e.code, error_body) from None
            raise HttpStatus(what, url, e.code, error_body) from None
        except _NETWORK_ERRORS as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            if isinstance(e, urllib.error.URLError) and isinstance(e.reason, socket.gaierror):
                raise HostNotFound(f"{what} to {_host(url)} failed: the host name wasn't found; "
                                   "check the URL setting") from None
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


def _r7_error(body: bytes) -> str:
    """Rapid7 answers an error with {"status", "message", "localized_message"}. Returns a short message."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    return str(data.get("message") or data.get("localized_message") or "")[:200] or "no message"


# ---------------------------------------------------------------- Rapid7

class InvalidCursor(BridgeError):
    """Rapid7 refused a saved cursor, so the window starts again from its first page."""


class Rapid7:
    """Calls the Cloud Integrations API with the API key in X-Api-Key on each request."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.definitions: dict = {}

    def _call(self, path: str, params: dict, body: dict, what: str) -> dict:
        url = f"{self.cfg['api_url']}{path}?{urllib.parse.urlencode(params)}"
        headers = {"X-Api-Key": self.cfg["api_key"], "Accept": "application/json", "Content-Type": "application/json"}
        try:
            _, raw = _request("POST", url, headers, json.dumps(body).encode("utf-8"), self.cfg["timeout"], what)
        except HttpStatus as e:
            if e.code in (401, 403):
                raise BridgeError(f"Rapid7 refused the API key (HTTP {e.code}): {_r7_error(e.body)}; check RAPID7_API_KEY "
                                  "and RAPID7_REGION, and that the key's user can view the assets") from None
            if e.code == 400:
                message = _r7_error(e.body)
                if "cursor" in params and "cursor" in message.lower():
                    raise InvalidCursor(f"Rapid7 refused the saved cursor: {message}") from None
                raise BridgeError(f"Rapid7 refused the {what} (HTTP 400): {message}") from None
            raise
        data = _json(raw, what)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise BridgeError(f"the {what} returned JSON with no data list")
        return data

    def assets(self, comparison: str | None, current: str, since: str | None, same: bool,
               cursor: str | None) -> tuple[list[dict], str | None]:
        """One page of assets with their finding lists, and the cursor of the next page, or None on the
        last one."""
        params = {"size": str(self.cfg["page_size"]), "currentTime": current,
                  "includeSame": "true" if same else "false", "includeUniqueIdentifiers": "true"}
        if comparison:
            params["comparisonTime"] = comparison
        if cursor:
            params["cursor"] = cursor
        body = {"asset": f"last_assessed_for_vulnerabilities > {since}"} if since else {}
        data = self._call(ASSETS_PATH, params, body, "assets request")
        page = [a for a in data["data"] if isinstance(a, dict)]
        meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        nxt = meta.get("cursor")
        if not page or not isinstance(nxt, str) or not nxt:
            return page, None
        if nxt == cursor:
            raise BridgeError("the assets request's next cursor is the one it was sent, so the bridge stops")
        return page, nxt

    def lookup(self, ids: list[str]) -> dict:
        """The definition of each vulnerability, read once and kept while the bridge runs."""
        wanted = sorted({i for i in ids if i not in self.definitions and VULN_ID.fullmatch(i)})
        for i in range(0, len(wanted), VULN_BATCH):
            chunk = wanted[i:i + VULN_BATCH]
            quoted = ", ".join(f"'{x}'" for x in chunk)
            found, cursor = {}, None
            for _ in range(MAX_PAGES):
                params = {"size": "500"}
                if cursor:
                    params["cursor"] = cursor
                data = self._call(VULNS_PATH, params, {"vulnerability": f"id IN [{quoted}]"}, "vulnerabilities request")
                for v in data["data"]:
                    if isinstance(v, dict) and isinstance(v.get("id"), str):
                        found[v["id"]] = {k: v[k] for k in VULN_FIELDS if k in v}
                meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
                nxt = meta.get("cursor")
                if not data["data"] or not isinstance(nxt, str) or not nxt or nxt == cursor:
                    break
                cursor = nxt
            if len(self.definitions) + len(chunk) > VULN_CACHE_MAX:
                self.definitions.clear()
            # A vulnerability Rapid7 doesn't return is remembered as missing, so it isn't asked for again.
            for x in chunk:
                self.definitions[x] = found.get(x)
        return {i: self.definitions.get(i) for i in ids}


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

_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")


def _seconds(value) -> int | None:
    """A time the bridge saved, such as 2026-10-14T03:12:45Z, in seconds since the epoch. Parsed by
    hand, so it reads the same on Python 3.9 to 3.13."""
    m = _TIME.fullmatch(str(value or "").strip())
    if not m:
        return None
    try:
        moment = datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None
    return calendar.timegm(moment.utctimetuple())


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime(TIME_FORMAT)


def findings_of(assets: list[dict]) -> list[tuple[str, dict, dict]]:
    """Each finding of each asset as (state, asset, finding): the new ones, then the remediated,
    then the same, in the order Rapid7 returned them."""
    out = []
    for asset in assets:
        base = {k: v for k, v in asset.items() if k not in STATES}
        for state in STATES:
            for finding in asset.get(state) or []:
                if isinstance(finding, dict):
                    out.append((state, base, finding))
    return out


def build(state: str, asset: dict, finding: dict, vuln: dict | None, cfg: dict) -> dict:
    rec = {RECORD_KEY: "finding", REGION_KEY: cfg["region"], STATE_KEY: state, "asset": asset, "finding": finding}
    if vuln:
        rec["vulnerability"] = vuln
    return rec


def collect(cfg: dict, state: dict, sink: Sink, save, client: Rapid7, now: int) -> int:
    """Reads the changes from the last run's time to BRIDGE_DELAY_SECONDS before now: the findings
    new since then, and those remediated since then, of each asset assessed since then. The first
    run has nothing to compare with, so it reads every current finding of the assets assessed in the
    lookback. A window left partway (a run that stopped after some pages) goes on from the next
    page, with the same times. The saved position only moves after HTTP Ingest accepted a page."""
    key = f"{cfg['region']}@{_host(cfg['api_url'])}"
    cur = state.setdefault(key, {})
    pending = cur.get("pending") if isinstance(cur.get("pending"), dict) else None
    if pending and _seconds(pending.get("current")) is not None:
        comparison, current = pending.get("comparison"), pending["current"]
        cursor = pending.get("cursor") if isinstance(pending.get("cursor"), str) else None
    else:
        last = _seconds(cur.get("current"))
        end = now - cfg["delay_seconds"]
        if last is not None and last >= end:
            LOG.info("findings: no new window yet")
            return 0
        comparison = _when(last) if last is not None else None
        current, cursor = _when(end), None
    if comparison is not None and _seconds(comparison) is None:
        comparison = None
    # The first run, with no earlier time, reads every current finding ("same") of the assets
    # assessed in the lookback. Later runs read the assets assessed since the last run.
    first = comparison is None
    since = _when(now - int(cfg["lookback_hours"] * 3600)) if first else comparison
    same = first or cfg["include_same"]
    sent = 0
    for _ in range(MAX_PAGES):
        try:
            assets, nxt = client.assets(comparison, current, since, same, cursor)
        except InvalidCursor as e:
            LOG.warning("%s; reading the window again from its first page, so some findings can arrive twice", e)
            cursor = None
            continue
        items = findings_of(assets)
        defs = client.lookup([str(f.get("vulnerability_id") or "") for _, _, f in items]) if cfg["definitions"] and items else {}
        fresh = [build(s, a, f, defs.get(str(f.get("vulnerability_id") or "")), cfg) for s, a, f in items]
        if fresh:
            sink.send(fresh)
            sent += len(fresh)
        if nxt:
            cursor = nxt
            cur["pending"] = {"comparison": comparison, "current": current, "cursor": cursor}
            save()
            continue
        cur.pop("pending", None)
        cur["current"] = current
        save()
        break
    else:
        LOG.warning("findings: stopped after %d pages; the next run goes on from there", MAX_PAGES)
    LOG.info("findings: %d sent", sent)
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
        json.dump(state, fh, separators=(",", ":"))
    os.replace(tmp, path)


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Rapid7 | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or Rapid7(cfg)
    count = collect(cfg, state, sink, save, client, int(time.time()))
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
    ap = argparse.ArgumentParser(description="Send Rapid7 InsightVM findings to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for the life of the bridge, so the definitions it read stay cached.
        client = Rapid7(cfg)
        worked = False
        while True:
            try:
                run_once(cfg, dry_run, client=client)
                worked = True
            except NetworkError as e:
                # A host name that doesn't resolve before any run has worked is most likely a
                # mistyped URL, so it stops the bridge.
                if not args.interval or (isinstance(e, HostNotFound) and not worked):
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
