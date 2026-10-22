#!/usr/bin/env python3
"""Pull Cortex Xpanse alerts with the Cortex Xpanse public API and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per alert. Python 3 standard library only.

Xpanse can forward alerts only by email, Slack or syslog, and Palo Alto documents no syslog format
for them, so this script asks for the attack surface (ASM) alerts Xpanse created in each new window:

  POST https://api-{tenant FQDN}/public_api/v2/alerts/get_alerts_multi_events/

with an API key whose role can read alerts. Each alert goes on as Xpanse returns it, with
"xpanse_record" ("alert") and the tenant first, so the library parser in
parsers/palo-alto-networks/cortex-xpanse can normalize it.

The request and response shapes follow Palo Alto's Cortex Xpanse REST API reference. Configuration
comes from environment variables (see README.md). A window's end only moves after HTTP Ingest
accepted every record in it. --dry-run prints what would be sent and changes nothing.
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
import secrets
import socket
import string
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
LOG = logging.getLogger("cortex_xpanse_bridge")
USER_AGENT = f"sophos-xdr-siem-library-cortex-xpanse-bridge/{__version__}"
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
RECORD_KEY = "xpanse_record"
TENANT_KEY = "xpanse_tenant"
ALERTS_PATH = "/public_api/v2/alerts/get_alerts_multi_events/"
# The most alerts one page holds, Xpanse's limit for search_to.
MAX_PAGE_SIZE = 100
SEVERITIES = {"informational", "low", "medium", "high", "critical", "unknown"}
NONCE_CHARS = string.ascii_letters + string.digits


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """Xpanse or HTTP Ingest couldn't be reached, even after the retries. With --interval the bridge
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
        "api_url": (_env(env, "XPANSE_API_URL") or "").rstrip("/"),
        "api_key": _env(env, "XPANSE_API_KEY"),
        "key_id": _env(env, "XPANSE_API_KEY_ID"),
        "key_type": (_env(env, "XPANSE_API_KEY_TYPE") or "advanced").lower(),
        "severities": _env(env, "XPANSE_SEVERITIES"),
        "page_size": _number(env, "XPANSE_PAGE_SIZE", "100", low=1, high=MAX_PAGE_SIZE),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "cortex_xpanse_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=8760),
        "delay_seconds": _number(env, "BRIDGE_DELAY_SECONDS", "300", high=86400),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["api_url"]:
        raise BridgeError("XPANSE_API_URL is required: the API URL from Settings > Configurations > API Keys, such as "
                          "https://api-example.crtx.au.paloaltonetworks.com")
    _refuse_user_info(cfg["api_url"], "XPANSE_API_URL")
    _require_https(cfg["api_url"], "XPANSE_API_URL")
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment or not parts.hostname:
        raise BridgeError("XPANSE_API_URL must be the API URL with no path, such as "
                          "https://api-example.crtx.au.paloaltonetworks.com")
    # The tenant is the API host without its api- prefix, as in api-example.crtx.au.paloaltonetworks.com.
    host = parts.hostname
    cfg["tenant"] = host[len("api-"):] if host.startswith("api-") else host
    if not cfg["api_key"] or not cfg["key_id"]:
        raise BridgeError("XPANSE_API_KEY and XPANSE_API_KEY_ID are required")
    if not cfg["key_id"].isdigit():
        raise BridgeError("XPANSE_API_KEY_ID must be the key's ID number, from the ID column of the API Keys page")
    if cfg["key_type"] not in ("advanced", "standard"):
        raise BridgeError("XPANSE_API_KEY_TYPE must be advanced or standard")
    if cfg["severities"] is not None:
        values = [x.strip().lower() for x in cfg["severities"].split(",") if x.strip()]
        if not values or any(x not in SEVERITIES for x in values):
            raise BridgeError("XPANSE_SEVERITIES must be a comma-separated list of informational, low, medium, high, "
                              "critical and unknown")
        cfg["severities"] = values
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


def _request(method: str, url: str, headers, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body).
    headers is a dict, or a function that makes them for each attempt, so a signed request gets a
    new nonce and time when it is sent again."""
    for attempt in range(MAX_ATTEMPTS):
        sent = headers() if callable(headers) else headers
        req = urllib.request.Request(url, data=body, method=method, headers={**sent, "User-Agent": USER_AGENT})
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


def _xp_error(body: bytes) -> str:
    """Xpanse answers an error with {"reply": {"err_code", "err_msg", "err_extra"}}. Returns a short message."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    reply = data.get("reply") if isinstance(data, dict) else None
    if not isinstance(reply, dict):
        return "no message"
    text = str(reply.get("err_msg") or "")
    extra = reply.get("err_extra")
    if extra and isinstance(extra, (str, int, float)):
        text = f"{text} ({extra})" if text else str(extra)
    return text[:200] or "no message"


# ---------------------------------------------------------------- Xpanse

class InvalidToken(BridgeError):
    """Xpanse refused a saved page token, so the window starts again from its first page."""


class Xpanse:
    """Calls the Get Alerts API. With an advanced key, each request carries a new 64-character nonce,
    the time in milliseconds and the SHA-256 of the key, nonce and time, so the key itself never
    leaves this machine. With a standard key, the key goes as Authorization."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _headers(self) -> dict:
        headers = {"x-xdr-auth-id": self.cfg["key_id"], "Accept": "application/json", "Content-Type": "application/json"}
        if self.cfg["key_type"] == "standard":
            headers["Authorization"] = self.cfg["api_key"]
            return headers
        nonce = "".join(secrets.choice(NONCE_CHARS) for _ in range(64))
        stamp = str(int(time.time()) * 1000)
        headers.update({"x-xdr-nonce": nonce, "x-xdr-timestamp": stamp,
                        "Authorization": hashlib.sha256(f"{self.cfg['api_key']}{nonce}{stamp}".encode("utf-8")).hexdigest()})
        return headers

    def alerts(self, start_ms: int, end_ms: int, token: str | None) -> tuple[list[dict], str | None]:
        """One page of the ASM alerts Xpanse created from start_ms to end_ms (both in), and the next
        page's token, or None on the last page."""
        filters = [{"field": "alert_source", "operator": "in", "value": ["ASM"]},
                   {"field": "server_creation_time", "operator": "gte", "value": start_ms},
                   {"field": "server_creation_time", "operator": "lte", "value": end_ms}]
        if self.cfg["severities"]:
            filters.append({"field": "severity", "operator": "in", "value": self.cfg["severities"]})
        data = {"filters": filters, "search_from": 0, "search_to": self.cfg["page_size"], "use_page_token": True}
        if token:
            data["next_page_token"] = token
        url = self.cfg["api_url"] + ALERTS_PATH
        body = json.dumps({"request_data": data}).encode("utf-8")
        try:
            _, raw = _request("POST", url, self._headers, body, self.cfg["timeout"], "alerts request")
        except HttpStatus as e:
            if e.code in (401, 402, 403):
                meaning = {401: "the key or its ID is wrong, or the key type doesn't match XPANSE_API_KEY_TYPE",
                           402: "the tenant's license doesn't include the API",
                           403: "the key's role can't read alerts"}[e.code]
                raise BridgeError(f"Xpanse refused the alerts request (HTTP {e.code}: {meaning}): {_xp_error(e.body)}") from None
            if e.code in (400, 422):
                if token:
                    raise InvalidToken(f"Xpanse refused the saved page token (HTTP {e.code}): {_xp_error(e.body)}") from None
                raise BridgeError(f"Xpanse refused the alerts request (HTTP {e.code}): {_xp_error(e.body)}") from None
            raise
        answer = _json(raw, "alerts request")
        reply = answer.get("reply") if isinstance(answer, dict) else None
        if not isinstance(reply, dict) or not isinstance(reply.get("alerts"), list):
            raise BridgeError("the alerts request returned JSON with no reply.alerts list")
        page = [a for a in reply["alerts"] if isinstance(a, dict)]
        nxt = reply.get("next_page_token")
        if not page or not isinstance(nxt, str) or not nxt:
            return page, None
        if nxt == token:
            raise BridgeError("the alerts request's next page token is the one it was sent, so the bridge stops")
        return page, nxt


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

def tag(alert: dict, cfg: dict) -> dict:
    out = {RECORD_KEY: "alert", TENANT_KEY: cfg["tenant"]}
    out.update({k: v for k, v in alert.items() if k not in (RECORD_KEY, TENANT_KEY)})
    return out


def collect(cfg: dict, state: dict, sink: Sink, save, client: Xpanse, now_ms: int) -> int:
    """Reads the alerts Xpanse created from where the last window ended to BRIDGE_DELAY_SECONDS before
    now, a page at a time, by page token. A window left partway (a run that stopped after some
    pages) goes on from the next page, with the same bounds. The saved position only moves after
    HTTP Ingest accepted a page."""
    cur = state.setdefault(cfg["tenant"], {})
    pending = cur.get("pending") if isinstance(cur.get("pending"), dict) else None
    ok = lambda x: isinstance(x, int) and not isinstance(x, bool)  # noqa: E731
    if pending and ok(pending.get("start_ms")) and ok(pending.get("end_ms")):
        start, end = pending["start_ms"], pending["end_ms"]
        token = pending.get("token") if isinstance(pending.get("token"), str) else None
    else:
        end = now_ms - cfg["delay_seconds"] * 1000
        start = cur["cursor_ms"] if ok(cur.get("cursor_ms")) else now_ms - int(cfg["lookback_hours"] * 3600) * 1000
        # A saved position later than the window's end (the clock went back) counts as the end.
        start, token = min(start, end), None
    if start >= end:
        LOG.info("alerts: no new window yet")
        return 0
    sent = 0
    for _ in range(MAX_PAGES):
        try:
            # The window is start to end - 1 ms, both in, so the next one starts at end.
            page, nxt = client.alerts(start, end - 1, token)
        except InvalidToken as e:
            LOG.warning("%s; reading the window again from its first page, so some alerts can arrive twice", e)
            token = None
            continue
        fresh = [tag(a, cfg) for a in page]
        if fresh:
            sink.send(fresh)
            sent += len(fresh)
        if nxt:
            token = nxt
            cur["pending"] = {"start_ms": start, "end_ms": end, "token": token}
            save()
            continue
        cur.pop("pending", None)
        cur["cursor_ms"] = end
        save()
        break
    else:
        LOG.warning("alerts: stopped after %d pages; the next run goes on from there", MAX_PAGES)
    LOG.info("alerts: %d sent", sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = Xpanse(cfg)
    count = collect(cfg, state, sink, save, client, int(time.time() * 1000))
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
    ap = argparse.ArgumentParser(description="Send Cortex Xpanse alerts to Sophos NG-SIEM HTTP Ingest.")
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
        worked = False
        while True:
            try:
                run_once(cfg, dry_run)
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
