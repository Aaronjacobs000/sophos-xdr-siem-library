#!/usr/bin/env python3
"""Pull WithSecure Elements security events and audit logs from the Elements API and send them to
a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

WithSecure Elements has no webhook, and its Elements Connector sends syslog in a layout WithSecure
doesn't publish, so this script reads the Elements API with a read-only API client:

  POST https://api.connect.withsecure.com/as/token.oauth2                    (client_credentials)
  POST https://api.connect.withsecure.com/security-events/v1/security-events (form body)
  GET  https://api.connect.withsecure.com/audit-logs/v1/audit-logs

and posts each item with "withsecure_record" first (security_event or audit_log), so the library
parsers in parsers/withsecure/elements can recognize and normalize it. API credentials made at
partner level read every company under the partner; organization.name in each item says which.

Each run reads, for each source, the window from the end of the last one, less an overlap, to
now, oldest first, following nextAnchor, and drops items it already sent. The request and response
shapes follow WithSecure's Elements API and Security Events API references. Configuration comes
from environment variables (see README.md). A window's end only moves after HTTP Ingest accepted
every item in it. --dry-run prints what would be sent and changes nothing.
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
LOG = logging.getLogger("withsecure_elements_bridge")
USER_AGENT = f"parser-studio-withsecure-elements-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 20000
RECORD_KEY = "withsecure_record"
TOKEN_PATH = "/as/token.oauth2"
EVENTS_PATH = "/security-events/v1/security-events"
AUDIT_PATH = "/audit-logs/v1/audit-logs"
SOURCES = {"security_events": "security_event", "audit_logs": "audit_log"}
ENGINE_GROUPS = ("epp", "edr", "ecp", "xm")
# A query may span at most 31 days, and its start must be within the last 31 days. The bridge
# keeps a day's margin.
MAX_WINDOW_SECONDS = 30 * 86400
# A window ends this long before now, so a clock a little ahead of WithSecure's never asks for the future.
END_MARGIN_SECONDS = 60
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


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


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


def _list(env: dict, name: str, default: str) -> list[str]:
    return list(dict.fromkeys(x.strip().lower() for x in (_env(env, name, default) or "").split(",") if x.strip()))


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "WITHSECURE_API_URL", "https://api.connect.withsecure.com") or "").rstrip("/"),
        "client_id": _env(env, "WITHSECURE_CLIENT_ID"),
        "client_secret": _env(env, "WITHSECURE_CLIENT_SECRET"),
        "organization_id": _env(env, "WITHSECURE_ORGANIZATION_ID"),
        "sources": _list(env, "WITHSECURE_SOURCES", "security_events,audit_logs"),
        "engine_groups": _list(env, "WITHSECURE_ENGINE_GROUPS", ",".join(ENGINE_GROUPS)),
        "page_size": _number(env, "WITHSECURE_PAGE_SIZE", "200", low=1, high=200),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "withsecure_elements_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise BridgeError("WITHSECURE_CLIENT_ID and WITHSECURE_CLIENT_SECRET are required")
    if cfg["organization_id"] and not UUID.match(cfg["organization_id"]):
        raise BridgeError("WITHSECURE_ORGANIZATION_ID must be an organization's UUID")
    if not cfg["sources"] or any(s not in SOURCES for s in cfg["sources"]):
        raise BridgeError("WITHSECURE_SOURCES takes security_events, audit_logs or both, separated by a comma")
    if not cfg["engine_groups"] or any(g not in ENGINE_GROUPS for g in cfg["engine_groups"]):
        raise BridgeError("WITHSECURE_ENGINE_GROUPS takes epp, edr, ecp and xm, separated by commas")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _require_https(cfg["api_url"], "WITHSECURE_API_URL")
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
                delay = _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None)
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


def _error_message(body: bytes) -> str:
    """Elements API errors are {"message", "code", "transactionId", "details": {"reasons"}}; the
    token endpoint can also answer {"error", "error_description"}. Keep the message short."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    message = str(data.get("message") or data.get("error_description") or data.get("error") or "")
    details = data.get("details") if isinstance(data.get("details"), dict) else {}
    reasons = [str(r) for r in details.get("reasons") or [] if isinstance(r, (str, int, float))]
    if reasons:
        message = f"{message} ({'; '.join(reasons)})" if message else "; ".join(reasons)
    return message[:300] or "no message"


# ---------------------------------------------------------------- Elements API

class Elements:
    """Gets an access token with the client credentials grant (scope connect.api.read) and calls
    the Elements API with 'Authorization: Bearer <token>'. Tokens last about 30 minutes; one is
    renewed a minute before it expires, and once more if WithSecure refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        url = f"{self.cfg['api_url']}{TOKEN_PATH}"
        basic = base64.b64encode(f"{self.cfg['client_id']}:{self.cfg['client_secret']}".encode()).decode()
        headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "connect.api.read"}).encode()
        try:
            _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"WithSecure refused the API credentials (HTTP {e.code}): {_error_message(e.body)}; "
                                  "check WITHSECURE_CLIENT_ID and WITHSECURE_CLIENT_SECRET") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 1799)
        except (TypeError, ValueError):
            lifetime = 1799.0
        self._token = token
        self._expires = time.monotonic() + max(60.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def _call(self, method: str, path: str, params: list, what: str) -> dict:
        """params is a list of (name, value) pairs, so a name can repeat, as engineGroup does."""
        encoded = urllib.parse.urlencode(params)
        if method == "GET":
            url, body, extra = f"{self.cfg['api_url']}{path}?{encoded}", None, {}
        else:
            url, body, extra = f"{self.cfg['api_url']}{path}", encoded.encode(), {"Content-Type": "application/x-www-form-urlencoded"}
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json", **extra}
            try:
                _, raw = _request(method, url, headers, body, self.cfg["timeout"], what)
                break
            except HttpStatus as e:
                if e.code == 401 and not renew:
                    LOG.info("%s returned 401; renewing the access token", what)
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"WithSecure refused the {what} (HTTP {e.code}): {_error_message(e.body)}; check that "
                                      "the API client can read this organization, or leave this source out of "
                                      "WITHSECURE_SOURCES") from None
                if e.code in (400, 404):
                    raise BridgeError(f"WithSecure rejected the {what} (HTTP {e.code}): {_error_message(e.body)}") from None
                raise
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
        return data

    def page(self, source: str, start: str, end: str, anchor: str | None) -> dict:
        params = []
        if self.cfg["organization_id"]:
            params.append(("organizationId", self.cfg["organization_id"]))
        if source == "security_events":
            params += [("persistenceTimestampStart", start), ("persistenceTimestampEnd", end)]
            params += [("engineGroup", g) for g in self.cfg["engine_groups"]]
        else:
            params += [("serverTimestampStart", start), ("serverTimestampEnd", end)]
        params += [("order", "asc"), ("limit", str(self.cfg["page_size"]))]
        if anchor:
            params.append(("anchor", anchor))
        if source == "security_events":
            return self._call("POST", EVENTS_PATH, params, "security events request")
        return self._call("GET", AUDIT_PATH, params, "audit logs request")


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

def _parse_time(value) -> float | None:
    """The API's times are ISO 8601 in UTC, such as 2023-08-31T09:31:03.292Z."""
    v = str(value or "").strip().replace("Z", "+00:00")
    if "." in v:  # fromisoformat before 3.11 takes 3 or 6 fraction digits only
        head, rest = v.split(".", 1)
        # The fraction is the digits right after the point. An offset after them keeps its place.
        tail = rest.lstrip("0123456789")
        v = head + "." + (rest[:len(rest) - len(tail)] + "000000")[:6] + tail
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def collect(source: str, cfg: dict, state: dict, sink: Sink, save, client: Elements, now: float) -> int:
    """Reads one source from the end of its last window, less the overlap, to now, oldest first,
    and sends the items not sent before. Security events are read by persistenceTimestamp, the
    time each one was written, and audit log entries by serverTimestamp. The window's end is saved
    only after every page of it was sent."""
    cur = state.setdefault(source, {})
    since = cur.get("until")
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, now - END_MARGIN_SECONDS) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) \
        else (now - cfg["lookback_hours"] * 3600)
    oldest = now - MAX_WINDOW_SECONDS
    if start < oldest:
        if isinstance(since, (int, float)):
            LOG.warning("%s: the last run was more than 30 days ago; a query can span 31 days at most, so older "
                        "items are skipped", source)
        start = oldest
    end = now - END_MARGIN_SECONDS
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    stamp = "persistenceTimestamp" if source == "security_events" else "serverTimestamp"
    start_s, end_s = _iso(start), _iso(end)
    sent, anchor = 0, None
    for _ in range(MAX_PAGES):
        data = client.page(source, start_s, end_s, anchor)
        items = data.get("items") or []
        if not isinstance(items, list):
            raise BridgeError(f"{source} request returned items that are not a list")
        fresh = {}
        for item in items:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            key = str(item["id"])
            if key not in seen and key not in fresh:
                t = _parse_time(item.get(stamp))
                fresh[key] = (t if t is not None else now, item)
        if fresh:
            sink.send([{RECORD_KEY: SOURCES[source], **item} for _, item in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        anchor = data.get("nextAnchor")
        if not anchor or not isinstance(anchor, str):
            break
    else:
        LOG.warning("%s: stopped after %d pages; the next run reads the same window again", source, MAX_PAGES)
        LOG.info("%s: %d sent", source, sent)
        return sent
    cur["until"] = end
    save()
    LOG.info("%s: %d sent", source, sent)
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
    client = Elements(cfg)
    now = time.time()
    count = sum(collect(s, cfg, state, sink, save, client, now) for s in cfg["sources"])
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
    ap = argparse.ArgumentParser(description="Send WithSecure Elements security events and audit logs to Sophos NG-SIEM HTTP Ingest.")
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
