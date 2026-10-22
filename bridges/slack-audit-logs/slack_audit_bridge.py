#!/usr/bin/env python3
"""Pull Slack audit logs from the Audit Logs API and send them to a Sophos NG-SIEM HTTP Ingest
integration, one JSON record per line. Python 3 standard library only.

Slack offers the audit logs of an Enterprise organization (sign-ins, member, role and session
changes, channel, file and app actions, settings changes, and Slack's anomaly detections) through
its Audit Logs API, which is pull only, so this script reads them with the user token of an app an
Org Owner installed on the organization with the auditlogs:read scope:

  GET https://api.slack.com/audit/v1/logs   (Authorization: Bearer xoxp-...)

Each entry goes out with "slack_record" first ("audit"), so the library parsers in
parsers/slack/slack-audit-logs can recognize and normalize it.

Each run reads from the end of its last window, less an overlap, to a minute before now, following
response_metadata.next_cursor, and drops entries it already sent by their id. The request and
response shapes follow Slack's Audit Logs API reference. Configuration comes from environment
variables (see README.md). A window's end only moves after HTTP Ingest accepted every entry in it.
--dry-run prints what would be sent and changes nothing.
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
import re
import socket
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
LOG = logging.getLogger("slack_audit_bridge")
USER_AGENT = f"sophos-xdr-siem-library-slack-audit-bridge/{__version__}"
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
LOGS_PATH = "/audit/v1/logs"
RECORD_KEY = "slack_record"
RECORD = "audit"
# Slack's audit logs start in March 2018; an earlier oldest is an invalid_range error.
EARLIEST = 1519862400  # 2018-03-01T00:00:00Z
# A window ends this long before now, so a clock a little ahead of Slack's never asks for the future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000
# The action filter takes up to 30 actions per request.
MAX_ACTIONS = 30
ACTION = re.compile(r"^[a-z0-9_.]{1,100}$")
# Slack's error codes for the Audit Logs API, and what to check for each.
SLACK_ERRORS = {
    "invalid_authentication": "Slack refused the token; SLACK_TOKEN must be the user token (xoxp-) of an app with the "
                              "auditlogs:read scope that an Org Owner installed on the Enterprise organization",
    "missing_authentication": "Slack found no token in the request; check SLACK_TOKEN",
    "user_not_authorized": "the user who installed the app is not an Owner of the Enterprise organization; an Org Owner "
                           "must install it",
    "team_not_authorized": "the app is installed on a workspace; install it on the Enterprise organization itself",
    "invalid_workspace": "the Audit Logs API only works for an Enterprise organization",
    "feature_not_enabled": "audit logs aren't available; the Audit Logs API needs an Enterprise plan",
    "method_not_allowed": "Slack doesn't allow this request with this token",
    "invalid_action": "an action in SLACK_ACTIONS isn't one Slack supports",
    "invalid_range": "the window isn't one Slack accepts (before March 2018 or in the future); check the clock",
    "invalid_cursor": "the paging cursor was refused or expired; the next run reads the window again",
}


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """The API or HTTP Ingest couldn't be reached, even after the retries. With --interval the
    bridge logs it and tries again at the next interval."""


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


def _list(env: dict, name: str, default: str = "") -> list[str]:
    return list(dict.fromkeys(x.strip() for x in (_env(env, name, default) or "").split(",") if x.strip()))


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "SLACK_API_URL", "https://api.slack.com") or "").rstrip("/"),
        "token": _env(env, "SLACK_TOKEN"),
        "actions": _list(env, "SLACK_ACTIONS"),
        "page_limit": _number(env, "SLACK_PAGE_LIMIT", "1000", low=1, high=9999),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "slack_audit_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["token"]:
        raise BridgeError("SLACK_TOKEN is required: the user token (xoxp-) of an app with the auditlogs:read scope that "
                          "an Org Owner installed on the Enterprise organization")
    if any(not ACTION.match(a) for a in cfg["actions"]):
        raise BridgeError("SLACK_ACTIONS takes action names such as user_login or file_downloaded, separated by commas")
    if len(cfg["actions"]) > MAX_ACTIONS:
        raise BridgeError(f"SLACK_ACTIONS takes up to {MAX_ACTIONS} actions, as Slack's action filter does")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["api_url"], "SLACK_API_URL")
    _require_https(cfg["api_url"], "SLACK_API_URL")
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
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, headers, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers, _read(resp, what, url)
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


def _slack_error(body: bytes) -> str | None:
    """Slack answers an error with {"ok": false, "error": "<code>"}. The code, kept short, or None."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    code = data.get("error") if isinstance(data, dict) else None
    return str(code)[:100] if code else None


def _explain(code: str | None) -> str:
    if not code:
        return "no error code"
    return f"{code}: {SLACK_ERRORS[code]}" if code in SLACK_ERRORS else code


# ---------------------------------------------------------------- Audit Logs API

class AuditLogs:
    """Calls the Audit Logs API with the user token in 'Authorization: Bearer'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def logs(self, params: dict) -> dict:
        """One page of entries, with response_metadata.next_cursor for the next."""
        url = f"{self.cfg['api_url']}{LOGS_PATH}?{urllib.parse.urlencode(params)}"
        headers = {"Authorization": f"Bearer {self.cfg['token']}", "Accept": "application/json"}
        try:
            _, _, raw = _request("GET", url, headers, None, self.cfg["timeout"], "logs request")
        except HttpStatus as e:
            # A status that outlasted the retries, a redirect, 501 and 505 keep their own errors.
            code = _slack_error(e.body)
            if code and not isinstance(e, RetriedStatus) and e.code not in REDIRECT_STATUS and e.code not in UNSUPPORTED_STATUS:
                raise BridgeError(f"Slack refused the logs request (HTTP {e.code}, {_explain(code)})") from None
            raise
        data = _json(raw, "logs request")
        if not isinstance(data, dict):
            raise BridgeError("logs request returned JSON that is not an object")
        if data.get("ok") is False:
            raise BridgeError(f"Slack refused the logs request ({_explain(_slack_error(raw))})")
        return data


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

def _key(entry: dict) -> str:
    """Every entry has a unique id. One without an id is known by the hash of the whole entry."""
    if isinstance(entry.get("id"), str) and entry["id"]:
        return "id:" + entry["id"]
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _entry_time(entry: dict, now: float) -> float:
    """date_create is Unix time in seconds. An entry without a usable one counts as now."""
    value = entry.get("date_create")
    if isinstance(value, bool):
        return now
    if isinstance(value, (int, float)):
        # NaN (which Python's json reads) fails the comparison and counts as now too.
        return float(value) if value == value and abs(value) < 1e12 else now
    try:
        return float(int(str(value).strip()))
    except ValueError:
        return now


def collect(cfg: dict, state: dict, sink: Sink, save, client: AuditLogs, now: float) -> int:
    """Reads from the end of the last window, less the overlap, to a minute before now, and sends
    the entries not sent before. Slack lists the newest entries first and, while there are more,
    gives response_metadata.next_cursor, which goes back as cursor with the same oldest and latest.
    The window's end is saved only after every page of it was sent."""
    cur = state.setdefault("logs", {})
    since = cur.get("until")
    end = int(now) - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) else (now - cfg["lookback_hours"] * 3600)
    # oldest and latest are whole seconds, both inclusive, and never before March 2018.
    start = min(max(int(start), EARLIEST), end)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    params = {"oldest": start, "latest": end, "limit": cfg["page_limit"]}
    if cfg["actions"]:
        params["action"] = ",".join(cfg["actions"])
    sent = 0
    cursor = None
    for _ in range(MAX_PAGES):
        data = client.logs(dict(params, cursor=cursor) if cursor else params)
        rows = data.get("entries") or []
        if not isinstance(rows, list):
            raise BridgeError("logs request returned entries that are not a list")
        fresh = {}
        for e in rows:
            if not isinstance(e, dict):
                continue
            k = _key(e)
            if k not in seen and k not in fresh:
                fresh[k] = (_entry_time(e, now), e)
        if fresh:
            # Slack lists the newest first; each page goes out oldest first.
            batch = sorted(fresh.values(), key=lambda te: te[0])
            sink.send([{RECORD_KEY: RECORD, **{f: v for f, v in e.items() if f != RECORD_KEY}} for _, e in batch])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            if len(seen) > SEEN_LIMIT:
                cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
            sent += len(fresh)
            save()
        meta = data.get("response_metadata")
        following = meta.get("next_cursor") if isinstance(meta, dict) else None
        # An empty, null or missing next_cursor means there are no more pages.
        if not following:
            break
        if not isinstance(following, str):
            raise BridgeError("logs request returned a next_cursor that is not text")
        if following == cursor:
            raise BridgeError("logs request returned the same next_cursor twice, so the next page can't be read")
        cursor = following
    else:
        LOG.warning("stopped after %d pages; the next run reads the same window again", MAX_PAGES)
        return sent
    cur["until"] = end
    save()
    LOG.info("%d sent", sent)
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
    count = collect(cfg, state, sink, save, AuditLogs(cfg), time.time())
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
    ap = argparse.ArgumentParser(description="Send Slack audit logs to Sophos NG-SIEM HTTP Ingest.")
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
