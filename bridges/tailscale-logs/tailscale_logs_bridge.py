#!/usr/bin/env python3
"""Pull Tailscale configuration audit logs and network flow logs from the Tailscale API and send them
to a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Tailscale streams its logs to Splunk HTTP Event Collector and other SIEMs, in a framing Sophos
NG-SIEM HTTP Ingest doesn't document taking, and offers the same logs through its API, which is
pull only. This script reads them with an OAuth client (or an API access token):

  POST https://api.tailscale.com/api/v2/oauth/token                          (client credentials)
  GET  https://api.tailscale.com/api/v2/tailnet/<tailnet>/logging/configuration?start=&end=
  GET  https://api.tailscale.com/api/v2/tailnet/<tailnet>/logging/network?start=&end=

Each configuration audit event goes out with "tailscale_record": "configuration" first. A network
flow log holds every connection a node saw in a few seconds, so the bridge sends one record per
connection, with "tailscale_record": "network", the kind of traffic, the node and the time span,
and the source and destination nodes Tailscale names. Both carry "tailscale_tailnet". The library
parsers in parsers/tailscale/tailscale-logs recognize and normalize them.

Each run reads each log from the end of its last window, less an overlap, to a minute before now,
at most TAILSCALE_WINDOW_MINUTES at a time, and drops records it already sent by a hash of each
one. The request and response shapes follow Tailscale's API reference (its OpenAPI document) and its
logging and OAuth client docs. Configuration comes from environment variables (see README.md). A
window's end only moves after HTTP Ingest accepted every record in it. --dry-run prints what would
be sent and changes nothing.
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
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("tailscale_logs_bridge")
USER_AGENT = f"sophos-xdr-siem-library-tailscale-logs-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_WINDOWS = 10000
RECORD_KEY = "tailscale_record"
TAILNET_KEY = "tailscale_tailnet"
TOKEN_PATH = "/api/v2/oauth/token"
LOGS = ("configuration", "network")
# Tailscale keeps configuration audit logs for 90 days and network flow logs for 30.
RETENTION_DAYS = {"configuration": 90, "network": 30}
TRAFFIC = ("virtual", "subnet", "exit", "physical")
CONNECTION_KEYS = ("proto", "src", "dst", "txPkts", "txBytes", "rxPkts", "rxBytes")
# A window ends this long before now, so a clock a little ahead of Tailscale's never asks for the future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000
# A token is renewed this long before Tailscale says it expires.
TOKEN_MARGIN_SECONDS = 60
TAILNET = re.compile(r"^(?:-|[A-Za-z0-9][A-Za-z0-9._@+-]{0,253})$")

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
        "api_url": (_env(env, "TAILSCALE_API_URL", "https://api.tailscale.com") or "").rstrip("/"),
        "client_id": _env(env, "TAILSCALE_OAUTH_CLIENT_ID"),
        "client_secret": _env(env, "TAILSCALE_OAUTH_CLIENT_SECRET"),
        "api_key": _env(env, "TAILSCALE_API_KEY"),
        "tailnet": _env(env, "TAILSCALE_TAILNET", "-"),
        "logs": [x.lower() for x in _list(env, "TAILSCALE_LOGS", "configuration,network")],
        "window_minutes": _number(env, "TAILSCALE_WINDOW_MINUTES", "60", low=1, high=1440),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "tailscale_logs_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=2160),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment:
        raise BridgeError("TAILSCALE_API_URL takes the scheme, host and port only, such as https://api.tailscale.com")
    _refuse_user_info(cfg["api_url"], "TAILSCALE_API_URL")
    _require_https(cfg["api_url"], "TAILSCALE_API_URL")
    oauth = bool(cfg["client_id"] or cfg["client_secret"])
    if oauth and not (cfg["client_id"] and cfg["client_secret"]):
        raise BridgeError("TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET are both needed for an OAuth client")
    if oauth and cfg["api_key"]:
        raise BridgeError("set either TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET, or TAILSCALE_API_KEY, "
                          "not both")
    if not oauth and not cfg["api_key"]:
        raise BridgeError("TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET are required: an OAuth client with "
                          "the logs:configuration:read and logs:network:read scopes (or set TAILSCALE_API_KEY)")
    if not TAILNET.match(cfg["tailnet"]):
        raise BridgeError("TAILSCALE_TAILNET takes the tailnet ID from the admin console's General settings, or - for "
                          "the tailnet of the key")
    if not cfg["logs"] or any(x not in LOGS for x in cfg["logs"]):
        raise BridgeError("TAILSCALE_LOGS takes configuration and network, separated by commas")
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


def _fromisoformat(text: str) -> datetime:
    """datetime.fromisoformat, the same on Python 3.9 to 3.13. Before 3.11 it takes no Z, only 3 or 6
    fraction digits and only +HH:MM offsets (no version takes z), so the text is rewritten first."""
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, rest = text.split(".", 1)
        # The fraction is the digits right after the point. An offset after them keeps its place.
        tail = rest.lstrip("0123456789")
        text = head + "." + (rest[:len(rest) - len(tail)] + "000000")[:6] + tail
    if text[-5:-4] in ("+", "-") and text[-4:].isdigit():
        text = text[:-2] + ":" + text[-2:]  # +1000 becomes +10:00
    return datetime.fromisoformat(text)

def _parse_time(value) -> float | None:
    """timestamp is RFC 3339 in UTC, such as 2026-10-14T00:12:44.123Z."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _ts_time(epoch: float) -> str:
    """start and end take RFC 3339, sent here in UTC to the whole second."""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _message(body: bytes) -> str:
    """Tailscale answers errors with {"message": "..."}."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    return " ".join(str(data.get("message") or "").split())[:200] or "no message"


# ---------------------------------------------------------------- Tailscale API

class Tailscale:
    """Calls the API with an access token from the OAuth client credentials grant, or with an API
    access token, either sent as 'Authorization: Bearer'. An OAuth token lasts an hour; it is
    renewed before it expires, and once more when Tailscale refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        url = self.cfg["api_url"] + TOKEN_PATH
        body = urllib.parse.urlencode({"client_id": self.cfg["client_id"], "client_secret": self.cfg["client_secret"]}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        try:
            _, _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "OAuth token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"Tailscale refused the OAuth token request (HTTP {e.code}: {_message(e.body)}); check "
                                  "TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET") from None
            raise
        data = _json(raw, "OAuth token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise BridgeError("OAuth token request returned no access_token")
        life = data.get("expires_in")
        life = float(life) if isinstance(life, (int, float)) and not isinstance(life, bool) and life > 0 else 3600.0
        self._token = token
        self._expires = time.time() + max(0.0, life - TOKEN_MARGIN_SECONDS)
        return token

    def _bearer(self) -> str:
        if self.cfg["api_key"]:
            return self.cfg["api_key"]
        if self._token and time.time() < self._expires:
            return self._token
        return self._new_token()

    def logs(self, log: str, start: float, end: float) -> dict:
        """One window of one log: the whole answer, since the API returns every log of the window at
        once, oldest first."""
        tailnet = urllib.parse.quote(self.cfg["tailnet"], safe="-")
        query = urllib.parse.urlencode({"start": _ts_time(start), "end": _ts_time(end)})
        url = f"{self.cfg['api_url']}/api/v2/tailnet/{tailnet}/logging/{log}?{query}"
        what = f"{log} logs request"
        for attempt in range(2):
            headers = {"Authorization": f"Bearer {self._bearer()}", "Accept": "application/json"}
            try:
                _, _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
            except HttpStatus as e:
                if e.code == 401 and attempt == 0 and not self.cfg["api_key"]:
                    self._token = None
                    continue
                if e.code == 401:
                    raise BridgeError(f"Tailscale refused the {what} (HTTP 401: {_message(e.body)}); check the OAuth client "
                                      "or TAILSCALE_API_KEY, and that it hasn't expired") from None
                if e.code == 403:
                    scope = "logs:configuration:read" if log == "configuration" else "logs:network:read"
                    raise BridgeError(f"Tailscale refused the {what} (HTTP 403: {_message(e.body)}); the OAuth client needs "
                                      f"the {scope} scope, or the user who made TAILSCALE_API_KEY a role that can view "
                                      "these logs") from None
                if e.code == 404:
                    raise BridgeError(f"Tailscale answered the {what} with HTTP 404 ({_message(e.body)}); check "
                                      "TAILSCALE_TAILNET, and for network flow logs that your plan has them and they are "
                                      "turned on") from None
                if e.code == 400:
                    raise BridgeError(f"Tailscale rejected the {what} (HTTP 400: {_message(e.body)})") from None
                raise
            data = _json(raw, what)
            if not isinstance(data, dict):
                raise BridgeError(f"{what} returned JSON that is not an object")
            return data
        raise BridgeError(f"Tailscale refused the {what}")


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

def _key(record: dict) -> str:
    """No log has a unique ID (eventGroupID is shared by every event of one operation), so a record
    is known by the hash of all of it."""
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()[:32]


def _address(endpoint) -> str:
    """The address of an addr:port, such as 100.64.0.1:443 or [fd7a:115c:a1e0::1]:443."""
    text = str(endpoint or "")
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    return text.rsplit(":", 1)[0] if text.count(":") == 1 else text


def connections(log: dict, tailnet: str) -> list[dict]:
    """One record per connection of a network flow log. Each takes the log's node and times, the
    kind of traffic (virtual, subnet, exit or physical), the connection's own counts, and the source
    and destination nodes the log names (from client version 1.92), matched by address."""
    nodes = {}
    for node in log.get("dstNodes") or []:
        if isinstance(node, dict):
            for addr in node.get("addresses") or []:
                nodes.setdefault(str(addr), node)
    src_node = log.get("srcNode") if isinstance(log.get("srcNode"), dict) else None
    base = {RECORD_KEY: "network", TAILNET_KEY: tailnet}
    base.update({k: log[k] for k in ("nodeId", "logged", "start", "end") if k in log})
    out = []
    for kind in TRAFFIC:
        for conn in log.get(kind + "Traffic") or []:
            if not isinstance(conn, dict):
                continue
            rec = {**base, "traffic": kind, **{k: conn[k] for k in CONNECTION_KEYS if k in conn}}
            if src_node:
                rec["srcNode"] = src_node
            dst = nodes.get(_address(conn.get("dst")))
            # Physical traffic runs from the peer's Tailscale address to its WireGuard endpoint.
            peer = nodes.get(_address(conn.get("src"))) if kind == "physical" else None
            if dst:
                rec["dstNode"] = dst
            if peer:
                rec["peerNode"] = peer
            out.append(rec)
    return out


def _record_time(record: dict, now: float) -> float:
    t = _parse_time(record.get("eventTime") or record.get("start") or record.get("logged"))
    return t if t is not None else now


def collect(log: str, cfg: dict, state: dict, sink: Sink, save, client: Tailscale, now: float) -> int:
    """Reads one log from the end of its last window, less the overlap, to a minute before now, a
    window of at most TAILSCALE_WINDOW_MINUTES at a time, and sends the records not sent before. Each
    window's end is saved only after it was sent."""
    cur = state.setdefault("logs", {}).setdefault(log, {})
    since = cur.get("until")
    end_all = now - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end_all) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) and not isinstance(since, bool) \
        else (now - cfg["lookback_hours"] * 3600)
    start = max(start, now - RETENTION_DAYS[log] * 86400)
    start = min(start, end_all - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 3600}
    cur["seen"] = seen
    step = cfg["window_minutes"] * 60
    sent = 0
    for _ in range(MAX_WINDOWS):
        end = min(start + step, end_all)
        data = client.logs(log, start, end)
        logs = data.get("logs")
        if logs is None:
            logs = []
        if not isinstance(logs, list):
            raise BridgeError(f"{log} logs request returned logs that are not a list")
        tailnet = data.get("tailnet") or data.get("tailnetId") or cfg["tailnet"]
        records = []
        for entry in logs:
            if not isinstance(entry, dict):
                continue
            if log == "network":
                records.extend(connections(entry, str(tailnet)))
            else:
                records.append({RECORD_KEY: "configuration", TAILNET_KEY: str(tailnet),
                                **{k: v for k, v in entry.items() if k not in (RECORD_KEY, TAILNET_KEY)}})
        fresh = {}
        for rec in records:
            k = _key(rec)
            if k not in seen and k not in fresh:
                fresh[k] = (_record_time(rec, now), rec)
        if fresh:
            sink.send([r for _, r in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            if len(seen) > SEEN_LIMIT:
                cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
            sent += len(fresh)
        cur["until"] = end
        save()
        if end >= end_all:
            break
        start = end
    else:
        LOG.warning("%s logs: stopped after %d windows; the next run goes on from there", log, MAX_WINDOWS)
    LOG.info("%s logs: %d sent", log, sent)
    return sent


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Tailscale | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or Tailscale(cfg)
    now = time.time()
    count = 0
    for log in cfg["logs"]:
        count += collect(log, cfg, state, sink, save, client, now)
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


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

def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Tailscale configuration audit and network flow logs to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for every run, so an OAuth token is kept until it expires.
        client = Tailscale(cfg)
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
