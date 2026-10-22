#!/usr/bin/env python3
"""Pull RingCentral audit trail records from the RingCentral platform API and send them to a Sophos
NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

RingCentral (RingEX) keeps an audit trail of account changes, Admin Portal sign-ins, and failed
sign-ins and locked accounts, and offers it only through a search API, which is pull only. This
script reads it with a private app that uses the JWT grant:

  POST <server>/restapi/oauth/token                          (grant_type jwt-bearer, Basic client auth)
  POST <server>/restapi/v1.0/account/~/audit-trail/search    (eventTimeFrom, eventTimeTo, page, perPage)

Each record goes out with "ringcentral_record": "audit_trail" first, then the record as RingCentral
returns it, so the library parsers in parsers/ringcentral/ringex-audit-trail can recognize and
normalize it.

Each run reads from the end of its last window, less an overlap, to a minute before now, page by page,
and drops records it already sent by their id. RingCentral puts the search API in its Heavy rate group
(10 requests a minute for each user and app, with a penalty that starts again with every request sent
during it), so the bridge spaces its searches and waits out a 429 instead of backing off quickly. The
request and response shapes follow RingCentral's OpenAPI spec (auditTrailSearch, getToken), its
Audit Trail and JWT guides and its rate limit guide. Configuration comes from environment variables
(see README.md). A window's end only moves after HTTP Ingest accepted every record in it. --dry-run
prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.client
import json
import logging
import os
import random
import socket
import ssl
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("ringcentral_audit_trail_bridge")
USER_AGENT = f"sophos-xdr-siem-library-ringcentral-audit-trail-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 1000
RECORD_KEY = "ringcentral_record"
DEFAULT_URL = "https://platform.ringcentral.com"
TOKEN_PATH = "/restapi/oauth/token"
SEARCH_PATH = "/restapi/v1.0/account/~/audit-trail/search"
JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# A window ends this long before now, so a clock a little ahead of RingCentral's never asks for the
# future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000
# The search keeps 180 days, so a first run can't reach further back.
MAX_LOOKBACK_HOURS = 180 * 24
# The Heavy group allows 10 requests a minute for each user and app, so searches are spaced 6.5 s apart.
PACE_SECONDS = 6.5
# A 429 without Retry-After waits out RingCentral's default 60 s penalty, since any request sent
# during the penalty starts it again.
PENALTY_SECONDS = 60.0
# A token is renewed this long before RingCentral says it expires.
TOKEN_MARGIN_SECONDS = 60


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


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "RINGCENTRAL_URL", DEFAULT_URL) or "").rstrip("/"),
        "client_id": _env(env, "RINGCENTRAL_CLIENT_ID"),
        "client_secret": _env(env, "RINGCENTRAL_CLIENT_SECRET"),
        "jwt": _env(env, "RINGCENTRAL_JWT"),
        "page_size": _number(env, "RINGCENTRAL_PAGE_SIZE", "1000", low=1, high=1000),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "ringcentral_audit_trail_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=MAX_LOOKBACK_HOURS),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if not parts.netloc or parts.path or parts.query or parts.fragment:
        raise BridgeError("RINGCENTRAL_URL takes the scheme and host only, such as https://platform.ringcentral.com")
    _refuse_user_info(cfg["api_url"], "RINGCENTRAL_URL")
    _require_https(cfg["api_url"], "RINGCENTRAL_URL")
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise BridgeError("RINGCENTRAL_CLIENT_ID and RINGCENTRAL_CLIENT_SECRET are required: the Client ID and Client "
                          "Secret of a private app that uses the JWT auth flow")
    if not cfg["jwt"]:
        raise BridgeError("RINGCENTRAL_JWT is required: a JWT credential of an admin who can read the audit trail")
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


def _retry_delay(attempt: int, retry_after: str | None, code: int | None = None) -> float:
    if retry_after:
        try:
            # Honor the server's wait for up to five minutes, so a bad value can't stall the bridge.
            return min(300.0, max(0.0, float(retry_after)))
        except ValueError:
            pass
    if code == 429:
        # RingCentral restarts its penalty with every request sent during it, so a 429 without
        # Retry-After waits the whole default penalty.
        return PENALTY_SECONDS + random.uniform(0, 1)
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
    """Send a request, retrying 408, 429, 500, 502, 503 and 504. Returns (status, headers, body)."""
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
                delay = _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None, e.code)
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS:
                raise RetriedStatus(what, url, e.code, error_body) from None
            raise HttpStatus(what, url, e.code, error_body) from None
        except _NETWORK_ERRORS as e:
            # A certificate that fails the check is refused at once: a retry gets the same certificate.
            reason = getattr(e, "reason", None)
            if isinstance(e, ssl.SSLCertVerificationError) or isinstance(reason, ssl.SSLCertVerificationError):
                raise BridgeError(f"{what} to {_host(url)} failed: the server's certificate isn't trusted or doesn't "
                                  "name this host") from None
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


def _rc_error(body: bytes) -> str:
    """RingCentral's error text: an OAuth error ({"error", "error_description"}) or the first of
    {"errors": [{"errorCode", "message"}]}, cut to 200 characters."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    parts = []
    if isinstance(data.get("error"), str):
        parts.append(data["error"])
    if isinstance(data.get("error_description"), str):
        parts.append(data["error_description"])
    errors = data.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        first = errors[0]
        code, message = first.get("errorCode"), first.get("message")
        parts.append(" ".join(str(x) for x in (code, message) if isinstance(x, str) and x))
    elif isinstance(data.get("message"), str):
        parts.append(data["message"])
    text = "; ".join(p for p in parts if p)
    return text[:200] or "no message"


# ---------------------------------------------------------------- RingCentral API

class RingCentral:
    """Calls the platform API with an access token from the JWT grant. The token is kept until a
    minute before it expires, since token requests count against the Auth rate group (5 a minute),
    and renewed once more when the API answers 401."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0
        self._last = None
        self._hold_until = 0.0

    def _pace(self) -> None:
        """Spaces searches under the Heavy group's limit, and waits out X-Rate-Limit-Window when the
        last answer said no requests were left. The first search doesn't wait: on some systems the
        monotonic clock starts near 0 when Python does."""
        due = self._hold_until if self._last is None else max(self._last + PACE_SECONDS, self._hold_until)
        wait = due - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _note_limits(self, headers) -> None:
        if headers is None:
            return
        remaining, window = headers.get("X-Rate-Limit-Remaining"), headers.get("X-Rate-Limit-Window")
        try:
            if remaining is not None and int(remaining) <= 0 and window is not None:
                self._hold_until = time.monotonic() + min(300.0, max(0.0, float(window)))
        except ValueError:
            pass

    def _new_token(self) -> str:
        url = f"{self.cfg['api_url']}{TOKEN_PATH}"
        basic = base64.b64encode(f"{self.cfg['client_id']}:{self.cfg['client_secret']}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        body = urllib.parse.urlencode({"grant_type": JWT_GRANT, "assertion": self.cfg["jwt"]}).encode()
        try:
            _, _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"RingCentral refused the JWT credential (HTTP {e.code}: {_rc_error(e.body)}); check "
                                  "RINGCENTRAL_CLIENT_ID, RINGCENTRAL_CLIENT_SECRET and RINGCENTRAL_JWT, and that the app "
                                  "uses the JWT auth flow and the JWT may be used with it") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise BridgeError("token request returned no access_token")
        expires_in = data.get("expires_in")
        life = float(expires_in) if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) \
            and expires_in > 0 else 3600.0
        self._token = token
        self._expires = time.monotonic() + max(60.0, life - TOKEN_MARGIN_SECONDS)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def search(self, start: str, end: str, page: int) -> dict:
        """One page of the audit trail search for the window, as RingCentral's guide sends it."""
        url = f"{self.cfg['api_url']}{SEARCH_PATH}"
        body = json.dumps({"eventTimeFrom": start, "eventTimeTo": end, "page": page, "perPage": self.cfg["page_size"],
                           "includeAdmins": True, "includeHidden": True}, separators=(",", ":")).encode()
        what = "audit trail search"
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Content-Type": "application/json",
                       "Accept": "application/json"}
            self._pace()
            try:
                _, resp_headers, raw = _request("POST", url, headers, body, self.cfg["timeout"], what)
            except HttpStatus as e:
                if e.code == 401 and not renew:
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"RingCentral refused the {what} (HTTP {e.code}: {_rc_error(e.body)}); the app needs "
                                      "the Read Audit Trail permission, and the JWT's user an admin role that can see "
                                      "the audit trail") from None
                if e.code == 400:
                    raise BridgeError(f"RingCentral rejected the {what} (HTTP 400: {_rc_error(e.body)})") from None
                if e.code == 404:
                    raise BridgeError(f"RingCentral answered the {what} with HTTP 404 ({_rc_error(e.body)}); check "
                                      "RINGCENTRAL_URL") from None
                raise
            self._note_limits(resp_headers)
            data = _json(raw, what)
            if not isinstance(data, dict):
                raise BridgeError(f"{what} returned JSON that is not an object")
            return data
        # Not reached: the second answer above always returns or raises.
        raise BridgeError(f"RingCentral refused the {what}")


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
    """eventTime is RFC 3339 in UTC, such as 2026-10-21T01:12:44.218Z."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _iso(epoch: float) -> str:
    """A time for eventTimeFrom and eventTimeTo: ISO 8601 in UTC, to the millisecond."""
    dt = datetime.fromtimestamp(epoch, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _key(record: dict) -> str:
    """Records have an id. One without it is known by the hash of the whole record."""
    rid = record.get("id")
    if isinstance(rid, (str, int)) and not isinstance(rid, bool) and str(rid):
        return "id:" + str(rid)
    return "sha:" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _count(value) -> int | None:
    """A whole number of zero or more from the paging object, or None."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def collect(cfg: dict, state: dict, sink: Sink, save, client: RingCentral, now: float) -> int:
    """Reads the audit trail from the end of the last window, less the overlap, to a minute before
    now, page by page, and sends the records not sent before. The window's end is saved only after
    every page of it was sent."""
    cur = state.setdefault("audit_trail", {})
    since = cur.get("until")
    end = now - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) and not isinstance(since, bool) \
        else (now - cfg["lookback_hours"] * 3600)
    # The search keeps 180 days, so the window never starts before that.
    start = max(start, now - MAX_LOOKBACK_HOURS * 3600 + END_MARGIN_SECONDS)
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    lo, hi = _iso(start), _iso(end)
    sent, got = 0, 0
    for page in range(1, MAX_PAGES + 1):
        data = client.search(lo, hi, page)
        records = data.get("records")
        if records is None:
            records = []
        if not isinstance(records, list):
            raise BridgeError("audit trail search returned records that are not a list")
        fresh = {}
        for r in records:
            if not isinstance(r, dict):
                continue
            k = _key(r)
            if k not in seen and k not in fresh:
                fresh[k] = (_parse_time(r.get("eventTime")) or now, r)
        if fresh:
            sink.send([{RECORD_KEY: "audit_trail", **{f: v for f, v in r.items() if f != RECORD_KEY}} for _, r in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            if len(seen) > SEEN_LIMIT:
                cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
            sent += len(fresh)
            save()
        got += len(records)
        if not records:
            break
        # paging.total is the number of pages and paging.totalFound the number of records. RingCentral
        # may leave either out, so then a page shorter than paging.perPage (or the size asked for)
        # is the last.
        paging = data.get("paging") if isinstance(data.get("paging"), dict) else {}
        pages, found, per = paging.get("total"), paging.get("totalFound"), paging.get("perPage")
        if _count(pages) is not None:
            if page >= pages:
                break
        elif _count(found) is not None:
            if got >= found:
                break
        elif len(records) < (per if _count(per) else cfg["page_size"]):
            break
    else:
        raise BridgeError(f"audit trail search had more than {MAX_PAGES} pages; the next run reads the same window again")
    cur["until"] = end
    save()
    LOG.info("audit trail %s to %s: %d sent", lo, hi, sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None, client: RingCentral | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or RingCentral(cfg)
    count = collect(cfg, state, sink, save, client, time.time())
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
    ap = argparse.ArgumentParser(description="Send RingCentral audit trail records to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for every run, so the token is kept until it expires and the searches stay spaced.
        client = RingCentral(cfg)
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
