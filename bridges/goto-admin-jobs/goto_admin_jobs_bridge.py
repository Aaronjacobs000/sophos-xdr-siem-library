#!/usr/bin/env python3
"""Pull GoTo Admin job records (GoTo's audit records of admin changes) from the GoTo Admin API and send
them to a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library
only.

GoTo Admin (admin.goto.com, which also manages GoTo Connect) records each change an admin makes as a
job: "an audit record that represents a modification operation performed by an admin", with the
admin, the request, the outcome and the users, devices and groups it touched. GoTo offers the jobs
only through its Admin API, which is pull only, so this script reads them with an OAuth client and a
personal access token or a refresh token:

  POST <auth>/oauth/token                                     (grant_type personal_access_token or refresh_token)
  GET  <api>/admin/rest/v1/me                                 (the account key, when it isn't set)
  GET  <api>/admin/rest/v1/accounts/<accountKey>/jobs         (fromDate, toDate, metadata=true)

Each record goes out with "goto_record": "admin_job" and the account key first, then the job as GoTo
returns it, so the library parsers in parsers/goto/goto-connect-admin-activity can recognize and
normalize it.

GoTo's spec documents the job fields and the query parameters, but not the body of a page of jobs, so
the bridge takes either a JSON array of jobs or {"results": [...]} as GoTo's other lists send, and
splits a window in two when an answer says it holds fewer jobs than its total. Each run reads from the
end of its last window, less an overlap, to a minute before now, in windows of GOTO_WINDOW_MINUTES,
and drops jobs it already sent in the same state. Configuration comes from environment variables
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
import re
import socket
import ssl
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
LOG = logging.getLogger("goto_admin_jobs_bridge")
USER_AGENT = f"sophos-xdr-siem-library-goto-admin-jobs-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# The most requests one window may take when it is split, so an answer that never completes can't loop.
MAX_SPLITS = 4096
RECORD_KEY = "goto_record"
DEFAULT_API_URL = "https://api.getgo.com"
DEFAULT_AUTH_URL = "https://authentication.logmeininc.com"
TOKEN_PATH = "/oauth/token"
ME_PATH = "/admin/rest/v1/me"
# A window ends this long before now, so a clock a little ahead of GoTo's never asks for the future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000
# GoTo's default rate limit is 10 requests a second for each API, so the bridge spaces its requests.
PACE_SECONDS = 0.15
# A token is renewed this long before GoTo says it expires.
TOKEN_MARGIN_SECONDS = 60
ACCOUNT_KEY = re.compile(r"^\d{1,40}$")


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


def _base_url(env: dict, name: str, default: str) -> str:
    url = (_env(env, name, default) or "").rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if not parts.netloc or parts.path or parts.query or parts.fragment:
        raise BridgeError(f"{name} takes the scheme and host only, such as {default}")
    _refuse_user_info(url, name)
    _require_https(url, name)
    return url


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": _base_url(env, "GOTO_API_URL", DEFAULT_API_URL),
        "auth_url": _base_url(env, "GOTO_AUTH_URL", DEFAULT_AUTH_URL),
        "client_id": _env(env, "GOTO_CLIENT_ID"),
        "client_secret": _env(env, "GOTO_CLIENT_SECRET"),
        "pat": _env(env, "GOTO_PAT"),
        "refresh_token": _env(env, "GOTO_REFRESH_TOKEN"),
        "account_key": _env(env, "GOTO_ACCOUNT_KEY"),
        "metadata": _flag(env, "GOTO_METADATA", True),
        "window_minutes": _number(env, "GOTO_WINDOW_MINUTES", "60", low=1, high=1440),
        "token_file": _env(env, "BRIDGE_TOKEN_FILE", "goto_refresh_token.json"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "goto_admin_jobs_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "900"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise BridgeError("GOTO_CLIENT_ID and GOTO_CLIENT_SECRET are required: the Client ID and Client Secret of "
                          "an OAuth client with the identity: scope")
    if bool(cfg["pat"]) == bool(cfg["refresh_token"]):
        raise BridgeError("set one of GOTO_PAT (a personal access token) and GOTO_REFRESH_TOKEN (a refresh token from "
                          "the authorization code grant), not both and not neither")
    if cfg["account_key"] and not ACCOUNT_KEY.match(cfg["account_key"]):
        raise BridgeError("GOTO_ACCOUNT_KEY must be the account key, digits only, or unset to read it from /me")
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


def _goto_error(body: bytes) -> str:
    """GoTo's error text, cut to 200 characters. The Admin API sends {"incidentId", "errors": [{"code",
    "field", "value"}]} (some answers send one error object bare), the OAuth endpoint {"error",
    "error_description"}, and GoTo's gateway {"int_err_code", "msg"}."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    if not isinstance(data, dict):
        return "no message"
    errors = data.get("errors")
    first = errors[0] if isinstance(errors, list) and errors and isinstance(errors[0], dict) else data
    parts = [first.get(k) for k in ("code", "field")] + [data.get(k) for k in ("error", "error_description", "int_err_code", "msg")]
    text = "; ".join(p for p in parts if isinstance(p, str) and p)
    return text[:200] or "no message"


def _token_refused(e: HttpStatus) -> bool:
    """A 401, or the 403 GoTo's gateway sends for a token it doesn't accept ("InvalidToken"), means the
    access token should be renewed. Any other 403 is a missing permission."""
    return e.code == 401 or (e.code == 403 and (b"InvalidToken" in e.body or b"invalid_token" in e.body))


# ---------------------------------------------------------------- GoTo Admin API

def _write_private(path: str, data: dict) -> None:
    """Writes a file only its owner can read, in one step, so a crash never leaves half a token."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".token-", dir=folder)
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


class GoTo:
    """Calls the Admin API with an access token from the personal access token grant, or from the
    refresh token grant. A refresh token GoTo replaces is saved to BRIDGE_TOKEN_FILE at once, since
    GoTo invalidates the old one, and that file is read first on the next start. The access token
    is kept until a minute before it expires, and renewed once more when the API refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0
        self._last = None
        self._account = cfg["account_key"]
        self._refresh = None
        if cfg["refresh_token"]:
            self._refresh = cfg["refresh_token"]
            try:
                with open(cfg["token_file"], encoding="utf-8") as fh:
                    saved = json.load(fh)
            except FileNotFoundError:
                saved = None
            except (OSError, ValueError):
                raise BridgeError("BRIDGE_TOKEN_FILE couldn't be read as the bridge's saved refresh token") from None
            if isinstance(saved, dict) and isinstance(saved.get("refresh_token"), str) and saved["refresh_token"]:
                self._refresh = saved["refresh_token"]

    def _pace(self) -> None:
        if self._last is not None:
            wait = self._last + PACE_SECONDS - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self._last = time.monotonic()

    def _new_token(self) -> str:
        url = f"{self.cfg['auth_url']}{TOKEN_PATH}"
        basic = base64.b64encode(f"{self.cfg['client_id']}:{self.cfg['client_secret']}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        if self.cfg["pat"]:
            form, what = {"grant_type": "personal_access_token", "pat": self.cfg["pat"]}, "personal access token"
        else:
            form, what = {"grant_type": "refresh_token", "refresh_token": self._refresh}, "refresh token"
        try:
            _, raw = _request("POST", url, headers, urllib.parse.urlencode(form).encode(), self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"GoTo refused the {what} (HTTP {e.code}: {_goto_error(e.body)}); check GOTO_CLIENT_ID "
                                  f"and GOTO_CLIENT_SECRET, and that the {what} is still valid for this OAuth client") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise BridgeError("token request returned no access_token")
        renewed = data.get("refresh_token")
        if self._refresh and isinstance(renewed, str) and renewed and renewed != self._refresh:
            # GoTo invalidates the old refresh token once it sends a new one, so the new one is saved
            # before anything else happens.
            try:
                _write_private(self.cfg["token_file"], {"refresh_token": renewed})
            except OSError:
                raise BridgeError("GoTo sent a new refresh token and invalidated the old one, but BRIDGE_TOKEN_FILE "
                                  "couldn't be written; fix the file's folder and get a new refresh token") from None
            self._refresh = renewed
            LOG.info("GoTo sent a new refresh token; saved it to BRIDGE_TOKEN_FILE")
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

    def get(self, path: str, query: dict, what: str):
        """One GET with the access token. A refused token is renewed and the request sent once more."""
        url = f"{self.cfg['api_url']}{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json"}
            self._pace()
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
            except HttpStatus as e:
                if _token_refused(e) and not renew:
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"GoTo refused the {what} (HTTP {e.code}: {_goto_error(e.body)}); the token needs "
                                      "the identity: scope and an admin who can see the account's activity") from None
                if e.code == 400:
                    raise BridgeError(f"GoTo rejected the {what} (HTTP 400: {_goto_error(e.body)})") from None
                if e.code == 404:
                    raise BridgeError(f"GoTo answered the {what} with HTTP 404 ({_goto_error(e.body)}); check "
                                      "GOTO_ACCOUNT_KEY and GOTO_API_URL") from None
                raise
            return _json(raw, what)
        # Not reached: the second answer above always returns or raises.
        raise BridgeError(f"GoTo refused the {what}")

    def account_key(self) -> str:
        """GOTO_ACCOUNT_KEY, or the accountKey of the token's admin from GET /admin/rest/v1/me."""
        if not self._account:
            me = self.get(ME_PATH, {}, "account request")
            key = me.get("accountKey") if isinstance(me, dict) else None
            if isinstance(key, bool) or not isinstance(key, (int, str)) or not ACCOUNT_KEY.match(str(key)):
                raise BridgeError("account request returned no accountKey; set GOTO_ACCOUNT_KEY")
            self._account = str(key)
        return self._account

    def jobs(self, account: str, lo: int, hi: int) -> tuple[list, int | None]:
        """The jobs submitted from lo to hi (epoch milliseconds), and the total GoTo gives, if any."""
        query = {"fromDate": lo, "toDate": hi}
        if self.cfg["metadata"]:
            query["metadata"] = "true"
        data = self.get(f"/admin/rest/v1/accounts/{account}/jobs", query, "jobs request")
        if isinstance(data, list):
            return data, None
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            total = data.get("total")
            return data["results"], (total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None)
        raise BridgeError("jobs request returned neither a JSON array nor {\"results\": [...]}; GoTo doesn't document "
                          "this answer, so please report the shape it sent")


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

def _key(job: dict) -> str:
    """A job is known by its id and status, so a job seen again after it completed or failed is sent
    once more in its new state. One without an id is known by the hash of the whole record."""
    jid = job.get("id")
    if isinstance(jid, (str, int)) and not isinstance(jid, bool) and str(jid):
        return f"id:{jid}:{job.get('status')}"
    return "sha:" + hashlib.sha256(json.dumps(job, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _job_time(job: dict, now: float) -> float:
    """submitTime is milliseconds since the epoch."""
    t = job.get("submitTime")
    return t / 1000.0 if isinstance(t, (int, float)) and not isinstance(t, bool) and t > 0 else now


def fetch(client: GoTo, account: str, lo: int, hi: int) -> list:
    """Every job from lo to hi (milliseconds, both included). When an answer gives a total above the
    jobs it holds, the range is split in two and each half read, down to one millisecond."""
    out, todo, calls = [], [(lo, hi)], 0
    while todo:
        a, b = todo.pop(0)
        calls += 1
        if calls > MAX_SPLITS:
            raise BridgeError(f"jobs request still held fewer jobs than its total after {MAX_SPLITS} requests; the next "
                              "run reads the same window again")
        rows, total = client.jobs(account, a, b)
        if total is not None and total > len(rows):
            if b <= a:
                raise BridgeError(f"jobs request for one millisecond held {len(rows)} of {total} jobs; the next run "
                                  "reads the same window again")
            mid = (a + b) // 2
            todo[:0] = [(a, mid), (mid + 1, b)]
            continue
        out.extend(r for r in rows if isinstance(r, dict))
    return out


def collect(cfg: dict, state: dict, sink: Sink, save, client: GoTo, now: float) -> int:
    """Reads the jobs from the end of the last window, less the overlap, to a minute before now, in
    windows of GOTO_WINDOW_MINUTES, and sends the ones not sent before in the same state. Each
    window's end is saved only after its jobs were sent."""
    account = client.account_key()
    cur = state.setdefault("accounts", {}).setdefault(account, {})
    since = cur.get("until")
    end = now - END_MARGIN_SECONDS
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, end) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) and not isinstance(since, bool) \
        else (now - cfg["lookback_hours"] * 3600)
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    # Windows run in whole milliseconds, each from a to b with both included, so none overlap or leave a gap.
    step = int(cfg["window_minutes"] * 60000)
    a, last = int(start * 1000), int(end * 1000)
    sent = 0
    while a <= last:
        b = min(a + step - 1, last)
        jobs = fetch(client, account, a, b)
        fresh = {}
        for j in jobs:
            k = _key(j)
            if k not in seen and k not in fresh:
                fresh[k] = (_job_time(j, now), j)
        if fresh:
            ctx = {RECORD_KEY: "admin_job", "goto_account_key": account}
            sink.send([{**ctx, **{f: v for f, v in j.items() if f not in ctx}} for _, j in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            if len(seen) > SEEN_LIMIT:
                cur["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
            sent += len(fresh)
        cur["until"] = b / 1000.0
        save()
        a = b + 1
    LOG.info("account %s jobs: %d sent", account, sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None, client: GoTo | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or GoTo(cfg)
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
    ap = argparse.ArgumentParser(description="Send GoTo Admin job records to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for every run, so the token and the account key are kept.
        client = GoTo(cfg)
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
