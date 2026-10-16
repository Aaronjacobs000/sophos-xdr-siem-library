#!/usr/bin/env python3
"""Pull Google Workspace audit activities from the Admin SDK Reports API and send them to a Sophos
NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Google Workspace's audit logs (sign-ins, admin changes, OAuth grants, SAML, Drive and Chrome) reach
other tools through the Reports API, which is pull only, so this script polls one application at a
time with a service account that has domain-wide delegation and the read-only audit scope:

  GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}
      (startTime, endTime, maxResults, pageToken, customerId)

Each activity can hold several events. The bridge sends one record per event: the activity with
"google_workspace_record": "activity" first and only that event in "events", plus "params", the
event's parameters as one object keyed by name, so the library parsers in
parsers/google/google-workspace-audit-logs can read them by name.

The service account signs its own token request (RS256), so the bridge carries a small RSA signer
built on the standard library. The request and response shapes follow Google's Reports API
reference. Configuration comes from environment variables (see README.md). A window's end only
moves after HTTP Ingest accepted every record in it. --dry-run prints what would be sent and
changes nothing.
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
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("google_workspace_audit_bridge")
USER_AGENT = f"sophos-xdr-siem-library-google-workspace-audit-bridge/{__version__}"
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
RECORD_KEY = "google_workspace_record"
SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
DEFAULT_APPS = "login,admin,token,saml,chrome,drive"
APP_NAME = re.compile(r"^[a-z][a-z_]{1,39}$")
# The Reports API keeps audit data for 180 days.
RETENTION_SECONDS = 180 * 86400
JWT_LIFETIME = 3600
# A window ends this long before now, so a clock a little ahead of Google's never asks for the future.
END_MARGIN_SECONDS = 60


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


def _service_account(env: dict) -> dict:
    """The service account's JSON key, from a file or from the variable itself. Neither the key
    nor the file's text ever reaches an error or the log."""
    path = _env(env, "GWS_SERVICE_ACCOUNT_KEY_FILE")
    text = _env(env, "GWS_SERVICE_ACCOUNT_KEY")
    if path and text:
        raise BridgeError("set GWS_SERVICE_ACCOUNT_KEY_FILE or GWS_SERVICE_ACCOUNT_KEY, not both")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(1024 * 1024)
        except OSError as e:
            raise BridgeError(f"GWS_SERVICE_ACCOUNT_KEY_FILE couldn't be read ({type(e).__name__})") from None
    if not text:
        raise BridgeError("GWS_SERVICE_ACCOUNT_KEY_FILE (the service account's JSON key file) is required")
    where = "GWS_SERVICE_ACCOUNT_KEY_FILE" if path else "GWS_SERVICE_ACCOUNT_KEY"
    try:
        key = json.loads(text)
    except ValueError:
        raise BridgeError(f"{where} is not a JSON key file") from None
    if not isinstance(key, dict) or key.get("type") != "service_account":
        raise BridgeError(f"{where} is not a service account key (its type must be service_account)")
    email, pem = key.get("client_email"), key.get("private_key")
    if not (isinstance(email, str) and "@" in email and isinstance(pem, str)):
        raise BridgeError(f"{where} has no client_email or private_key")
    return {"client_email": email, "private_key": pem}


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "GWS_API_URL", "https://admin.googleapis.com") or "").rstrip("/"),
        "token_url": _env(env, "GWS_TOKEN_URL", "https://oauth2.googleapis.com/token"),
        "admin_email": _env(env, "GWS_ADMIN_EMAIL"),
        "customer_id": _env(env, "GWS_CUSTOMER_ID"),
        "apps": [a.strip() for a in (_env(env, "GWS_APPLICATIONS", DEFAULT_APPS) or "").split(",") if a.strip()],
        "page_size": _number(env, "GWS_PAGE_SIZE", "1000", low=1, high=1000),
        "token_overlap_seconds": _number(env, "GWS_TOKEN_OVERLAP_SECONDS", "14400"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "google_workspace_audit_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["admin_email"] or not re.fullmatch(r"[^@\s]+@[^@\s]+", cfg["admin_email"]):
        raise BridgeError("GWS_ADMIN_EMAIL is required: the administrator the service account acts as")
    if cfg["customer_id"] and not re.fullmatch(r"[A-Za-z0-9_]{1,64}", cfg["customer_id"]):
        raise BridgeError("GWS_CUSTOMER_ID must be the customer ID from the Admin console, such as C03az79cb")
    if not cfg["apps"]:
        raise BridgeError("GWS_APPLICATIONS must name at least one application, such as login")
    bad = [a for a in cfg["apps"] if not APP_NAME.match(a)]
    if bad:
        raise BridgeError("GWS_APPLICATIONS takes Reports API application names in lowercase, such as login,admin,token")
    cfg["apps"] = list(dict.fromkeys(cfg["apps"]))
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["api_url"], "GWS_API_URL")
    _require_https(cfg["api_url"], "GWS_API_URL")
    _refuse_user_info(cfg["token_url"], "GWS_TOKEN_URL")
    _require_https(cfg["token_url"], "GWS_TOKEN_URL")
    if cfg["ingest_url"]:
        _refuse_user_info(cfg["ingest_url"], "NGSIEM_INGEST_URL")
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    cfg["service_account"] = _service_account(env)
    # Parse the key now, so a bad key stops the bridge before it reads anything.
    cfg["rsa_key"] = rsa_private_key(cfg["service_account"]["private_key"])
    return cfg


# ---------------------------------------------------------------- RS256 signing

_RSA_OID = bytes.fromhex("2a864886f70d010101")
# DER DigestInfo prefix for SHA-256 (RFC 8017, section 9.2, note 1).
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _der(data: bytes, pos: int, tag: int) -> tuple[int, int]:
    """The start and end of the value of the DER element at pos, which must have the given tag."""
    if pos + 2 > len(data) or data[pos] != tag:
        raise ValueError("unexpected DER element")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4 or pos + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("DER element runs past the end")
    return pos, pos + length


def _der_ints(data: bytes, pos: int, end: int, count: int) -> list[int]:
    out = []
    for _ in range(count):
        start, stop = _der(data, pos, 0x02)
        out.append(int.from_bytes(data[start:stop], "big", signed=True))
        pos = stop
        if pos > end:
            raise ValueError("DER integers run past their sequence")
    return out


def rsa_private_key(pem: str) -> dict:
    """Reads a PKCS #8 (BEGIN PRIVATE KEY, as Google issues) or PKCS #1 (BEGIN RSA PRIVATE KEY)
    PEM RSA key. Returns n, e, d and the CRT values."""
    try:
        m = re.search(r"-----BEGIN (RSA )?PRIVATE KEY-----(.+?)-----END \1?PRIVATE KEY-----", pem, re.S)
        if not m:
            raise ValueError("no PEM block")
        der = base64.b64decode("".join(m.group(2).split()), validate=True)
        if not m.group(1):
            # PrivateKeyInfo: SEQUENCE { INTEGER version, SEQUENCE { OID, NULL }, OCTET STRING key }
            start, end = _der(der, 0, 0x30)
            _, pos = _der(der, start, 0x02)
            alg_start, alg_end = _der(der, pos, 0x30)
            oid_start, oid_end = _der(der, alg_start, 0x06)
            if der[oid_start:oid_end] != _RSA_OID:
                raise ValueError("not an RSA key")
            key_start, key_end = _der(der, alg_end, 0x04)
            der = der[key_start:key_end]
        start, end = _der(der, 0, 0x30)
        _, n, e, d, p, q, dp, dq, qi = _der_ints(der, start, end, 9)
    except (ValueError, IndexError, TypeError):
        raise BridgeError("the service account's private_key is not a PEM RSA private key") from None
    if n.bit_length() < 1024 or n != p * q or e < 3:
        raise BridgeError("the service account's private_key is not a usable RSA key")
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qi": qi}


def rs256(key: dict, message: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), with the CRT, checked against the public key
    before it is used."""
    k = (key["n"].bit_length() + 7) // 8
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    m = int.from_bytes(em, "big")
    s1 = pow(m, key["dp"], key["p"])
    s2 = pow(m, key["dq"], key["q"])
    s = s2 + ((key["qi"] * (s1 - s2)) % key["p"]) * key["q"]
    if pow(s, key["e"], key["n"]) != m:
        raise BridgeError("signing the token request failed its own check")
    return s.to_bytes(k, "big")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def service_account_jwt(cfg: dict, now: float | None = None) -> str:
    """The signed JWT for the token request: the service account as issuer and the administrator
    as subject (domain-wide delegation), with only the read-only audit scope."""
    iat = int(time.time() if now is None else now)
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": cfg["service_account"]["client_email"], "sub": cfg["admin_email"], "scope": SCOPE,
              "aud": cfg["token_url"], "iat": iat, "exp": iat + JWT_LIFETIME}
    signing_input = _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64url(json.dumps(claims, separators=(",", ":")).encode())
    return signing_input + "." + _b64url(rs256(cfg["rsa_key"], signing_input.encode("ascii")))


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
    # Google asks for exponential backoff from about 5 seconds on 503 quota errors.
    return min(60.0, 5 * 2 ** attempt) + random.uniform(0, 1)


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


def _google_error(body: bytes) -> tuple[str, str]:
    """Google APIs answer {"error": {"code", "message", "status", "errors": [{"reason"}]}}, and the
    token endpoint {"error": "invalid_grant", "error_description"}. Returns (code, short message)."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "", "no message"
    if not isinstance(data, dict):
        return "", "no message"
    err = data.get("error")
    if isinstance(err, dict):
        reasons = [e.get("reason") for e in err.get("errors") or [] if isinstance(e, dict) and e.get("reason")]
        code = str(err.get("status") or (reasons[0] if reasons else "") or "")
        return code, str(err.get("message") or "")[:200] or "no message"
    return str(err or ""), str(data.get("error_description") or "")[:200] or "no message"


# ---------------------------------------------------------------- Google Reports API

class Reports:
    """Gets an access token with the service account's signed JWT (domain-wide delegation) and
    reads activities with 'Authorization: Bearer <token>'. Tokens last an hour; one is renewed a
    minute before it expires, and once more if Google refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": service_account_jwt(self.cfg)}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        try:
            _, raw = _request("POST", self.cfg["token_url"], headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                code, message = _google_error(e.body)
                raise BridgeError(f"Google refused the service account token request (HTTP {e.code} {code}): {message}; "
                                  "check that the key is current, that GWS_ADMIN_EMAIL is an administrator in the domain, "
                                  "and that domain-wide delegation grants the client ID the scope " + SCOPE) from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            lifetime = 3600.0
        self._token = token
        self._expires = time.monotonic() + max(60.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def activities(self, app: str, start: str, end: str, page_token: str | None) -> dict:
        params = {"startTime": start, "endTime": end, "maxResults": self.cfg["page_size"]}
        if page_token:
            params["pageToken"] = page_token
        if self.cfg["customer_id"]:
            params["customerId"] = self.cfg["customer_id"]
        url = (f"{self.cfg['api_url']}/admin/reports/v1/activity/users/all/applications/"
               f"{urllib.parse.quote(app, safe='')}?{urllib.parse.urlencode(params)}")
        what = f"{app} activities request"
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json"}
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
                break
            except HttpStatus as e:
                code, message = _google_error(e.body)
                if e.code == 401 and not renew:
                    continue
                if e.code in (401, 403):
                    raise BridgeError(f"Google refused the {what} (HTTP {e.code} {code}): {message}; check that "
                                      "GWS_ADMIN_EMAIL has the Reports administrator privilege and that the application "
                                      "is one the edition reports") from None
                if e.code in (400, 404):
                    raise BridgeError(f"Google rejected the {what} (HTTP {e.code} {code}): {message}") from None
                raise
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
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
    """id.time is RFC 3339 in UTC in Google's samples, such as 2026-10-13T01:10:04.218Z; the
    reference also calls it epoch seconds, so plain numbers work too."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    v = str(value or "").strip()
    if re.fullmatch(r"\d+(\.\d+)?", v):
        return float(v)
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _rfc3339(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _param_value(p: dict):
    for k in ("value", "multiValue", "intValue", "multiIntValue", "boolValue"):
        if k in p:
            return p[k]
    if isinstance(p.get("messageValue"), dict):
        return flat_params(p["messageValue"].get("parameter"))
    if isinstance(p.get("multiMessageValue"), list):
        return [flat_params(m.get("parameter")) for m in p["multiMessageValue"] if isinstance(m, dict)]
    return None


def flat_params(params) -> dict:
    """An event's parameters ([{"name", "value" | "multiValue" | "intValue" | "boolValue" |
    "messageValue" ...}]) as one object keyed by name, values as Google sends them."""
    out = {}
    for p in params if isinstance(params, list) else []:
        if isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"]:
            out[p["name"]] = _param_value(p)
    return out


def records(activity: dict) -> list[tuple[str, dict]]:
    """One (key, record) per event of the activity. The key identifies the event for dropping
    repeats: the activity's time and unique qualifier and the event's place in it."""
    ident = activity.get("id") if isinstance(activity.get("id"), dict) else {}
    events = [e for e in activity.get("events") or [] if isinstance(e, dict)]
    out = []
    for i, event in enumerate(events):
        rec = {RECORD_KEY: "activity"}
        for k, v in activity.items():
            if k == "events":
                rec["events"] = [event]
                rec["params"] = flat_params(event.get("parameters"))
            elif k not in (RECORD_KEY, "params"):
                rec[k] = v
        key = f"{ident.get('time')}|{ident.get('uniqueQualifier')}|{i}|{event.get('name')}"
        out.append((key, rec))
    return out


def collect_app(cfg: dict, app: str, state: dict, sink: Sink, save, client: Reports, now: float) -> int:
    """Reads one application from the end of the last window, less the overlap, to now. Google
    lists the newest first and some events arrive late (OAuth token events by up to a few hours),
    so each window starts before the last one ended and repeats are dropped by key. The window's
    end is saved only after every page of it was sent."""
    cur = state.setdefault("apps", {}).setdefault(app, {})
    overlap = cfg["token_overlap_seconds"] if app == "token" else cfg["overlap_seconds"]
    since = cur.get("until")
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, now - END_MARGIN_SECONDS) - overlap) if isinstance(since, (int, float)) else (now - cfg["lookback_hours"] * 3600)
    start = max(start, now - RETENTION_SECONDS + 600)
    seen = {k: t for k, t in (cur.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    cur["seen"] = seen
    end = now - END_MARGIN_SECONDS
    start = min(start, end - 1)
    start_s, end_s = _rfc3339(start), _rfc3339(end)
    sent, page_token = 0, None
    for _ in range(MAX_PAGES):
        data = client.activities(app, start_s, end_s, page_token)
        fresh = {}
        for activity in data.get("items") or []:
            if not isinstance(activity, dict):
                continue
            t = _parse_time((activity.get("id") or {}).get("time") if isinstance(activity.get("id"), dict) else None)
            for key, rec in records(activity):
                if key not in seen and key not in fresh:
                    fresh[key] = (t if t is not None else now, rec)
        if fresh:
            sink.send([rec for _, rec in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({key: t for key, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    else:
        LOG.warning("%s: stopped after %d pages; the next run reads the same window again", app, MAX_PAGES)
        LOG.info("%s: %d sent", app, sent)
        return sent
    cur["until"] = end
    save()
    LOG.info("%s: %d sent", app, sent)
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
    client = Reports(cfg)
    now = time.time()
    count = sum(collect_app(cfg, app, state, sink, save, client, now) for app in cfg["apps"])
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
    ap = argparse.ArgumentParser(description="Send Google Workspace audit activities to Sophos NG-SIEM HTTP Ingest.")
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
