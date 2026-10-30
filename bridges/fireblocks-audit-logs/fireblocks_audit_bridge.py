#!/usr/bin/env python3
"""Pull Fireblocks audit log events from the Fireblocks API and send them to a Sophos NG-SIEM HTTP
Ingest integration, one JSON record per line. Python 3 standard library only.

Fireblocks has no syslog, and its audit log reaches other tools through one endpoint, which is
pull only and which Fireblocks names as the route for SIEM platforms:

  GET https://api.fireblocks.io/v1/management/audit_logs
      (startTime, endTime, order, pageSize, pageCursor, category)

Every request carries the API user's key in X-API-Key and a short-lived JWT, signed with the API
user's RSA private key (RS256), that names the request's URI and a fresh nonce. The bridge carries
a small RSA signer built on the standard library for that.

Each event goes to HTTP Ingest with "fireblocks_record": "audit_log" first, so the library parsers
in parsers/fireblocks/fireblocks-platform can tell it from a Fireblocks webhook. The request and
response shapes follow Fireblocks' API reference. Configuration comes from environment variables
(see README.md). A window's end only moves after HTTP Ingest accepted every event in it.
--dry-run prints what would be sent and changes nothing.
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
import uuid
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("fireblocks_audit_bridge")
USER_AGENT = f"sophos-xdr-siem-library-fireblocks-audit-bridge/{__version__}"
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
RECORD_KEY = "fireblocks_record"
AUDIT_PATH = "/v1/management/audit_logs"
# startTime may be at most a year before now.
RETENTION_SECONDS = 365 * 86400
# Fireblocks wants exp less than 30 seconds after iat.
JWT_LIFETIME = 29
# A window ends this long before now, so a clock a little ahead of Fireblocks' never asks for the future.
END_MARGIN_SECONDS = 60
# The audit log's 15 categories, as the API's category filter takes them.
CATEGORIES = ("Administration", "Whitelist", "Wallets", "Exchanges", "Settlements", "Policies", "Compliance",
              "Transactions", "Web3", "Developers", "Assets", "Keys", "Automation", "Orders", "Security")


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


def _api_url(value: str) -> str:
    """The API's scheme and host. Fireblocks gives base URLs with /v1, such as
    https://api.fireblocks.io/v1, so a trailing /v1 is taken off; any other path is refused."""
    url = value.rstrip("/")
    if url.endswith("/v1"):
        url = url[:-3]
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc or parts.path or parts.query or parts.fragment:
        raise BridgeError("FIREBLOCKS_API_URL must be the API's base URL, such as https://api.fireblocks.io")
    return url


def _secret_key(env: dict) -> str:
    """The API user's private key (the fireblocks_secret.key file), from a file or from the
    variable itself. Neither the key nor the file's text ever reaches an error or the log."""
    path = _env(env, "FIREBLOCKS_SECRET_KEY_FILE")
    text = _env(env, "FIREBLOCKS_SECRET_KEY")
    if path and text:
        raise BridgeError("set FIREBLOCKS_SECRET_KEY_FILE or FIREBLOCKS_SECRET_KEY, not both")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(1024 * 1024)
        except (OSError, UnicodeDecodeError) as e:
            raise BridgeError(f"FIREBLOCKS_SECRET_KEY_FILE couldn't be read ({type(e).__name__})") from None
    if not text:
        raise BridgeError("FIREBLOCKS_SECRET_KEY_FILE (the API user's private key, fireblocks_secret.key) is required")
    return text


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": _api_url(_env(env, "FIREBLOCKS_API_URL", "https://api.fireblocks.io")),
        "api_key": _env(env, "FIREBLOCKS_API_KEY"),
        "categories": [x.strip() for x in (_env(env, "FIREBLOCKS_CATEGORIES", "") or "").split(",") if x.strip()],
        "page_size": _number(env, "FIREBLOCKS_PAGE_SIZE", "500", low=1, high=500),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "fireblocks_audit_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=8760),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "600", high=86400),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["api_key"]:
        raise BridgeError("FIREBLOCKS_API_KEY is required: the API key (API user ID) from Developer center > API users")
    # The key goes in a request header, and http.client would put a header value it refuses in its error.
    if not re.fullmatch(r"[\x21-\x7e]{1,200}", cfg["api_key"]):
        raise BridgeError("FIREBLOCKS_API_KEY must be the API key as Fireblocks shows it, with no spaces or line breaks")
    bad = [x for x in cfg["categories"] if x not in CATEGORIES]
    if bad:
        raise BridgeError("FIREBLOCKS_CATEGORIES takes audit log categories as Fireblocks names them, such as "
                          "Administration,Security; leave it empty for every category")
    cfg["categories"] = list(dict.fromkeys(cfg["categories"]))
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _refuse_user_info(cfg["api_url"], "FIREBLOCKS_API_URL")
    _require_https(cfg["api_url"], "FIREBLOCKS_API_URL")
    if cfg["ingest_url"]:
        _refuse_user_info(cfg["ingest_url"], "NGSIEM_INGEST_URL")
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    # Parse the key now, so a bad key stops the bridge before it reads anything.
    cfg["rsa_key"] = rsa_private_key(_secret_key(env))
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
    """Reads a PKCS #8 (BEGIN PRIVATE KEY, as Fireblocks' automatic CSR gives) or PKCS #1 (BEGIN
    RSA PRIVATE KEY) PEM RSA key. Returns n, e, d and the CRT values."""
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
        raise BridgeError("the API user's private key is not a PEM RSA private key") from None
    # Fireblocks asks for a 4096-bit key in the CSR; anything under 2048 bits is refused.
    if n.bit_length() < 2048 or n != p * q or e < 3:
        raise BridgeError("the API user's private key is not a usable RSA key of 2048 bits or more")
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qi": qi}


def rs256(key: dict, message: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), with the CRT and blinding (so the time taken
    doesn't follow the key), checked against the public key before it is used."""
    k = (key["n"].bit_length() + 7) // 8
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    m = int.from_bytes(em, "big")
    n = key["n"]
    while True:
        r = random.SystemRandom().randrange(2, n - 1)
        try:
            r_inv = pow(r, -1, n)
            break
        except ValueError:
            continue
    blinded = (m * pow(r, key["e"], n)) % n
    s1 = pow(blinded, key["dp"], key["p"])
    s2 = pow(blinded, key["dq"], key["q"])
    s = (s2 + ((key["qi"] * (s1 - s2)) % key["p"]) * key["q"]) * r_inv % n
    if pow(s, key["e"], n) != m:
        raise BridgeError("signing the API request failed its own check")
    return s.to_bytes(k, "big")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def request_jwt(cfg: dict, uri: str, body: bytes = b"", now: float | None = None) -> str:
    """The JWT Fireblocks wants on every request: the request's path and query as uri, a nonce
    used once, iat and exp under 30 seconds apart, the API key as sub, and the hex SHA-256 of the
    raw body (an empty body for a GET)."""
    iat = int(time.time() if now is None else now)
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"uri": uri, "nonce": str(uuid.uuid4()), "iat": iat, "exp": iat + JWT_LIFETIME,
              "sub": cfg["api_key"], "bodyHash": hashlib.sha256(body).hexdigest()}
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
    return min(60.0, 2 * 2 ** attempt) + random.uniform(0, 1)


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
    headers is a dict, or a function that returns one, called for every attempt so each attempt
    can carry a freshly signed token."""
    for attempt in range(MAX_ATTEMPTS):
        hdrs = headers() if callable(headers) else headers
        req = urllib.request.Request(url, data=body, method=method, headers={**hdrs, "User-Agent": USER_AGENT})
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


def _fireblocks_error(body: bytes) -> tuple[str, str]:
    """Fireblocks answers errors with {"message": "...", "code": 2903}. Returns (code, short message)."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "", "no message"
    if not isinstance(data, dict):
        return "", "no message"
    return str(data.get("code") or ""), str(data.get("message") or "")[:200] or "no message"


# ---------------------------------------------------------------- Fireblocks audit log API

class AuditLogs:
    """Reads the audit log with X-API-Key and a JWT signed for each request."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def page(self, start_ms: int, end_ms: int, cursor: str | None) -> dict:
        params = [("startTime", str(start_ms)), ("endTime", str(end_ms)), ("order", "ASC"),
                  ("pageSize", str(self.cfg["page_size"]))]
        params += [("category", x) for x in self.cfg["categories"]]
        if cursor:
            params.append(("pageCursor", cursor))
        uri = f"{AUDIT_PATH}?{urllib.parse.urlencode(params)}"
        url = self.cfg["api_url"] + uri
        what = "audit log request"

        def headers():
            # A new JWT, with its own nonce, for every attempt.
            return {"X-API-Key": self.cfg["api_key"], "Authorization": f"Bearer {request_jwt(self.cfg, uri)}",
                    "Accept": "application/json"}

        try:
            _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
        except HttpStatus as e:
            code, message = _fireblocks_error(e.body)
            if e.code == 401:
                raise BridgeError(f"Fireblocks refused the {what} (HTTP 401 {code}): {message}; check that FIREBLOCKS_API_KEY "
                                  "and the private key belong to the same API user, that FIREBLOCKS_API_URL is the "
                                  "workspace's region, that the API user's IP allowlist includes this host, and that "
                                  "this machine's clock is right") from None
            if e.code == 403:
                raise BridgeError(f"Fireblocks refused the {what} (HTTP 403 {code}): {message}; the API user needs the "
                                  "Admin, Non-Signing Admin, Auditor, Security Admin or Security Auditor role") from None
            if e.code in (400, 404):
                raise BridgeError(f"Fireblocks rejected the {what} (HTTP {e.code} {code}): {message}") from None
            raise
        data = _json(raw, what)
        if not isinstance(data, dict) or not isinstance(data.get("data", []), list):
            raise BridgeError(f"{what} returned JSON without a data list")
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


def _event_ms(value) -> int | None:
    """An audit event's timestamp in epoch milliseconds. Fireblocks' API reference gives a number
    and its Audit Logs guide ISO 8601, so both are read; a number under 10^11 counts as seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
    else:
        v = str(value or "").strip()
        if re.fullmatch(r"\d+(\.\d+)?", v):
            number = float(v)
        else:
            try:
                dt = _fromisoformat(v)
            except ValueError:
                return None
            return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp() * 1000)
    return int(number if number >= 1e11 else number * 1000)


def _key(event: dict) -> str:
    """What identifies an event for dropping repeats: its id, or the whole event when it has none."""
    eid = event.get("id")
    if isinstance(eid, (str, int)) and str(eid):
        return str(eid)
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def collect(cfg: dict, state: dict, sink: Sink, save, client: AuditLogs, now: float) -> int:
    """Reads the audit log from the end of the last window, less the overlap, to now, oldest first.
    Each window starts before the last one ended, so an event recorded late still arrives, and
    repeats are dropped by event ID. The window's end is saved only after every page was sent."""
    cur = state.setdefault("audit_log", {})
    now_ms = int(now * 1000)
    end = now_ms - END_MARGIN_SECONDS * 1000
    since = cur.get("until")
    # A saved end later than now (the clock went back) counts as now.
    if isinstance(since, int) and not isinstance(since, bool):
        start = min(since, end) - cfg["overlap_seconds"] * 1000
    else:
        start = now_ms - int(cfg["lookback_hours"] * 3600 * 1000)
    # Fireblocks takes a startTime no more than a year back; stay a day inside that.
    start = max(start, now_ms - (RETENTION_SECONDS - 86400) * 1000)
    start = min(start, end - 1)
    seen = {k: t for k, t in (cur.get("seen") or {}).items()
            if isinstance(t, int) and not isinstance(t, bool) and t >= start - 60000}
    cur["seen"] = seen
    sent, cursor = 0, None
    for _ in range(MAX_PAGES):
        data = client.page(start, end, cursor)
        fresh = {}
        for event in data.get("data") or []:
            if not isinstance(event, dict):
                continue
            key = _key(event)
            if key in seen or key in fresh:
                continue
            rec = {RECORD_KEY: "audit_log", **{k: v for k, v in event.items() if k != RECORD_KEY}}
            t = _event_ms(event.get("timestamp"))
            fresh[key] = (t if t is not None else end, rec)
        if fresh:
            sink.send([rec for _, rec in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({key: t for key, (t, _) in fresh.items()})
            sent += len(fresh)
            save()
        # next is the cursor; cursor is its deprecated copy.
        cursor = data.get("next") or data.get("cursor")
        if not cursor:
            break
        if not isinstance(cursor, str):
            raise BridgeError("audit log request returned a next cursor that is not text")
    else:
        LOG.warning("audit log: stopped after %d pages; the next run reads the same window again", MAX_PAGES)
        LOG.info("audit log: %d sent", sent)
        return sent
    cur["until"] = end
    save()
    LOG.info("audit log: %d sent", sent)
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
    ap = argparse.ArgumentParser(description="Send Fireblocks audit log events to Sophos NG-SIEM HTTP Ingest.")
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
