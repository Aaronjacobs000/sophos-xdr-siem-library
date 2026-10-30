#!/usr/bin/env python3
"""Receive Huntress, ConnectWise ScreenConnect, Hudu, Autotask, Juniper Mist, FortiCNAPP and
Fireblocks webhooks, check that each one came from the vendor, and forward the body to a Sophos
NG-SIEM HTTP Ingest integration with the Authorization: Bearer header that all but Mist can't add.
Python 3 standard library only.

  POST /huntress                 Svix signature (HMAC-SHA256 over id, timestamp and body)
  POST /autotask                 X-Hook-Signature (HMAC-SHA1 over the body, base64)
  POST /hudu/<secret>            no signing option: a long random secret in the path
  POST /screenconnect/<secret>   no signing option: a long random secret in the path
  POST /mist                     X-Mist-Signature-v2 (HMAC-SHA256 over the body, hex)
  POST /forticnapp/<secret>      no signing option: a long random secret in the path
  POST /fireblocks               Fireblocks-Webhook-Signature (RS512 detached JWS, keys from
                                 Fireblocks' JWKS)

Mist sends several events in one body, {"topic": ..., "events": [...]}, for most topics. With
BRIDGE_SPLIT_BATCHES=1 the relay forwards each event as its own record, in the same envelope with
one event, so HTTP Ingest stores one record per event.

Configuration comes from environment variables (see README.md). Listen on 127.0.0.1 behind a
reverse proxy that terminates TLS. --dry-run checks deliveries and prints each body instead of
forwarding it.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import http.client
import io
import json
import logging
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "0.1.0"
LOG = logging.getLogger("webhook_relay")
USER_AGENT = f"sophos-xdr-siem-library-webhook-relay/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the relay uses"}
# The opener doesn't follow these (see _NoRedirect), so the log names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 5
# Svix's own libraries reject a timestamp more than five minutes from the receiver's clock.
SVIX_TOLERANCE_SECONDS = 300
MIN_SECRET_CHARS = 32
AUTOTASK_MAX_KEY_CHARS = 64
LOOPBACK = ("127.0.0.1", "localhost", "::1")
# Each vendor's path and how its deliveries are checked.
VENDORS = {
    "huntress": "svix",
    "autotask": "autotask",
    "hudu": "path",
    "screenconnect": "path",
    "mist": "mist",
    "forticnapp": "path",
    "fireblocks": "fireblocks",
}
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
# A sender gets this long in all, however slowly it sends, for its request line, headers and body.
REQUEST_SECONDS = 30
LINE_BREAK = re.compile(rb"\r\n|\r|\n")
# Deepest JSON nesting the relay forwards; the vendors' webhooks nest a few levels. Some Pythons
# raise RecursionError on deep nesting and some (3.14) parse 100,000 levels, so the relay counts.
MAX_JSON_DEPTH = 64
# Fireblocks' signing keys: its JWKS says to cache them an hour. A key ID the relay doesn't know
# fetches the set again, at most once a minute, and the last good set is used for up to a day while
# the JWKS endpoint can't be reached.
JWKS_MAX_AGE = 3600
JWKS_RETRY_SECONDS = 60
JWKS_STALE_SECONDS = 86400
JWKS_MAX_BYTES = 1024 * 1024
JWKS_TIMEOUT = 10
MIN_RSA_BITS = 2048
# DER DigestInfo prefix for SHA-512 (RFC 8017, section 9.2, note 1).
SHA512_PREFIX = bytes.fromhex("3051300d060960864801650304020305000440")
B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class RelayError(Exception):
    """A configuration problem that stops the relay before it listens."""


class BodyError(Exception):
    """A delivery body the relay can't read, refused with 400."""


class KeysUnavailable(Exception):
    """The relay can't check a Fireblocks signature right now: it has no current signing keys, or
    the key a delivery names may be a new one it can't fetch yet. Answered with 503, so Fireblocks
    sends the delivery again."""


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


def _require_https(url: str, what: str) -> None:
    """The ingest key travels with every request, so only https is allowed (plain http to this
    machine is allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK):
        return
    raise RelayError(f"{what} must be an https URL")


def _refuse_user_info(url: str, what: str) -> None:
    """urllib sends no user name or password from a URL, and the host isn't found with them in
    it, so a URL setting that has them can never work."""
    if "@" in urllib.parse.urlsplit(url).netloc:
        raise RelayError(f"{what} has a user name or password before the host (user:pass@), which the relay "
                         "can't use; remove it")


def _svix_key(secret: str) -> bytes:
    """Huntress shows the signing secret as whsec_<base64>; the HMAC key is the decoded part."""
    raw = secret[len("whsec_"):] if secret.startswith("whsec_") else secret
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise RelayError("HUNTRESS_SIGNING_SECRET is not the whsec_ value from View Signing Secret") from None
    if len(key) < 16:
        raise RelayError("HUNTRESS_SIGNING_SECRET is too short to be a Huntress signing secret")
    return key


def _shared_secret(env: dict, name: str, max_chars: int | None = None) -> str | None:
    value = _env(env, name)
    if value is None:
        return None
    if len(value) < MIN_SECRET_CHARS:
        raise RelayError(f"{name} must be at least {MIN_SECRET_CHARS} characters; generate one with "
                         "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'")
    if max_chars and len(value) > max_chars:
        raise RelayError(f"{name} can be at most {max_chars} characters")
    if not re.fullmatch(r"[\x21-\x7e]+", value):
        raise RelayError(f"{name} must be printable ASCII without spaces")
    return value


def _jwks_url(env: dict) -> str | None:
    """FIREBLOCKS_JWKS_URL: the JWKS endpoint for the workspace's environment. The relay trusts
    whatever keys it serves, so only https is taken."""
    url = _env(env, "FIREBLOCKS_JWKS_URL")
    if url is None:
        return None
    _refuse_user_info(url, "FIREBLOCKS_JWKS_URL")
    _require_https(url, "FIREBLOCKS_JWKS_URL")
    return url


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    try:
        cfg = {
            "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
            "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
            "host": _env(env, "BRIDGE_LISTEN_HOST", "127.0.0.1"),
            "port": int(_env(env, "BRIDGE_LISTEN_PORT", "8080")),
            "max_body": int(_env(env, "BRIDGE_MAX_BODY_BYTES", "524288")),
            "deadline": float(_env(env, "BRIDGE_FORWARD_DEADLINE", "8")),
            "max_connections": int(_env(env, "BRIDGE_MAX_CONNECTIONS", "32")),
        }
    except ValueError:
        raise RelayError("BRIDGE_LISTEN_PORT, BRIDGE_MAX_BODY_BYTES, BRIDGE_FORWARD_DEADLINE and BRIDGE_MAX_CONNECTIONS "
                         "must be numbers") from None
    secrets = {
        "huntress": _svix_key(_env(env, "HUNTRESS_SIGNING_SECRET")) if _env(env, "HUNTRESS_SIGNING_SECRET") else None,
        "autotask": _shared_secret(env, "AUTOTASK_SECRET_KEY", AUTOTASK_MAX_KEY_CHARS),
        "hudu": _shared_secret(env, "HUDU_PATH_SECRET"),
        "screenconnect": _shared_secret(env, "SCREENCONNECT_PATH_SECRET"),
        "mist": _shared_secret(env, "MIST_WEBHOOK_SECRET"),
        "forticnapp": _shared_secret(env, "FORTICNAPP_PATH_SECRET"),
        "fireblocks": _jwks_url(env),
    }
    cfg["vendors"] = {name: secret for name, secret in secrets.items() if secret}
    if not cfg["vendors"]:
        raise RelayError("set at least one of HUNTRESS_SIGNING_SECRET, AUTOTASK_SECRET_KEY, HUDU_PATH_SECRET, "
                         "SCREENCONNECT_PATH_SECRET, MIST_WEBHOOK_SECRET, FORTICNAPP_PATH_SECRET and FIREBLOCKS_JWKS_URL")
    cfg["split_batches"] = _flag(env, "BRIDGE_SPLIT_BATCHES", False)
    if cfg["ingest_url"]:
        _refuse_user_info(cfg["ingest_url"], "NGSIEM_INGEST_URL")
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    # The key goes in a request header, and http.client would put a header value it refuses in its error.
    if cfg["ingest_key"] and re.search(r"[\x00-\x1f\x7f]", cfg["ingest_key"]):
        raise RelayError("NGSIEM_INGEST_KEY has a line break or another control character")
    if not 0 <= cfg["port"] <= 65535:
        raise RelayError("BRIDGE_LISTEN_PORT must be between 0 and 65535")
    if cfg["max_body"] < 1024:
        raise RelayError("BRIDGE_MAX_BODY_BYTES must be at least 1024")
    if not 0 < cfg["deadline"] <= 60:
        raise RelayError("BRIDGE_FORWARD_DEADLINE must be more than 0 and at most 60 seconds")
    if not 1 <= cfg["max_connections"] <= 1000:
        raise RelayError("BRIDGE_MAX_CONNECTIONS must be between 1 and 1000")
    return cfg


# ---------------------------------------------------------------- authenticity checks

def verify_svix(key: bytes, headers, body: bytes, now: float | None = None) -> str | None:
    """Huntress signs with Svix: base64 HMAC-SHA256 of "<id>.<timestamp>.<body>" in a
    space-separated list of "v1,<signature>". Svix also sends the same headers with a webhook-
    prefix instead of svix-. Returns None when the delivery checks out, else the reason."""
    prefix = "svix-" if headers.get("svix-id") else "webhook-"
    msg_id, stamp, sigs = (headers.get(prefix + h) for h in ("id", "timestamp", "signature"))
    if not (msg_id and stamp and sigs):
        return "missing signature headers"
    try:
        sent = int(stamp)
    except ValueError:
        return "timestamp is not a number"
    try:
        skew = abs((time.time() if now is None else now) - sent)
    except OverflowError:
        # Too large for a float, so far outside the window.
        skew = float("inf")
    if skew > SVIX_TOLERANCE_SECONDS:
        return "timestamp is more than 5 minutes from this machine's clock"
    signed = f"{msg_id}.{stamp}.".encode("utf-8") + body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest())
    matched = False
    for entry in sigs.split():
        version, _, sig = entry.partition(",")
        # Compare every v1 entry so the time taken doesn't depend on which one matched.
        if version == "v1" and hmac.compare_digest(sig.encode("utf-8"), expected):
            matched = True
    return None if matched else "signature does not match"


def verify_autotask(key: str, headers, body: bytes) -> str | None:
    """Autotask sends X-Hook-Signature: sha1=<base64 HMAC-SHA1 of the body with the SecretKey>."""
    given = (headers.get("X-Hook-Signature") or "").strip()
    if not given:
        return "missing X-Hook-Signature"
    if given[:5].lower() == "sha1=":
        given = given[5:]
    expected = base64.b64encode(hmac.new(key.encode("utf-8"), body, hashlib.sha1).digest())
    return None if hmac.compare_digest(given.encode("utf-8"), expected) else "signature does not match"


def verify_mist(key: str, headers, body: bytes) -> str | None:
    """Mist sends X-Mist-Signature-v2: HMAC-SHA256 of the body with the webhook's secret, in hex
    (and X-Mist-Signature with SHA-1, which the relay doesn't use)."""
    given = (headers.get("X-Mist-Signature-v2") or "").strip().lower()
    if not given:
        return "missing X-Mist-Signature-v2"
    expected = hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return None if hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8")) else "signature does not match"


def path_secret_matches(expected: str, given: str) -> bool:
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


def _b64url_decode(text: str) -> bytes:
    if not B64URL.match(text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FireblocksKeys:
    """Fireblocks' webhook signing keys, read from its JWKS endpoint ({"keys": [{"kty": "RSA",
    "kid", "use": "sig", "alg": "RS512", "n", "e"}]}) and cached. Shared by every request thread."""

    def __init__(self, url: str):
        self.url = url
        self.lock = threading.Lock()
        self.keys: dict = {}
        self.fetched = None  # monotonic time of the last good fetch
        self.tried = None    # monotonic time of the last fetch, good or not
        self.opener = urllib.request.build_opener(_NoRedirect)

    def _fetch(self) -> dict:
        req = urllib.request.Request(self.url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
        try:
            with self.opener.open(req, timeout=JWKS_TIMEOUT) as resp:
                raw = resp.read(JWKS_MAX_BYTES + 1)
        except urllib.error.HTTPError as e:
            e.close()
            # A redirect is refused like any other answer that isn't the key set.
            raise ValueError(f"HTTP {e.code}") from None
        if len(raw) > JWKS_MAX_BYTES:
            raise ValueError("the key set is too large")
        data = json.loads(raw)
        keys = {}
        for k in data.get("keys") or [] if isinstance(data, dict) else []:
            if not isinstance(k, dict) or k.get("kty") != "RSA" or k.get("use", "sig") != "sig" or k.get("alg", "RS512") != "RS512":
                continue
            kid, n, e = k.get("kid"), k.get("n"), k.get("e")
            if not (isinstance(kid, str) and kid and isinstance(n, str) and isinstance(e, str)):
                continue
            try:
                n, e = int.from_bytes(_b64url_decode(n), "big"), int.from_bytes(_b64url_decode(e), "big")
            except ValueError:
                continue
            if n.bit_length() >= MIN_RSA_BITS and e >= 3 and e % 2:
                keys[kid] = (n, e)
        if not keys:
            raise ValueError("no RS512 signing keys")
        return keys

    def get(self, kid: str):
        """The (n, e) for a key ID, or None when a key set fetched just now doesn't have it. Raises
        KeysUnavailable when the relay can't tell: it has no current key set, or the key ID is new
        and the set was fetched less than a minute ago."""
        with self.lock:
            now = time.monotonic()
            stale = self.fetched is None or now - self.fetched >= JWKS_MAX_AGE
            refreshed = False
            if (stale or kid not in self.keys) and (self.tried is None or now - self.tried >= JWKS_RETRY_SECONDS):
                self.tried = now
                try:
                    self.keys, self.fetched, refreshed = self._fetch(), now, True
                except (OSError, http.client.HTTPException, ValueError) as e:
                    # OSError covers URLError, timeouts (socket.timeout too, on Python 3.9) and
                    # connection errors.
                    reason = str(e) if isinstance(e, ValueError) and str(e).startswith(("HTTP ", "no RS512", "the key set")) \
                        else type(e).__name__
                    LOG.warning("fireblocks: couldn't fetch the signing keys from %s (%s)", _host(self.url), reason)
            if self.fetched is None or now - self.fetched >= JWKS_STALE_SECONDS:
                raise KeysUnavailable("no current Fireblocks signing keys")
            if kid in self.keys:
                return self.keys[kid]
            if refreshed:
                return None
            raise KeysUnavailable("a signing key the relay hasn't fetched yet")


def verify_fireblocks(keys: FireblocksKeys, headers, body: bytes) -> str | None:
    """Fireblocks signs each delivery with a detached JWS in Fireblocks-Webhook-Signature,
    "<header>..<signature>": RS512 (RSASSA-PKCS1-v1_5 with SHA-512) over "<header>.<the body in
    base64url>", with the key named by the header's kid in Fireblocks' JWKS."""
    given = (headers.get("Fireblocks-Webhook-Signature") or "").strip()
    if not given:
        return "missing Fireblocks-Webhook-Signature"
    parts = given.split(".")
    if len(parts) != 3 or parts[1] != "" or not parts[0] or not parts[2]:
        return "Fireblocks-Webhook-Signature is not a detached JWS"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        sig = _b64url_decode(parts[2])
    except ValueError:
        return "Fireblocks-Webhook-Signature can't be read"
    if not isinstance(header, dict) or header.get("alg") != "RS512":
        return "the signature is not RS512"
    if "crit" in header or header.get("b64", True) is not True:
        return "the signature uses JWS options Fireblocks doesn't"
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > 256:
        return "the signature names no key"
    key = keys.get(kid)
    if key is None:
        return "the signature names a key that isn't one of Fireblocks' signing keys"
    n, e = key
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(sig, "big")
    if len(sig) != k or s >= n:
        return "signature does not match"
    t = SHA512_PREFIX + hashlib.sha512(parts[0].encode("ascii") + b"." + base64.urlsafe_b64encode(body).rstrip(b"=")).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return None if hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), expected) else "signature does not match"


# ---------------------------------------------------------------- forwarding

def _load_json(body: bytes):
    """json.loads, with BodyError for JSON nested deeper than MAX_JSON_DEPTH. ValueError for a
    body that isn't JSON."""
    try:
        data = json.loads(body)
    except RecursionError:
        raise BodyError("its JSON is nested too deeply") from None
    containers = [(data, 1)] if isinstance(data, (dict, list)) else []
    while containers:
        value, depth = containers.pop()
        if depth > MAX_JSON_DEPTH:
            raise BodyError("its JSON is nested too deeply")
        children = value.values() if isinstance(value, dict) else value
        containers.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return data


def one_record(body: bytes) -> tuple[bytes, str]:
    """HTTP Ingest reads each line as a separate record, and the library parsers expect one
    record per delivery. A body with no line break inside goes on byte for byte. Otherwise JSON
    gets its line breaks turned into spaces (JSON only allows them between values, so the data
    doesn't change), and text gets each line break replaced with the two characters \\n."""
    try:
        is_json = isinstance(_load_json(body), dict)
    except ValueError:
        is_json = False
    ctype = "application/json" if is_json else "text/plain"
    core = body.strip(b"\r\n")
    if b"\n" not in core and b"\r" not in core:
        return body, ctype
    return LINE_BREAK.sub(b" " if is_json else b"\\\\n", core), ctype


def split_batch(body: bytes) -> tuple[bytes, int] | None:
    """A Mist body, {"topic": ..., "events": [...]}, with two or more events, as one line per
    event, each in the same envelope with only that event, and the number of lines. None for any
    other body, which goes on as one record."""
    try:
        data = _load_json(body)
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("events"), list) or len(data["events"]) < 2:
        return None
    rest = {k: v for k, v in data.items() if k != "events"}
    lines = [json.dumps({**rest, "events": [e]}, separators=(",", ":"), ensure_ascii=False) for e in data["events"]]
    return "\n".join(lines).encode("utf-8"), len(lines)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the bearer token to another URL, so it is treated as a refusal."""

    def redirect_request(self, *args, **kwargs):
        return None


def _host(url: str) -> str:
    """The host and port, for log lines and errors. A user name or password in the URL is a
    credential, so it shows as [redacted]."""
    _, at, host = urllib.parse.urlsplit(url).netloc.rpartition("@")
    return f"[redacted]@{host}" if at else host


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
    return min(4.0, 0.5 * 2 ** attempt) + random.uniform(0, 0.25)


class Relay:
    """Routes, checks and forwards deliveries. One instance serves every request thread."""

    def __init__(self, cfg: dict, dry_run: bool = False, out=None):
        self.cfg, self.dry_run = cfg, dry_run
        self.out = out or sys.stdout
        self.out_lock = threading.Lock()
        self.opener = urllib.request.build_opener(_NoRedirect)
        url = cfg["vendors"].get("fireblocks")
        self.fireblocks_keys = FireblocksKeys(url) if url else None
        if not dry_run and not (cfg["ingest_url"] and cfg["ingest_key"]):
            raise RelayError("NGSIEM_INGEST_URL and NGSIEM_INGEST_KEY are required unless --dry-run is set")

    def route(self, raw_path: str) -> str | None:
        """Returns the vendor for a path, or None for an unknown path, a vendor that isn't
        configured, or a wrong path secret (all look the same to the sender)."""
        parts = urllib.parse.urlsplit(raw_path).path.strip("/").split("/")
        vendor = parts[0]
        if vendor not in self.cfg["vendors"]:
            return None
        if VENDORS[vendor] == "path":
            ok = len(parts) == 2 and path_secret_matches(self.cfg["vendors"][vendor], parts[1])
            return vendor if ok else None
        return vendor if len(parts) == 1 else None

    def verify(self, vendor: str, headers, body: bytes) -> str | None:
        kind = VENDORS[vendor]
        if kind == "svix":
            return verify_svix(self.cfg["vendors"][vendor], headers, body)
        if kind == "autotask":
            return verify_autotask(self.cfg["vendors"][vendor], headers, body)
        if kind == "mist":
            return verify_mist(self.cfg["vendors"][vendor], headers, body)
        if kind == "fireblocks":
            return verify_fireblocks(self.fireblocks_keys, headers, body)
        return None  # path secret, already checked in route()

    def forward(self, vendor: str, body: bytes) -> tuple[int, str]:
        """Posts one delivery to HTTP Ingest. Returns the status and text for the sender:
        200 when HTTP Ingest took it, 502 when it refused it, 503 when it stayed unavailable
        until the deadline, so the sender's own retries take over. With BRIDGE_SPLIT_BATCHES, a
        Mist batch goes as one record per event, in one request."""
        split = split_batch(body) if self.cfg.get("split_batches") and VENDORS[vendor] == "mist" else None
        if split:
            record, ctype = split[0], "application/json"
            LOG.info("%s: split a batch of %d events", vendor, split[1])
        else:
            record, ctype = one_record(body)
        if self.dry_run:
            with self.out_lock:
                self.out.write(record.decode("utf-8", "replace") + "\n")
                self.out.flush()
            return 200, "checked (dry run, not forwarded)"
        url, host = self.cfg["ingest_url"], _host(self.cfg["ingest_url"])
        headers = {"Authorization": f"Bearer {self.cfg['ingest_key']}", "Content-Type": ctype, "User-Agent": USER_AGENT}
        deadline = time.monotonic() + self.cfg["deadline"]
        for attempt in range(MAX_ATTEMPTS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            req = urllib.request.Request(url, data=record, method="POST", headers=headers)
            try:
                with self.opener.open(req, timeout=remaining) as resp:
                    resp.read()
                return 200, "forwarded"
            except urllib.error.HTTPError as e:
                # Close the error response now so its socket is released.
                e.close()
                if e.code in REDIRECT_STATUS:
                    LOG.error("%s: HTTP Ingest at %s answered with a redirect (HTTP %s), which the relay refuses so the "
                              "token never goes to another URL; check NGSIEM_INGEST_URL. Not retried", vendor, host, e.code)
                    return 502, "HTTP Ingest refused the delivery"
                if e.code in UNSUPPORTED_STATUS:
                    LOG.error("%s: HTTP Ingest at %s answered HTTP %s: %s, and a retry won't change that; check "
                              "NGSIEM_INGEST_URL. Not retried", vendor, host, e.code, UNSUPPORTED_STATUS[e.code])
                    return 502, "HTTP Ingest refused the delivery"
                if e.code not in RETRY_STATUS:
                    LOG.error("%s: HTTP Ingest at %s answered HTTP %s; not retried", vendor, host, e.code)
                    return 502, "HTTP Ingest refused the delivery"
                delay = _retry_delay(attempt, e.headers.get("Retry-After"))
                problem = f"HTTP {e.code}"
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.IncompleteRead) as e:
                # IncompleteRead: the connection closed before HTTP Ingest's reply was complete, so
                # it is tried again like any connection that fails partway.
                delay = _retry_delay(attempt, None)
                problem = type(e).__name__
            if attempt == MAX_ATTEMPTS - 1 or time.monotonic() + delay >= deadline:
                LOG.warning("%s: HTTP Ingest at %s failed (%s)", vendor, host, problem)
                break
            LOG.warning("%s: HTTP Ingest at %s failed (%s); retrying in %.1fs", vendor, host, problem, delay)
            time.sleep(delay)
        LOG.error("%s: HTTP Ingest at %s did not take the delivery in time; answered 503 so the sender retries", vendor, host)
        return 503, "HTTP Ingest unavailable, retry later"


# ---------------------------------------------------------------- HTTP server

class _DeadlineReader(io.RawIOBase):
    """Reads a request from a socket until a deadline. A read past it raises TimeoutError, which
    the request handler treats as a timed-out request and closes the connection."""

    def __init__(self, sock, deadline: float, per_read: float):
        self.sock, self.deadline, self.per_read = sock, deadline, per_read

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("the request took too long")
        self.sock.settimeout(min(left, self.per_read))
        return self.sock.recv_into(buffer)


def _safe_id(value: str | None) -> str:
    return value if value and SAFE_ID.match(value) else "-"


class Handler(BaseHTTPRequestHandler):
    relay: Relay = None
    # Seconds a sender may take over any one read. REQUEST_SECONDS bounds the whole request.
    timeout = 30

    def setup(self):
        super().setup()
        # A sender that trickles a byte at a time never hits the per-read timeout, so every read
        # waits at most the time left of REQUEST_SECONDS, and none starts after it.
        self.rfile.close()
        self.rfile = io.BufferedReader(_DeadlineReader(self.connection, time.monotonic() + REQUEST_SECONDS, self.timeout))

    def version_string(self) -> str:
        return "webhook-relay"

    def log_message(self, format, *args):
        # The default access log prints the request line, which holds the Hudu, ScreenConnect and
        # FortiCNAPP path secrets. The relay logs its own lines instead.
        pass

    def _reply(self, code: int, text: str) -> None:
        body = (text + "\n").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if code == 405:
            self.send_header("Allow", "POST")
        self.end_headers()
        self.wfile.write(body)

    def _not_allowed(self):
        self.close_connection = True
        self._reply(405, "use POST")

    do_GET = do_PUT = do_PATCH = do_DELETE = _not_allowed

    def do_POST(self):
        relay, peer = self.relay, self.client_address[0]
        vendor = relay.route(self.path)
        if vendor is None:
            self.close_connection = True
            LOG.warning("rejected a request from %s: unknown path, vendor not configured, or wrong path secret", peer)
            return self._reply(404, "not found")
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or not lengths:
            self.close_connection = True
            LOG.warning("%s: rejected a request from %s without Content-Length", vendor, peer)
            return self._reply(411, "Content-Length required")
        try:
            size = int(lengths[0]) if len(lengths) == 1 else -1
        except ValueError:
            size = -1
        if size < 0:
            self.close_connection = True
            return self._reply(400, "bad Content-Length")
        if size > relay.cfg["max_body"]:
            self.close_connection = True
            LOG.warning("%s: rejected %d bytes from %s, over BRIDGE_MAX_BODY_BYTES", vendor, size, peer)
            return self._reply(413, "body too large")
        body = self.rfile.read(size)
        self.connection.settimeout(self.timeout)
        if len(body) != size:
            self.close_connection = True
            return self._reply(400, "body shorter than Content-Length")
        try:
            problem = relay.verify(vendor, self.headers, body)
        except KeysUnavailable as e:
            LOG.warning("%s: answered 503 to a delivery from %s: %s", vendor, peer, e)
            return self._reply(503, "can't check the signature yet, retry later")
        if problem:
            LOG.warning("%s: rejected a delivery from %s: %s", vendor, peer, problem)
            return self._reply(401, "authenticity check failed")
        if not body.strip():
            return self._reply(400, "empty body")
        # Huntress asks receivers to log the delivery ID, to match View Delivery Attempts.
        delivery = f" (delivery {_safe_id(self.headers.get('svix-id') or self.headers.get('webhook-id'))})" if vendor == "huntress" else ""
        try:
            code, text = relay.forward(vendor, body)
        except BodyError as e:
            LOG.warning("%s: rejected a delivery from %s: %s", vendor, peer, e)
            return self._reply(400, "body can't be read")
        if code == 200:
            LOG.info("%s: %s %d bytes%s", vendor, "checked" if relay.dry_run else "forwarded", size, delivery)
        else:
            LOG.warning("%s: answered %d for %d bytes%s", vendor, code, size, delivery)
        self._reply(code, text)


class Server(ThreadingHTTPServer):
    """Handles at most max_connections requests at once, so slow or numerous senders can't use up
    the relay's threads and file descriptors. A connection past the limit gets 503 and is closed."""

    daemon_threads = True

    def __init__(self, address, handler, max_connections: int):
        super().__init__(address, handler)
        self.max_connections = max_connections
        self.slots = threading.BoundedSemaphore(max_connections)
        self.busy_logged = None

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self._busy(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def _busy(self, request):
        try:
            request.settimeout(1)
            request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
                            b"Content-Length: 5\r\nConnection: close\r\n\r\nbusy\n")
        except OSError:
            pass
        self.shutdown_request(request)
        now = time.monotonic()
        if self.busy_logged is None or now - self.busy_logged >= 60:
            self.busy_logged = now
            LOG.warning("all %d connections are in use; answering 503 to new ones", self.max_connections)

    def handle_error(self, request, client_address):
        # A sender that hangs up or stops mid-request isn't worth a traceback in the log.
        if isinstance(sys.exc_info()[1], OSError):
            LOG.debug("a connection from %s ended early", client_address[0])
            return
        super().handle_error(request, client_address)


def make_server(cfg: dict, dry_run: bool = False, out=None) -> ThreadingHTTPServer:
    relay = Relay(cfg, dry_run, out)
    handler = type("RelayHandler", (Handler,), {"relay": relay})
    return Server((cfg["host"], cfg["port"]), handler, cfg.get("max_connections", 32))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Relay Huntress, ScreenConnect, Hudu, Autotask, Juniper Mist, FortiCNAPP and Fireblocks webhooks to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="check deliveries and print each body; forward nothing")
    ap.add_argument("--log-level", default=_env(dict(os.environ), "BRIDGE_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "BRIDGE_DRY_RUN", False)
    try:
        cfg = load_config()
        server = make_server(cfg, dry_run)
    except RelayError as e:
        LOG.error("%s", e)
        return 1
    except OSError as e:
        LOG.error("can't listen on %s port %s: %s", cfg["host"], cfg["port"], e.strerror or type(e).__name__)
        return 1
    host, port = server.server_address[:2]
    LOG.info("listening on %s port %s for %s%s", host, port, ", ".join(sorted(cfg["vendors"])),
             " (dry run, nothing is forwarded)" if dry_run else "")
    if cfg["host"] not in LOOPBACK:
        LOG.warning("listening on %s: vendors must reach the relay only through a TLS proxy", cfg["host"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
