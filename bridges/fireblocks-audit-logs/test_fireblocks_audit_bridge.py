"""Unit tests for fireblocks_audit_bridge.py against a local mock server.

The mock serves the shapes in Fireblocks' API reference: GET /v1/management/audit_logs (startTime,
endTime, order, pageSize, pageCursor and repeated category; answering {"data": [AuditLogData],
"next", "cursor"} with next null on the last page, and {"message", "code"} on failure), which it
answers only for a request with the API key in X-API-Key and a JWT that verifies with the API
user's public key and names the request's URI, a nonce not used before, the API key and the hash
of the empty body. Plus a Sophos NG-SIEM HTTP Ingest endpoint. The tests make their own RSA keys.
No real service is called.

  python3 -m unittest discover -s bridges/fireblocks-audit-logs -p 'test_*.py' -v
"""
import base64
import contextlib
import gc
import gzip
import hashlib
import io
import json
import logging
import os
import random
import socket
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fireblocks_audit_bridge as c  # noqa: E402

API_KEY = "test-fireblocks-api-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
WORKSPACE = "52020d9c-c625-45e1-91e5-b4faa015b982"
EMPTY_BODY_HASH = hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------- test RSA keys, made here

def _probable_prime(n, rounds=24):
    if n < 4:
        return n in (2, 3)
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.Random(n)
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits, rng):
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if (n - 1) % 65537 and _probable_prime(n):
            return n


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + head + body


def _der_int(v):
    return _der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def make_key(seed=7, bits=1024):
    rng = random.Random(seed)
    e = 65537
    while True:
        p, q = _prime(bits // 2, rng), _prime(bits // 2, rng)
        if p != q and (p * q).bit_length() == bits:
            break
    n, phi = p * q, (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    pkcs1 = _der(0x30, b"".join(_der_int(x) for x in (0, n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))))
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    pkcs8 = _der(0x30, _der_int(0) + alg + _der(0x04, pkcs1))

    def pem(label, der):
        b64 = base64.b64encode(der).decode()
        return f"-----BEGIN {label}-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + f"\n-----END {label}-----\n"

    return {"n": n, "e": e, "pkcs8": pem("PRIVATE KEY", pkcs8), "pkcs1": pem("RSA PRIVATE KEY", pkcs1)}


# Fireblocks asks for a 4096-bit key; 2048 bits keeps the tests quick and is the smallest the bridge takes.
KEY = make_key(bits=2048)
OTHER_KEY = make_key(seed=11, bits=2048)
SMALL_KEY = make_key(seed=3, bits=1024)


def verify_jwt(jwt, key):
    """Checks an RS256 JWT against the public key; returns the claims or None."""
    try:
        head, body, sig = jwt.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        s = int.from_bytes(base64.urlsafe_b64decode(pad(sig)), "big")
        k = (key["n"].bit_length() + 7) // 8
        em = pow(s, key["e"], key["n"]).to_bytes(k, "big")
        t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(f"{head}.{body}".encode()).digest()
        if em != b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t:
            return None
        if json.loads(base64.urlsafe_b64decode(pad(head))) != {"alg": "RS256", "typ": "JWT"}:
            return None
        return json.loads(base64.urlsafe_b64decode(pad(body)))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------- audit events

def ms(dt):
    return int(dt.timestamp() * 1000)


def event(i, when, category="Administration", subject="User", name="Signed in", user="Pat Example", iso=False):
    t = ms(when)
    return {"id": f"evt-{i:04d}", "timestamp": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if iso else t,
            "createdAt": t + 150, "user": user, "subject": subject, "event": name, "category": category,
            "tenantId": WORKSPACE, "userId": "ad0da9d5-4343-449c-af29-549e2691e2c8"}


class Mock:
    def __init__(self):
        self.events = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.claims = []
        self.nonces = set()
        self.api_keys = []
        self.key = KEY
        self.cursor_field = "next"


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self):
        return self._send(401, {"message": "Unauthorized: JWT is not valid", "code": -7})

    def do_GET(self):
        m = self.mock
        parts = urllib.parse.urlsplit(self.path)
        if parts.path != "/v1/management/audit_logs":
            return self._send(404, {"message": "Not found", "code": 404})
        m.api_keys.append(self.headers.get("X-API-Key"))
        auth = self.headers.get("Authorization") or ""
        claims = verify_jwt(auth[len("Bearer "):], m.key) if auth.startswith("Bearer ") else None
        m.claims.append(claims)
        if self.headers.get("X-API-Key") != API_KEY or not claims:
            return self._refuse()
        # The JWT names this request, is used once, and lives under 30 seconds.
        if (claims.get("uri") != self.path or claims.get("sub") != API_KEY or claims.get("bodyHash") != EMPTY_BODY_HASH
                or claims.get("nonce") in m.nonces or not 0 < claims["exp"] - claims["iat"] < 30):
            return self._refuse()
        m.nonces.add(claims["nonce"])
        if m.codes:
            code = m.codes.pop(0)
            if code == 403:
                return self._send(403, {"message": "The API user's role is not permitted to read audit logs", "code": 1403})
            return self._send(code, {"message": "Too many requests", "code": code}, {"Retry-After": "0"})
        q = urllib.parse.parse_qs(parts.query)
        one = {k: v[0] for k, v in q.items()}
        m.queries.append({**one, "category": q.get("category", [])})
        start, end = int(one["startTime"]), int(one["endTime"])
        if end <= start or one.get("order") != "ASC":
            return self._send(400, {"message": "Invalid query", "code": 2903})
        rows = [e for e in m.events if start <= c._event_ms(e["timestamp"]) <= end]
        if q.get("category"):
            rows = [e for e in rows if e["category"] in q["category"]]
        rows.sort(key=lambda e: c._event_ms(e["timestamp"]))
        size = int(one.get("pageSize") or 200)
        cursor = one.get("pageCursor")
        pos = json.loads(base64.urlsafe_b64decode(cursor))["offset"] if cursor else 0
        chunk = rows[pos:pos + size]
        nxt = base64.urlsafe_b64encode(json.dumps({"offset": pos + size}).encode()).decode() if pos + size < len(rows) else None
        out = {"data": chunk}
        if m.cursor_field == "next":
            out.update({"next": nxt, "cursor": nxt})
        else:
            out["cursor"] = nxt
        return self._send(200, out)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._send(401, {})
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._send(code, {})
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        m.ingested.append({"headers": dict(self.headers), "raw": body.decode(),
                           "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
        self._send(200, {})


class Redirects:
    """A server that answers every request with a redirect to /elsewhere on itself, and records
    any request that follows one there. None should."""

    def __init__(self):
        self.code = 302
        self.redirected = []
        self.followed = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                seen = (self.command, self.path, dict(self.headers))
                if self.path.startswith("/elsewhere"):
                    outer.followed.append(seen)
                    self.send_response(200)
                else:
                    outer.redirected.append(seen)
                    self.send_response(outer.code)
                    self.send_header("Location", f"{outer.base}/elsewhere")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_POST = _answer

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Sized:
    """A server that answers every request with the given status and a body of the given size,
    and notes when the bridge has closed the connection."""

    def __init__(self, size, code=200):
        self.closed_by_bridge = closed = threading.Event()

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(size))
                self.end_headers()
                try:
                    self.wfile.write(b" " * size)
                    self.connection.recv(1)  # returns once the bridge closes the connection
                except ConnectionError:
                    pass  # the bridge closed it before reading everything, as a capped read should
                closed.set()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class CutShort:
    """A server that starts a chunked answer with the given status, then closes the connection
    partway through it, as a dropped connection would. With length, the answer has a Content-Length
    of that many bytes and fewer arrive. With whole_after, only the first answers are cut short."""

    def __init__(self, code=200, length=None, whole_after=None):
        self.requests = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests += 1
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                if whole_after is not None and outer.requests > whole_after:
                    self.send_header("Content-Length", str(len(b'{"whole": true}')))
                    self.end_headers()
                    self.wfile.write(b'{"whole": true}')
                    return
                if length is None:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self.wfile.write(b'100\r\n{"partial":')
                else:
                    # What arrives is valid JSON, so only the Content-Length shows it is short.
                    self.send_header("Content-Length", str(length))
                    self.end_headers()
                    self.wfile.write(b'{"partial": true}')
                self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("FIREBLOCKS_PAGE_SIZE", "page_size", 500, 100, int, 500),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 8760),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 600, 300, int, 86400),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"FIREBLOCKS_API_KEY": API_KEY, "FIREBLOCKS_SECRET_KEY": KEY["pkcs8"]}
    e.update(extra)
    return e


class BridgeTest(unittest.TestCase):
    def setUp(self):
        # A test that leaves a socket or file open fails: tearDown collects garbage and checks
        # for ResourceWarnings. Other warnings print as usual.
        self.leaks = []
        self._warnings = warnings.catch_warnings()
        self._warnings.__enter__()
        warnings.simplefilter("always", ResourceWarning)
        show = warnings.showwarning
        warnings.showwarning = lambda m, c_, *a, **k: self.leaks.append(str(m)) if issubclass(c_, ResourceWarning) else show(m, c_, *a, **k)
        self.mock = Mock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Handler,), {"mock": self.mock}))
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state.json")
        self.logbuf = io.StringIO()
        self.handler = logging.StreamHandler(self.logbuf)
        c.LOG.addHandler(self.handler)
        c.LOG.setLevel(logging.DEBUG)
        self._sleep = c.time.sleep
        c.time.sleep = lambda s: None
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        c.time.sleep = self._sleep
        c.LOG.removeHandler(self.handler)
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()
        gc.collect()
        self._warnings.__exit__(None, None, None)
        self.assertEqual(self.leaks, [], "a socket or file was left open")

    def cfg(self, **extra):
        e = base_env(NGSIEM_INGEST_URL=f"{self.base}/http-endpoint/v1/00000000-example-integration", NGSIEM_INGEST_KEY=INGEST_KEY,
                     BRIDGE_STATE_FILE=self.state, FIREBLOCKS_API_URL=self.base)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name, url in (("FIREBLOCKS_API_URL", "https://user:secret@api.example.com"),
                          ("FIREBLOCKS_API_URL", "https://secret@api.example.com"),
                          ("NGSIEM_INGEST_URL", "https://user:secret@ingest.example.com/v1"),
                          ("NGSIEM_INGEST_URL", "https://secret@ingest.example.com")):
            with self.subTest(name=name, url=url):
                with self.assertRaises(c.BridgeError) as caught:
                    self.cfg(**{name: url})
                self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                 "(user:pass@), which the bridge can't use; remove it")

    def test_pages_are_read_oldest_first_and_tagged(self):
        self.mock.events = [event(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(FIREBLOCKS_PAGE_SIZE="2")), 5)
        rows = self.sent()
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"fireblocks_record":"audit_log","id":"evt-0000","timestamp":'))
        self.assertEqual([r["id"] for r in rows], [f"evt-{i:04d}" for i in range(5)])
        self.assertEqual(rows[0]["subject"], "User")
        self.assertEqual(rows[0]["tenantId"], WORKSPACE)
        # Every page was read, oldest first, in one window.
        cursors = [q.get("pageCursor") for q in self.mock.queries]
        self.assertEqual(len(cursors), 3)
        self.assertIsNone(cursors[0])
        self.assertEqual(len({(q["startTime"], q["endTime"]) for q in self.mock.queries}), 1)
        self.assertEqual({(q["order"], q["pageSize"]) for q in self.mock.queries}, {("ASC", "2")})

    def test_every_request_carries_the_api_key_and_its_own_signed_jwt(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        c.run_once(self.cfg(FIREBLOCKS_PAGE_SIZE="1"))
        self.assertEqual(set(self.mock.api_keys), {API_KEY})
        self.assertEqual(len(self.mock.claims), 3)
        for claims in self.mock.claims:
            self.assertIsNotNone(claims, "the JWT signature didn't verify with the API user's public key")
            self.assertEqual(claims["sub"], API_KEY)
            self.assertEqual(claims["bodyHash"], EMPTY_BODY_HASH)
            self.assertEqual(claims["exp"] - claims["iat"], 29)
            self.assertTrue(claims["uri"].startswith("/v1/management/audit_logs?startTime="), claims["uri"])
        self.assertEqual(len({x["nonce"] for x in self.mock.claims}), 3)
        self.assertEqual(len(self.sent()), 3)

    def test_a_retried_request_gets_a_new_jwt(self):
        # Fireblocks takes a nonce once, so the retry after a 503 signs a new JWT.
        self.mock.events = [event(0, self.ago(5))]
        self.mock.codes = [503, 429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.mock.claims), 3)
        self.assertEqual(len({x["nonce"] for x in self.mock.claims}), 3)
        self.assertEqual(len(self.sent()), 1)

    def test_a_pkcs1_key_file_works_too(self):
        path = os.path.join(self.tmp.name, "fireblocks_secret.key")
        with open(path, "w") as fh:
            fh.write(KEY["pkcs1"])
        self.mock.events = [event(0, self.ago(5))]
        c.run_once(self.cfg(FIREBLOCKS_SECRET_KEY=None, FIREBLOCKS_SECRET_KEY_FILE=path))
        self.assertIsNotNone(self.mock.claims[0])
        self.assertEqual(len(self.sent()), 1)

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1800")
        c.run_once(cfg)
        first_end = int(self.mock.queries[0]["endTime"])
        self.assertEqual(self.saved()["audit_log"]["until"], first_end)
        self.mock.ingested.clear()
        self.mock.queries.clear()
        # A late event inside the overlap, and a new one.
        self.mock.events += [event(7, self.ago(20)), event(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["id"] for r in self.sent()), ["evt-0007", "evt-0008"])
        self.assertEqual(int(self.mock.queries[0]["startTime"]), first_end - 1800 * 1000)

    def test_lookback_sets_the_first_window_within_a_year(self):
        self.mock.events = [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["id"] for r in self.sent()], ["evt-0001"])
        q = self.mock.queries[0]
        self.assertAlmostEqual((int(q["endTime"]) - int(q["startTime"])) / 1000, 86400 - 60, delta=10)
        # The window ends a minute before now, so a clock a little ahead never asks for the future.
        self.assertLessEqual(int(q["endTime"]), ms(datetime.now(timezone.utc)) - 59000)
        self.mock.queries.clear()
        os.remove(self.state)
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="8760"))
        q = self.mock.queries[0]
        self.assertLess(int(q["endTime"]) - int(q["startTime"]), 365 * 86400 * 1000)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(FIREBLOCKS_PAGE_SIZE="2"))
        saved = self.saved()["audit_log"]
        self.assertNotIn("until", saved)
        self.assertEqual(sorted(saved["seen"]), ["evt-0000", "evt-0001"])
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(FIREBLOCKS_PAGE_SIZE="2"))
        self.assertEqual(sorted(r["id"] for r in self.sent()), ["evt-0002", "evt-0003"])
        self.assertIn("until", self.saved()["audit_log"])

    def test_categories_are_sent_as_repeated_filters(self):
        self.mock.events = [event(0, self.ago(9)), event(1, self.ago(8), "Policies", "Policy states", "Published policy"),
                            event(2, self.ago(7), "Security", "FSPM", "Finding created")]
        c.run_once(self.cfg(FIREBLOCKS_CATEGORIES="Security, Policies,Security"))
        self.assertEqual(self.mock.queries[0]["category"], ["Security", "Policies"])
        self.assertEqual(sorted(r["id"] for r in self.sent()), ["evt-0001", "evt-0002"])
        self.mock.queries.clear()
        os.remove(self.state)
        c.run_once(self.cfg())
        self.assertEqual(self.mock.queries[0]["category"], [])

    def test_the_deprecated_cursor_field_is_followed_too(self):
        self.mock.cursor_field = "cursor"
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        c.run_once(self.cfg(FIREBLOCKS_PAGE_SIZE="2"))
        self.assertEqual(len(self.sent()), 3)

    def test_iso_timestamps_and_events_without_an_id(self):
        # The Audit Logs guide shows timestamp as ISO 8601. An event with no id is told apart by
        # its whole content.
        a = event(0, self.ago(5), iso=True)
        b = {k: v for k, v in event(1, self.ago(4)).items() if k != "id"}
        self.mock.events = [a, b]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 2)
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual(self.sent(), [])

    def test_refused_credentials_stop_with_clear_errors(self):
        # A key that isn't the API user's: the JWT doesn't verify.
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(FIREBLOCKS_SECRET_KEY=OTHER_KEY["pkcs8"]))
        self.assertIn("HTTP 401 -7", str(cm.exception))
        self.assertIn("belong to the same API user", str(cm.exception))
        with self.assertRaisesRegex(c.BridgeError, "HTTP 401"):
            c.run_once(self.cfg(FIREBLOCKS_API_KEY="some-other-api-key"))
        self.mock.codes = [403]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403 1403", str(cm.exception))
        self.assertIn("Security Auditor role", str(cm.exception))
        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("audit_log", {}))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["fireblocks_record"] for x in lines], ["audit_log"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [503, 429, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_retry_waits_honor_retry_after_and_back_off(self):
        self.assertEqual(c._retry_delay(0, "7"), 7.0)
        self.assertTrue(2 <= c._retry_delay(0, None) <= 3)
        self.assertTrue(4 <= c._retry_delay(1, None) <= 5)

    def test_gzip_batches_and_headers(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = [event(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(FIREBLOCKS_SECRET_KEY=OTHER_KEY["pkcs8"]))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("audit log", logged)
        pem_body = "".join(KEY["pkcs8"].splitlines()[1:-1])
        for secret in (INGEST_KEY, API_KEY, "00000000-example-integration", pem_body[:40], pem_body[-40:]):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        bad_pem = "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"
        cases = [
            base_env(FIREBLOCKS_API_URL="http://api.example.com"),
            base_env(FIREBLOCKS_API_URL="https://api.example.com/v1/management"),
            base_env(FIREBLOCKS_API_URL="https://api.example.com/?x=1"),
            base_env(FIREBLOCKS_API_URL="api.example.com"),
            {"FIREBLOCKS_SECRET_KEY": KEY["pkcs8"]},
            base_env(FIREBLOCKS_API_KEY="has a space"),
            base_env(FIREBLOCKS_API_KEY="line\nbreak"),
            {"FIREBLOCKS_API_KEY": API_KEY},
            {"FIREBLOCKS_API_KEY": API_KEY, "FIREBLOCKS_SECRET_KEY_FILE": "/nonexistent/fireblocks_secret.key"},
            base_env(FIREBLOCKS_SECRET_KEY="not a key"),
            base_env(FIREBLOCKS_SECRET_KEY=bad_pem),
            base_env(FIREBLOCKS_CATEGORIES="Security,Login"),
            base_env(FIREBLOCKS_CATEGORIES="security"),
            base_env(FIREBLOCKS_PAGE_SIZE="0"),
            base_env(FIREBLOCKS_PAGE_SIZE="501"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(BRIDGE_LOOKBACK_HOURS="8761"),
        ]
        for env in cases:
            with self.subTest(env={k: v[:40] for k, v in env.items()}), self.assertRaises(c.BridgeError):
                c.load_config(env)
        with self.assertRaisesRegex(c.BridgeError, "not both"):
            c.load_config(base_env(FIREBLOCKS_SECRET_KEY_FILE="/nonexistent/fireblocks_secret.key"))
        cfg = c.load_config(base_env())
        self.assertEqual(cfg["api_url"], "https://api.fireblocks.io")
        self.assertEqual(cfg["categories"], [])
        for given, kept in (("https://eu-api.fireblocks.io/v1", "https://eu-api.fireblocks.io"),
                            ("https://eu2-api.fireblocks.io/", "https://eu2-api.fireblocks.io"),
                            ("https://sandbox-api.fireblocks.io/v1/", "https://sandbox-api.fireblocks.io")):
            with self.subTest(given=given):
                self.assertEqual(c.load_config(base_env(FIREBLOCKS_API_URL=given))["api_url"], kept)

    def test_a_bad_key_error_never_shows_the_key(self):
        broken = KEY["pkcs8"].replace("\n-----END", "!!\n-----END")
        with self.assertRaises(c.BridgeError) as cm:
            c.load_config(base_env(FIREBLOCKS_SECRET_KEY=broken))
        self.assertNotIn(KEY["pkcs8"].splitlines()[1][:30], str(cm.exception))

    def test_event_times_in_milliseconds_seconds_and_iso(self):
        want = int(datetime(2026, 10, 29, 1, 2, 11, tzinfo=timezone.utc).timestamp() * 1000)
        for value, expected in [(want + 482, want + 482), (str(want + 482), want + 482), (want // 1000, want),
                                ("2026-10-29T01:02:11.482Z", want + 482), ("2026-10-29T12:02:11.482+11:00", want + 482),
                                ("2026-10-29T01:02:11Z", want), ("2026-10-29T01:02:11.123456789Z", want + 123)]:
            with self.subTest(value=value):
                self.assertEqual(c._event_ms(value), expected)
        self.assertIsNone(c._event_ms("yesterday"))
        self.assertIsNone(c._event_ms(None))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.events = [event(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Fireblocks API": self.cfg(FIREBLOCKS_API_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, cfg in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaisesRegex(c.BridgeError, rf"answered with a redirect \(HTTP {code}\), which the bridge refuses"):
                            c.run_once(cfg)
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved()["audit_log"])
        finally:
            r.close()

    def request_sized(self, size, code=200):
        """_request against a server whose answer has a body of `size` bytes, with the cap at 1 MB.
        Fails if the bridge hasn't closed the connection by the time _request returns or raises."""
        saved, c.MAX_RESPONSE_BYTES = c.MAX_RESPONSE_BYTES, 1024 * 1024
        server = Sized(size, code)
        try:
            return c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
        finally:
            closed = server.closed_by_bridge.wait(5)
            server.close()
            c.MAX_RESPONSE_BYTES = saved
            self.assertTrue(closed, "the bridge left the response open")

    def test_response_up_to_the_limit_is_read(self):
        self.assertEqual(len(self.request_sized(1024 * 1024)[-1]), 1024 * 1024)

    def test_response_over_the_limit_stops_the_run(self):
        # A broken or hostile endpoint can't make the bridge hold any amount in memory. The larger
        # body is only partly read, so it also shows the bridge closes what it stopped reading.
        for size in (1024 * 1024 + 1, 2 * 1024 * 1024):
            with self.subTest(size=size), self.assertRaisesRegex(c.BridgeError, "sent more than 1 MB"):
                self.request_sized(size)

    def test_error_response_over_the_limit_stops_the_run(self):
        for size in (1024 * 1024 + 1, 2 * 1024 * 1024):
            with self.subTest(size=size), self.assertRaisesRegex(c.BridgeError, "sent more than 1 MB"):
                self.request_sized(size, code=400)

    def test_retried_status_is_retried_whatever_the_size_of_its_body(self):
        # A 503 whose body is over the limit is retried like any other, and ends in the same error.
        saved, c.MAX_RESPONSE_BYTES = c.MAX_RESPONSE_BYTES, 1024 * 1024
        server = Sized(2 * 1024 * 1024, 503)
        try:
            with self.assertRaises(c.HttpStatus) as caught:
                c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
        finally:
            server.close()
            c.MAX_RESPONSE_BYTES = saved
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(self.logbuf.getvalue().count("returned 503; retrying"), c.MAX_ATTEMPTS - 1)

    def test_bad_numbers_stop_with_one_plain_error(self):
        for name, _, _, _, cast, high in NUMBERS:
            for value in ["abc", "nan", "inf", "-1", str(high + 1)] + (["1.5"] if cast is int else []):
                with self.subTest(name=name, value=value), self.assertRaisesRegex(c.BridgeError, f"^{name} "):
                    self.cfg(**{name: value})

    def test_numbers_still_load(self):
        for name, key, default, normal, cast, _ in NUMBERS:
            for extra, expected in (({}, default), ({name: str(normal)}, normal)):
                with self.subTest(name=name, extra=extra):
                    value = self.cfg(**extra)[key]
                    self.assertEqual((value, type(value)), (expected, cast))


class SigningTest(unittest.TestCase):
    def test_signature_verifies_with_the_public_key(self):
        cfg = c.load_config(base_env())
        claims = verify_jwt(c.request_jwt(cfg, "/v1/management/audit_logs?startTime=1", now=1793235731), KEY)
        self.assertEqual((claims["iat"], claims["exp"]), (1793235731, 1793235731 + 29))
        self.assertEqual((claims["uri"], claims["sub"], claims["bodyHash"]),
                         ("/v1/management/audit_logs?startTime=1", API_KEY, EMPTY_BODY_HASH))
        self.assertNotEqual(claims["nonce"], verify_jwt(c.request_jwt(cfg, "/x"), KEY)["nonce"])

    def test_pkcs1_and_pkcs8_read_the_same_key(self):
        a, b = c.rsa_private_key(KEY["pkcs8"]), c.rsa_private_key(KEY["pkcs1"])
        self.assertEqual(a, b)
        self.assertEqual((a["n"], a["e"]), (KEY["n"], KEY["e"]))
        # Blinding changes the work, not the signature: RSASSA-PKCS1-v1_5 is deterministic.
        self.assertEqual(c.rs256(a, b"x"), c.rs256(b, b"x"))

    def test_keys_that_are_not_rsa_or_too_small_are_refused(self):
        for pem in ("", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----", SMALL_KEY["pkcs8"]):
            with self.subTest(pem=pem[:30]), self.assertRaises(c.BridgeError):
                c.rsa_private_key(pem)


class LegacyNameTest(unittest.TestCase):
    """Bridges were called collectors: a setup that still sets the COLLECTOR_ names keeps working."""

    def test_collector_names_still_work(self):
        self.assertEqual(c._env({"COLLECTOR_LOG_LEVEL": "DEBUG"}, "BRIDGE_LOG_LEVEL", "INFO"), "DEBUG")
        self.assertEqual(c._env({"COLLECTOR_LOG_LEVEL": "DEBUG", "BRIDGE_LOG_LEVEL": "WARNING"}, "BRIDGE_LOG_LEVEL", "INFO"), "WARNING")
        self.assertEqual(c._env({}, "BRIDGE_LOG_LEVEL", "INFO"), "INFO")
        self.assertTrue(c._flag({"COLLECTOR_DRY_RUN": "1"}, "BRIDGE_DRY_RUN", False))
        self.assertFalse(c._flag({"COLLECTOR_DRY_RUN": "1", "BRIDGE_DRY_RUN": "0"}, "BRIDGE_DRY_RUN", False))


class RequestSafetyTest(unittest.TestCase):
    def test_retry_after_is_capped_at_five_minutes(self):
        for value in ("99999999", "1e12", "inf", "nan", "-5"):
            delay = c._retry_delay(0, value)
            self.assertTrue(0.0 <= delay <= 300.0, (value, delay))

    def test_key_with_a_line_break_stays_out_of_the_error(self):
        # http.client refuses the header before it connects, so nothing listens on the port.
        with self.assertRaises(c.BridgeError) as caught:
            c._request("GET", "http://127.0.0.1:9/x", {"Authorization": "Bearer key-part-one\nkey-part-two"}, None, 2.0,
                       what="test request")
        self.assertNotIn("key-part", str(caught.exception))
        self.assertIn("line break", str(caught.exception))

    def test_unreachable_host_is_a_network_error_that_names_only_the_host(self):
        # Nothing listens on port 9 here, so every attempt is refused. The backoff is skipped.
        saved, c.time.sleep = c.time.sleep, lambda s: None
        try:
            with self.assertRaises(c.NetworkError) as caught:
                c._request("POST", "http://127.0.0.1:9/http-endpoint/v1/00000000-example-integration",
                           {"Authorization": "Bearer key-part-not-real"}, b"{}", 2.0, what="HTTP Ingest POST")
        finally:
            c.time.sleep = saved
        self.assertEqual(str(caught.exception), "HTTP Ingest POST to 127.0.0.1:9 failed: URLError")

    def test_read_timeout_is_retried_then_a_network_error(self):
        # The listener never accepts, so no answer comes and every attempt times out. On Python 3.9
        # that is socket.timeout, which isn't a TimeoutError yet. The backoff is skipped.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        host = f"127.0.0.1:{listener.getsockname()[1]}"
        slept = []
        saved, c.time.sleep = c.time.sleep, slept.append
        try:
            with self.assertRaises(c.NetworkError) as caught:
                c._request("GET", f"http://{host}/x", {}, None, 0.05, what="test request")
        finally:
            c.time.sleep = saved
            listener.close()
        self.assertEqual(len(slept), c.MAX_ATTEMPTS - 1)
        self.assertRegex(str(caught.exception), rf"^test request to {host} failed: (timeout|TimeoutError)$")

    def test_answer_cut_short_is_retried_then_a_network_error(self):
        # The connection closes partway through every answer (IncompleteRead), whether its status
        # is OK or one that is retried. The error names the type, never the partial body.
        for code, ending in ((200, "failed: IncompleteRead"), (503, "failed with HTTP 503")):
            with self.subTest(code=code):
                server, slept = CutShort(code), []
                saved, c.time.sleep = c.time.sleep, slept.append
                try:
                    with self.assertRaises(c.NetworkError) as caught:
                        c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
                finally:
                    c.time.sleep = saved
                    server.close()
                self.assertEqual((server.requests, len(slept)), (c.MAX_ATTEMPTS, c.MAX_ATTEMPTS - 1))
                self.assertTrue(str(caught.exception).endswith(ending), str(caught.exception))
                self.assertNotIn("partial", str(caught.exception))

    def test_501_and_505_stop_at_once_with_a_plain_message(self):
        # 501 and 505 say the server will never take the request as it is sent, so a retry can't
        # help, unlike 500, 502, 503 and 504. They stop the run at the first answer and say why.
        for code, meaning in ((501, "the server doesn't support this request"),
                              (505, "the server doesn't support HTTP/1.1, the version the bridge uses")):
            with self.subTest(code=code):
                server, slept = Sized(10, code), []
                saved, c.time.sleep = c.time.sleep, slept.append
                try:
                    with self.assertRaises(c.BridgeError) as caught:
                        c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
                finally:
                    c.time.sleep = saved
                    server.close()
                self.assertNotIsInstance(caught.exception, c.NetworkError)
                self.assertEqual(slept, [])
                self.assertEqual(str(caught.exception), f"test request to {server.base[len('http://'):]} failed with HTTP "
                                 f"{code}: {meaning}, and a retry won't change that; check the URL setting")

    def test_user_info_in_a_url_stays_out_of_log_lines_and_errors(self):
        # A user name or password in a URL setting is a credential. Log lines and errors name the
        # host and port, with the user info redacted.
        self.assertEqual(c._host("https://user:secret@api.example.com:8443/v1/x?q=1"), "[redacted]@api.example.com:8443")
        self.assertEqual(c._host("https://token-value@api.example.com/v1"), "[redacted]@api.example.com")
        self.assertEqual(c._host("https://api.example.com/v1?q=a@b"), "api.example.com")
        with self.assertRaises(c.BridgeError) as caught:
            c._read(io.BytesIO(b"xx"), "test request", "https://user:secret@api.example.com/x", limit=1)
        self.assertTrue(str(caught.exception).startswith("test request to [redacted]@api.example.com sent more than"),
                        str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))

    def test_error_answer_cut_short_still_stops_at_once(self):
        # A status that isn't retried stops the run at the first answer, cut short or not.
        server = CutShort(400)
        try:
            with self.assertRaises(c.BridgeError) as caught:
                c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
        finally:
            server.close()
        self.assertNotIsInstance(caught.exception, c.NetworkError)
        self.assertEqual(server.requests, 1)
        self.assertTrue(str(caught.exception).endswith("failed with HTTP 400"), str(caught.exception))

    def test_answer_short_of_its_content_length_is_retried_then_a_network_error(self):
        # The connection closes before the body reaches its Content-Length. http.client's read(n)
        # returns what arrived with no error, so the bridge checks the count itself: a short body
        # is retried like any answer cut short, and never passes as the whole answer.
        for code, ending in ((200, "failed: IncompleteRead"), (503, "failed with HTTP 503")):
            with self.subTest(code=code):
                server, slept = CutShort(code, length=100), []
                saved, c.time.sleep = c.time.sleep, slept.append
                try:
                    with self.assertRaises(c.NetworkError) as caught:
                        c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
                finally:
                    c.time.sleep = saved
                    server.close()
                self.assertEqual((server.requests, len(slept)), (c.MAX_ATTEMPTS, c.MAX_ATTEMPTS - 1))
                self.assertTrue(str(caught.exception).endswith(ending), str(caught.exception))
                self.assertNotIn("partial", str(caught.exception))
        # Short once, then whole: the retry returns the whole answer.
        server = CutShort(200, length=100, whole_after=1)
        saved, c.time.sleep = c.time.sleep, lambda s: None
        try:
            answer = c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
        finally:
            c.time.sleep = saved
            server.close()
        self.assertEqual((answer[0], answer[-1], server.requests), (200, b'{"whole": true}', 2))
        # A status that isn't retried still stops the run at the first answer.
        server = CutShort(400, length=100)
        try:
            with self.assertRaises(c.BridgeError) as caught:
                c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request")
        finally:
            server.close()
        self.assertNotIsInstance(caught.exception, c.NetworkError)
        self.assertEqual(server.requests, 1)
        self.assertTrue(str(caught.exception).endswith("failed with HTTP 400"), str(caught.exception))


class RangeTest(unittest.TestCase):
    """A number outside its range stops the bridge with an error that gives the range."""

    def load(self, **extra):
        return c.load_config(base_env(**extra))

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "501"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^FIREBLOCKS_PAGE_SIZE must be between 1 and 500$"):
                self.load(FIREBLOCKS_PAGE_SIZE=value)
        self.assertEqual(self.load(FIREBLOCKS_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(FIREBLOCKS_PAGE_SIZE="500")["page_size"], 500)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config(base_env())
        self.saved = (c.load_config, c.run_once, c.time.sleep, c.logging.basicConfig)
        self.calls, self.slept = [], []
        c.load_config = lambda env=None: self.cfg
        c.time.sleep = self.slept.append
        # main sets up the root logger; a handler left there would print the log of later tests.
        c.logging.basicConfig = lambda **kwargs: None
        self.log = io.StringIO()
        self.handler = logging.StreamHandler(self.log)
        self.handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        c.LOG.addHandler(self.handler)

    def tearDown(self):
        c.load_config, c.run_once, c.time.sleep, c.logging.basicConfig = self.saved
        c.LOG.removeHandler(self.handler)

    def run_once_raises(self, *errors):
        """run_once raises each error in turn, then KeyboardInterrupt, so main can't loop forever."""
        errors = list(errors)

        def run_once(cfg, *args, **kwargs):
            self.calls.append(kwargs)
            raise errors.pop(0) if errors else KeyboardInterrupt()

        c.run_once = run_once

    def test_unexpected_error_is_logged_without_its_message_and_polling_goes_on(self):
        self.run_once_raises(RuntimeError("secret-value-not-real"))
        self.assertEqual(c.main(["--interval", "5"]), 130)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.slept, [5])
        errors = [line for line in self.log.getvalue().splitlines() if line.startswith("ERROR")]
        self.assertEqual(len(errors), 1)
        self.assertRegex(errors[0], r"unexpected RuntimeError at line \d+ in main;")
        self.assertNotIn("secret-value-not-real", self.log.getvalue())

    def test_bridge_error_still_stops_the_bridge(self):
        self.run_once_raises(c.BridgeError("test failure"))
        self.assertEqual(c.main(["--interval", "5"]), 1)
        self.assertEqual(len(self.calls), 1)

    def test_single_run_still_raises_an_unexpected_error(self):
        self.run_once_raises(RuntimeError("secret-value-not-real"))
        with self.assertRaises(RuntimeError):
            c.main([])
        self.assertEqual(len(self.calls), 1)

    def test_network_error_is_logged_and_polling_goes_on(self):
        self.run_once_raises(c.NetworkError("HTTP Ingest POST to ingest.example.com failed: URLError"))
        self.assertEqual(c.main(["--interval", "5"]), 130)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.slept, [5])
        errors = [line for line in self.log.getvalue().splitlines() if line.startswith("ERROR")]
        self.assertEqual(errors, ["ERROR HTTP Ingest POST to ingest.example.com failed: URLError; trying again in 5 seconds"])

    def test_network_error_still_stops_a_single_run(self):
        self.run_once_raises(c.NetworkError("HTTP Ingest POST to ingest.example.com failed: URLError"))
        self.assertEqual(c.main([]), 1)
        self.assertEqual(len(self.calls), 1)

    def test_outage_past_the_retries_is_logged_by_host_and_polling_goes_on(self):
        """The real run, with every connection refused: it ends after the retries with a network
        error that names only the host, and the bridge runs again at the next interval."""
        runs = []

        def run_once(*args, **kwargs):
            runs.append(1)
            if len(runs) > 1:
                raise KeyboardInterrupt()
            return self.saved[1](*args, **kwargs)

        def refuse(opener, req, *args, **kwargs):
            raise c.urllib.error.URLError(ConnectionRefusedError("refused"))

        c.run_once = run_once
        opener = c.urllib.request.OpenerDirector
        saved_open, opener.open = opener.open, refuse
        try:
            self.assertEqual(c.main(["--interval", "5", "--dry-run"]), 130)
        finally:
            opener.open = saved_open
        self.assertEqual(len(runs), 2)
        self.assertEqual(len(self.slept), c.MAX_ATTEMPTS)
        self.assertEqual(self.slept[-1], 5)
        errors = [line for line in self.log.getvalue().splitlines() if line.startswith("ERROR")]
        self.assertEqual(len(errors), 1)
        self.assertRegex(errors[0], r"^ERROR .+ to [a-z0-9.-]+ failed: URLError; trying again in 5 seconds$")
        self.assertNotRegex(self.log.getvalue(), r"not-?real")

    def test_negative_interval_is_refused(self):
        self.run_once_raises()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            c.main(["--interval", "-1"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.calls, [])

    def every_request_fails(self, error, argv):
        """main with the real run and every request failing with error(url); a second run stops the
        loop. Returns main's exit code and the number of runs."""
        runs = []

        def run_once(*args, **kwargs):
            runs.append(1)
            if len(runs) > 1:
                raise KeyboardInterrupt()
            return self.saved[1](*args, **kwargs)

        def fail(opener, req, *args, **kwargs):
            raise error(req.full_url)

        c.run_once = run_once
        opener = c.urllib.request.OpenerDirector
        saved_open, opener.open = opener.open, fail
        try:
            return c.main(argv), len(runs)
        finally:
            opener.open = saved_open

    @staticmethod
    def status(code):
        return lambda url: c.urllib.error.HTTPError(url, code, "test status", c.http.client.HTTPMessage(), io.BytesIO(b"{}"))

    def errors(self):
        return [line for line in self.log.getvalue().splitlines() if line.startswith("ERROR")]

    def test_retried_status_past_the_retries_is_logged_by_host_and_polling_goes_on(self):
        for code in (429, 503):
            with self.subTest(code=code):
                self.log.seek(0)
                self.log.truncate()
                del self.slept[:]
                self.assertEqual(self.every_request_fails(self.status(code), ["--interval", "5", "--dry-run"]), (130, 2))
                self.assertEqual(len(self.slept), c.MAX_ATTEMPTS)
                self.assertEqual(self.slept[-1], 5)
                errors = self.errors()
                self.assertEqual(len(errors), 1)
                self.assertRegex(errors[0], rf"^ERROR .+ to [a-z0-9.-]+ failed with HTTP {code}; trying again in 5 seconds$")
                self.assertNotRegex(self.log.getvalue(), r"not-?real")

    def test_other_statuses_and_redirects_still_stop_the_bridge(self):
        for code in (302, 400, 401, 403, 404):
            with self.subTest(code=code):
                self.assertEqual(self.every_request_fails(self.status(code), ["--interval", "5", "--dry-run"]), (1, 1))

    def test_unknown_host_before_a_run_has_worked_stops_the_bridge(self):
        """A host name that doesn't resolve before any run has worked is most likely a mistyped URL,
        so after the retries it stops the bridge, even with --interval."""
        def not_found(url):
            return c.urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "test lookup failure"))

        self.assertEqual(self.every_request_fails(not_found, ["--interval", "5", "--dry-run"]), (1, 1))
        self.assertEqual(len(self.slept), c.MAX_ATTEMPTS - 1)
        errors = self.errors()
        self.assertEqual(len(errors), 1)
        self.assertRegex(errors[0], r"^ERROR .+ to [a-z0-9.-]+ failed: the host name wasn't found; check the URL setting$")
        self.assertNotRegex(self.log.getvalue(), r"not-?real")

    def test_unknown_host_after_a_run_has_worked_is_logged_and_polling_goes_on(self):
        error = c.HostNotFound("events request to api.example.com failed: the host name wasn't found; check the URL setting")
        results = [None, error]

        def run_once(cfg, *args, **kwargs):
            self.calls.append(kwargs)
            if not results:
                raise KeyboardInterrupt()
            result = results.pop(0)
            if result:
                raise result

        c.run_once = run_once
        self.assertEqual(c.main(["--interval", "5"]), 130)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.slept, [5, 5])
        self.assertEqual(self.errors(), [f"ERROR {error}; trying again in 5 seconds"])


if __name__ == "__main__":
    unittest.main()
