"""Unit tests for google_workspace_audit_bridge.py against a local mock server.

The mock serves the shapes in Google's Reports API reference: the OAuth 2.0 token endpoint for a
service account (grant_type urn:ietf:params:oauth:grant-type:jwt-bearer with an RS256 JWT,
answering {"access_token", "expires_in", "token_type"} or {"error", "error_description"}), and
GET /admin/reports/v1/activity/users/all/applications/{app} (startTime, endTime, maxResults,
pageToken, customerId; answering {"kind": "reports#activities", "items": [Activity],
"nextPageToken"}, newest first, and {"error": {"code", "message", "errors", "status"}} on
failure, with 503 for quota). Plus a Sophos NG-SIEM HTTP Ingest endpoint. The tests make their
own RSA key and check every token request's signature with it. No real service is called.

  python3 -m unittest discover -s bridges/google-workspace-audit -p 'test_*.py' -v
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
import google_workspace_audit_bridge as c  # noqa: E402

ADMIN = "reports.admin@example.com"
SA_EMAIL = "ngsiem-bridge@example-project.iam.gserviceaccount.example"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ACCESS_TOKEN = "test-google-access-token-not-real"


# ---------------------------------------------------------------- a test RSA key, made here

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


KEY = make_key()
OTHER_KEY = make_key(seed=11)


def key_json(pem=None, email=SA_EMAIL):
    return json.dumps({"type": "service_account", "project_id": "example-project", "private_key_id": "0123456789abcdef",
                       "private_key": pem or KEY["pkcs8"], "client_email": email, "client_id": "100000000000000000001",
                       "token_uri": "https://oauth2.googleapis.com/token"})


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


# ---------------------------------------------------------------- activities

def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def activity(i, when, app="login", events=None):
    return {"kind": "audit#activity", "id": {"time": iso(when), "uniqueQualifier": str(-4000000000000000000 + i),
                                             "applicationName": app, "customerId": "C03az79cb"},
            "etag": f"\"etag-{i}\"", "actor": {"callerType": "USER", "email": "pat@example.com", "profileId": "114000000000000000001"},
            "ownerDomain": "example.com", "ipAddress": "203.0.113.10",
            "events": events or [{"type": "login", "name": "login_success",
                                  "parameters": [{"name": "login_type", "value": "google_password"},
                                                 {"name": "login_challenge_method", "multiValue": ["password", "security_key"]},
                                                 {"name": "is_suspicious", "boolValue": False}]}],
            "networkInfo": {"ipAsn": [64500], "regionCode": "AU", "subdivisionCode": "AU-NSW"}}


class Mock:
    def __init__(self):
        self.activities = {}
        self.codes = []
        self.ingest_codes = []
        self.token_error = None
        self.refuse_token_once = False
        self.ingested = []
        self.queries = []
        self.token_requests = []
        self.api_auth = []
        self.key = KEY


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

    def do_GET(self):
        m = self.mock
        parts = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parts.query))
        prefix = "/admin/reports/v1/activity/users/all/applications/"
        if not parts.path.startswith(prefix):
            return self._send(404, {"error": {"code": 404, "message": "Not Found", "status": "NOT_FOUND"}})
        auth = self.headers.get("Authorization")
        m.api_auth.append(auth)
        if auth != f"Bearer {ACCESS_TOKEN}" or (m.refuse_token_once and len(m.token_requests) < 2):
            return self._send(401, {"error": {"code": 401, "message": "Request had invalid authentication credentials.",
                                              "errors": [{"reason": "authError"}], "status": "UNAUTHENTICATED"}})
        if m.codes:
            code = m.codes.pop(0)
            if code == 403:
                return self._send(403, {"error": {"code": 403, "message": "Not Authorized to access this resource/api",
                                                  "errors": [{"reason": "forbidden"}], "status": "PERMISSION_DENIED"}})
            return self._send(code, {"error": {"code": code, "message": "Quota exceeded", "errors": [{"reason": "rateLimitExceeded"}]}})
        app = parts.path[len(prefix):]
        m.queries.append({"app": app, **q})
        start, end = c._parse_time(q["startTime"]), c._parse_time(q["endTime"])
        rows = [a for a in m.activities.get(app, []) if start <= c._parse_time(a["id"]["time"]) <= end]
        rows.sort(key=lambda a: a["id"]["time"], reverse=True)
        size = int(q.get("maxResults") or 1000)
        pos = int(q.get("pageToken") or 0)
        chunk = rows[pos:pos + size]
        out = {"kind": "reports#activities", "etag": "\"list\""}
        if chunk:
            out["items"] = chunk
        if pos + size < len(rows):
            out["nextPageToken"] = str(pos + size)
        return self._send(200, out)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/token":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            claims = verify_jwt(form.get("assertion", ""), m.key)
            m.token_requests.append({"form": form, "claims": claims})
            if m.token_error:
                code, err, desc = m.token_error
                return self._send(code, {"error": err, "error_description": desc})
            if form.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" or not claims:
                return self._send(400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
            return self._send(200, {"access_token": ACCESS_TOKEN, "expires_in": 3599, "token_type": "Bearer"})
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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("GWS_PAGE_SIZE", "page_size", 1000, 500, int, 1000),
    ("GWS_TOKEN_OVERLAP_SECONDS", "token_overlap_seconds", 14400, 7200, int, 10 ** 9),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 3600, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"GWS_SERVICE_ACCOUNT_KEY": key_json(), "GWS_ADMIN_EMAIL": ADMIN}
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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
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
                     GWS_APPLICATIONS="login", BRIDGE_STATE_FILE=self.state, GWS_API_URL=self.base)
        e["GWS_TOKEN_URL"] = self.base + "/token"
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_pages_are_read_split_and_flattened(self):
        two = [{"type": "USER_SETTINGS", "name": "CREATE_USER", "parameters": [{"name": "USER_EMAIL", "value": "new.user@example.com"}]},
               {"type": "USER_SETTINGS", "name": "GRANT_ADMIN_PRIVILEGE",
                "parameters": [{"name": "USER_EMAIL", "value": "new.user@example.com"}, {"name": "COUNT", "intValue": "3"},
                               {"name": "NESTED", "messageValue": {"parameter": [{"name": "city", "value": "Sydney"}]}},
                               {"name": "MANY", "multiMessageValue": [{"parameter": [{"name": "a", "boolValue": True}]}]}]}]
        self.mock.activities["login"] = [activity(i, self.ago(50 - i)) for i in range(5)]
        self.mock.activities["admin"] = [activity(9, self.ago(3), "admin", two)]
        self.assertEqual(c.run_once(self.cfg(GWS_PAGE_SIZE="2", GWS_APPLICATIONS="login,admin")), 7)
        rows = self.sent()
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"google_workspace_record":"activity","kind":"audit#activity","id":'))
        logins = [r for r in rows if r["id"]["applicationName"] == "login"]
        self.assertEqual(len(logins), 5)
        self.assertEqual(logins[0]["params"], {"login_type": "google_password", "login_challenge_method": ["password", "security_key"],
                                               "is_suspicious": False})
        self.assertEqual(logins[0]["networkInfo"]["regionCode"], "AU")
        admin = [r for r in rows if r["id"]["applicationName"] == "admin"]
        self.assertEqual([r["events"][0]["name"] for r in admin], ["CREATE_USER", "GRANT_ADMIN_PRIVILEGE"])
        self.assertTrue(all(len(r["events"]) == 1 for r in rows))
        self.assertEqual(admin[1]["params"], {"USER_EMAIL": "new.user@example.com", "COUNT": "3", "NESTED": {"city": "Sydney"},
                                              "MANY": [{"a": True}]})
        # Every page of each application was read, in one window per application.
        login_q = [q for q in self.mock.queries if q["app"] == "login"]
        self.assertEqual([q.get("pageToken") for q in login_q], [None, "2", "4"])
        self.assertEqual(len({(q["startTime"], q["endTime"]) for q in login_q}), 1)
        self.assertEqual(login_q[0]["maxResults"], "2")

    def test_token_request_is_a_signed_jwt_for_the_admin(self):
        self.mock.activities["login"] = [activity(0, self.ago(5))]
        self.mock.activities["token"] = [activity(1, self.ago(5), "token")]
        c.run_once(self.cfg(GWS_APPLICATIONS="login,token"))
        self.assertEqual(len(self.mock.token_requests), 1)
        claims = self.mock.token_requests[0]["claims"]
        self.assertIsNotNone(claims, "the JWT signature didn't verify with the service account's public key")
        self.assertEqual((claims["iss"], claims["sub"], claims["scope"], claims["aud"]),
                         (SA_EMAIL, ADMIN, "https://www.googleapis.com/auth/admin.reports.audit.readonly", f"{self.base}/token"))
        self.assertEqual(claims["exp"] - claims["iat"], 3600)
        self.assertEqual(set(self.mock.api_auth), {f"Bearer {ACCESS_TOKEN}"})

    def test_a_pkcs1_key_file_works_too(self):
        path = os.path.join(self.tmp.name, "key.json")
        with open(path, "w") as fh:
            fh.write(key_json(KEY["pkcs1"]))
        self.mock.activities["login"] = [activity(0, self.ago(5))]
        c.run_once(self.cfg(GWS_SERVICE_ACCOUNT_KEY=None, GWS_SERVICE_ACCOUNT_KEY_FILE=path))
        self.assertIsNotNone(self.mock.token_requests[0]["claims"])
        self.assertEqual(len(self.sent()), 1)

    def test_a_refused_access_token_is_renewed_once(self):
        self.mock.activities["login"] = [activity(0, self.ago(5))]
        self.mock.refuse_token_once = True
        c.run_once(self.cfg())
        self.assertEqual(len(self.mock.token_requests), 2)
        self.assertEqual(len(self.sent()), 1)

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.activities["login"] = [activity(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1800")
        c.run_once(cfg)
        first_end = c._parse_time(self.mock.queries[0]["endTime"])
        self.assertAlmostEqual(self.saved()["apps"]["login"]["until"], first_end, delta=0.01)
        self.mock.ingested.clear()
        self.mock.queries.clear()
        # A late event inside the overlap, and a new one.
        self.mock.activities["login"] += [activity(7, self.ago(20)), activity(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["id"]["uniqueQualifier"] for r in self.sent()),
                         sorted(activity(i, self.now)["id"]["uniqueQualifier"] for i in (7, 8)))
        self.assertAlmostEqual(c._parse_time(self.mock.queries[0]["startTime"]), first_end - 1800, delta=0.01)

    def test_token_events_use_the_longer_overlap(self):
        self.mock.activities["token"] = [activity(0, self.ago(5), "token")]
        cfg = self.cfg(GWS_APPLICATIONS="login,token", BRIDGE_OVERLAP_SECONDS="600", GWS_TOKEN_OVERLAP_SECONDS="7200")
        c.run_once(cfg)
        self.mock.queries.clear()
        c.run_once(cfg)
        q = {x["app"]: c._parse_time(x["endTime"]) - c._parse_time(x["startTime"]) for x in self.mock.queries}
        self.assertAlmostEqual(q["login"], 600, delta=60)
        self.assertAlmostEqual(q["token"], 7200, delta=60)
        self.assertEqual(len(self.sent()), 1)

    def test_lookback_sets_the_first_window_within_retention(self):
        self.mock.activities["login"] = [activity(0, self.now - timedelta(days=3)), activity(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["id"]["uniqueQualifier"] for r in self.sent()], [activity(1, self.now)["id"]["uniqueQualifier"]])
        q = self.mock.queries[0]
        self.assertAlmostEqual(c._parse_time(q["endTime"]) - c._parse_time(q["startTime"]), 86400 - 60, delta=10)
        # The window ends a minute before now, so a clock a little ahead never asks for the future.
        self.assertLessEqual(c._parse_time(q["endTime"]), datetime.now(timezone.utc).timestamp() - 59)
        self.mock.queries.clear()
        os.remove(self.state)
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="10000"))
        q = self.mock.queries[0]
        self.assertLess(c._parse_time(q["endTime"]) - c._parse_time(q["startTime"]), 180 * 86400)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.activities["login"] = [activity(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(GWS_PAGE_SIZE="2"))
        saved = self.saved()["apps"]["login"]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(GWS_PAGE_SIZE="2"))
        self.assertEqual(sorted(r["id"]["uniqueQualifier"] for r in self.sent()),
                         sorted(activity(i, self.now)["id"]["uniqueQualifier"] for i in (0, 1)))
        self.assertIn("until", self.saved()["apps"]["login"])

    def test_customer_id_is_sent_when_set(self):
        c.run_once(self.cfg(GWS_CUSTOMER_ID="C03az79cb"))
        self.assertEqual(self.mock.queries[0]["customerId"], "C03az79cb")
        self.mock.queries.clear()
        c.run_once(self.cfg())
        self.assertNotIn("customerId", self.mock.queries[0])

    def test_refused_credentials_stop_with_clear_errors(self):
        self.mock.token_error = (401, "unauthorized_client", "Client is unauthorized to retrieve access tokens using this method.")
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 401 unauthorized_client", str(cm.exception))
        self.assertIn("domain-wide delegation", str(cm.exception))
        self.mock.token_error = None
        # A key the service account doesn't own: the signature doesn't verify.
        with self.assertRaisesRegex(c.BridgeError, "HTTP 400 invalid_grant"):
            c.run_once(self.cfg(GWS_SERVICE_ACCOUNT_KEY=key_json(OTHER_KEY["pkcs8"])))
        self.mock.codes = [403]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403 PERMISSION_DENIED", str(cm.exception))
        self.assertIn("Reports administrator privilege", str(cm.exception))
        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("apps", {}).get("login", {}))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.activities["login"] = [activity(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["google_workspace_record"] for x in lines], ["activity"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_quota_and_server_errors_are_retried(self):
        self.mock.activities["login"] = [activity(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [503, 429, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_retry_waits_honor_retry_after_and_back_off(self):
        self.assertEqual(c._retry_delay(0, "7"), 7.0)
        self.assertTrue(5 <= c._retry_delay(0, None) <= 6)
        self.assertTrue(10 <= c._retry_delay(1, None) <= 11)

    def test_gzip_batches_and_headers(self):
        self.mock.activities["login"] = [activity(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.activities["login"] = [activity(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        self.mock.token_error = (400, "invalid_grant", "Invalid JWT Signature.")
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("login", logged)
        pem_body = "".join(KEY["pkcs8"].splitlines()[1:-1])
        for secret in (INGEST_KEY, ACCESS_TOKEN, "00000000-example-integration", pem_body[:40], pem_body[-40:]):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        bad_pem = key_json("-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n")
        cases = [
            base_env(GWS_API_URL="http://admin.example.com"),
            base_env(GWS_TOKEN_URL="http://oauth2.example.com/token"),
            {"GWS_SERVICE_ACCOUNT_KEY": key_json()},
            base_env(GWS_ADMIN_EMAIL="not-an-email"),
            {"GWS_ADMIN_EMAIL": ADMIN},
            {"GWS_ADMIN_EMAIL": ADMIN, "GWS_SERVICE_ACCOUNT_KEY_FILE": "/nonexistent/key.json"},
            base_env(GWS_SERVICE_ACCOUNT_KEY="not json"),
            base_env(GWS_SERVICE_ACCOUNT_KEY=json.dumps({"type": "authorized_user"})),
            base_env(GWS_SERVICE_ACCOUNT_KEY=bad_pem),
            base_env(GWS_APPLICATIONS="Login"),
            base_env(GWS_APPLICATIONS="../users"),
            base_env(GWS_APPLICATIONS=" , "),
            base_env(GWS_PAGE_SIZE="0"),
            base_env(GWS_PAGE_SIZE="1001"),
            base_env(GWS_CUSTOMER_ID="C03/../x"),
        ]
        for env in cases:
            with self.subTest(env={k: v[:40] for k, v in env.items()}), self.assertRaises(c.BridgeError):
                c.load_config(env)
        with self.assertRaisesRegex(c.BridgeError, "not both"):
            c.load_config(base_env(GWS_SERVICE_ACCOUNT_KEY_FILE="/nonexistent/key.json"))
        cfg = c.load_config(base_env())
        self.assertEqual(cfg["api_url"], "https://admin.googleapis.com")
        self.assertEqual(cfg["token_url"], "https://oauth2.googleapis.com/token")
        self.assertEqual(cfg["apps"], ["login", "admin", "token", "saml", "chrome", "drive"])

    def test_a_bad_key_error_never_shows_the_key(self):
        broken = KEY["pkcs8"].replace("\n-----END", "!!\n-----END")
        with self.assertRaises(c.BridgeError) as cm:
            c.load_config(base_env(GWS_SERVICE_ACCOUNT_KEY=key_json(broken)))
        self.assertNotIn(KEY["pkcs8"].splitlines()[1][:30], str(cm.exception))

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2026, 10, 13, 1, 10, 4, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-13T01:10:04Z", want), ("2026-10-13T01:10:04.218Z", want + 0.218),
                               ("2026-10-13T01:10:04.2Z", want + 0.2), ("2026-10-13T12:10:04.218+11:00", want + 0.218),
                               ("2026-10-13T01:10:04.123456789Z", want + 0.123456), (str(int(want)), want), (want, want)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.activities["login"] = [activity(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "token endpoint": self.cfg(GWS_TOKEN_URL=f"{r.base}/token"),
                     "Reports API": self.cfg(GWS_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved()["apps"]["login"])
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

    def test_times_read_alike_on_python_3_9_to_3_13(self):
        # Z or z, an offset with or without its colon, and 0 to 9 fraction digits. Before 3.11,
        # fromisoformat took no Z, no +1000 and no fraction but 3 or 6 digits; no version takes z.
        at = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        for zone, minutes in (("Z", 0), ("z", 0), ("+10:00", 600), ("+1000", 600), ("-05:30", -330), ("-0530", -330)):
            local = (at + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
            for digits in range(10):
                fraction = "123456789"[:digits]
                text = local + ("." if fraction else "") + fraction + zone
                expected = at + timedelta(microseconds=int((fraction + "000000")[:6]))
                with self.subTest(text=text):
                    self.assertAlmostEqual(c._parse_time(text), expected.timestamp(), places=5)


class SigningTest(unittest.TestCase):
    def test_signature_verifies_with_the_public_key(self):
        cfg = c.load_config(base_env())
        claims = verify_jwt(c.service_account_jwt(cfg, now=1791853804), KEY)
        self.assertEqual(claims["iat"], 1791853804)
        self.assertEqual(claims["exp"], 1791853804 + 3600)

    def test_pkcs1_and_pkcs8_read_the_same_key(self):
        a, b = c.rsa_private_key(KEY["pkcs8"]), c.rsa_private_key(KEY["pkcs1"])
        self.assertEqual(a, b)
        self.assertEqual((a["n"], a["e"]), (KEY["n"], KEY["e"]))
        self.assertEqual(c.rs256(a, b"x"), c.rs256(b, b"x"))

    def test_keys_that_are_not_rsa_or_too_small_are_refused(self):
        for pem in ("", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----", make_key(seed=3, bits=512)["pkcs8"]):
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
        for value in ("-1", "0", "1001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^GWS_PAGE_SIZE must be between 1 and 1,000$"):
                self.load(GWS_PAGE_SIZE=value)
        self.assertEqual(self.load(GWS_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(GWS_PAGE_SIZE="1000")["page_size"], 1000)


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
