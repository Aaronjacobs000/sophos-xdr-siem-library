"""Unit tests for google_cloud_pubsub_bridge.py against a local mock server.

The mock serves the shapes in Google's OAuth 2.0 service account docs and the Pub/Sub REST
reference: POST /token with grant_type urn:ietf:params:oauth:grant-type:jwt-bearer and an RS256
JWT, answering {"access_token", "expires_in", "token_type"}; POST
/v1/projects/<p>/subscriptions/<s>:pull with {"maxMessages"}, answering {"receivedMessages": [{"ackId",
"message": {"data", "attributes", "messageId", "publishTime"}, "deliveryAttempt"}]} or {} when there are
none; POST ...:acknowledge with {"ackIds"}, answering {}; and {"error": {"code", "message", "status"}} on
errors. A message not acknowledged comes back on a later pull, as after its acknowledgement deadline.
Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/google-cloud-pubsub -p 'test_*.py' -v
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import google_cloud_pubsub_bridge as c  # noqa: E402

SA_EMAIL = "ngsiem-bridge@example-project.iam.gserviceaccount.example"
SUB = "projects/example-project/subscriptions/ngsiem-logs"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


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


# ---------------------------------------------------------------- messages

def log_entry(i):
    """A Cloud DNS query log entry, as a Cloud Logging sink publishes it."""
    return {"insertId": f"1x2y3z4a5b{i:04d}", "jsonPayload": {"queryName": f"host{i}.example.com.", "queryType": "A",
                                                             "responseCode": "NOERROR", "sourceIP": "192.0.2.5", "protocol": "UDP"},
            "logName": "projects/example-project/logs/dns.googleapis.com%2Fdns_queries", "resource": {"type": "dns_query"},
            "severity": "INFO", "timestamp": "2026-10-20T01:02:03.456789Z"}


def message(i, data=None):
    raw = json.dumps(log_entry(i)).encode() if data is None else data
    return {"data": base64.b64encode(raw).decode(), "attributes": {"logging.googleapis.com/timestamp": "2026-10-20T01:02:03.456789Z"},
            "messageId": f"1234567890{i:04d}", "publishTime": "2026-10-20T01:02:04.5Z"}


class Mock:
    def __init__(self):
        self.queue = []          # messages not yet acknowledged
        self.outstanding = {}    # ackId -> message, handed out and not yet acknowledged
        self.acked = []
        self.pulls = []
        self.token_requests = []
        self.tokens = []
        self.answers = []        # statuses to answer :pull with instead, in order
        self.ack_answers = []
        self.token_answers = []
        self.page_cap = 1000
        self.expires_in = 3600
        self.duplicate = False
        self.ingest_codes = []
        self.ingested = []
        self.key = KEY


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, status, message):
        self._send(code, {"error": {"code": code, "message": message, "status": status}})

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == "/token":
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append(form)
            if m.token_answers:
                return self._error(m.token_answers.pop(0), "test", "test status")
            claims = verify_jwt(form.get("assertion", [""])[0], m.key)
            if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"] or not claims:
                return self._send(400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
            token = f"ya29.test-token-{len(m.tokens):04d}-not-real"
            m.tokens.append(token)
            m.token_claims = claims
            return self._send(200, {"access_token": token, "expires_in": m.expires_in, "token_type": "Bearer"})
        if url.path.startswith(f"/v1/{SUB}:"):
            auth = self.headers.get("Authorization") or ""
            if not auth.startswith("Bearer ") or auth[len("Bearer "):] not in m.tokens:
                return self._error(401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
            req = json.loads(body)
            action = url.path.rsplit(":", 1)[1]
            if action == "pull":
                m.pulls.append({"body": req, "headers": dict(self.headers)})
                if m.answers:
                    code = m.answers.pop(0)
                    return self._error(code, {403: "PERMISSION_DENIED", 404: "NOT_FOUND", 400: "INVALID_ARGUMENT"}.get(code, "UNAVAILABLE"),
                                       "test status")
                # Messages handed out before and not acknowledged come back, as after their deadline.
                m.queue = list(m.outstanding.values()) + m.queue
                m.outstanding = {}
                take = m.queue[:min(int(req.get("maxMessages", 1)), m.page_cap)]
                m.queue = m.queue[len(take):]
                out = []
                for i, msg in enumerate(take):
                    ack = f"ack-{msg['messageId']}-{len(m.pulls)}-{i}"
                    m.outstanding[ack] = msg
                    out.append({"ackId": ack, "message": msg, "deliveryAttempt": 1})
                if m.duplicate and out:
                    ack = out[0]["ackId"] + "-again"
                    m.outstanding[ack] = out[0]["message"]
                    out.append({"ackId": ack, "message": out[0]["message"], "deliveryAttempt": 2})
                return self._send(200, {"receivedMessages": out} if out else {})
            if action == "acknowledge":
                if m.ack_answers:
                    return self._error(m.ack_answers.pop(0), "UNAVAILABLE", "test status")
                for ack in req.get("ackIds") or []:
                    if m.outstanding.pop(ack, None) is not None:
                        m.acked.append(ack)
                return self._send(200, {})
            return self._error(404, "NOT_FOUND", "Method not found.")
        if url.path.startswith("/v1/"):
            return self._error(404, "NOT_FOUND", f"Resource not found (resource={url.path.split(':')[0][4:]}).")
        if not url.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
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
    ("PUBSUB_MAX_MESSAGES", "max_messages", 1000, 500, int, 1000),
    ("PUBSUB_MAX_PULLS", "max_pulls", 100, 50, int, 10000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"PUBSUB_SERVICE_ACCOUNT_KEY": key_json(), "PUBSUB_SUBSCRIPTION": SUB}
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
        self.logbuf = io.StringIO()
        self.handler = logging.StreamHandler(self.logbuf)
        c.LOG.addHandler(self.handler)
        c.LOG.setLevel(logging.DEBUG)
        self._sleep = c.time.sleep
        self.slept = []
        c.time.sleep = self.slept.append

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
                     PUBSUB_API_URL=self.base, PUBSUB_TOKEN_URL=f"{self.base}/token")
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("PUBSUB_API_URL", "PUBSUB_TOKEN_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_log_entries_are_sent_as_they_were_published_and_acknowledged(self):
        self.mock.queue = [message(i) for i in range(3)]
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual(self.sent(), [log_entry(i) for i in range(3)])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"insertId":"1x2y3z4a5b0000","jsonPayload":'))
        self.assertEqual(len(self.mock.acked), 3)
        self.assertEqual(self.mock.queue, [])
        self.assertEqual(self.mock.outstanding, {})
        # Pulls until one comes back empty.
        self.assertEqual(len(self.mock.pulls), 2)
        self.assertEqual(self.mock.pulls[0]["body"], {"maxMessages": 1000})
        headers = {k.lower(): v for k, v in self.mock.pulls[0]["headers"].items()}
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["authorization"], f"Bearer {self.mock.tokens[0]}")

    def test_messages_are_pulled_until_none_are_left_or_the_pull_limit(self):
        self.mock.page_cap = 2
        self.mock.queue = [message(i) for i in range(7)]
        self.assertEqual(c.run_once(self.cfg(PUBSUB_MAX_PULLS="2", PUBSUB_MAX_MESSAGES="2")), 4)
        self.assertEqual(len(self.mock.pulls), 2)
        self.assertEqual(len(self.mock.queue), 3)
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual([r["insertId"] for r in self.sent()], [log_entry(i)["insertId"] for i in range(7)])

    def test_a_message_is_acknowledged_only_after_ingest_accepts_it(self):
        self.mock.queue = [message(i) for i in range(3)]
        self.mock.ingest_codes = [400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg())
        self.assertEqual(self.mock.acked, [])
        # Not acknowledged, so Pub/Sub delivers them again.
        self.mock.ingested.clear()
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual(len(self.mock.acked), 3)

    def test_a_message_delivered_twice_in_a_run_is_sent_once_and_both_acknowledged(self):
        self.mock.queue = [message(0), message(1)]
        self.mock.duplicate = True
        self.assertEqual(c.run_once(self.cfg()), 2)
        self.assertEqual(len(self.sent()), 2)
        self.assertEqual(len(self.mock.acked), 3)

    def test_data_that_is_not_a_json_object_is_sent_with_the_message(self):
        self.mock.queue = [message(0, b"plain text line"), message(1, b"[1, 2]"), message(2, b"\xff\xfe")]
        self.mock.queue.append({**message(3), "data": "not base64!"})
        c.run_once(self.cfg())
        recs = self.sent()
        self.assertEqual([r["pubsub_data"] for r in recs], ["plain text line", "[1, 2]", "��", ""])
        self.assertEqual((recs[0]["pubsub_subscription"], recs[0]["pubsub_message_id"], recs[0]["pubsub_publish_time"]),
                         (SUB, "12345678900000", "2026-10-20T01:02:04.5Z"))
        self.assertEqual(recs[0]["pubsub_attributes"], {"logging.googleapis.com/timestamp": "2026-10-20T01:02:03.456789Z"})

    def test_the_token_request_is_signed_with_only_the_pubsub_scope(self):
        self.mock.queue = [message(0)]
        cfg = self.cfg()
        client = c.PubSub(cfg)
        c.run_once(cfg, client=client)
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        claims = self.mock.token_claims
        self.assertEqual((claims["iss"], claims["scope"], claims["aud"]), (SA_EMAIL, "https://www.googleapis.com/auth/pubsub", f"{self.base}/token"))
        self.assertNotIn("sub", claims)
        self.assertEqual(claims["exp"] - claims["iat"], 3600)
        # A refused token is renewed once.
        self.mock.tokens.clear()
        self.mock.queue = [message(1)]
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.assertEqual(len(self.sent()), 2)

    def test_a_pkcs1_key_signs_too(self):
        self.mock.queue = [message(0)]
        c.run_once(self.cfg(PUBSUB_SERVICE_ACCOUNT_KEY=key_json(KEY["pkcs1"])))
        self.assertEqual(len(self.sent()), 1)

    def test_a_key_file_is_read(self):
        path = os.path.join(self.tmp.name, "key.json")
        with open(path, "w") as fh:
            fh.write(key_json())
        self.mock.queue = [message(0)]
        c.run_once(self.cfg(PUBSUB_SERVICE_ACCOUNT_KEY=None, PUBSUB_SERVICE_ACCOUNT_KEY_FILE=path))
        self.assertEqual(len(self.sent()), 1)

    def test_a_refused_key_stops_with_google_s_message(self):
        self.mock.key = OTHER_KEY
        with self.assertRaisesRegex(c.BridgeError, r"Google refused the service account token request \(HTTP 400 invalid_grant\): "
                                    r"Invalid JWT Signature\.; check that the key is current"):
            c.run_once(self.cfg())

    def test_http_errors_stop_with_clear_errors(self):
        cases = [(403, r"HTTP 403 PERMISSION_DENIED\): test status; give the service account the Pub/Sub Subscriber role"),
                 (404, r"Google has no subscription projects/example-project/subscriptions/ngsiem-logs \(HTTP 404 NOT_FOUND\)"),
                 (400, r"Google rejected the pull request \(HTTP 400 INVALID_ARGUMENT\): test status")]
        for code, message_ in cases:
            with self.subTest(code=code):
                self.mock.answers = [code]
                with self.assertRaisesRegex(c.BridgeError, message_):
                    c.run_once(self.cfg())

    def test_the_subscription_goes_in_the_path(self):
        client = c.PubSub(self.cfg(PUBSUB_SUBSCRIPTION="projects/example.com:example-project/subscriptions/logs~a+b%c"))
        self.assertEqual(client.base, f"{self.base}/v1/projects/example.com:example-project/subscriptions/logs~a%2Bb%25c")

    def test_dry_run_pulls_once_prints_and_acknowledges_nothing(self):
        self.mock.page_cap = 2
        self.mock.queue = [message(i) for i in range(4)]
        out = io.StringIO()
        self.assertEqual(c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out), 2)
        self.assertEqual([json.loads(x)["insertId"] for x in out.getvalue().splitlines()], [log_entry(i)["insertId"] for i in range(2)])
        self.assertEqual(len(self.mock.pulls), 1)
        self.assertEqual((self.mock.ingested, self.mock.acked), ([], []))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.queue = [message(i) for i in range(3)]
        self.mock.answers = [429, 503]
        self.mock.token_answers = [500]
        self.mock.ack_answers = [503]
        self.mock.ingest_codes = [429]
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual(len(self.mock.acked), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.queue = [message(i) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1000"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.queue = [message(0)]
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        self.mock.key = OTHER_KEY
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("pull request", logged)
        for secret in (INGEST_KEY, "00000000-example-integration", self.mock.tokens[0], "BEGIN PRIVATE KEY", KEY["pkcs8"][40:80]):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(PUBSUB_SUBSCRIPTION=None),
            base_env(PUBSUB_SUBSCRIPTION="ngsiem-logs"),
            base_env(PUBSUB_SUBSCRIPTION="projects/example-project/topics/ngsiem-logs"),
            base_env(PUBSUB_SUBSCRIPTION="projects/example-project/subscriptions/../x"),
            base_env(PUBSUB_SERVICE_ACCOUNT_KEY=None),
            base_env(PUBSUB_SERVICE_ACCOUNT_KEY="not json"),
            base_env(PUBSUB_SERVICE_ACCOUNT_KEY=json.dumps({"type": "authorized_user"})),
            base_env(PUBSUB_SERVICE_ACCOUNT_KEY=key_json("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")),
            base_env(PUBSUB_SERVICE_ACCOUNT_KEY_FILE="/nonexistent/key.json", PUBSUB_SERVICE_ACCOUNT_KEY=None),
            base_env(PUBSUB_SERVICE_ACCOUNT_KEY_FILE="/nonexistent/key.json"),
            base_env(PUBSUB_API_URL="http://pubsub.example.com"),
            base_env(PUBSUB_API_URL="https://pubsub.googleapis.com/v1"),
            base_env(PUBSUB_TOKEN_URL="http://oauth2.example.com/token"),
            base_env(PUBSUB_MAX_MESSAGES="0"),
            base_env(PUBSUB_MAX_MESSAGES="1001"),
            base_env(PUBSUB_MAX_PULLS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env={k: v[:60] for k, v in env.items()}), self.assertRaises(c.BridgeError) as cm:
                c.load_config(env)
            self.assertNotIn("AAAA", str(cm.exception))
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["api_url"], cfg["token_url"], cfg["max_messages"], cfg["max_pulls"]),
                         ("https://pubsub.googleapis.com", "https://oauth2.googleapis.com/token", 1000, 100))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the token to another URL, so the run fails instead, and
        # nothing reaches the redirect's target.
        self.mock.queue = [message(0)]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Pub/Sub": self.cfg(PUBSUB_API_URL=r.base), "token": self.cfg(PUBSUB_TOKEN_URL=f"{r.base}/token")}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, cfg in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        acked = len(self.mock.acked)
                        with self.assertRaisesRegex(c.BridgeError, rf"answered with a redirect \(HTTP {code}\), which the bridge refuses"):
                            c.run_once(cfg)
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertEqual(len(self.mock.acked), acked)
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

    def test_max_messages_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "1001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^PUBSUB_MAX_MESSAGES must be between 1 and 1,000$"):
                self.load(PUBSUB_MAX_MESSAGES=value)
        self.assertEqual(self.load(PUBSUB_MAX_MESSAGES="1")["max_messages"], 1)


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
