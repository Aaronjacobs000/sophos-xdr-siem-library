"""Unit tests for onepassword_events_bridge.py against a local mock server.

The mock serves the 1Password Events API shapes from 1Password's Events API reference:
GET /api/v2/auth/introspect ({"uuid", "issued_at", "features", "account_uuid"}), and
POST /api/v2/signinattempts, /api/v2/itemusages and /api/v2/auditevents, each taking a ResetCursor
({"limit", "start_time"}) or {"cursor"} and answering {"cursor", "has_more", "items"}, with
'Authorization: Bearer <token>' and the ErrorResponse {"status", "message"} on errors, plus a
Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/1password-events -p 'test_*.py' -v
"""
import base64
import contextlib
import gc
import gzip
import io
import json
import logging
import os
import sys
import tempfile
import threading
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onepassword_events_bridge as c  # noqa: E402

TOKEN = "test-1password-events-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
PATHS = {"/api/v2/signinattempts": "signinattempts", "/api/v2/itemusages": "itemusages", "/api/v2/auditevents": "auditevents"}


def ts(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signin(i, when, category="success"):
    return {"uuid": f"SIGNIN{i:020d}", "session_uuid": f"SESSION{i:019d}", "timestamp": ts(when), "category": category,
            "type": "credentials_ok" if category == "success" else "password_secret_bad", "country": "AU",
            "target_user": {"uuid": "USER0000000000000000000001", "name": "Pat Example", "email": f"user{i}@example.com"},
            "client": {"app_name": "1Password Browser Extension", "app_version": "20240", "platform_name": "Chrome",
                       "platform_version": "141.0", "os_name": "MacOSX", "os_version": "15.6", "ip_address": "203.0.113.10"},
            "location": {"country": "Australia", "region": "New South Wales", "city": "Sydney", "latitude": -33.8, "longitude": 151.2}}


def usage(i, when):
    return {"uuid": f"USAGE{i:021d}", "timestamp": ts(when), "used_version": 3, "vault_uuid": "VAULT00000000000000000001",
            "item_uuid": f"ITEM{i:022d}", "user": {"uuid": "USER0000000000000000000001", "name": "Pat Example", "email": "pat@example.com"},
            "client": {"app_name": "1Password for Mac", "app_version": "81000", "platform_name": "MacBook Pro", "platform_version": "arm64",
                       "os_name": "MacOSX", "os_version": "15.6", "ip_address": "198.51.100.20"}, "action": "reveal"}


def audit(i, when):
    return {"uuid": f"AUDIT{i:021d}", "timestamp": ts(when), "actor_uuid": "USER0000000000000000000002",
            "actor_details": {"uuid": "USER0000000000000000000002", "name": "Sam Admin", "email": "admin@example.com"},
            "action": "grant", "object_type": "vault", "object_uuid": "VAULT00000000000000000001", "aux_id": 100 + i,
            "aux_uuid": "USER0000000000000000000001", "aux_info": "R",
            "session": {"uuid": "SESSION00000000000000000009", "login_time": ts(when), "device_uuid": "DEVICE000000000000000001", "ip": "198.51.100.30"}}


class Mock:
    def __init__(self):
        self.events = {"signinattempts": [], "itemusages": [], "auditevents": []}
        self.features = ["auditevents", "itemusages", "signinattempts"]
        self.page_size = 2
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.bodies = []


def make_cursor(feature, position, limit):
    return base64.urlsafe_b64encode(json.dumps({"f": feature, "p": position, "l": limit}).encode()).decode()


def read_cursor(cursor):
    return json.loads(base64.urlsafe_b64decode(cursor.encode()))


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

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, {"status": 401, "message": "Unauthorized access"})
        if self.path != "/api/v2/auth/introspect":
            return self._send(404, {"status": 404, "message": "Not found"})
        self._send(200, {"uuid": "INTEGRATION000000000000001", "issued_at": "2026-10-01T00:00:00Z",
                         "features": m.features, "account_uuid": "ACCOUNT0000000000000000001"})

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
        if self.path in PATHS:
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                return self._send(401, {"status": 401, "message": "Unauthorized access"})
            if m.codes:
                code = m.codes.pop(0)
                return self._send(code, {"status": code, "message": "try again"})
            feature = PATHS[self.path]
            req = json.loads(body)
            m.bodies.append((feature, req))
            rows = m.events[feature]
            if "cursor" in req:
                cur = read_cursor(req["cursor"])
                position, limit = cur["p"], cur["l"]
            else:
                if not isinstance(req.get("limit"), int) or not 1 <= req["limit"] <= 1000:
                    return self._send(400, {"Error": {"Message": "Invalid limit"}})
                start = req.get("start_time")
                position = sum(1 for r in rows if start and r["timestamp"] < start)
                limit = req["limit"]
            size = min(limit, m.page_size)
            chunk = rows[position:position + size]
            position += len(chunk)
            return self._send(200, {"cursor": make_cursor(feature, position, limit), "has_more": position < len(rows), "items": chunk})
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


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_PAGE_LIMIT", "page_limit", 1000, 100, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


class BridgeTest(unittest.TestCase):
    def setUp(self):
        # A test that leaves a socket or file open fails: tearDown collects garbage and checks
        # for ResourceWarnings. Other warnings print as usual.
        self.leaks = []
        self._warnings = warnings.catch_warnings()
        self._warnings.__enter__()
        warnings.simplefilter("always", ResourceWarning)
        show = warnings.showwarning
        warnings.showwarning = lambda m, c, *a, **k: self.leaks.append(str(m)) if issubclass(c, ResourceWarning) else show(m, c, *a, **k)
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
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration", "NGSIEM_INGEST_KEY": INGEST_KEY,
             "ONEPASSWORD_EVENTS_URL": self.base, "ONEPASSWORD_EVENTS_TOKEN": TOKEN, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self, kind=None):
        rows = [line for post in self.mock.ingested for line in post["lines"]]
        return [r for r in rows if kind is None or r["onepassword_record"] == kind]

    def test_features_are_paged_tagged_and_in_order(self):
        self.mock.events["signinattempts"] = [signin(i, self.ago(60 - i)) for i in range(5)]
        self.mock.events["itemusages"] = [usage(i, self.ago(30 - i)) for i in range(3)]
        self.mock.events["auditevents"] = [audit(i, self.ago(20 - i)) for i in range(2)]
        counts = c.run_once(self.cfg())
        self.assertEqual(counts, {"signinattempts": 5, "itemusages": 3, "auditevents": 2})
        self.assertEqual([r["target_user"]["email"] for r in self.sent("signin_attempt")], [f"user{i}@example.com" for i in range(5)])
        self.assertEqual(len(self.sent("item_usage")), 3)
        self.assertEqual(len(self.sent("audit_event")), 2)
        first = self.sent()[0]
        self.assertEqual({k: v for k, v in first.items() if k != "onepassword_record"}, self.mock.events["signinattempts"][0])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"onepassword_record":"signin_attempt"'))
        # The first request of each feature is a ResetCursor; the pages after it carry the cursor.
        signin_bodies = [b for f, b in self.mock.bodies if f == "signinattempts"]
        self.assertEqual(set(signin_bodies[0]), {"limit", "start_time"})
        self.assertEqual(signin_bodies[0]["limit"], 1000)
        self.assertTrue(all(set(b) == {"cursor"} for b in signin_bodies[1:]))
        self.assertEqual(len(signin_bodies), 3)
        self.assertEqual(self.mock.requests[0][1], "/api/v2/auth/introspect")

    def test_next_run_resumes_from_the_saved_cursor(self):
        self.mock.events["signinattempts"] = [signin(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg(ONEPASSWORD_FEATURES="signinattempts")
        c.run_once(cfg)
        with open(self.state) as fh:
            saved = json.load(fh)["signinattempts"]["cursor"]
        self.mock.ingested.clear()
        self.mock.bodies.clear()
        self.mock.events["signinattempts"].append(signin(9, self.now))
        c.run_once(cfg)
        self.assertEqual([r["uuid"] for r in self.sent()], [signin(9, self.now)["uuid"]])
        self.assertEqual(self.mock.bodies[0], ("signinattempts", {"cursor": saved}))

    def test_lookback_sets_the_first_start_time(self):
        self.mock.events["auditevents"] = [audit(0, self.now - timedelta(days=3)), audit(1, self.ago(60))]
        c.run_once(self.cfg(ONEPASSWORD_FEATURES="auditevents", BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["uuid"] for r in self.sent()], [audit(1, self.now)["uuid"]])
        start = datetime.strptime(self.mock.bodies[0][1]["start_time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.assertAlmostEqual((self.now - start).total_seconds(), 86400, delta=120)

    def test_cursor_moves_only_after_ingest_accepts_a_page(self):
        self.mock.events["itemusages"] = [usage(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(ONEPASSWORD_FEATURES="itemusages"))
        with open(self.state) as fh:
            saved = read_cursor(json.load(fh)["itemusages"]["cursor"])
        self.assertEqual(saved["p"], 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(ONEPASSWORD_FEATURES="itemusages"))
        self.assertEqual([r["item_uuid"] for r in self.sent()], [usage(i, self.now)["item_uuid"] for i in (2, 3)])

    def test_a_feature_the_token_lacks_stops_before_reading(self):
        self.mock.features = ["signinattempts"]
        self.mock.events["signinattempts"] = [signin(0, self.ago(5))]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("itemusages, auditevents", str(cm.exception))
        self.assertEqual(self.mock.bodies, [])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))
        c.run_once(self.cfg(ONEPASSWORD_FEATURES="signinattempts"))
        self.assertEqual(len(self.sent()), 1)

    def test_a_refused_token_stops_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(ONEPASSWORD_EVENTS_TOKEN="wrong-token-0000000000"))
        self.assertIn("HTTP 401", str(cm.exception))
        self.assertIn("ONEPASSWORD_EVENTS_TOKEN", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_a_rejected_request_names_the_api_message(self):
        # The OpenAPI spec's error shape, {"Error": {"Message": ...}}, from the mock's limit check.
        cfg = self.cfg(ONEPASSWORD_FEATURES="auditevents")
        cfg["page_limit"] = 5000
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 400\): Invalid limit"):
            c.run_once(cfg)
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events["signinattempts"] = [signin(i, self.ago(10 - i)) for i in range(3)]
        self.mock.events["auditevents"] = [audit(0, self.ago(5))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["onepassword_record"] for x in lines], ["signin_attempt"] * 3 + ["audit_event"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events["signinattempts"] = [signin(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(ONEPASSWORD_FEATURES="signinattempts"))
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.page_size = 50
        self.mock.events["auditevents"] = [audit(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(ONEPASSWORD_FEATURES="auditevents", BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events["signinattempts"] = [signin(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(ONEPASSWORD_EVENTS_TOKEN="another-wrong-token-000000"))
        logged = self.logbuf.getvalue()
        self.assertIn("signinattempts", logged)
        for secret in (TOKEN, INGEST_KEY, "00000000-example-integration", "another-wrong-token-000000"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_unknown_features_and_missing_values(self):
        with self.assertRaises(c.BridgeError):
            c.load_config({"ONEPASSWORD_EVENTS_URL": "http://events.example.com", "ONEPASSWORD_EVENTS_TOKEN": TOKEN})
        with self.assertRaises(c.BridgeError):
            c.load_config({"ONEPASSWORD_EVENTS_TOKEN": TOKEN, "ONEPASSWORD_FEATURES": "signinattempts,vaults"})
        with self.assertRaises(c.BridgeError):
            c.load_config({"ONEPASSWORD_EVENTS_TOKEN": TOKEN, "BRIDGE_PAGE_LIMIT": "5000"})
        with self.assertRaises(c.BridgeError):
            c.load_config({})
        cfg = c.load_config({"ONEPASSWORD_EVENTS_TOKEN": TOKEN})
        self.assertEqual(cfg["api_url"], "https://events.1password.com")
        self.assertEqual(cfg["features"], ["signinattempts", "itemusages", "auditevents"])

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.events["signinattempts"] = [signin(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Events API": self.cfg(ONEPASSWORD_EVENTS_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state))
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


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config({"ONEPASSWORD_EVENTS_TOKEN": TOKEN})
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


if __name__ == "__main__":
    unittest.main()
