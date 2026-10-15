"""Unit tests for zoom_report_bridge.py against a local mock server.

The mock serves the shapes in Zoom's API reference and OpenAPI document: the Server-to-Server
OAuth token endpoint (POST, 'Authorization: Basic base64(client_id:client_secret)', form body
grant_type=account_credentials and account_id; answering {"access_token", "token_type",
"expires_in", "scope", "api_url"}), GET /v2/report/activities ({"from", "to", "page_size",
"next_page_token", "activity_logs": [{email, time, type, ip_address, client_type, version}]}) and
GET /v2/report/operationlogs ({"next_page_token", "page_size", "operation_logs": [{time, operator,
category_type, action, operation_detail}]}), with from and to as dates in UTC, and {"code",
"message"} on failure, including Zoom's per-second and daily 429 messages. Plus a Sophos NG-SIEM
HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/zoom-report-logs -p 'test_*.py' -v
"""
import base64
import contextlib
import gc
import gzip
import io
import json
import logging
import os
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
import zoom_report_bridge as c  # noqa: E402

ACCOUNT = "AbCdEf123456GhIjKl7890"
CLIENT_ID = "testzoomclientid0001"
SECRET = "test-zoom-client-secret-not-real"
TOKEN = "test-zoom-access-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
BASE = {"ZOOM_ACCOUNT_ID": ACCOUNT, "ZOOM_CLIENT_ID": CLIENT_ID, "ZOOM_CLIENT_SECRET": SECRET}


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signin(i, when, kind="Sign in"):
    return {"email": f"user{i}@example.com", "time": iso(when), "type": kind, "ip_address": "203.0.113.10",
            "client_type": "Browser", "version": "6.5.3.12345"}


def operation(i, when, action="Update"):
    return {"time": iso(when), "operator": "admin@example.com", "category_type": "User",
            "action": action, "operation_detail": f"Update user - user{i}@example.com"}


class Mock:
    def __init__(self):
        self.activities = []
        self.operations = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.token_forms = []
        self.refuse_token_once = False
        self.daily_limit = False


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
        if self.headers.get("Authorization") != f"Bearer {TOKEN}" or (m.refuse_token_once and len(m.token_forms) < 2):
            return self._send(401, {"code": 124, "message": "Invalid access token."})
        if m.daily_limit:
            return self._send(429, {"code": 429, "message": "You have reached the maximum daily rate limit for this API. Refer to the response header for details on when you can make another request."},
                              {"Retry-After": "2026-10-16T00:00:00Z"})
        if m.codes:
            code = m.codes.pop(0)
            if code == 429:
                return self._send(429, {"code": 429, "message": "You have reached the maximum per-second rate limit for this API. Try again later."})
            return self._send(code, {"code": code, "message": "try again"})
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.path == "/v2/report/activities":
            rows, key = m.activities, "activity_logs"
        elif parts.path == "/v2/report/operationlogs":
            rows, key = m.operations, "operation_logs"
        else:
            return self._send(404, {"code": 404, "message": "Not found"})
        m.queries.append({"path": parts.path, **q})
        first, last = datetime.strptime(q["from"], "%Y-%m-%d").date(), datetime.strptime(q["to"], "%Y-%m-%d").date()
        if (last - first).days > 31:
            return self._send(400, {"code": 300, "message": "The date range can't exceed one month."})
        rows = [r for r in rows if first <= datetime.strptime(r["time"], "%Y-%m-%dT%H:%M:%SZ").date() <= last]
        rows = sorted(rows, key=lambda r: r["time"], reverse=True)
        size, pos = int(q.get("page_size", 30)), int(q.get("next_page_token") or 0)
        out = {key: rows[pos:pos + size], "page_size": size, "next_page_token": str(pos + size) if pos + size < len(rows) else ""}
        if key == "activity_logs":
            out.update({"from": q["from"], "to": q["to"]})
        return self._send(200, out)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/oauth/token":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            m.token_forms.append(form)
            good = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            if self.headers.get("Authorization") != good or form != {"grant_type": "account_credentials", "account_id": ACCOUNT}:
                return self._send(400, {"reason": "Invalid client_id or client_secret", "error": "invalid_client"})
            return self._send(200, {"access_token": TOKEN, "token_type": "bearer", "expires_in": 3599,
                                    "scope": "report:read:user_activities:admin report:read:operation_logs:admin",
                                    "api_url": "https://api.zoom.us"})
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
    partway through it, as a dropped connection would."""

    def __init__(self, code=200):
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
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b'100\r\n{"partial":')
                self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("ZOOM_PAGE_SIZE", "page_size", 300, 100, int, 300),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 3600, 600, int, 10 ** 9),
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
        self.slept = []
        c.time.sleep = self.slept.append
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
             "ZOOM_API_URL": self.base, "BRIDGE_STATE_FILE": self.state, **BASE}
        e["ZOOM_TOKEN_URL"] = self.base + "/oauth/token"
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self, record=None):
        rows = [line for post in self.mock.ingested for line in post["lines"]]
        return [r for r in rows if record is None or r["zoom_record"] == record]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_both_reports_are_paged_and_tagged(self):
        self.mock.activities = [signin(i, self.ago(50 - i)) for i in range(5)]
        self.mock.operations = [operation(i, self.ago(40 - i)) for i in range(3)]
        self.assertEqual(c.run_once(self.cfg(ZOOM_PAGE_SIZE="2")), 8)
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"zoom_record":"signin","account_id":"' + ACCOUNT + '","email":'))
        signins, ops = self.sent("signin"), self.sent("operation")
        self.assertEqual(len(signins), 5)
        self.assertEqual(len(ops), 3)
        self.assertEqual({k: v for k, v in ops[0].items() if k not in ("zoom_record", "account_id")}, operation(2, self.ago(38)))
        act_q = [q for q in self.mock.queries if q["path"] == "/v2/report/activities"]
        self.assertEqual([q.get("next_page_token") for q in act_q], [None, "2", "4"])
        op_q = [q for q in self.mock.queries if q["path"] == "/v2/report/operationlogs"]
        self.assertEqual({q["category_type"] for q in op_q}, {"all"})
        self.assertEqual(act_q[0]["to"], self.now.strftime("%Y-%m-%d"))
        self.assertEqual(len(self.mock.token_forms), 1)

    def test_whole_days_are_read_again_and_repeats_dropped(self):
        self.mock.activities = [signin(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.mock.activities += [signin(7, self.ago(1))]
        c.run_once(cfg)
        self.assertEqual([r["email"] for r in self.sent()], ["user7@example.com"])

    def test_identical_records_in_the_same_second_are_both_sent(self):
        when = self.ago(10)
        self.mock.activities = [signin(1, when), signin(1, when)]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 2)
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual(self.sent(), [])
        self.mock.activities.append(signin(1, when))
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)

    def test_a_long_lookback_is_read_in_ranges_of_a_month_within_retention(self):
        self.mock.operations = [operation(0, self.now - timedelta(days=70)), operation(1, self.now - timedelta(days=5)),
                                operation(2, self.now - timedelta(days=200))]
        c.run_once(self.cfg(ZOOM_REPORTS="operationlogs", BRIDGE_LOOKBACK_HOURS=str(24 * 400)))
        self.assertEqual(sorted(r["operation_detail"] for r in self.sent()), ["Update user - user0@example.com", "Update user - user1@example.com"])
        spans = [(datetime.strptime(q["from"], "%Y-%m-%d"), datetime.strptime(q["to"], "%Y-%m-%d")) for q in self.mock.queries]
        self.assertTrue(all((b - a).days <= 29 for a, b in spans))
        self.assertTrue(all(spans[i][1] + timedelta(days=1) == spans[i + 1][0] for i in range(len(spans) - 1)))
        self.assertGreaterEqual(spans[0][0], (self.now - timedelta(days=181)).replace(tzinfo=None))

    def test_ranges_cover_every_day_once(self):
        start = datetime(2026, 8, 1, 13, tzinfo=timezone.utc).timestamp()
        now = datetime(2026, 10, 15, 2, tzinfo=timezone.utc).timestamp()
        self.assertEqual(c.ranges(start, now), [("2026-08-01", "2026-08-30"), ("2026-08-31", "2026-09-29"), ("2026-09-30", "2026-10-15")])
        self.assertEqual(c.ranges(now - 60, now), [("2026-10-15", "2026-10-15")])

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.activities = [signin(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(ZOOM_PAGE_SIZE="2", ZOOM_REPORTS="activities"))
        saved = self.saved()["activities"]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(ZOOM_PAGE_SIZE="2", ZOOM_REPORTS="activities"))
        self.assertEqual(sorted(r["email"] for r in self.sent()), ["user0@example.com", "user1@example.com"])
        self.assertIn("until", self.saved()["activities"])

    def test_a_refused_access_token_is_renewed_once(self):
        self.mock.activities = [signin(0, self.ago(5))]
        self.mock.refuse_token_once = True
        c.run_once(self.cfg(ZOOM_REPORTS="activities"))
        self.assertEqual(len(self.mock.token_forms), 2)
        self.assertEqual(len(self.sent()), 1)

    def test_refused_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(ZOOM_CLIENT_SECRET="wrong-secret-0000000000"))
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("Invalid client_id or client_secret", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.activities = [signin(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["zoom_record"] for x in lines], ["signin"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_per_second_limits_and_server_errors_are_retried(self):
        self.mock.activities = [signin(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(ZOOM_REPORTS="activities"))
        self.assertEqual(len(self.sent()), 3)

    def test_the_daily_limit_ends_the_run_as_a_network_error_without_retries(self):
        self.mock.activities = [signin(0, self.ago(5))]
        self.mock.daily_limit = True
        with self.assertRaises(c.RateLimited) as cm:
            c.run_once(self.cfg())
        self.assertIsInstance(cm.exception, c.NetworkError)
        self.assertIn("daily API rate limit", str(cm.exception))
        self.assertEqual(self.slept, [])

    def test_gzip_batches_and_headers(self):
        self.mock.activities = [signin(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="800", ZOOM_REPORTS="activities"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.activities = [signin(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(ZOOM_CLIENT_SECRET="another-wrong-secret-000"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("activities", logged)
        basic = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
        for secret in (SECRET, TOKEN, INGEST_KEY, basic, "00000000-example-integration", "another-wrong-secret-000"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "ZOOM_API_URL": "http://api.zoom.example"}, {**BASE, "ZOOM_TOKEN_URL": "http://zoom.example/oauth/token"},
                    {"ZOOM_CLIENT_ID": CLIENT_ID, "ZOOM_CLIENT_SECRET": SECRET}, {"ZOOM_ACCOUNT_ID": ACCOUNT, "ZOOM_CLIENT_ID": CLIENT_ID},
                    {**BASE, "ZOOM_ACCOUNT_ID": "../x"}, {**BASE, "ZOOM_CLIENT_ID": "a:b"}, {**BASE, "ZOOM_REPORTS": "meetings"},
                    {**BASE, "ZOOM_REPORTS": " , "}, {**BASE, "ZOOM_OPERATION_CATEGORY": "everything"},
                    {**BASE, "ZOOM_PAGE_SIZE": "301"}, {**BASE, "ZOOM_PAGE_SIZE": "0"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "ZOOM_CLIENT_SECRET"}), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["api_url"], cfg["token_url"]), ("https://api.zoom.us", "https://zoom.us/oauth/token"))
        self.assertEqual((cfg["reports"], cfg["category"], cfg["page_size"]), (["activities", "operationlogs"], "all", 300))

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2026, 10, 13, 1, 10, 4, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-13T01:10:04Z", want), ("2026-10-13T01:10:04.5Z", want + 0.5),
                               ("2026-10-13T12:10:04.123456789+11:00", want + 0.123456)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.activities = [signin(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "token endpoint": self.cfg(ZOOM_TOKEN_URL=r.base + "/oauth/token"),
                     "Reports API": self.cfg(ZOOM_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("activities", {}))
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


class RangeTest(unittest.TestCase):
    """A number outside its range stops the bridge with an error that gives the range."""

    def load(self, **extra):
        return c.load_config({**BASE, **extra})

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "301"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^ZOOM_PAGE_SIZE must be between 1 and 300$"):
                self.load(ZOOM_PAGE_SIZE=value)
        self.assertEqual(self.load(ZOOM_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(ZOOM_PAGE_SIZE="300")["page_size"], 300)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config(BASE)
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

    def test_a_used_up_rate_limit_keeps_polling_too(self):
        self.run_once_raises(c.RateLimited("activities report request to api.zoom.us: Zoom's daily API rate limit is used up"))
        self.assertEqual(c.main(["--interval", "300"]), 130)
        self.assertEqual(len(self.calls), 2)

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
