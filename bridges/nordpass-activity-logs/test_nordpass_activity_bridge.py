"""Unit tests for nordpass_activity_bridge.py against a local mock server.

The mock serves the NordPass Activity Logs API as its article documents it: POST
/activities/query with 'Authorization: <token>' and a JSON body {"timestamp_from",
"timestamp_to", "per_page", "page"}, answering {"data": [{"type", "action", "timestamp",
"organization_uuid", "user": {"uuid", "email"}, "metadata"}], "metadata": {"total", "per_page",
"current_page", "total_pages"}}; 400 for a window over 90 days, a timestamp_to in the future, a
page past the last one or past the 10,000 most recent results; 401 without a token and 403
"[authorization error] invalid token" with a wrong one. Plus a Sophos NG-SIEM HTTP Ingest
endpoint. No real service is called.

  python3 -m unittest discover -s bridges/nordpass-activity-logs -p 'test_*.py' -v
"""
import contextlib
import gc
import gzip
import io
import json
import logging
import math
import os
import sys
import tempfile
import threading
import time
import unittest
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nordpass_activity_bridge as c  # noqa: E402

TOKEN = "test-nordpass-events-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ORG = "235e26d1-dfba-4f40-ba63-d83b6210c7de"


def activity(i, ts, kind="login", action="user_login_successful", metadata=None):
    return {"type": kind, "action": action, "timestamp": int(ts), "organization_uuid": ORG,
            "user": {"uuid": f"726163f5-d18e-41cc-8aa4-{i:012d}", "email": f"user{i}@example.com"},
            "metadata": metadata if metadata is not None else {"ip_address": "203.0.113.10", "provider": "business_auth"}}


class Mock:
    def __init__(self):
        self.activities = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.cap = 10000


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

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/activities/query":
            auth = self.headers.get("Authorization")
            if not auth:
                return self._send(401, {"message": "Unauthorized"})
            if auth != TOKEN:
                return self._send(403, {"message": "[authorization error] invalid token"})
            if m.codes:
                code = m.codes.pop(0)
                return self._send(code, {"message": "try again"})
            q = json.loads(body)
            m.queries.append(q)
            start, end, per, page = q.get("timestamp_from"), q.get("timestamp_to"), q.get("per_page", 30), q.get("page", 1)
            if not isinstance(start, int) or not isinstance(end, int) or start > end or end > time.time() or end - start > 90 * 86400:
                return self._send(400, {"message": "Invalid request payload"})
            if not 1 <= per <= 100 or page < 1:
                return self._send(400, {"message": "Invalid request payload"})
            rows = sorted((a for a in m.activities if start <= a["timestamp"] <= end), key=lambda a: a["timestamp"], reverse=True)
            total = len(rows)
            pages = math.ceil(total / per) if total else 0
            if (pages and page > pages) or page * per > m.cap + per:
                return self._send(400, {"message": "Invalid request payload"})
            reachable = rows[:m.cap]
            chunk = reachable[(page - 1) * per:page * per]
            return self._send(200, {"data": chunk, "metadata": {"total": total, "per_page": per, "current_page": page, "total_pages": pages}})
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
    ("NORDPASS_PER_PAGE", "per_page", 100, 50, int, 10 ** 9),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 600, 300, int, 10 ** 9),
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
        c.time.sleep = lambda s: None
        self.now = int(time.time())

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
             "NORDPASS_API_URL": self.base, "NORDPASS_TOKEN": TOKEN, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - minutes * 60

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_pages_are_read_tagged_and_sent_oldest_first(self):
        self.mock.activities = [activity(i, self.ago(50 - i)) for i in range(7)]
        self.assertEqual(c.run_once(self.cfg(NORDPASS_PER_PAGE="3")), 7)
        rows = self.sent()
        self.assertEqual([r["timestamp"] for r in rows], sorted(a["timestamp"] for a in self.mock.activities))
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"nordpass_record":"activity","type":"login"'))
        self.assertEqual({k: v for k, v in rows[0].items() if k != "nordpass_record"}, self.mock.activities[0])
        # One fixed window, read page by page.
        self.assertEqual([q["page"] for q in self.mock.queries], [1, 2, 3])
        self.assertEqual(len({(q["timestamp_from"], q["timestamp_to"]) for q in self.mock.queries}), 1)
        self.assertEqual({q["per_page"] for q in self.mock.queries}, {3})
        self.assertLess(self.mock.queries[0]["timestamp_to"], self.now)

    def test_lookback_sets_the_first_window(self):
        self.mock.activities = [activity(0, self.now - 3 * 86400), activity(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24", BRIDGE_OVERLAP_SECONDS="0"))
        self.assertEqual([r["user"]["email"] for r in self.sent()], ["user1@example.com"])
        q = self.mock.queries[0]
        self.assertAlmostEqual(q["timestamp_to"] - q["timestamp_from"], 86400, delta=10)

    def test_a_window_over_90_days_is_split(self):
        self.mock.activities = [activity(0, self.now - 100 * 86400), activity(1, self.now - 30 * 86400)]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS=str(101 * 24)))
        self.assertEqual(len(self.sent()), 2)
        self.assertGreaterEqual(len(self.mock.queries), 2)
        for q in self.mock.queries:
            self.assertLessEqual(q["timestamp_to"] - q["timestamp_from"], 90 * 86400)

    def test_a_window_past_the_result_cap_is_split(self):
        cap = c.MAX_RESULTS
        c.MAX_RESULTS = self.mock.cap = 4
        try:
            self.mock.activities = [activity(i, self.ago(300 - i * 20)) for i in range(10)]
            c.run_once(self.cfg(NORDPASS_PER_PAGE="2"))
        finally:
            c.MAX_RESULTS = cap
        self.assertEqual(sorted(r["user"]["email"] for r in self.sent()), sorted(a["user"]["email"] for a in self.mock.activities))
        self.assertEqual(len(self.sent()), 10)

    def test_next_run_overlaps_and_drops_repeats(self):
        self.mock.activities = [activity(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        # One that reached NordPass late, with a time inside the overlap, and a new one.
        self.mock.activities += [activity(7, self.ago(5), "item_access", "item_viewed", {"platform": "extension"}),
                                 activity(8, self.now - 6, "item_access", "item_copied", {"platform": "extension"})]
        c.run_once(cfg)
        self.assertEqual(sorted(r["action"] for r in self.sent()), ["item_copied", "item_viewed"])

    def test_cursor_moves_only_after_ingest_accepts(self):
        self.mock.activities = [activity(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 4)

    def test_a_refused_token_stops_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(NORDPASS_TOKEN="wrong-token-0000000000"))
        self.assertIn("HTTP 403", str(cm.exception))
        self.assertIn("invalid token", str(cm.exception))
        self.assertIn("NORDPASS_TOKEN", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_a_rejected_query_names_the_api_message(self):
        client = c.NordPass(self.cfg())
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 400\): Invalid request payload"):
            client.query(self.now - 10, self.now + 3600, 1)

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.activities = [activity(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["nordpass_record"] for x in lines], ["activity"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.activities = [activity(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.activities = [activity(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1000"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.activities = [activity(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(NORDPASS_TOKEN="another-wrong-token-000000"))
        logged = self.logbuf.getvalue()
        self.assertIn("activities", logged)
        for secret in (TOKEN, INGEST_KEY, "00000000-example-integration", "another-wrong-token-000000"):
            self.assertNotIn(secret, logged)

    def test_config_regions_and_validation(self):
        self.assertEqual(c.load_config({"NORDPASS_TOKEN": TOKEN})["api_url"], "https://api-activities.eu.nordpass.com")
        self.assertEqual(c.load_config({"NORDPASS_TOKEN": TOKEN, "NORDPASS_REGION": "US"})["api_url"], "https://api-activities.us.nordpass.com")
        for bad in ({"NORDPASS_TOKEN": TOKEN, "NORDPASS_REGION": "au"}, {"NORDPASS_TOKEN": TOKEN, "NORDPASS_PER_PAGE": "500"},
                    {"NORDPASS_TOKEN": TOKEN, "NORDPASS_API_URL": "http://api-activities.example.com"}, {}):
            with self.assertRaises(c.BridgeError):
                c.load_config(bad)

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the token or key to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.activities = [activity(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Activity Logs API": self.cfg(NORDPASS_API_URL=r.base)}
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


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config({"NORDPASS_TOKEN": TOKEN})
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

    def test_negative_interval_is_refused(self):
        self.run_once_raises()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            c.main(["--interval", "-1"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
