"""Unit tests for cisco_secure_endpoint_bridge.py against a local mock server.

The mock serves the shapes in Cisco's Secure Endpoint API v1 reference and OpenAPI files:
GET /v1/events (start_date ISO 8601 and inclusive, limit, offset, event_type[], group_guid[];
answering {"version", "metadata": {"links": {"self", "next"}, "results": {"total",
"current_item_count", "index", "items_per_page"}}, "data": [event]} newest first), 'Authorization:
Basic base64(client_id:api_key)', {"errors": [{"error_code", "description", "details"}]} on
failure, and 429 with X-RateLimit-Reset (seconds until the hourly limit resets). Plus a Sophos
NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/cisco-secure-endpoint-events -p 'test_*.py' -v
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
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cisco_secure_endpoint_bridge as c  # noqa: E402

CLIENT_ID = "a1b2c3d4e5f6a7b8c9d0"
API_KEY = "test-cisco-api-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
GROUP = "e766a0e9-96da-41b9-b1e8-87dd010d6b68"


def event(i, when, type_id=1090519054, name="Threat Detected"):
    return {"id": 6180351977805840000 + i, "timestamp": int(when.timestamp()), "timestamp_nanoseconds": 548000000,
            "date": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"), "event_type": name,
            "event_type_id": type_id, "detection": "W32.Example.Test", "detection_id": str(6180351977805840385 + i),
            "connector_guid": "538738f5-3a14-4449-933b-86142553de06", "group_guids": [GROUP], "severity": "Medium",
            "computer": {"connector_guid": "538738f5-3a14-4449-933b-86142553de06", "hostname": "WS-EXAMPLE-01",
                         "external_ip": "203.0.113.40", "user": "pat@WS-EXAMPLE-01", "active": True,
                         "network_addresses": [{"ip": "192.0.2.10", "mac": "00:00:5e:00:53:01"}]},
            "file": {"disposition": "Malicious", "file_name": "invoice.exe", "file_path": "\\\\?\\C:\\Users\\pat\\invoice.exe",
                     "identity": {"sha256": "9f2c4e1b7a3d5f60812c3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8"}}}


class Mock:
    def __init__(self):
        self.events = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.rate_reset = "1"
        # Events that arrive between two page requests, as Cisco would add them mid-walk.
        self.arrive_after_first_page = []


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
        if parts.path != "/v1/events":
            return self._send(404, {"version": "v1.2.0", "data": {}, "errors": [{"error_code": 404, "description": "Not Found", "details": "Not Found"}]})
        good = "Basic " + base64.b64encode(f"{CLIENT_ID}:{API_KEY}".encode()).decode()
        if self.headers.get("Authorization") != good:
            return self._send(401, {"version": "v0.1.0", "data": {}, "errors": [
                {"error_code": 401, "description": "Unauthorized", "details": ["Unknown API key or Client ID"]}]})
        if m.codes:
            code = m.codes.pop(0)
            headers = {"X-RateLimit-Limit": "3000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": m.rate_reset} if code == 429 else None
            return self._send(code, {"version": "v1.2.0", "data": {}, "errors": [{"error_code": code, "description": "try again", "details": []}]}, headers)
        q = urllib.parse.parse_qs(parts.query)
        flat = {k: v[0] for k, v in q.items()}
        m.queries.append({**flat, "event_type[]": q.get("event_type[]", []), "group_guid[]": q.get("group_guid[]", [])})
        if "start_date" not in flat:
            return self._send(400, {"version": "v1.2.0", "data": {}, "errors": [{"error_code": 400, "description": "Bad Request", "details": ["start_date"]}]})
        start = c._parse_time(flat["start_date"])
        rows = [e for e in m.events if e["timestamp"] >= start]
        if q.get("event_type[]"):
            rows = [e for e in rows if str(e["event_type_id"]) in q["event_type[]"]]
        rows.sort(key=lambda e: (e["timestamp"], e["id"]), reverse=True)
        limit, offset = int(flat.get("limit", 500)), int(flat.get("offset", 0))
        chunk = rows[offset:offset + limit]
        if offset == 0 and m.arrive_after_first_page:
            m.events.extend(m.arrive_after_first_page)
            m.arrive_after_first_page = []
        base = f"http://{self.headers['Host']}/v1/events"
        links = {"self": f"{base}?{parts.query}"}
        if offset + limit < len(rows):
            # Cisco keeps the other parameters and moves the offset on by the limit.
            links["next"] = f"https://elsewhere.example/v1/events?start_date={urllib.parse.quote(flat['start_date'])}&limit={limit}&offset={offset + limit}"
        return self._send(200, {"version": "v1.2.0", "metadata": {"links": links, "results": {
            "total": len(rows), "current_item_count": len(chunk), "index": offset, "items_per_page": limit}}, "data": chunk})

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
    ("CISCO_SE_PAGE_SIZE", "page_size", 500, 100, int, 10 ** 9),
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
             "CISCO_SE_API_URL": self.base, "CISCO_SE_CLIENT_ID": CLIENT_ID, "CISCO_SE_API_KEY": API_KEY,
             "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_pages_are_read_and_tagged(self):
        self.mock.events = [event(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(CISCO_SE_PAGE_SIZE="2")), 5)
        rows = self.sent()
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"cisco_se_record":"event","event_id":"61803519778058400'))
        # The 64-bit id goes on exactly, as a number and as text.
        newest = rows[0]
        self.assertEqual(newest["id"], 6180351977805840004)
        self.assertEqual(newest["event_id"], "6180351977805840004")
        self.assertIn('"id":6180351977805840004,', self.mock.ingested[0]["raw"])
        self.assertEqual({k: v for k, v in newest.items() if k not in ("cisco_se_record", "event_id")}, event(4, self.ago(46)))
        self.assertEqual([q["offset"] for q in self.mock.queries], ["0", "2", "4"])
        self.assertEqual({q["limit"] for q in self.mock.queries}, {"2"})
        self.assertEqual(len({q["start_date"] for q in self.mock.queries}), 1)

    def test_the_next_link_host_is_never_used(self):
        # The mock's links.next names another host; the bridge works the offset out itself.
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        c.run_once(self.cfg(CISCO_SE_PAGE_SIZE="1"))
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(len(self.mock.queries), 3)

    def test_filters_are_sent_as_arrays(self):
        self.mock.events = [event(0, self.ago(5)), event(1, self.ago(4), 553648130, "Policy Update")]
        c.run_once(self.cfg(CISCO_SE_EVENT_TYPES="1090519054, 553648143", CISCO_SE_GROUP_GUIDS=GROUP))
        q = self.mock.queries[0]
        self.assertEqual(q["event_type[]"], ["1090519054", "553648143"])
        self.assertEqual(q["group_guid[]"], [GROUP])
        self.assertEqual([r["event_type_id"] for r in self.sent()], [1090519054])

    def test_an_event_arriving_mid_walk_is_sent_once(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.arrive_after_first_page = [event(9, self.ago(1))]
        c.run_once(self.cfg(CISCO_SE_PAGE_SIZE="2"))
        ids = [r["event_id"] for r in self.sent()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 4)
        c.run_once(self.cfg(CISCO_SE_PAGE_SIZE="2"))
        ids = [r["event_id"] for r in self.sent()]
        self.assertEqual(len(ids), 5)
        self.assertEqual(len(ids), len(set(ids)))

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1800")
        c.run_once(cfg)
        until = self.saved()["events"]["until"]
        self.mock.ingested.clear()
        self.mock.queries.clear()
        self.mock.events += [event(7, self.ago(20)), event(8, self.now)]
        c.run_once(cfg)
        self.assertEqual(sorted(r["event_id"] for r in self.sent()), sorted(str(event(i, self.now)["id"]) for i in (7, 8)))
        self.assertAlmostEqual(c._parse_time(self.mock.queries[0]["start_date"]), until - 1800, delta=1.01)

    def test_lookback_sets_the_first_start_date(self):
        self.mock.events = [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["event_id"] for r in self.sent()], [str(event(1, self.now)["id"])])
        start = c._parse_time(self.mock.queries[0]["start_date"])
        self.assertAlmostEqual(self.now.timestamp() - start, 86400, delta=120)
        self.assertRegex(self.mock.queries[0]["start_date"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(CISCO_SE_PAGE_SIZE="2"))
        saved = self.saved()["events"]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(CISCO_SE_PAGE_SIZE="2"))
        self.assertEqual(sorted(r["event_id"] for r in self.sent()), sorted(str(event(i, self.now)["id"]) for i in (0, 1)))
        self.assertIn("until", self.saved()["events"])

    def test_a_refused_credential_stops_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(CISCO_SE_API_KEY="wrong-key-0000000000"))
        self.assertIn("HTTP 401", str(cm.exception))
        self.assertIn("Unknown API key or Client ID", str(cm.exception))
        self.assertIn("CISCO_SE_API_URL", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["cisco_se_record"] for x in lines], ["event"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_server_errors_and_a_short_rate_limit_are_retried(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [503, 429]
        self.mock.rate_reset = "42"
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        # The 429 waited for X-RateLimit-Reset.
        self.assertTrue(any(42 <= s <= 43 for s in self.slept), self.slept)

    def test_a_long_rate_limit_wait_ends_the_run_as_a_network_error(self):
        self.mock.events = [event(0, self.ago(5))]
        self.mock.codes = [429]
        self.mock.rate_reset = "2400"
        with self.assertRaises(c.RateLimited) as cm:
            c.run_once(self.cfg())
        self.assertIsInstance(cm.exception, c.NetworkError)
        self.assertIn("resets in 2400 seconds", str(cm.exception))
        self.assertEqual(self.slept, [])

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
            c.run_once(self.cfg(CISCO_SE_API_KEY="another-wrong-key-000000"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("events", logged)
        basic = base64.b64encode(f"{CLIENT_ID}:{API_KEY}".encode()).decode()
        for secret in (API_KEY, INGEST_KEY, basic, "00000000-example-integration", "another-wrong-key-000000"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        base = {"CISCO_SE_CLIENT_ID": CLIENT_ID, "CISCO_SE_API_KEY": API_KEY}
        for bad in ({**base, "CISCO_SE_API_URL": "http://api.amp.cisco.example"}, {"CISCO_SE_CLIENT_ID": CLIENT_ID},
                    {"CISCO_SE_API_KEY": API_KEY}, {**base, "CISCO_SE_CLIENT_ID": "a:b"},
                    {**base, "CISCO_SE_EVENT_TYPES": "Threat Detected"}, {**base, "CISCO_SE_GROUP_GUIDS": "../groups"},
                    {**base, "CISCO_SE_PAGE_SIZE": "501"}, {**base, "CISCO_SE_PAGE_SIZE": "0"}):
            with self.subTest(bad=bad), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(base)
        self.assertEqual(cfg["api_url"], "https://api.amp.cisco.com")
        self.assertEqual((cfg["event_types"], cfg["group_guids"], cfg["page_size"]), ([], [], 500))

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2026, 10, 13, 1, 10, 4, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-13T01:10:04+00:00", want), ("2026-10-13T01:10:04Z", want),
                               ("2026-10-13T01:10:04.5+00:00", want + 0.5), ("2026-10-13T12:10:04.123456789+11:00", want + 0.123456)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertEqual(c.event_time({"timestamp": 1791853804, "date": "x"}), 1791853804.0)
        self.assertEqual(c.event_time({"date": "2026-10-13T01:10:04+00:00"}), want)

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key to another URL, so the run fails instead, and
        # nothing reaches the redirect's target.
        self.mock.events = [event(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Secure Endpoint API": self.cfg(CISCO_SE_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved()["events"])
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

    def test_rate_limit_reset_is_read_only_when_it_makes_sense(self):
        self.assertEqual(c._rate_reset({"X-RateLimit-Reset": "881"}), 881.0)
        for bad in ("", "soon", "-1", "nan", "1e12"):
            self.assertIsNone(c._rate_reset({"X-RateLimit-Reset": bad}), bad)

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
        self.cfg = c.load_config({"CISCO_SE_CLIENT_ID": CLIENT_ID, "CISCO_SE_API_KEY": API_KEY})
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
        self.run_once_raises(c.RateLimited("events request to api.amp.cisco.com: the hourly API rate limit is used up and resets in 2400 seconds"))
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


if __name__ == "__main__":
    unittest.main()
