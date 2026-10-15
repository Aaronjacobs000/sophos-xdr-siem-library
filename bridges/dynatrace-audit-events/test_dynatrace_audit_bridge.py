"""Unit tests for dynatrace_audit_bridge.py against a local mock server.

The mock serves the shapes in Dynatrace's Platform API reference: POST
/platform/storage/query/v1/query:execute (a JSON body with query, defaultTimeframeStart,
defaultTimeframeEnd, timezone, maxResultRecords and requestTimeoutMilliseconds; answering 200 with
{"state": "SUCCEEDED", "progress", "ttlSeconds", "result": {"records", "types", "metadata"}} or 202
with {"state": "RUNNING", "requestToken", ...}), GET .../query:poll?request-token=... and POST
.../query:cancel?request-token=..., with {"error": {"code", "message", "details"}} on failure.
Records are audit events of dt.system.events with flat dotted keys and ISO 8601 timestamps with nine
fraction digits. It runs the bridge's DQL filter and sort on its own events. Plus the OAuth token
endpoint (POST /sso/oauth2/token, form body grant_type=client_credentials, client_id, client_secret,
scope and resource; answering {"token_type", "access_token", "expires_in", "scope", "resource"}) and a
Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/dynatrace-audit-events -p 'test_*.py' -v
"""
import contextlib
import gc
import gzip
import io
import json
import logging
import os
import re
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
import dynatrace_audit_bridge as c  # noqa: E402

PLATFORM_TOKEN = "dt0s16.TESTPLATFORMTOKENNOTREAL.test-platform-token-secret-part-not-real"
CLIENT_ID = "dt0s02.TESTCLIENTNOTREAL"
SECRET = "test-dynatrace-client-secret-not-real"
ACCESS = "test-dynatrace-access-token-not-real"
ACCOUNT_URN = "urn:dtaccount:12345678-90ab-cdef-1234-567890abcdef"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ENV = "abc12345"
BASE = {"DYNATRACE_ENV_URL": f"https://{ENV}.apps.dynatrace.com", "DYNATRACE_PLATFORM_TOKEN": PLATFORM_TOKEN}
OAUTH = {"DYNATRACE_CLIENT_ID": CLIENT_ID, "DYNATRACE_CLIENT_SECRET": SECRET, "DYNATRACE_ACCOUNT_URN": ACCOUNT_URN}
QUERY = "/platform/storage/query/v1/query"


def iso(dt, nanos=0):
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond * 1000 + nanos:09d}Z"


def event(i, when, provider="SETTINGS", nanos=0, **extra):
    rec = {"timestamp": iso(when, nanos), "event.kind": "AUDIT_EVENT",
           "event.id": f"{5547782627070661074 + i}_{int(when.timestamp()) * 1000}", "event.provider": provider,
           "event.type": "PUT", "event.outcome": "success", "event.version": "1.0.0",
           "user.id": "3f2a1b0c-9d8e-4f7a-b6c5-d4e3f2a1b0c9", "user.name": f"user{i}@example.com",
           "origin.address": "203.0.113.45", "origin.type": "REST", "resource": f"vu9U3hXa3q0AAAAB{i:04d}"}
    rec.update(extra)
    return rec


class Mock:
    def __init__(self):
        self.events = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.polls = []
        self.cancels = []
        self.token_forms = []
        self.auth = []
        self.running = 0
        self.poll_wait = 0.0
        self.final_state = "SUCCEEDED"
        self.poll_code = None
        self.refuse_token_once = False
        self.pending = None


def run_dql(events, dql):
    """The bridge's query on the mock's events: the event kind, the window, the sort and the limit."""
    assert dql.startswith("fetch dt.system.events\n| filter event.kind == \"AUDIT_EVENT\"\n"), dql
    m = re.search(r'timestamp >= toTimestamp\((\d+)\) and timestamp < toTimestamp\((\d+)\)\n'
                  r'\| sort timestamp asc, event\.id asc\n\| limit (\d+)$', dql)
    assert m, dql
    start, end, limit = int(m.group(1)), int(m.group(2)), int(m.group(3))
    rows = [e for e in events if e.get("event.kind") == "AUDIT_EVENT" and start <= c._ns(e["timestamp"]) < end]
    rows.sort(key=lambda e: (c._ns(e["timestamp"]), e["event.id"]))
    return rows[:limit]


def result(records):
    return {"state": "SUCCEEDED", "progress": 100, "ttlSeconds": 300,
            "result": {"records": records,
                       "types": [{"indexRange": [0, max(0, len(records) - 1)],
                                  "mappings": {"timestamp": {"type": "timestamp"}, "event.id": {"type": "string"}}}],
                       "metadata": {"grail": {"scannedRecords": len(records), "notifications": []}}}}


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        m = self.mock
        auth = self.headers.get("Authorization")
        m.auth.append(auth)
        if m.refuse_token_once and len(m.token_forms) < 2:
            return False
        return auth in (f"Bearer {PLATFORM_TOKEN}", f"Bearer {ACCESS}")

    def _error(self, code):
        if code == 429:
            return self._send(429, {"error": {"code": 429, "message": "Too many requests", "retryAfterSeconds": 1}},
                              {"Retry-After": "1"})
        return self._send(code, {"error": {"code": code, "message": "try again"}})

    def do_GET(self):
        m = self.mock
        parts = urllib.parse.urlsplit(self.path)
        if parts.path != QUERY + ":poll":
            return self._send(404, {"error": {"code": 404, "message": "Not found"}})
        if not self._authorized():
            return self._send(401, {"error": {"code": 401, "message": "Authentication failed"}})
        q = dict(urllib.parse.parse_qsl(parts.query))
        m.polls.append(q)
        if m.poll_code:
            return self._error(m.poll_code)
        if q.get("request-token") != "test-request-token-1" or m.pending is None:
            return self._send(404, {"error": {"code": 404, "message": "QueryNotFound"}})
        if m.running > 0:
            m.running -= 1
            # The tests replace time.sleep, so the wait for an answer uses an event instead.
            threading.Event().wait(m.poll_wait)
            return self._send(200, {"state": "RUNNING", "progress": 50, "ttlSeconds": 300})
        if m.final_state != "SUCCEEDED":
            return self._send(200, {"state": m.final_state, "progress": 100, "ttlSeconds": 300})
        return self._send(200, result(m.pending))

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == "/sso/oauth2/token":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            m.token_forms.append(form)
            if form != {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": SECRET,
                        "scope": "storage:system:read storage:buckets:read", "resource": ACCOUNT_URN}:
                return self._send(400, {"error": "invalid_client", "error_description": "Invalid client credentials"})
            return self._send(200, {"token_type": "Bearer", "access_token": ACCESS, "expires_in": 300,
                                    "scope": form["scope"], "resource": ACCOUNT_URN})
        if parts.path == QUERY + ":cancel":
            m.cancels.append(dict(urllib.parse.parse_qsl(parts.query)))
            return self._send(202, None)
        if parts.path == QUERY + ":execute":
            if not self._authorized():
                return self._send(401, {"error": {"code": 401, "message": "Authentication failed"}})
            if m.codes:
                code = m.codes.pop(0)
                if isinstance(code, tuple):
                    return self._send(code[0], code[1])
                return self._error(code)
            req = json.loads(body)
            m.queries.append(req)
            records = run_dql(m.events, req["query"])
            if m.running > 0:
                m.pending = records
                return self._send(202, {"state": "RUNNING", "requestToken": "test-request-token-1", "progress": 0,
                                        "ttlSeconds": 300})
            if m.final_state != "SUCCEEDED":
                return self._send(200, {"state": m.final_state, "progress": 100, "ttlSeconds": 300})
            return self._send(200, result(records))
        if not parts.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
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
    ("DYNATRACE_PAGE_SIZE", "page_size", 1000, 500, int, 100000),
    ("DYNATRACE_QUERY_TIMEOUT", "query_timeout", 300.0, 120.5, float, 3600),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 8760),
    ("BRIDGE_DELAY_SECONDS", "delay_seconds", 300, 60, int, 86400),
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

    def cfg(self, oauth=False, **extra):
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration", "NGSIEM_INGEST_KEY": INGEST_KEY,
             "DYNATRACE_ENV_URL": self.base, "BRIDGE_STATE_FILE": self.state}
        if oauth:
            e.update(OAUTH)
            e["DYNATRACE_TOKEN_URL"] = self.base + "/sso/oauth2/token"
        else:
            e["DYNATRACE_PLATFORM_TOKEN"] = PLATFORM_TOKEN
        e.update(extra)
        cfg = c.load_config(e)
        # The mock runs on 127.0.0.1, so name the environment as a real platform URL would.
        cfg["environment"] = ENV
        return cfg

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_events_are_tagged_and_sent_oldest_first(self):
        self.mock.events = [event(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(DYNATRACE_PAGE_SIZE="2")), 5)
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"dynatrace_record":"audit","dynatrace_environment":"' + ENV
                                                                + '","timestamp":"'))
        sent = self.sent()
        self.assertEqual([r["user.name"] for r in sent], [f"user{i}@example.com" for i in range(5)])
        self.assertEqual({k: v for k, v in sent[2].items() if k not in ("dynatrace_record", "dynatrace_environment")},
                         event(2, self.ago(48)))
        # Pages of two; each page starts at the time of the last one's last record, which it skips.
        self.assertEqual(len(self.mock.queries), 5)
        first = self.mock.queries[0]
        self.assertEqual((first["timezone"], first["maxResultRecords"], first["requestTimeoutMilliseconds"]), ("UTC", 2, 10000))
        self.assertIn(f"timestamp >= toTimestamp({c._ns(iso(self.ago(49)))})", self.mock.queries[1]["query"])
        self.assertEqual(set(self.mock.auth), {f"Bearer {PLATFORM_TOKEN}"})
        self.assertEqual(self.mock.token_forms, [])

    def test_the_window_ends_the_delay_before_now(self):
        self.mock.events = [event(0, self.ago(10)), event(1, self.ago(2))]
        c.run_once(self.cfg())
        self.assertEqual([r["user.name"] for r in self.sent()], ["user0@example.com"])
        end = int(re.search(r'timestamp < toTimestamp\((\d+)\)', self.mock.queries[0]["query"]).group(1))
        expected = int((self.now - timedelta(seconds=300)).timestamp() * c.NS)
        self.assertLess(abs(end - expected), 5 * c.NS)
        self.assertEqual(self.saved()[ENV]["cursor_ns"], end)
        # The query's own timeframe is a second wider than the filter on each side.
        q = self.mock.queries[0]
        start = int(re.search(r'timestamp >= toTimestamp\((\d+)\)', q["query"]).group(1))
        self.assertEqual((c._ns(q["defaultTimeframeStart"]), c._ns(q["defaultTimeframeEnd"])), (start - c.NS, end + c.NS))
        self.mock.ingested.clear()
        c.run_once(self.cfg(BRIDGE_DELAY_SECONDS="0"))
        self.assertEqual([r["user.name"] for r in self.sent()], ["user1@example.com"])

    def test_the_first_run_starts_the_lookback_before_now(self):
        self.mock.events = [event(0, self.now - timedelta(hours=30)), event(1, self.now - timedelta(hours=20))]
        c.run_once(self.cfg())
        self.assertEqual([r["user.name"] for r in self.sent()], ["user1@example.com"])

    def test_the_next_run_starts_where_the_last_ended_without_repeats(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(3)]
        c.run_once(self.cfg())
        self.mock.ingested.clear()
        # The first window ended five minutes ago, so this event is in the next one.
        self.mock.events.append(event(7, self.ago(3)))
        cfg = self.cfg(BRIDGE_DELAY_SECONDS="0")
        c.run_once(cfg)
        self.assertEqual([r["user.name"] for r in self.sent()], ["user7@example.com"])
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])

    def test_events_that_share_a_time_across_pages_are_each_sent_once(self):
        when = self.ago(20)
        self.mock.events = [event(0, self.ago(25))] + [event(i, when, nanos=123) for i in (1, 2, 3)] + [event(9, self.ago(10))]
        c.run_once(self.cfg(DYNATRACE_PAGE_SIZE="2"))
        self.assertEqual([r["user.name"] for r in self.sent()],
                         ["user0@example.com", "user1@example.com", "user2@example.com", "user3@example.com", "user9@example.com"])
        # The page that held only records of one time came back twice as large, then went back to two.
        self.assertEqual([q["maxResultRecords"] for q in self.mock.queries], [2, 2, 4, 2])

    def test_more_events_at_one_time_than_the_largest_page_stop_with_a_clear_error(self):
        when = self.ago(20)
        self.mock.events = [event(i, when) for i in range(5)]
        saved, c.MAX_PAGE_SIZE = c.MAX_PAGE_SIZE, 4
        try:
            with self.assertRaisesRegex(c.BridgeError, "^more than 4 audit events share the time .*, so the bridge can't page past them$"):
                c.run_once(self.cfg(DYNATRACE_PAGE_SIZE="2"))
        finally:
            c.MAX_PAGE_SIZE = saved
        self.assertEqual(len(self.sent()), 4)
        self.assertEqual(self.saved()[ENV]["boundary_ids"], sorted(e["event.id"] for e in self.mock.events[:4]))
        c.run_once(self.cfg(DYNATRACE_PAGE_SIZE="8"))
        self.assertEqual(sorted(r["user.name"] for r in self.sent()), [f"user{i}@example.com" for i in range(5)])

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(DYNATRACE_PAGE_SIZE="2"))
        saved = self.saved()[ENV]
        self.assertEqual(saved["cursor_ns"], c._ns(self.mock.events[1]["timestamp"]))
        self.assertEqual(saved["boundary_ids"], [self.mock.events[1]["event.id"]])
        self.mock.ingested.clear()
        c.run_once(self.cfg(DYNATRACE_PAGE_SIZE="2"))
        self.assertEqual([r["user.name"] for r in self.sent()], ["user2@example.com", "user3@example.com"])

    def test_a_running_query_is_polled_until_it_finishes(self):
        self.mock.events = [event(i, self.ago(20 - i)) for i in range(3)]
        self.mock.running = 2
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.mock.polls, [{"request-token": "test-request-token-1", "request-timeout-milliseconds": "10000"}] * 3)

    def test_a_query_past_its_time_limit_is_cancelled_and_the_window_kept(self):
        self.mock.events = [event(0, self.ago(20))]
        self.mock.running = 1000
        self.mock.poll_wait = 0.3
        with self.assertRaisesRegex(c.NetworkError, "didn't finish within 1 seconds, so it was cancelled"):
            c.run_once(self.cfg(DYNATRACE_QUERY_TIMEOUT="1"))
        self.assertEqual(self.mock.cancels, [{"request-token": "test-request-token-1"}])
        self.assertLess(len(self.mock.polls), 10)
        self.assertEqual(self.sent(), [])
        self.assertFalse(os.path.exists(self.state))

    def test_failed_and_expired_queries(self):
        self.mock.events = [event(0, self.ago(20))]
        self.mock.final_state = "FAILED"
        with self.assertRaisesRegex(c.BridgeError, "^the query ended in state FAILED$") as cm:
            c.run_once(self.cfg())
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.mock.final_state = "RESULT_GONE"
        with self.assertRaisesRegex(c.NetworkError, "gone before the bridge read it"):
            c.run_once(self.cfg())
        self.mock.final_state = "SUCCEEDED"
        self.mock.running, self.mock.poll_code = 1, 410
        with self.assertRaisesRegex(c.NetworkError, "gone before the bridge read it"):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_a_refused_query_stops_with_dynatraces_message(self):
        self.mock.events = [event(0, self.ago(20))]
        self.mock.codes = [(400, {"error": {"code": 400, "message": "The query couldn't be parsed.",
                                            "details": {"errorType": "PARSE_ERROR"}}})]
        with self.assertRaisesRegex(c.BridgeError, r"refused the query request \(HTTP 400\): The query couldn't be parsed\.$"):
            c.run_once(self.cfg())
        self.mock.codes = [(403, {"error": {"code": 403, "message": "Forbidden",
                                            "details": {"missingScopes": ["storage:system:read"]}}})]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403): Forbidden (missing: storage:system:read)", str(cm.exception))
        self.assertIn("policy statements", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_oauth_client_gets_a_token_with_only_the_audit_scopes(self):
        self.mock.events = [event(i, self.ago(20 - i)) for i in range(3)]
        c.run_once(self.cfg(oauth=True, DYNATRACE_PAGE_SIZE="2"))
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.mock.token_forms, [{"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": SECRET,
                                                  "scope": "storage:system:read storage:buckets:read", "resource": ACCOUNT_URN}])
        self.assertEqual(set(self.mock.auth), {f"Bearer {ACCESS}"})

    def test_a_refused_access_token_is_renewed_once(self):
        self.mock.events = [event(0, self.ago(5 + 10))]
        self.mock.refuse_token_once = True
        c.run_once(self.cfg(oauth=True))
        self.assertEqual(len(self.mock.token_forms), 2)
        self.assertEqual(len(self.sent()), 1)

    def test_a_refused_platform_token_stops_at_once(self):
        self.mock.events = [event(0, self.ago(20))]
        with self.assertRaisesRegex(c.BridgeError, r"refused the query request \(HTTP 401\): Authentication failed; check the token"):
            c.run_once(self.cfg(DYNATRACE_PLATFORM_TOKEN="dt0s16.WRONG.wrong-platform-token-not-real"))
        self.assertEqual((self.mock.token_forms, len(self.mock.auth)), ([], 1))

    def test_refused_client_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(oauth=True, DYNATRACE_CLIENT_SECRET="wrong-secret-0000000000"))
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("Invalid client credentials", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [event(i, self.ago(20 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["dynatrace_record"] for x in lines], ["audit"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.events = [event(i, self.ago(20 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.slept[0], 1.0)

    def test_gzip_batches_and_headers(self):
        self.mock.events = [event(i, self.ago(40 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = [event(0, self.ago(20))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg(oauth=True))
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(oauth=True, DYNATRACE_CLIENT_SECRET="another-wrong-secret-000"))
        with self.assertRaises(c.BridgeError) as cm2:
            c.run_once(self.cfg(DYNATRACE_PLATFORM_TOKEN="dt0s16.WRONG.wrong-platform-token-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception) + str(cm2.exception)
        self.assertIn("query request", logged)
        for secret in (SECRET, ACCESS, INGEST_KEY, PLATFORM_TOKEN, "00000000-example-integration", "another-wrong-secret-000",
                       "wrong-platform-token-not-real", "test-request-token-1"):
            self.assertNotIn(secret, logged)

    def test_state_is_kept_per_environment(self):
        self.mock.events = [event(0, self.ago(20))]
        cfg = self.cfg()
        c.run_once(cfg)
        cfg["environment"] = "xyz98765"
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(set(self.saved()), {ENV, "xyz98765"})

    def test_a_saved_position_older_than_a_year_starts_at_the_retention_limit(self):
        old = int((self.now - timedelta(days=500)).timestamp()) * c.NS
        with open(self.state, "w") as fh:
            json.dump({ENV: {"cursor_ns": old, "boundary_ids": ["x"]}}, fh)
        self.mock.events = [event(0, self.now - timedelta(days=400)), event(1, self.now - timedelta(days=300))]
        c.run_once(self.cfg())
        self.assertEqual([r["user.name"] for r in self.sent()], ["user1@example.com"])

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "DYNATRACE_ENV_URL": "http://abc12345.apps.dynatrace.com"},
                    {**BASE, "DYNATRACE_ENV_URL": "https://abc12345.apps.dynatrace.com/platform"},
                    {**BASE, "DYNATRACE_ENV_URL": "https://abc12345.apps.dynatrace.com?x=1"},
                    {"DYNATRACE_PLATFORM_TOKEN": PLATFORM_TOKEN}, {"DYNATRACE_ENV_URL": BASE["DYNATRACE_ENV_URL"]},
                    {**BASE, **OAUTH}, {"DYNATRACE_ENV_URL": BASE["DYNATRACE_ENV_URL"], "DYNATRACE_CLIENT_ID": CLIENT_ID,
                                         "DYNATRACE_CLIENT_SECRET": SECRET},
                    {"DYNATRACE_ENV_URL": BASE["DYNATRACE_ENV_URL"], **OAUTH, "DYNATRACE_ACCOUNT_URN": "12345678-90ab"},
                    {"DYNATRACE_ENV_URL": BASE["DYNATRACE_ENV_URL"], **OAUTH, "DYNATRACE_TOKEN_URL": "http://sso.example/token"},
                    {**BASE, "NGSIEM_INGEST_URL": "http://ingest.example/http-endpoint/v1/x"},
                    {**BASE, "DYNATRACE_PAGE_SIZE": "0"}, {**BASE, "BRIDGE_LOOKBACK_HOURS": "8761"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k not in ("DYNATRACE_CLIENT_SECRET", "DYNATRACE_PLATFORM_TOKEN")}), \
                    self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["env_url"], cfg["environment"], cfg["token_url"]),
                         (f"https://{ENV}.apps.dynatrace.com", ENV, "https://sso.dynatrace.com/sso/oauth2/token"))
        self.assertEqual((cfg["page_size"], cfg["delay_seconds"], cfg["lookback_hours"]), (1000, 300, 24.0))
        self.assertEqual(c.load_config({**BASE, "DYNATRACE_ENV_URL": f"https://{ENV}.apps.dynatrace.com/"})["env_url"],
                         f"https://{ENV}.apps.dynatrace.com")
        self.assertEqual(c.load_config({"DYNATRACE_ENV_URL": BASE["DYNATRACE_ENV_URL"], **OAUTH})["account_urn"], ACCOUNT_URN)

    def test_times_keep_nanoseconds_and_read_offsets(self):
        want = int(datetime(2026, 10, 15, 1, 25, 23, tzinfo=timezone.utc).timestamp()) * c.NS
        for text, expected in [("2026-10-15T01:25:23Z", want), ("2026-10-15T01:25:23.987000000Z", want + 987000000),
                               ("2026-10-15T01:25:23.5Z", want + 500000000),
                               ("2026-10-15T12:25:23.123456789+11:00", want + 123456789),
                               ("2026-10-14T20:55:23.000000001-0430", want + 1), ("2026-10-15T01:25:23.1234567891Z", want + 123456789),
                               ("2026-10-15 01:25:23z", want), (want + 7, want + 7)]:
            with self.subTest(text=text):
                self.assertEqual(c._ns(text), expected)
        for bad in ("yesterday", "", None, True, "2026-13-15T01:25:23Z", "2026-10-15T01:25:23+1"):
            with self.subTest(bad=bad):
                self.assertIsNone(c._ns(bad))
        self.assertEqual(c._iso(want + 987000000), "2026-10-15T01:25:23.987000000Z")
        self.assertEqual(c._ns(c._iso(want + 1)), want + 1)

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.events = [event(0, self.ago(20))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": lambda: self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "token endpoint": lambda: self.cfg(oauth=True, DYNATRACE_TOKEN_URL=r.base + "/sso/oauth2/token"),
                     "Query API": lambda: self.cfg(DYNATRACE_ENV_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, make in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaisesRegex(c.BridgeError, rf"answered with a redirect \(HTTP {code}\), which the bridge refuses"):
                            c.run_once(make())
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state) and self.saved().get(ENV, {}).get("cursor_ns"))
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
        return c.load_config({**BASE, **extra})

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "100001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^DYNATRACE_PAGE_SIZE must be between 1 and 100,000$"):
                self.load(DYNATRACE_PAGE_SIZE=value)
        self.assertEqual(self.load(DYNATRACE_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(DYNATRACE_PAGE_SIZE="100000")["page_size"], 100000)

    def test_query_timeout_out_of_range_gives_its_range(self):
        for value in ("0", "0.5", "3601"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^DYNATRACE_QUERY_TIMEOUT must be between 1 and 3,600$"):
                self.load(DYNATRACE_QUERY_TIMEOUT=value)
        self.assertEqual(self.load(DYNATRACE_QUERY_TIMEOUT="3600")["query_timeout"], 3600.0)

    def test_lookback_is_at_most_a_year(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 8,760$"):
            self.load(BRIDGE_LOOKBACK_HOURS="8761")
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be above 0$"):
            self.load(BRIDGE_LOOKBACK_HOURS="0")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="8760")["lookback_hours"], 8760.0)


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

    def test_a_query_that_ran_too_long_keeps_polling_too(self):
        self.run_once_raises(c.NetworkError("the query didn't finish within 300 seconds, so it was cancelled; the next run "
                                            "tries the same window again"))
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
