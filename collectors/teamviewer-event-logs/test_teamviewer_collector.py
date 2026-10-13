"""Unit tests for teamviewer_collector.py against a local mock server.

The mock serves POST /api/v2/EventLogging in the shape TeamViewer's Web API spec gives
(AuditLogParameters in, AuditLogRequestApiResult out: AuditEvents, PaginationToken,
ParsingError; Authorization: Bearer script token), plus a Sophos NG-SIEM HTTP Ingest endpoint.
No real service is called.

  python3 -m unittest discover -s collectors/teamviewer-event-logs -p 'test_*.py' -v
"""
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
import teamviewer_collector as c  # noqa: E402

TOKEN = "1234567-test-teamviewer-script-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
PAGE = 50


def event(i, when, name="StartedSession", etype="Session"):
    return {"EventDetails": [{"OldValue": None, "NewValue": "ACME-WS-014", "PolicyEnforcementNewValue": False,
                              "PolicyEnforcementOldValue": False, "PropertyName": "PartnerName", "PropertyCategory": "Session"}],
            "EventName": name, "EventType": etype, "Timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "Author": "Alex Kim", "AuthorEmail": "tech.akim@example.com", "AffectedItem": f"Example item {i}"}


class Mock:
    def __init__(self):
        self.events = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.bodies = []


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
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
        m.requests.append(("POST", self.path, dict(self.headers)))
        if self.path == "/api/v2/EventLogging":
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                return self._json({"error": "invalid_token"}, 401)
            if m.codes:
                return self._json({}, m.codes.pop(0))
            q = json.loads(body)
            m.bodies.append(q)
            start, end = c._parse_time(q["StartDate"]), c._parse_time(q["EndDate"])
            rows = [e for e in m.events if start <= c._parse_time(e["Timestamp"]) <= end
                    and (not q.get("EventTypes") or e["EventType"] in q["EventTypes"])]
            offset = int(q.get("PaginationToken") or 0)
            page = rows[offset:offset + PAGE]
            nxt = str(offset + PAGE) if offset + PAGE < len(rows) else None
            return self._json({"PaginationToken": nxt, "AuditEvents": page, "ParsingError": None})
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._json({}, 401)
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._json({}, code)
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        m.ingested.append({"headers": dict(self.headers), "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
        self._json({})


class CollectorTest(unittest.TestCase):
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
             "TEAMVIEWER_API_URL": self.base, "TEAMVIEWER_SCRIPT_TOKEN": TOKEN, "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def add(self, n, minutes_ago=120, **kw):
        now = datetime.now(timezone.utc)
        start = len(self.mock.events)
        self.mock.events.extend([event(start + i, now - timedelta(minutes=minutes_ago) + timedelta(seconds=i), **kw) for i in range(n)])

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_pages_and_events_unchanged(self):
        self.add(120)
        c.run_once(self.cfg())
        sent = self.sent()
        self.assertEqual(len(sent), 120)
        self.assertEqual(sent[0], self.mock.events[0])
        self.assertEqual(len(self.mock.bodies), 3)
        self.assertEqual([b.get("PaginationToken") for b in self.mock.bodies], [None, "50", "100"])
        self.assertTrue(self.mock.bodies[0]["StartDate"].endswith("Z"))

    def test_overlap_reread_sends_only_new_events(self):
        self.add(10, minutes_ago=3)
        cfg = self.cfg(COLLECTOR_SETTLE_SECONDS="0")
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 10)
        self.mock.ingested.clear()
        self.add(1, minutes_ago=0.1, name="SentFile")
        c.run_once(cfg)
        self.assertEqual([e["EventName"] for e in self.sent()], ["SentFile"])

    def test_event_type_filter_is_sent(self):
        self.add(3)
        self.add(2, name="UserCreated", etype="UserProfile")
        c.run_once(self.cfg(TEAMVIEWER_EVENT_TYPES="UserProfile"))
        self.assertEqual(self.mock.bodies[0]["EventTypes"], ["UserProfile"])
        self.assertEqual(len(self.sent()), 2)

    def test_dry_run_prints_and_changes_nothing(self):
        self.add(4)
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 4)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_bad_token_stops(self):
        self.add(4)
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(TEAMVIEWER_SCRIPT_TOKEN="1234567-wrong-token-00000"))
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.add(4)
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 4)

    def test_ingest_failure_keeps_the_cursor(self):
        self.add(4)
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_gzip_batches_and_headers(self):
        self.add(30)
        c.run_once(self.cfg(COLLECTOR_BATCH_BYTES="2000"))
        self.assertGreater(len(self.mock.ingested), 1)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.add(4)
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.logbuf.getvalue()
        self.assertIn("event log", logged)
        for secret in (TOKEN, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_missing_token(self):
        with self.assertRaises(c.CollectorError):
            c.load_config({"TEAMVIEWER_API_URL": "http://webapi.example.com", "TEAMVIEWER_SCRIPT_TOKEN": TOKEN})
        with self.assertRaises(c.CollectorError):
            c.load_config({})
        self.assertEqual(c.load_config({"TEAMVIEWER_SCRIPT_TOKEN": TOKEN})["api_url"], "https://webapi.teamviewer.com")


if __name__ == "__main__":
    unittest.main()
