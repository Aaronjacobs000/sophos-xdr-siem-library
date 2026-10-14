"""Unit tests for kaseya_vsa10_bridge.py against a local mock server.

The mock serves GET /api/v3/auditlogs in the shape the VSA 10 API documentation gives (Data
and Meta, the audit record fields, OData $filter, $orderby and $top, HTTP Basic token
authentication), plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/kaseya-vsa10-audit-logs -p 'test_*.py' -v
"""
import base64
import gc
import gzip
import io
import json
import logging
import os
import re
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kaseya_vsa10_bridge as c  # noqa: E402

TOKEN_ID = "test-vsa-token-id-not-real"
TOKEN_SECRET = "test-vsa-token-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def record(i, when):
    return {"AuditLogRecordId": 55000 + i, "AuditLogRecordDateTime": when.strftime("%Y-%m-%dT%H:%M:%S"), "ActionId": 1,
            "UserAgentDevice": "edge", "UserAgentDeviceId": "2-e66f9f68-7859-46e6-b082-4bf648341309", "User": "tech.akim",
            "ExtraInformation": None, "RequestIpAddress": "198.51.100.23", "RequestSource": "WebApp.0",
            "DeviceIdentifier": "e9dcef68-339a-4a4f-b218-09ab403502e9", "DeviceName": "ACME-WS-014",
            "DeviceGroupName": "Org > Site > Group", "EventDescription": f"Execute automation ad-hoc script 'Example {i}'",
            "AssociatedAccountUsername": None, "CategoryId": 1, "EventTypeId": 1}


class Mock:
    def __init__(self):
        self.records = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []


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

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        if u.path != "/api/v3/auditlogs":
            return self._json({"Data": None, "Meta": {"ResponseCode": 404, "ErrorMessage": "Entity is not found."}}, 404)
        basic = base64.b64encode(f"{TOKEN_ID}:{TOKEN_SECRET}".encode()).decode()
        if self.headers.get("Authorization") != f"Basic {basic}":
            return self._json({"Data": None, "Meta": {"ResponseCode": 401, "ErrorMessage": "Unauthorized"}}, 401)
        if m.codes:
            code = m.codes.pop(0)
            return self._json({"Data": None, "Meta": {"ResponseCode": code}}, code)
        q = urllib.parse.parse_qs(u.query)
        rows = list(m.records)
        f = q["$filter"][0]
        if mm := re.fullmatch(r"AuditLogRecordId gt (\d+)", f):
            rows = [r for r in rows if r["AuditLogRecordId"] > int(mm.group(1))]
        elif mm := re.fullmatch(r"AuditLogRecordDateTime ge (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z", f):
            rows = [r for r in rows if r["AuditLogRecordDateTime"] >= mm.group(1)]
        else:
            return self._json({"Data": None, "Meta": {"ResponseCode": 400, "ErrorMessage": "Bad filter"}}, 400)
        assert q["$orderby"] == ["AuditLogRecordId asc"]
        rows.sort(key=lambda r: r["AuditLogRecordId"])
        top = int(q["$top"][0])
        self._json({"Data": rows[:top], "Meta": {"ResponseCode": 200}})

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
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
        self.log = io.StringIO()
        self.handler = logging.StreamHandler(self.log)
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
             "VSA10_API_URL": f"{self.base}/api/v3", "VSA10_TOKEN_ID": TOKEN_ID, "VSA10_TOKEN_SECRET": TOKEN_SECRET,
             "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def add(self, n, hours_ago=2):
        now = datetime.now(timezone.utc)
        start = len(self.mock.records)
        self.mock.records.extend([record(start + i, now - timedelta(hours=hours_ago) + timedelta(seconds=i)) for i in range(n)])

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_first_run_uses_lookback_then_keyset_pages(self):
        self.add(5, hours_ago=48)  # older than the default 24-hour lookback
        self.add(2500, hours_ago=2)
        c.run_once(self.cfg())
        sent = self.sent()
        self.assertEqual(len(sent), 2500)
        self.assertEqual(sent[0], self.mock.records[5])
        gets = [urllib.parse.unquote(r[1]) for r in self.mock.requests if r[0] == "GET"]
        self.assertIn("AuditLogRecordDateTime ge", gets[0])
        self.assertIn("AuditLogRecordId gt", gets[1])
        self.assertEqual(len(gets), 3)  # 1000 + 1000 + 500
        self.assertEqual(self.saved()["audit_logs"]["last_id"], self.mock.records[-1]["AuditLogRecordId"])

    def test_next_run_sends_only_new_records(self):
        self.add(10)
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.add(3, hours_ago=0)
        c.run_once(cfg)
        self.assertEqual([r["AuditLogRecordId"] for r in self.sent()], [55010, 55011, 55012])

    def test_start_id_overrides_the_lookback(self):
        self.add(10, hours_ago=100)
        c.run_once(self.cfg(VSA10_START_ID="55006"))
        self.assertEqual([r["AuditLogRecordId"] for r in self.sent()], [55007, 55008, 55009])

    def test_dry_run_prints_and_changes_nothing(self):
        self.add(4)
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 4)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_bad_token_stops(self):
        self.add(4)
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(VSA10_TOKEN_SECRET="wrong-secret-000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.add(4)
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 4)

    def test_ingest_failure_keeps_the_cursor(self):
        self.add(1500)
        cfg = self.cfg(BRIDGE_BATCH_BYTES="10000000")  # one POST per page
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(cfg)
        # The first page was accepted, so the cursor sits at its last id; the second wasn't.
        self.assertEqual(self.saved()["audit_logs"]["last_id"], 55999)
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 500)

    def test_gzip_batches_and_headers(self):
        self.add(30)
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="3000"))
        self.assertGreater(len(self.mock.ingested), 1)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.add(4)
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.log.getvalue()
        self.assertIn("audit logs", logged)
        basic = base64.b64encode(f"{TOKEN_ID}:{TOKEN_SECRET}".encode()).decode()
        for secret in (TOKEN_ID, TOKEN_SECRET, basic, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_bad_values(self):
        with self.assertRaises(c.BridgeError):
            c.load_config({"VSA10_API_URL": "http://vsa.example.com/api/v3", "VSA10_TOKEN_ID": TOKEN_ID, "VSA10_TOKEN_SECRET": TOKEN_SECRET})
        with self.assertRaises(c.BridgeError):
            c.load_config({"VSA10_API_URL": "https://vsa.example.com/api/v3", "VSA10_TOKEN_ID": TOKEN_ID})
        with self.assertRaises(c.BridgeError):
            c.load_config({"VSA10_API_URL": "https://vsa.example.com/api/v3", "VSA10_TOKEN_ID": TOKEN_ID,
                           "VSA10_TOKEN_SECRET": TOKEN_SECRET, "VSA10_START_ID": "abc"})

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.add(5)
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "VSA 10 API": self.cfg(VSA10_API_URL=f"{r.base}/api/v3")}
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


class LegacyNameTest(unittest.TestCase):
    """Bridges were called collectors: a setup that still sets the COLLECTOR_ names keeps working."""

    def test_collector_names_still_work(self):
        self.assertEqual(c._env({"COLLECTOR_LOG_LEVEL": "DEBUG"}, "BRIDGE_LOG_LEVEL", "INFO"), "DEBUG")
        self.assertEqual(c._env({"COLLECTOR_LOG_LEVEL": "DEBUG", "BRIDGE_LOG_LEVEL": "WARNING"}, "BRIDGE_LOG_LEVEL", "INFO"), "WARNING")
        self.assertEqual(c._env({}, "BRIDGE_LOG_LEVEL", "INFO"), "INFO")
        self.assertTrue(c._flag({"COLLECTOR_DRY_RUN": "1"}, "BRIDGE_DRY_RUN", False))
        self.assertFalse(c._flag({"COLLECTOR_DRY_RUN": "1", "BRIDGE_DRY_RUN": "0"}, "BRIDGE_DRY_RUN", False))


if __name__ == "__main__":
    unittest.main()
