"""Unit tests for syncro_collector.py against a local mock server.

The mock serves GET /api/v1/rmm_alerts in the shape Syncro's public API spec gives
(rmm_alerts and meta total_pages and page, 25 alerts a page, status and created_after filters,
bearer token), plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s collectors/syncro-rmm-alerts -p 'test_*.py' -v
"""
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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syncro_collector as c  # noqa: E402

TOKEN = "T0000test-syncro-api-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
PAGE = 25


def alert(i, when):
    return {"id": 9000 + i, "customer_id": 31, "ticket_number": None, "ticket_status": None, "computer_name": "ACME-WS-014",
            "properties": {"trigger": "Antivirus"}, "resolved": False, "check_id": 77, "status": "active",
            "formatted_output": f"Threat detected {i}", "description": "Antivirus threat detected",
            "created_at": when.astimezone(timezone(timedelta(hours=-7))).isoformat(timespec="milliseconds"),
            "updated_at": when.astimezone(timezone(timedelta(hours=-7))).isoformat(timespec="milliseconds"), "asset_id": 1201}


class Mock:
    def __init__(self):
        self.alerts = []
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
        if u.path != "/api/v1/rmm_alerts":
            return self._json({"error": "not found"}, 404)
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._json({"error": "unauthorized"}, 401)
        if m.codes:
            return self._json({}, m.codes.pop(0))
        q = urllib.parse.parse_qs(u.query)
        assert q["status"] == ["all"]
        after = c._parse_time(q["created_after"][0])
        rows = sorted((a for a in m.alerts if c._parse_time(a["created_at"]) > after), key=lambda a: a["id"], reverse=True)
        page = int(q.get("page", ["1"])[0])
        pages = max(1, -(-len(rows) // PAGE))
        self._json({"rmm_alerts": rows[(page - 1) * PAGE:page * PAGE], "meta": {"total_pages": pages, "page": page}})

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


class CollectorTest(unittest.TestCase):
    def setUp(self):
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

    def cfg(self, **extra):
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration", "NGSIEM_INGEST_KEY": INGEST_KEY,
             "SYNCRO_API_URL": f"{self.base}/api/v1", "SYNCRO_API_TOKEN": TOKEN, "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def add(self, n, minutes_ago=120):
        now = datetime.now(timezone.utc)
        start = len(self.mock.alerts)
        self.mock.alerts.extend([alert(start + i, now - timedelta(minutes=minutes_ago) + timedelta(seconds=i)) for i in range(n)])

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_pages_oldest_first_and_unchanged(self):
        self.add(60)
        c.run_once(self.cfg())
        sent = self.sent()
        self.assertEqual(len(sent), 60)
        self.assertEqual(sent[0], self.mock.alerts[0])
        self.assertEqual([a["id"] for a in sent], sorted(a["id"] for a in sent))
        self.assertEqual(len([r for r in self.mock.requests if r[0] == "GET"]), 3)

    def test_next_run_sends_only_new_alerts(self):
        self.add(10, minutes_ago=3)
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.add(2, minutes_ago=1)
        c.run_once(cfg)
        self.assertEqual([a["id"] for a in self.sent()], [9010, 9011])

    def test_lookback_limits_the_first_run(self):
        self.add(3, minutes_ago=48 * 60)
        self.add(2)
        c.run_once(self.cfg())
        self.assertEqual([a["id"] for a in self.sent()], [9003, 9004])

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
            c.run_once(self.cfg(SYNCRO_API_TOKEN="T0000wrong-token-0000"))
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
        self.assertIn("RMM alerts", logged)
        for secret in (TOKEN, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_missing_values(self):
        with self.assertRaises(c.CollectorError):
            c.load_config({"SYNCRO_API_URL": "http://acme.example.com/api/v1", "SYNCRO_API_TOKEN": TOKEN})
        with self.assertRaises(c.CollectorError):
            c.load_config({"SYNCRO_API_URL": "https://acme.example.com/api/v1"})


if __name__ == "__main__":
    unittest.main()
