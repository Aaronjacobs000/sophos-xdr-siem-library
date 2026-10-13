"""Unit tests for it_glue_collector.py against a local mock server.

The mock serves GET /logs in the shape the IT Glue API documentation gives (JSON:API data with
the log attributes, filter[created_at] as a comma-separated UTC range, sort=created_at,
page[size] and page[number] up to 5, and meta total-pages and total-count), plus a Sophos
NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s collectors/it-glue-activity-logs -p 'test_*.py' -v
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
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import it_glue_collector as c  # noqa: E402

API_KEY = "ITG.test-it-glue-api-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def log(i, when, action="update", rtype="Password"):
    return {"id": str(574989297464115201 + i), "type": "logs",
            "attributes": {"created-at": when.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "level": 2, "account-id": 1, "user-id": 41,
                           "organization-id": 91234, "action": action, "resource-type": rtype, "resource-name": f"Example {i}",
                           "ip-address": "198.51.100.23", "ip-city": "Sydney", "ip-region": "NSW", "ip-country": "Australia",
                           "user-agent": "Mozilla/5.0"}}


class Mock:
    def __init__(self):
        self.logs = []
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
        self.send_header("Content-Type", "application/vnd.api+json")
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        if u.path != "/logs":
            return self._json({"errors": [{"status": "404", "title": "Not Found"}]}, 404)
        if self.headers.get("x-api-key") != API_KEY:
            return self._json({"errors": [{"status": "401", "title": "Unauthorized"}]}, 401)
        if m.codes:
            code = m.codes.pop(0)
            return self._json({"errors": [{"status": str(code)}]}, code)
        q = urllib.parse.parse_qs(u.query)
        start, end = (c._parse_time(x) for x in q["filter[created_at]"][0].split(","))
        assert end - start <= timedelta(days=7), "range longer than a week"
        assert q["sort"] == ["created_at"]
        size = int(q["page[size]"][0])
        number = int(q["page[number]"][0])
        if not 1 <= number <= 5:
            return self._json({"errors": [{"status": "422", "title": "page[number] must be 1 to 5"}]}, 422)
        rows = sorted((r for r in m.logs if start <= c._created(r) <= end), key=lambda r: (c._created(r), r["id"]))
        pages = max(1, -(-len(rows) // size))
        self._json({"data": rows[(number - 1) * size:number * size], "meta": {"total-pages": pages, "total-count": len(rows)}})

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
             "ITGLUE_API_URL": self.base, "ITGLUE_API_KEY": API_KEY, "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def add(self, n, minutes_ago=120, step_seconds=1):
        now = datetime.now(timezone.utc)
        start = len(self.mock.logs)
        self.mock.logs.extend([log(start + i, now - timedelta(minutes=minutes_ago) + timedelta(seconds=i * step_seconds)) for i in range(n)])

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def gets(self):
        return [urllib.parse.unquote(r[1]) for r in self.mock.requests if r[0] == "GET"]

    def test_pages_and_records_unchanged(self):
        self.add(250)
        c.run_once(self.cfg(ITGLUE_PAGE_SIZE="100"))
        sent = self.sent()
        self.assertEqual(len(sent), 250)
        self.assertEqual(sent[0], self.mock.logs[0])
        self.assertEqual(len(self.gets()), 3)

    def test_more_than_five_pages_continues_from_the_newest_record(self):
        self.add(1230)
        c.run_once(self.cfg(ITGLUE_PAGE_SIZE="100"))
        ids = [r["id"] for r in self.sent()]
        self.assertEqual(len(ids), 1230)
        self.assertEqual(len(set(ids)), 1230)
        self.assertTrue(all("page[number]=6" not in g for g in self.gets()))

    def test_long_lookback_is_split_into_week_windows(self):
        self.add(3, minutes_ago=20 * 24 * 60, step_seconds=6 * 24 * 3600)
        c.run_once(self.cfg(COLLECTOR_LOOKBACK_HOURS="500"))
        self.assertEqual(len(self.sent()), 3)
        self.assertGreaterEqual(len(self.gets()), 3)

    def test_overlap_reread_sends_only_new_records(self):
        self.add(10, minutes_ago=3)
        cfg = self.cfg(COLLECTOR_SETTLE_SECONDS="0")
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 10)
        self.mock.ingested.clear()
        self.add(1, minutes_ago=0.1)
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], [self.mock.logs[-1]["id"]])

    def test_dry_run_prints_and_changes_nothing(self):
        self.add(4)
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 4)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_bad_key_stops(self):
        self.add(4)
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(ITGLUE_API_KEY="ITG.wrong-key-000000"))
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
        self.assertIn("activity logs", logged)
        for secret in (API_KEY, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_bad_values(self):
        with self.assertRaises(c.CollectorError):
            c.load_config({"ITGLUE_API_URL": "http://api.example.com", "ITGLUE_API_KEY": API_KEY})
        with self.assertRaises(c.CollectorError):
            c.load_config({})
        with self.assertRaises(c.CollectorError):
            c.load_config({"ITGLUE_API_KEY": API_KEY, "COLLECTOR_LOOKBACK_HOURS": "1000"})
        self.assertEqual(c.load_config({"ITGLUE_API_KEY": API_KEY})["api_url"], "https://api.itglue.com")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.add(4)
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "IT Glue API": self.cfg(ITGLUE_API_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, cfg in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaises(c.CollectorError):
                            c.run_once(cfg)
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state))
        finally:
            r.close()


if __name__ == "__main__":
    unittest.main()
