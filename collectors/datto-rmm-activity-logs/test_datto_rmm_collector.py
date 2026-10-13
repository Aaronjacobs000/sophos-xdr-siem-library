"""Unit tests for datto_rmm_collector.py against a local mock server.

The mock serves the token endpoint and GET /api/v2/activity-logs in the shapes Datto RMM
documents (API help page and the public OpenAPI spec: ActivityLogsPage, ActivityLog,
PaginationData), plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s collectors/datto-rmm-activity-logs -p 'test_*.py' -v
"""
import base64
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
import datto_rmm_collector as c  # noqa: E402

API_KEY = "test-datto-api-key-not-real"
API_SECRET = "test-datto-api-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
TOKEN = "test-datto-access-token-not-real"


def activity(i, when, category="job", action="deployment", entity="DEVICE"):
    return {"id": f"0000{i:04d}-aaaa-4bbb-8ccc-dddddddddddd", "entity": entity, "category": category, "action": action,
            "date": round(when.timestamp(), 3), "site": {"id": 4, "name": "Acme Dental"}, "deviceId": 120155,
            "hostname": "ACME-WS-014", "user": {"id": 17, "userName": "tech.akim", "firstName": "Alex", "lastName": "Kim"},
            "details": "{\"job_name\":\"Example job\"}", "hasStdOut": False, "hasStdErr": False}


class Mock:
    def __init__(self):
        self.activities = []
        self.token_requests = 0
        self.expire_token_once = False
        self.ingest_codes = []
        self.activity_codes = []
        self.ingested = []
        self.requests = []
        self.next_page_host = None


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
        if self.path == "/auth/oauth/token":
            basic = base64.b64encode(b"public-client:public").decode()
            form = urllib.parse.parse_qs(body.decode())
            if self.headers.get("Authorization") != f"Basic {basic}" or form.get("grant_type") != ["password"]:
                return self._json({"error": "invalid_client"}, 401)
            if form.get("username") != [API_KEY] or form.get("password") != [API_SECRET]:
                return self._json({"error": "invalid_grant"}, 400)
            m.token_requests += 1
            return self._json({"access_token": f"{TOKEN}-{m.token_requests}", "token_type": "bearer", "expires_in": 359999})
        if self.path.startswith("/http-endpoint/v1/"):
            if self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
                return self._json({}, 401)
            if m.ingest_codes:
                code = m.ingest_codes.pop(0)
                if code != 200:
                    return self._json({}, code, {"Retry-After": "0"})
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            m.ingested.append({"headers": dict(self.headers), "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
            return self._json({})
        self._json({}, 404)

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path != "/api/v2/activity-logs":
            return self._json({}, 404)
        auth = self.headers.get("Authorization", "")
        if not auth.startswith(f"Bearer {TOKEN}-"):
            return self._json({"timestamp": 0, "status": 401, "error": "Unauthorized", "path": u.path}, 401)
        if m.expire_token_once and auth == f"Bearer {TOKEN}-1":
            m.expire_token_once = False
            return self._json({"timestamp": 0, "status": 401, "error": "Unauthorized", "path": u.path}, 401)
        if m.activity_codes:
            code = m.activity_codes.pop(0)
            return self._json({"timestamp": 0, "status": code, "error": "x", "path": u.path}, code, {"Retry-After": "0"})
        frm = datetime.strptime(q["from"][0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        until = datetime.strptime(q["until"][0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        assert q["order"] == ["asc"]
        size = int(q.get("size", ["50"])[0])
        rows = sorted((a for a in m.activities if frm <= a["date"] <= until), key=lambda a: (a["date"], a["id"]))
        if "searchAfter" in q:
            after = q["searchAfter"][0].split(",")[1]
            rows = rows[[a["id"] for a in rows].index(after) + 1:]
        page = rows[:size]
        nxt = None
        if len(rows) > size:
            last = page[-1]
            nq = dict((k, v[0]) for k, v in q.items() if k != "searchAfter")
            nq.update(searchAfter=f"{int(last['date'] * 1000)},{last['id']}", page="next")
            host = m.next_page_host or self.headers["Host"]
            nxt = f"http://{host}/api/v2/activity-logs?{urllib.parse.urlencode(nq)}"
        self._json({"pageDetails": {"count": len(page), "totalCount": len(rows), "prevPageUrl": None, "nextPageUrl": nxt},
                    "activities": page})


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
             "DATTO_RMM_API_URL": self.base, "DATTO_RMM_API_KEY": API_KEY, "DATTO_RMM_API_SECRET": API_SECRET,
             "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def add(self, n, minutes_ago=120):
        now = datetime.now(timezone.utc)
        start = len(self.mock.activities)
        self.mock.activities.extend([activity(start + i, now - timedelta(minutes=minutes_ago) + timedelta(seconds=i))
                                     for i in range(n)])

    def test_pages_cursor_and_records_unchanged(self):
        self.add(600)
        c.run_once(self.cfg())
        sent = self.sent()
        self.assertEqual(len(sent), 600)
        self.assertEqual(sent[0], self.mock.activities[0])
        self.assertEqual([a["date"] for a in sent], sorted(a["date"] for a in sent))
        pages = [r for r in self.mock.requests if r[1].startswith("/api/v2/activity-logs")]
        self.assertEqual(len(pages), 3)  # 250 + 250 + 100
        self.assertEqual(self.mock.token_requests, 1)
        with open(self.state) as fh:
            st = json.load(fh)["activity_logs"]
        self.assertTrue(st["since"].endswith("Z"))

    def test_overlap_reread_sends_only_new_records(self):
        self.add(10, minutes_ago=3)
        cfg = self.cfg(COLLECTOR_SETTLE_SECONDS="0")
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 10)
        self.mock.ingested.clear()
        # until is whole seconds, so the new record has to be at least a second old.
        self.add(1, minutes_ago=0.1)
        c.run_once(cfg)
        self.assertEqual([a["id"] for a in self.sent()], [self.mock.activities[-1]["id"]])

    def test_settle_window_leaves_newest_for_next_run(self):
        self.add(3, minutes_ago=0)
        c.run_once(self.cfg(COLLECTOR_SETTLE_SECONDS="600"))
        self.assertEqual(self.sent(), [])

    def test_dry_run_prints_and_changes_nothing(self):
        self.add(5)
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 5)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_expired_token_is_renewed_once(self):
        self.add(5)
        self.mock.expire_token_once = True
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 5)
        self.assertEqual(self.mock.token_requests, 2)

    def test_bad_key_pair_stops(self):
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(DATTO_RMM_API_SECRET="wrong-secret-000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.add(5)
        self.mock.activity_codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 5)

    def test_403_stops_without_moving_the_cursor(self):
        self.add(5)
        self.mock.activity_codes = [403]
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_ingest_401_stops_without_moving_the_cursor(self):
        self.add(5)
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_next_page_on_another_host_is_refused(self):
        self.add(300)
        self.mock.next_page_host = "203.0.113.9"
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg())
        gets = [r for r in self.mock.requests if r[0] == "GET"]
        self.assertEqual(len(gets), 1)
        self.assertEqual(self.mock.ingested, [])

    def test_gzip_batches_and_headers(self):
        self.add(40)
        c.run_once(self.cfg(COLLECTOR_BATCH_BYTES="2000"))
        self.assertGreater(len(self.mock.ingested), 1)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")
        self.assertEqual(len(self.sent()), 40)

    def test_secrets_never_logged(self):
        self.add(5)
        self.mock.expire_token_once = True
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.log.getvalue()
        self.assertIn("activity logs", logged)
        for secret in (API_KEY, API_SECRET, INGEST_KEY, TOKEN, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_missing_values(self):
        with self.assertRaises(c.CollectorError):
            c.load_config({"DATTO_RMM_API_URL": "http://merlot-api.example.com", "DATTO_RMM_API_KEY": API_KEY, "DATTO_RMM_API_SECRET": API_SECRET})
        with self.assertRaises(c.CollectorError):
            c.load_config({"DATTO_RMM_API_URL": "https://merlot-api.example.com", "DATTO_RMM_API_KEY": API_KEY})
        with self.assertRaises(c.CollectorError):
            c.Sink(c.load_config({"DATTO_RMM_API_URL": "https://merlot-api.example.com", "DATTO_RMM_API_KEY": API_KEY,
                                  "DATTO_RMM_API_SECRET": API_SECRET}), dry_run=False)

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.add(5)
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Datto RMM API": self.cfg(DATTO_RMM_API_URL=r.base)}
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
