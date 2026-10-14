"""Unit tests for atlassian_org_audit_collector.py against a local mock server.

The mock serves the Atlassian Organizations REST API shapes from its reference and OpenAPI
document: GET /admin/v1/orgs/{orgId}/events-stream (from in epoch milliseconds, cursor, limit,
sortOrder; answers {"data": [EventModel], "meta": {"next", "page_size"}, "links"}), GET
/admin/v1/orgs/{orgId}/event-actions ({"data": [{"id", "type", "attributes": {"displayName",
"groupDisplayName"}}]}), 'Authorization: Bearer <API key>', 400 {"errors": [{"code":
"ADMIN-400-1"}]} for a cursor it doesn't know, 401 {"code", "message"}, and 429 with
X-RateLimit-Reset. Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s collectors/atlassian-org-audit -p 'test_*.py' -v
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
import atlassian_org_audit_collector as c  # noqa: E402

ORG = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
API_KEY = "test-atlassian-admin-api-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ACTIONS = [("user_login", "Logged in to account", "User sign-in"),
           ("group_created", "Created group", "Group management")]


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def event(i, when, action="user_login"):
    return {"id": f"0f1e2d3c-4b5a-4968-8776-{i:012d}", "type": "events",
            "attributes": {"time": iso(when), "processedAt": iso(when + timedelta(seconds=2)), "action": action,
                           "actor": {"id": "5b10ac8d82e05b22cc7d4ef5", "name": "Pat Example", "email": "pat@example.com"},
                           "context": [{"id": "5b10ac8d82e05b22cc7d4ef5", "type": "users"}],
                           "container": [{"id": ORG, "type": "organizations"}],
                           "location": {"ip": "203.0.113.10", "countryName": "Australia", "regionName": "New South Wales", "city": "Sydney"}}}


def cursor(pos, epoch=0):
    return base64.urlsafe_b64encode(json.dumps({"p": pos, "e": epoch}).encode()).decode()


class Mock:
    def __init__(self):
        self.events = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.actions_calls = 0
        # Cursors from an older epoch are refused, as Atlassian refuses one it no longer knows.
        self.epoch = 0


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
        q = dict(urllib.parse.parse_qsl(parts.query))
        base = f"/admin/v1/orgs/{ORG}"
        if not parts.path.startswith(base):
            return self._send(404, {"errors": [{"code": "ADMIN-404-2", "title": "Not Found", "detail": "Organization not found"}]})
        if self.headers.get("Authorization") != f"Bearer {API_KEY}":
            return self._send(401, {"code": 401, "message": "Unauthorized"})
        if m.codes:
            code = m.codes.pop(0)
            reset = (datetime.now(timezone.utc) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self._send(code, {"code": code, "message": "try again"}, {"X-RateLimit-Reset": reset} if code == 429 else None)
        if parts.path == f"{base}/event-actions":
            m.actions_calls += 1
            return self._send(200, {"data": [{"id": k, "type": "event-actions", "attributes": {"displayName": n, "groupDisplayName": g}}
                                             for k, n, g in ACTIONS]})
        if parts.path != f"{base}/events-stream":
            return self._send(404, {"errors": [{"code": "ADMIN-404-1", "title": "Not Found", "detail": "Unknown resource"}]})
        m.queries.append(q)
        rows = sorted(m.events, key=lambda e: e["attributes"]["processedAt"])
        limit = int(q.get("limit") or 200)
        if "cursor" in q:
            cur = json.loads(base64.urlsafe_b64decode(q["cursor"]))
            if cur["e"] != m.epoch:
                return self._send(400, {"errors": [{"id": "x", "status": "400", "code": "ADMIN-400-1", "title": "Bad Request", "detail": "Invalid page cursor"}]})
            pos = cur["p"]
        else:
            start = int(q.get("from") or 0) / 1000
            pos = sum(1 for e in rows if c._epoch(e["attributes"]["processedAt"]) < start)
        chunk = rows[pos:pos + limit]
        return self._send(200, {"data": chunk, "meta": {"next": cursor(pos + len(chunk), m.epoch), "page_size": len(chunk)},
                                "links": {"self": self.path}})

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


class CollectorTest(unittest.TestCase):
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
             "ATLASSIAN_API_URL": self.base, "ATLASSIAN_API_KEY": API_KEY, "ATLASSIAN_ORG_ID": ORG, "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_pages_are_read_tagged_and_named(self):
        self.mock.events = [event(i, self.ago(50 - i)) for i in range(4)] + [event(9, self.ago(5), "group_created"), event(10, self.ago(4), "some_new_action")]
        self.assertEqual(c.run_once(self.cfg(ATLASSIAN_PAGE_LIMIT="2")), 6)
        rows = self.sent()
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"atlassian_record":"event","orgId":"' + ORG + '","id":'))
        self.assertEqual({k: v for k, v in rows[0].items() if k in self.mock.events[0]}, self.mock.events[0])
        self.assertEqual((rows[0]["actionDisplayName"], rows[0]["actionGroup"]), ("Logged in to account", "User sign-in"))
        self.assertEqual(rows[4]["actionDisplayName"], "Created group")
        self.assertNotIn("actionDisplayName", rows[5])
        # The first request starts from the lookback, in ascending order; the rest follow the cursor.
        q = self.mock.queries
        self.assertEqual((q[0]["sortOrder"], q[0]["limit"]), ("asc", "2"))
        self.assertIn("from", q[0])
        self.assertTrue(all("cursor" in x and "from" not in x for x in q[1:]))
        self.assertEqual(self.mock.actions_calls, 1)

    def test_next_run_continues_from_the_saved_cursor(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        with open(self.state) as fh:
            saved = json.load(fh)["events"]["cursor"]
        self.mock.ingested.clear()
        self.mock.queries.clear()
        self.mock.events.append(event(7, self.now))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], [event(7, self.now)["id"]])
        self.assertEqual(self.mock.queries[0]["cursor"], saved)

    def test_lookback_sets_the_first_from(self):
        self.mock.events = [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]
        c.run_once(self.cfg(COLLECTOR_LOOKBACK_HOURS="24"))
        self.assertEqual([r["id"] for r in self.sent()], [event(1, self.now)["id"]])
        start = int(self.mock.queries[0]["from"]) / 1000
        self.assertAlmostEqual(self.now.timestamp() - start, 86400, delta=120)

    def test_a_refused_cursor_restarts_from_the_last_event_and_drops_repeats(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.mock.epoch = 1
        self.mock.events.append(event(8, self.now))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], [event(8, self.now)["id"]])
        self.assertIn("refused the saved cursor", self.logbuf.getvalue())

    def test_cursor_moves_only_after_ingest_accepts(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(ATLASSIAN_PAGE_LIMIT="2"))
        with open(self.state) as fh:
            saved = json.load(fh)["events"]
        self.assertEqual(json.loads(base64.urlsafe_b64decode(saved["cursor"]))["p"], 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(ATLASSIAN_PAGE_LIMIT="2"))
        self.assertEqual([r["id"] for r in self.sent()], [event(i, self.now)["id"] for i in (2, 3)])

    def test_action_names_can_be_turned_off(self):
        self.mock.events = [event(0, self.ago(5))]
        c.run_once(self.cfg(ATLASSIAN_ACTION_NAMES="0"))
        self.assertEqual(self.mock.actions_calls, 0)
        self.assertNotIn("actionDisplayName", self.sent()[0])

    def test_a_refused_key_and_a_wrong_org_stop_with_clear_errors(self):
        with self.assertRaises(c.CollectorError) as cm:
            c.run_once(self.cfg(ATLASSIAN_API_KEY="wrong-key-0000000000"))
        self.assertIn("HTTP 401", str(cm.exception))
        self.assertIn("read:events:admin", str(cm.exception))
        with self.assertRaisesRegex(c.CollectorError, r"HTTP 404 \(ADMIN-404-2\); check ATLASSIAN_ORG_ID"):
            c.run_once(self.cfg(ATLASSIAN_ORG_ID="00000000-0000-4000-8000-000000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["atlassian_record"] for x in lines], ["event"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_rate_limit_reset_header_sets_the_wait(self):
        soon = (datetime.now(timezone.utc) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(28 <= c._retry_delay(0, {"X-RateLimit-Reset": soon}) <= 32)
        self.assertEqual(c._retry_delay(0, {"Retry-After": "7"}), 7.0)

    def test_gzip_batches_and_headers(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(COLLECTOR_BATCH_BYTES="1500"))
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
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(ATLASSIAN_API_KEY="another-wrong-key-000000"))
        logged = self.logbuf.getvalue()
        self.assertIn("events", logged)
        for secret in (API_KEY, INGEST_KEY, "00000000-example-integration", "another-wrong-key-000000"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_missing_values(self):
        base = {"ATLASSIAN_API_KEY": API_KEY, "ATLASSIAN_ORG_ID": ORG}
        for bad in ({**base, "ATLASSIAN_API_URL": "http://api.example.com"}, {"ATLASSIAN_ORG_ID": ORG}, {"ATLASSIAN_API_KEY": API_KEY},
                    {**base, "ATLASSIAN_ORG_ID": "../../users"}, {**base, "ATLASSIAN_PAGE_LIMIT": "900"}):
            with self.assertRaises(c.CollectorError):
                c.load_config(bad)
        cfg = c.load_config(base)
        self.assertEqual(cfg["api_url"], "https://api.atlassian.com")
        self.assertTrue(cfg["action_names"])

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key to another URL, so the run fails instead, and
        # nothing reaches the redirect's target.
        self.mock.events = [event(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration", ATLASSIAN_ACTION_NAMES="0"),
                     "Organizations API": self.cfg(ATLASSIAN_API_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, cfg in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaisesRegex(c.CollectorError, rf"answered with a redirect \(HTTP {code}\), which the collector refuses"):
                            c.run_once(cfg)
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state))
        finally:
            r.close()


if __name__ == "__main__":
    unittest.main()
