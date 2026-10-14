"""Unit tests for druva_events_collector.py against a local mock server.

The mock serves the Druva API shapes from Druva's API reference: POST /token (client credentials,
'Authorization: Basic base64(<client id>:<secret key>)', form body grant_type=client_credentials
and scope=read, answering {"access_token", "token_type", "expires_in"}), and
GET /platform/eventmanagement/v3/events (pageSize on the first request, pageToken after it, never
both; answering {"events": [...], "nextPageToken": "..."} with the v3 event envelope:
category, details, feature, globalID, timeStamp, productID, syslogFacility, syslogSeverity, type),
with APIError {"code", "message", "retryable"} bodies on errors, plus a Sophos NG-SIEM HTTP Ingest
endpoint. No real service is called.

  python3 -m unittest discover -s collectors/druva-platform-events -p 'test_*.py' -v
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
import druva_events_collector as c  # noqa: E402

CLIENT_ID = "test-druva-client-id-not-real"
SECRET = "test-druva-secret-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
GLOBAL_ID = "a5da4ad9-cf6c-461f-b5d6-8f8798aafef5"


def admin_login(i, when, status="Success"):
    return {"category": "EVENT", "details": {"email": f"admin{i}@example.com", "status": status, "sourceIP": "203.0.113.10"},
            "feature": "Admin Event", "globalID": GLOBAL_ID, "timeStamp": int(when.timestamp()), "productID": 0,
            "syslogFacility": 23, "syslogSeverity": 6 if status == "Success" else 3, "type": "Password Verified"}


def anomaly(i, when):
    return {"category": "EVENT", "details": {"alertName": "Data Anomalies", "udaType": ["Encryption"], "alertTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                             "resourceID": str(100 + i), "resourceName": f"fs-{i:02d}", "resourceType": "File Server",
                                             "fileInfo": {"newFiles": 0, "updatedFiles": 12, "deletedFiles": 0, "encryptedFiles": 340}},
            "feature": "Alerts And Notifications", "globalID": GLOBAL_ID, "timeStamp": int(when.timestamp()), "productID": 12289,
            "syslogFacility": 23, "syslogSeverity": 3, "type": "Alert"}


class Mock:
    def __init__(self):
        self.events = []
        self.page_size_cap = 2
        self.access_tokens = []
        self.expired = set()
        self.token_requests = []
        self.event_requests = []
        self.event_codes = []
        self.token_codes = []
        self.ingest_codes = []
        self.ingested = []
        self.invalid_tokens = set()


_ISSUED = []


def page_token(position, size):
    # Each token is new, as a real one would be, so a token from an earlier walk never repeats.
    _ISSUED.append(position)
    return base64.urlsafe_b64encode(json.dumps({"p": position, "s": size, "n": len(_ISSUED)}).encode()).decode()


def read_token(token):
    return json.loads(base64.urlsafe_b64decode(token.encode()))


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
        if self.path == "/token":
            m.token_requests.append({"headers": dict(self.headers), "form": urllib.parse.parse_qs(body.decode())})
            if m.token_codes:
                code = m.token_codes.pop(0)
                return self._send(code, {"code": "x", "message": "token service unavailable", "retryable": True})
            expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            if self.headers.get("Authorization") != expected:
                return self._send(401, {"error": "invalid_client"})
            token = f"access-token-{len(m.access_tokens) + 1}"
            m.access_tokens.append(token)
            return self._send(200, {"access_token": token, "token_type": "bearer", "expires_in": 1800})
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

    def do_GET(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        if url.path != "/platform/eventmanagement/v3/events":
            return self._send(404, {"code": "404", "message": "The requested resource was not found."})
        query = urllib.parse.parse_qs(url.query)
        m.event_requests.append({"query": query, "headers": dict(self.headers)})
        auth = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
        if auth not in m.access_tokens or auth in m.expired:
            return self._send(403, {"code": "403", "message": "User is not authorized to access this resource with an explicit deny"})
        if m.event_codes:
            code = m.event_codes.pop(0)
            return self._send(code, {"code": str(code), "message": "slow down", "retryable": True})
        if "pageToken" in query:
            if len(query) > 1:
                return self._send(400, {"code": "400", "message": "pageToken and filters can't be used together"})
            token = query["pageToken"][0]
            if token in m.invalid_tokens:
                return self._send(400, {"code": "400", "message": "Invalid tracker"})
            cur = read_token(token)
            position, size = cur["p"], cur["s"]
        else:
            size = int(query.get("pageSize", ["500"])[0])
            if not 1 <= size <= 500:
                return self._send(400, {"code": "400", "message": "Invalid pageSize"})
            position = 0
        chunk = m.events[position:position + min(size, m.page_size_cap)]
        # With nothing new, the token comes back unchanged.
        nxt = query["pageToken"][0] if "pageToken" in query and not chunk else page_token(position + len(chunk), size)
        return self._send(200, {"events": chunk, "nextPageToken": nxt})


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
             "DRUVA_API_URL": self.base, "DRUVA_CLIENT_ID": CLIENT_ID, "DRUVA_SECRET_KEY": SECRET, "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)["page_token"]

    def test_pages_are_read_tagged_and_the_token_saved(self):
        self.mock.events = [admin_login(i, self.ago(50 - i)) for i in range(3)] + [anomaly(i, self.ago(40 - i)) for i in range(2)]
        self.assertEqual(c.run_once(self.cfg()), 5)
        rows = self.sent()
        self.assertEqual([r["type"] for r in rows], ["Password Verified"] * 3 + ["Alert"] * 2)
        self.assertTrue(all(r["druva_record"] == "platform_event" for r in rows))
        self.assertEqual({k: v for k, v in rows[0].items() if k != "druva_record"}, self.mock.events[0])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"druva_record":"platform_event","category":"EVENT"'))
        # The first request carries pageSize only; every later one carries pageToken only.
        queries = [r["query"] for r in self.mock.event_requests]
        self.assertEqual(queries[0], {"pageSize": ["500"]})
        self.assertTrue(all(set(q) == {"pageToken"} for q in queries[1:]))
        # Three pages of two, two and one, then an empty page that ends the run.
        self.assertEqual(len(queries), 4)
        self.assertEqual(read_token(self.saved())["p"], 5)

    def test_token_request_uses_basic_auth_and_the_form_body(self):
        self.mock.events = [admin_login(0, self.ago(5))]
        c.run_once(self.cfg())
        req = self.mock.token_requests[0]
        self.assertEqual(req["headers"]["Authorization"], "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode())
        self.assertEqual(req["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(req["form"], {"grant_type": ["client_credentials"], "scope": ["read"]})
        self.assertEqual(self.mock.event_requests[0]["headers"]["Authorization"], "Bearer access-token-1")
        # One token serves the whole run.
        self.assertEqual(len(self.mock.token_requests), 1)

    def test_next_run_resumes_from_the_saved_token(self):
        self.mock.events = [admin_login(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        saved = self.saved()
        self.mock.ingested.clear()
        self.mock.event_requests.clear()
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])
        self.assertEqual(self.mock.event_requests[0]["query"], {"pageToken": [saved]})
        self.assertEqual(self.saved(), saved)
        self.mock.events.append(anomaly(9, self.now))
        c.run_once(cfg)
        self.assertEqual([r["details"]["resourceName"] for r in self.sent()], ["fs-09"])

    def test_first_run_sends_only_the_lookback(self):
        self.mock.events = [admin_login(0, self.now - timedelta(days=3)), admin_login(1, self.ago(90)),
                            {**admin_login(2, self.ago(30)), "timeStamp": self.ago(30).strftime("%Y-%m-%dT%H:%M:%S.000Z")}]
        c.run_once(self.cfg(COLLECTOR_LOOKBACK_HOURS="1"))
        self.assertEqual([r["details"]["email"] for r in self.sent()], ["admin2@example.com"])
        self.assertIn("older than the 1-hour lookback", self.logbuf.getvalue())
        # After the first run, every new event is sent whatever its time.
        self.mock.events.append(admin_login(3, self.now - timedelta(days=2)))
        self.mock.ingested.clear()
        c.run_once(self.cfg(COLLECTOR_LOOKBACK_HOURS="1"))
        self.assertEqual([r["details"]["email"] for r in self.sent()], ["admin3@example.com"])

    def test_features_filter_keeps_only_the_named_features(self):
        self.mock.events = [admin_login(0, self.ago(5)), anomaly(1, self.ago(4)), admin_login(2, self.ago(3))]
        c.run_once(self.cfg(DRUVA_FEATURES="alerts and notifications, Threat Watch"))
        self.assertEqual([r["feature"] for r in self.sent()], ["Alerts And Notifications"])
        self.assertEqual(read_token(self.saved())["p"], 3)

    def test_expired_access_token_is_renewed_once(self):
        self.mock.events = [admin_login(i, self.ago(10 - i)) for i in range(4)]
        cfg = self.cfg()
        client = c.DruvaClient(cfg)
        client.token()
        self.mock.expired.add("access-token-1")
        state, sink = {}, c.Sink(cfg, False)
        c.collect(cfg, state, sink, lambda: None, client)
        self.assertEqual(len(self.sent()), 4)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.assertEqual(self.mock.event_requests[-1]["headers"]["Authorization"], "Bearer access-token-2")

    def test_a_refused_events_request_names_the_reset(self):
        self.mock.events = [admin_login(0, self.ago(5)), admin_login(1, self.ago(4))]
        cfg = self.cfg()
        c.run_once(cfg)
        saved = self.saved()
        self.mock.invalid_tokens.add(saved)
        with self.assertRaises(c.CollectorError) as cm:
            c.run_once(cfg)
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("Invalid tracker", str(cm.exception))
        self.assertIn("--reset", str(cm.exception))
        self.assertEqual(self.saved(), saved)
        # --reset starts again without the token, within the lookback.
        self.mock.ingested.clear()
        c.run_once(cfg, reset=True)
        self.assertEqual(len(self.sent()), 2)
        self.assertNotEqual(self.saved(), saved)

    def test_bad_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.CollectorError) as cm:
            c.run_once(self.cfg(DRUVA_SECRET_KEY="wrong-secret-0000000000"))
        self.assertIn("HTTP 401", str(cm.exception))
        self.assertIn("DRUVA_CLIENT_ID and DRUVA_SECRET_KEY", str(cm.exception))
        self.assertEqual(self.mock.event_requests, [])
        self.assertFalse(os.path.exists(self.state))

    def test_token_moves_only_after_ingest_accepts_a_page(self):
        self.mock.events = [admin_login(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg())
        self.assertEqual(read_token(self.saved())["p"], 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual([r["details"]["email"] for r in self.sent()], ["admin2@example.com", "admin3@example.com"])

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [admin_login(0, self.ago(5)), anomaly(1, self.ago(4))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["type"] for x in lines], ["Password Verified", "Alert"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events = [admin_login(i, self.ago(10 - i)) for i in range(3)]
        self.mock.event_codes = [429, 503]
        self.mock.token_codes = [503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.page_size_cap = 50
        self.mock.events = [anomaly(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(COLLECTOR_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = [admin_login(0, self.ago(5))]
        self.mock.event_codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(DRUVA_SECRET_KEY="another-wrong-secret-000000"))
        logged = self.logbuf.getvalue()
        self.assertIn("events request", logged)
        for secret in (CLIENT_ID, SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-000000", "access-token-1"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_bad_page_size_and_missing_values(self):
        with self.assertRaises(c.CollectorError):
            c.load_config({"DRUVA_API_URL": "http://apis.example.com", "DRUVA_CLIENT_ID": CLIENT_ID, "DRUVA_SECRET_KEY": SECRET})
        with self.assertRaises(c.CollectorError):
            c.load_config({"DRUVA_CLIENT_ID": CLIENT_ID, "DRUVA_SECRET_KEY": SECRET, "COLLECTOR_PAGE_SIZE": "501"})
        with self.assertRaises(c.CollectorError):
            c.load_config({"DRUVA_CLIENT_ID": CLIENT_ID})
        with self.assertRaises(c.CollectorError):
            c.load_config({})
        cfg = c.load_config({"DRUVA_CLIENT_ID": CLIENT_ID, "DRUVA_SECRET_KEY": SECRET})
        self.assertEqual(cfg["api_url"], "https://apis.druva.com")
        self.assertEqual(cfg["page_size"], 500)
        self.assertEqual(cfg["features"], [])

    def test_event_time_reads_seconds_and_rfc3339(self):
        self.assertEqual(c.event_time({"timeStamp": 1786527870}), datetime(2026, 8, 12, 9, 44, 30, tzinfo=timezone.utc))
        self.assertEqual(c.event_time({"timeStamp": "2022-05-03T23:28:01.631Z"}).year, 2022)
        self.assertEqual(c.event_time({"timeStamp": "1786527870"}).month, 8)
        self.assertIsNone(c.event_time({"timeStamp": "not a time"}))
        self.assertIsNone(c.event_time({}))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.events = [admin_login(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Druva API": self.cfg(DRUVA_API_URL=r.base)}
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
