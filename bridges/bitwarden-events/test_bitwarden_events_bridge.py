"""Unit tests for bitwarden_events_bridge.py against a local mock server.

The mock serves the Bitwarden shapes from the Public API reference and OpenAPI document:
POST /connect/token (form: grant_type=client_credentials, scope=api.organization, client_id,
client_secret; answers {"access_token", "expires_in", "token_type"}, or 400 {"error":
"invalid_client"}), GET /public/events (start, end, continuationToken; newest first; answers
{"object": "list", "data": [EventResponseModel], "continuationToken"}), GET /public/members
({"object": "list", "data": [MemberResponseModel]}) with 'Authorization: Bearer <token>', and a
Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/bitwarden-events -p 'test_*.py' -v
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
import bitwarden_events_bridge as c  # noqa: E402

ORG = "6f1c2e8a-1b2d-4c3e-9f4a-5b6c7d8e9f01"
CLIENT_ID = f"organization.{ORG}"
CLIENT_SECRET = "test-bitwarden-client-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
USER_PAT = "a2549f79-a71f-4eb9-9234-eb7247333f94"
MEMBER_PAT = "e68b8629-85eb-4929-92c0-b84464976ba4"
MEMBER_JO = "0c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5"


def ts(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def event(i, when, etype=1000, **extra):
    e = {"object": "event", "type": etype, "itemId": None, "collectionId": None, "groupId": None, "policyId": None,
         "memberId": None, "actingUserId": USER_PAT, "installationId": None, "date": ts(when), "device": 9,
         "ipAddress": f"203.0.113.{i % 250 + 1}", "secretId": None, "projectId": None, "serviceAccountId": None}
    e.update(extra)
    return e


class Mock:
    def __init__(self):
        self.events = []
        self.page_size = 2
        self.tokens_issued = 0
        self.valid_tokens = set()
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.event_queries = []
        self.members_calls = 0


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        if code == 401:
            self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        auth = self.headers.get("Authorization") or ""
        return auth.startswith("Bearer ") and auth[7:] in self.mock.valid_tokens

    def do_GET(self):
        m = self.mock
        parts = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parts.query))
        m.requests.append(("GET", parts.path, dict(self.headers)))
        if parts.path not in ("/public/events", "/public/members"):
            return self._send(404, {"object": "error", "message": "Resource not found."})
        if not self._authorized():
            return self._send(401, None)
        if m.codes:
            code = m.codes.pop(0)
            return self._send(code, {"object": "error", "message": "try again"})
        if parts.path == "/public/members":
            m.members_calls += 1
            return self._send(200, {"object": "list", "data": [
                {"object": "member", "id": MEMBER_PAT, "userId": USER_PAT, "name": "Pat Example", "email": "pat@example.com",
                 "type": 0, "status": 2, "twoFactorEnabled": True, "resetPasswordEnrolled": False, "collections": []},
                {"object": "member", "id": MEMBER_JO, "userId": "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9", "name": "Jo Nguyen",
                 "email": "jo.nguyen@example.com", "type": 2, "status": 2, "twoFactorEnabled": False, "resetPasswordEnrolled": False,
                 "collections": []}]})
        m.event_queries.append(q)
        start, end = c._epoch(q.get("start")), c._epoch(q.get("end"))
        if start is not None and end is not None and end - start >= 367 * 86400:
            return self._send(400, {"object": "error", "message": "Date range must be < 367 days."})
        rows = [e for e in m.events if (start is None or c._epoch(e["date"]) >= start) and (end is None or c._epoch(e["date"]) <= end)]
        rows.sort(key=lambda e: c._epoch(e["date"]), reverse=True)
        offset = int(q.get("continuationToken") or 0)
        chunk = rows[offset:offset + m.page_size]
        nxt = offset + len(chunk)
        return self._send(200, {"object": "list", "data": chunk, "continuationToken": str(nxt) if nxt < len(rows) else None})

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
        if self.path == "/connect/token":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if (form.get("grant_type") != "client_credentials" or form.get("scope") != "api.organization"
                    or form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET):
                return self._send(400, {"error": "invalid_client"})
            m.tokens_issued += 1
            token = f"test-access-token-{m.tokens_issued}"
            m.valid_tokens.add(token)
            return self._send(200, {"access_token": token, "expires_in": 3600, "token_type": "Bearer", "scope": "api.organization"})
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
             "BITWARDEN_API_URL": self.base, "BITWARDEN_IDENTITY_URL": self.base, "BITWARDEN_CLIENT_ID": CLIENT_ID,
             "BITWARDEN_CLIENT_SECRET": CLIENT_SECRET, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_pages_are_read_tagged_enriched_and_sent_oldest_first(self):
        self.mock.events = [event(i, self.ago(50 - i)) for i in range(5)]
        self.mock.events.append(event(9, self.ago(10), 1502, memberId=MEMBER_JO))
        self.assertEqual(c.run_once(self.cfg()), 6)
        rows = self.sent()
        self.assertEqual([r["date"] for r in rows], sorted(r["date"] for r in rows))
        first = rows[0]
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"bitwarden_record":"event","organizationId":"' + ORG + '"'))
        self.assertEqual({k: v for k, v in first.items() if k in self.mock.events[0]}, self.mock.events[0])
        self.assertEqual((first["actingUserEmail"], first["actingUserName"]), ("pat@example.com", "Pat Example"))
        self.assertNotIn("memberEmail", first)
        last = rows[-1]
        self.assertEqual((last["type"], last["memberEmail"], last["memberName"]), (1502, "jo.nguyen@example.com", "Jo Nguyen"))
        # Every page repeats the same window, and the pages after the first carry the token.
        queries = self.mock.event_queries
        self.assertEqual(len(queries), 3)
        self.assertEqual(len({(q["start"], q["end"]) for q in queries}), 1)
        self.assertNotIn("continuationToken", queries[0])
        self.assertEqual([q.get("continuationToken") for q in queries[1:]], ["2", "4"])
        self.assertEqual(self.mock.members_calls, 1)

    def test_member_lookup_can_be_turned_off(self):
        self.mock.events = [event(0, self.ago(5))]
        c.run_once(self.cfg(BITWARDEN_MEMBER_LOOKUP="0"))
        self.assertEqual(self.mock.members_calls, 0)
        self.assertNotIn("actingUserEmail", self.sent()[0])
        self.assertEqual(self.sent()[0]["organizationId"], ORG)

    def test_lookback_sets_the_first_window(self):
        self.mock.events = [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24", BRIDGE_OVERLAP_SECONDS="0"))
        self.assertEqual([r["ipAddress"] for r in self.sent()], [event(1, self.now)["ipAddress"]])
        start = c._epoch(self.mock.event_queries[0]["start"])
        self.assertAlmostEqual(self.now.timestamp() - start, 86400, delta=120)

    def test_next_run_overlaps_and_drops_repeats(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 3)
        self.mock.ingested.clear()
        self.mock.event_queries.clear()
        # A client event that reaches Bitwarden late, with a time inside the overlap, and a new one.
        self.mock.events += [event(7, self.ago(30), 1107, itemId="3767a302-8208-4dc6-b842-030428a1cfad"), event(8, self.now, 1114)]
        c.run_once(cfg)
        self.assertEqual(sorted(r["type"] for r in self.sent()), [1107, 1114])
        with open(self.state) as fh:
            saved = json.load(fh)["events"]
        self.assertEqual(len(saved["seen"]), 5)

    def test_cursor_moves_only_after_ingest_accepts(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 4)

    def test_expired_token_is_renewed_once(self):
        self.mock.events = [event(0, self.ago(5))]
        client = c.Bitwarden(self.cfg())
        c.run_once(self.cfg(), client=client)
        self.mock.valid_tokens.clear()
        self.mock.events.append(event(1, self.ago(1)))
        self.mock.ingested.clear()
        c.run_once(self.cfg(), client=client)
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.mock.tokens_issued, 2)

    def test_a_refused_api_key_stops_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(BITWARDEN_CLIENT_SECRET="wrong-secret-0000000000"))
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("BITWARDEN_CLIENT_SECRET", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))
        self.assertEqual(self.mock.event_queries, [])

    def test_a_rejected_request_names_the_api_message(self):
        cfg = self.cfg()
        cfg["lookback_hours"] = 400 * 24
        state = {"events": {"since": self.now.timestamp() - 400 * 86400, "seen": []}}
        with open(self.state, "w") as fh:
            json.dump(state, fh)
        # The bridge caps the window at 366 days, so the API's 367-day limit is never hit.
        c.run_once(cfg)
        q = self.mock.event_queries[0]
        self.assertLess(c._epoch(q["end"]) - c._epoch(q["start"]), 367 * 86400)
        bw = c.Bitwarden(cfg)
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 400\): Date range must be < 367 days"):
            bw.get("/public/events", {"start": c._iso(self.now.timestamp() - 400 * 86400), "end": c._iso(self.now.timestamp())}, "events request")

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["bitwarden_record"] for x in lines], ["event"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.page_size = 50
        self.mock.events = [event(i, self.ago(30 - i), 1107, itemId=f"3767a302-8208-4dc6-b842-{i:012d}") for i in range(12)]
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
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(BITWARDEN_CLIENT_SECRET="another-wrong-secret-000000"))
        logged = self.logbuf.getvalue()
        self.assertIn("events", logged)
        for secret in (CLIENT_SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-000000", "test-access-token-1"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_bad_client_ids_and_missing_values(self):
        base = {"BITWARDEN_CLIENT_ID": CLIENT_ID, "BITWARDEN_CLIENT_SECRET": CLIENT_SECRET}
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "BITWARDEN_API_URL": "http://api.example.com"})
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "BITWARDEN_IDENTITY_URL": "http://identity.example.com"})
        for bad in ("user.6f1c2e8a-1b2d-4c3e-9f4a-5b6c7d8e9f01", ORG, "organization.not-a-guid"):
            with self.assertRaises(c.BridgeError):
                c.load_config({**base, "BITWARDEN_CLIENT_ID": bad})
        with self.assertRaises(c.BridgeError):
            c.load_config({"BITWARDEN_CLIENT_ID": CLIENT_ID})
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "BRIDGE_LOOKBACK_HOURS": "9000"})
        cfg = c.load_config(base)
        self.assertEqual((cfg["api_url"], cfg["identity_url"]), ("https://api.bitwarden.com", "https://identity.bitwarden.com"))
        self.assertEqual(cfg["organization_id"], ORG)
        self.assertTrue(cfg["member_lookup"])

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.events = [event(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "token": self.cfg(BITWARDEN_IDENTITY_URL=r.base),
                     "Public API": self.cfg(BITWARDEN_API_URL=r.base)}
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
