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
import contextlib
import gc
import gzip
import io
import json
import logging
import os
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
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

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
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

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
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 8784),
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
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()
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

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("BITWARDEN_API_URL", "BITWARDEN_IDENTITY_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

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

    def test_times_read_alike_on_python_3_9_to_3_13(self):
        # Z or z, an offset with or without its colon, and 0 to 9 fraction digits. Before 3.11,
        # fromisoformat took no Z, no +1000 and no fraction but 3 or 6 digits; no version takes z.
        at = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        for zone, minutes in (("Z", 0), ("z", 0), ("+10:00", 600), ("+1000", 600), ("-05:30", -330), ("-0530", -330)):
            local = (at + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
            for digits in range(10):
                fraction = "123456789"[:digits]
                text = local + ("." if fraction else "") + fraction + zone
                expected = at + timedelta(microseconds=int((fraction + "000000")[:6]))
                with self.subTest(text=text):
                    self.assertAlmostEqual(c._epoch(text), expected.timestamp(), places=5)


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

    def test_501_or_505_from_the_sign_in_is_not_called_a_credential_problem(self):
        # The sign-in reports a refusal as a problem with the credentials, but 501 and 505 are about
        # the server, so they keep their own message. A 400 is still about the credentials.
        client = c.Bitwarden(c.load_config({"BITWARDEN_CLIENT_ID": CLIENT_ID, "BITWARDEN_CLIENT_SECRET": CLIENT_SECRET}))
        saved = c._request
        try:
            for code in (501, 505, 400):
                with self.subTest(code=code):
                    def answer(method, url, *args, **kwargs):
                        raise c.HttpStatus("Bitwarden token request", url, code)
                    c._request = answer
                    with self.assertRaises(c.BridgeError) as caught:
                        client.sign_in()
                    if code == 400:
                        self.assertIn("refused the API key", str(caught.exception))
                    else:
                        self.assertIn(f"failed with HTTP {code}: the server doesn't support", str(caught.exception))
                        self.assertNotIn("refused the API key", str(caught.exception))
        finally:
            c._request = saved

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
        env = {"BITWARDEN_CLIENT_ID": CLIENT_ID, "BITWARDEN_CLIENT_SECRET": CLIENT_SECRET}
        env.update(extra)
        return c.load_config(env)

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_lookback_out_of_range_gives_its_range_and_reason(self):
        message = r"^BRIDGE_LOOKBACK_HOURS must be above 0 and at most 8784 \(366 days\), the longest range the API accepts$"
        for value in ("-1", "-0.5", "8784.5", "9000", "1000001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, message):
                self.load(BRIDGE_LOOKBACK_HOURS=value)
        with self.assertRaisesRegex(c.BridgeError, "BRIDGE_LOOKBACK_HOURS must be above 0$"):
            self.load(BRIDGE_LOOKBACK_HOURS="0")
        for value in ("0.5", "24", "8784"):
            self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS=value)["lookback_hours"], float(value))


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config({"BITWARDEN_CLIENT_ID": CLIENT_ID, "BITWARDEN_CLIENT_SECRET": CLIENT_SECRET})
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

    def test_one_client_serves_every_attempt(self):
        # The client holds the access token, so a new attempt doesn't ask for a new one.
        self.run_once_raises(RuntimeError("secret-value-not-real"))
        self.assertEqual(c.main(["--interval", "5"]), 130)
        first, second = (call["client"] for call in self.calls)
        self.assertIsInstance(first, c.Bitwarden)
        self.assertIs(first, second)

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
