"""Unit tests for webex_bridge.py against a local mock server.

The mock serves the shapes in Webex's API reference: POST /v1/access_token with the refresh token
form (grant_type, client_id, client_secret, refresh_token), answering {"access_token", "expires_in",
"refresh_token", "refresh_token_expires_in"} or {"message", "errors": [{"description"}], "trackingId"};
GET /v1/adminAudit/events (orgId, from, to, max, offset), GET /v1/admin/securityAudit/events (orgId,
startTime, endTime, max) and GET /v1/cdr_stream (startTime, endTime, max), each answering
{"items": [...]} with a Link header (<url>; rel="next") for the next page. The call history mock
refuses a window over 2 hours, a start over 12 hours ago and an end less than a minute ago, as Webex
documents, and can answer 451 for an organization kept in another region. Plus a Sophos NG-SIEM HTTP
Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/webex-audit-and-call-history -p 'test_*.py' -v
"""
import base64
import contextlib
import gc
import gzip
import io
import json
import logging
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webex_bridge as c  # noqa: E402

# The bridge spaces its requests; the tests record the waits instead of sleeping.
c.PACE_SECONDS = 0

ORG_UUID = "96abc2aa-3dcc-11e5-a152-fe34819cdc9a"
ORG = base64.b64encode(f"ciscospark://us/ORGANIZATION/{ORG_UUID}".encode()).decode().rstrip("=")
CLIENT_ID = "C0123456789abcdef-test-client-not-real"
CLIENT_SECRET = "test-webex-client-secret-not-real"
REFRESH = "test-webex-refresh-token-0000-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def wtime(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def admin(i, when, category="USERS"):
    return {"id": f"YWRtaW4tYXVkaXQtdGVzdC0{i:04d}", "actorOrgId": ORG, "actorId": "cGVyc29uLXRlc3QtMDAwMQ",
            "created": wtime(when),
            "data": {"actorOrgName": "Acme Inc.", "targetName": f"user{i}@example.com", "eventDescription": "A user was updated",
                     "actorName": "Sam Admin", "actorEmail": "sam.admin@example.com", "adminRoles": ["Full_Admin"],
                     "trackingId": f"ATLAS_test_{i}", "targetType": "USER", "targetId": "dGFyZ2V0LXRlc3QtMDAwMQ",
                     "eventCategory": category, "actorUserAgent": "Mozilla/5.0", "actorIp": "192.0.2.10",
                     "targetOrgId": ORG, "actionText": f"Sam Admin updated user{i}@example.com", "targetOrgName": "Acme Inc."}}


def security(i, when, category="LOGINS"):
    return {"id": f"c2VjdXJpdHktYXVkaXQtdGVzdC0{i:04d}", "actorOrgId": ORG, "actorId": "cGVyc29uLXRlc3QtMDAwMg",
            "created": wtime(when),
            "data": {"actorOrgName": "Acme Inc.", "eventDescription": "A user logged in", "actorName": "Pat Example",
                     "actorEmail": "pat@example.com", "actorUserAgent": "Webex/44.10", "trackingId": f"ATLAS_test_s{i}",
                     "eventCategory": category, "actorIp": "198.51.100.20", "actionText": "Pat Example logged into organization Acme Inc."}}


def cdr(i, when):
    return {"Report ID": f"0a0c2eb7-f1f6-3326-86f9-565d2e11{i:04d}", "Report time": wtime(when), "Start time": wtime(when - timedelta(minutes=2)),
            "Call type": "SIP_INTERNATIONAL", "Direction": "ORIGINATING", "Calling number": "+61255501234",
            "Called number": "+442079460123", "International country": "GB", "Duration": 95, "User": "Pat Example",
            "Call outcome": "Success", "Call outcome reason": "Normal", "Org UUID": ORG_UUID}


class Mock:
    def __init__(self):
        # rows[path] = [(insertion time, row)]; audit rows use their created time.
        self.rows = {"/v1/adminAudit/events": [], "/v1/admin/securityAudit/events": [], "/v1/cdr_stream": []}
        self.page_cap = 1000
        # Page the admin audit API by offset with no Link header, as its spec lists no Link.
        self.offset_mode = False
        self.requests = []
        self.tokens = []
        self.token_requests = []
        self.refresh_tokens = {REFRESH}
        self.rotate = False
        self.refresh_left = 7776000
        self.expires_in = 1209599
        # Answers to send instead of the normal one, in order: an HTTP status.
        self.answers = []
        self.token_answers = []
        self.ingest_codes = []
        self.ingested = []
        self.next_link = None
        self.region_451 = False


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, link=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        if link:
            self.send_header("Link", f'<{link}>; rel="next"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message):
        self._send(code, {"message": message, "errors": [{"description": message}], "trackingId": "ROUTER_test_0001"})

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == "/v1/access_token":
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append({"form": form, "headers": dict(self.headers)})
            if m.token_answers:
                return self._error(m.token_answers.pop(0), "The refresh token provided is expired, revoked, malformed, or invalid.")
            if form.get("grant_type") != ["refresh_token"] or form.get("client_id") != [CLIENT_ID] \
                    or form.get("client_secret") != [CLIENT_SECRET]:
                return self._error(401, "Invalid client.")
            given = (form.get("refresh_token") or [""])[0]
            if given not in m.refresh_tokens:
                return self._error(400, "The refresh token provided is expired, revoked, malformed, or invalid.")
            refresh = given
            if m.rotate:
                m.refresh_tokens.discard(given)
                refresh = f"test-webex-refresh-token-{len(m.token_requests):04d}-not-real"
                m.refresh_tokens.add(refresh)
            token = f"test-webex-access-token-{len(m.tokens):04d}-not-real"
            m.tokens.append(token)
            return self._send(200, {"access_token": token, "expires_in": m.expires_in, "refresh_token": refresh,
                                    "refresh_token_expires_in": m.refresh_left})
        if not url.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
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
        query = urllib.parse.parse_qs(url.query)
        m.requests.append({"path": url.path, "query": query, "headers": dict(self.headers)})
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] not in m.tokens:
            return self._error(401, "The request requires a valid access token set in the Authorization request header.")
        if m.answers:
            return self._error(m.answers.pop(0), "test status")
        if url.path not in m.rows:
            return self._error(404, "The requested resource could not be found.")
        now = datetime.now(timezone.utc)
        if url.path == "/v1/cdr_stream":
            if m.region_451:
                return self._send(451, {"message": "Organization data is in another region",
                                        "endpoint": "https://analytics-calling-au.webexapis.com"})
            lo, hi = parse(query["startTime"][0]), parse(query["endTime"][0])
            if hi - lo > timedelta(hours=2) or lo < now - timedelta(hours=12) or hi > now - timedelta(minutes=1) or hi <= lo:
                return self._error(400, "startTime and endTime are out of range.")
        elif url.path == "/v1/adminAudit/events":
            if query.get("orgId") != [ORG]:
                return self._error(403, "Not authorized for this organization.")
            lo, hi = parse(query["from"][0]), parse(query["to"][0])
        else:
            if query.get("orgId") != [ORG]:
                return self._error(403, "Not authorized for this organization.")
            lo, hi = parse(query["startTime"][0]), parse(query["endTime"][0])
        rows = [r for t, r in m.rows[url.path] if lo <= t <= hi]
        size = min(int(query.get("max", ["100"])[0]), m.page_cap)
        start = int(query.get("cursor", query.get("offset", ["0"]))[0])
        chunk = rows[start:start + size]
        link = None
        if start + size < len(rows) and not (m.offset_mode and url.path == "/v1/adminAudit/events"):
            q = {k: v[0] for k, v in query.items() if k not in ("cursor", "offset")}
            q["cursor"] = str(start + size)
            link = m.next_link or f"http://{self.headers.get('Host')}{url.path}?{urllib.parse.urlencode(q)}"
        self._send(200, {"items": chunk}, link)


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
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"WEBEX_CLIENT_ID": CLIENT_ID, "WEBEX_CLIENT_SECRET": CLIENT_SECRET, "WEBEX_REFRESH_TOKEN": REFRESH,
         "WEBEX_ORG_ID": ORG_UUID}
    e.update(extra)
    return e


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
        self.tokens = os.path.join(self.tmp.name, "tokens.json")
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

    def cfg(self, **extra):
        e = base_env(NGSIEM_INGEST_URL=f"{self.base}/http-endpoint/v1/00000000-example-integration", NGSIEM_INGEST_KEY=INGEST_KEY,
                     WEBEX_API_URL=self.base, WEBEX_CDR_URL=self.base, BRIDGE_STATE_FILE=self.state,
                     WEBEX_TOKEN_FILE=self.tokens)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def add(self, path, rows, inserted=None):
        for r in rows:
            when = inserted or parse(r.get("created") or r["Report time"])
            self.mock.rows[path].append((when, r))

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def calls(self, path):
        return [r for r in self.mock.requests if r["path"] == path]

    def test_all_three_logs_are_read_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.add("/v1/adminAudit/events", [admin(i, self.ago(50 - i)) for i in range(5)])
        self.add("/v1/admin/securityAudit/events", [security(1, self.ago(20)), security(2, self.ago(10), "LOGOUT")])
        self.add("/v1/cdr_stream", [cdr(i, self.ago(30 - i)) for i in range(3)])
        self.assertEqual(c.run_once(self.cfg()), 10)
        sent = self.sent()
        audits = [r for r in sent if r["webex_record"] == "admin_audit"]
        self.assertEqual(sorted(r["id"] for r in audits), sorted(r["id"] for _, r in self.mock.rows["/v1/adminAudit/events"]))
        first = audits[0]
        self.assertEqual(list(first)[0], "webex_record")
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"webex_record":"admin_audit","id":"'))
        original = next(r for _, r in self.mock.rows["/v1/adminAudit/events"] if r["id"] == first["id"])
        self.assertEqual({k: v for k, v in first.items() if k != "webex_record"}, original)
        self.assertEqual([r["data"]["eventCategory"] for r in sent if r["webex_record"] == "security_audit"], ["LOGINS", "LOGOUT"])
        self.assertEqual(len([r for r in sent if r["webex_record"] == "cdr"]), 3)
        # Five admin events at two a page: three pages through the Link header, each with the same window.
        reqs = self.calls("/v1/adminAudit/events")
        self.assertEqual([r["query"].get("cursor", ["0"])[0] for r in reqs], ["0", "2", "4"])
        self.assertEqual({(r["query"]["from"][0], r["query"]["to"][0]) for r in reqs}.__len__(), 1)
        self.assertEqual((reqs[0]["query"]["orgId"], reqs[0]["query"]["max"]), ([ORG], ["200"]))
        lo, hi = parse(reqs[0]["query"]["from"][0]), parse(reqs[0]["query"]["to"][0])
        self.assertAlmostEqual((hi - lo).total_seconds(), 86400 - 60, delta=10)
        sec = self.calls("/v1/admin/securityAudit/events")[0]["query"]
        self.assertEqual((sec["orgId"], sec["max"], sorted(sec)), ([ORG], ["1000"], ["endTime", "max", "orgId", "startTime"]))
        self.assertEqual(self.calls("/v1/cdr_stream")[0]["query"]["max"], ["5000"])

    def test_admin_audit_without_a_link_header_is_paged_by_offset(self):
        self.mock.page_cap = 2
        self.mock.offset_mode = True
        self.add("/v1/adminAudit/events", [admin(i, self.ago(50 - i)) for i in range(5)])
        saved, c.AUDIT = c.AUDIT, {**c.AUDIT, "admin_audit": ("/v1/adminAudit/events", "from", "to", 2)}
        try:
            self.assertEqual(c.run_once(self.cfg(WEBEX_LOGS="admin_audit")), 5)
        finally:
            c.AUDIT = saved
        self.assertEqual([r["query"].get("offset", ["0"])[0] for r in self.calls("/v1/adminAudit/events")], ["0", "2", "4"])

    def test_the_refresh_token_grant_and_the_access_token_are_kept(self):
        self.add("/v1/adminAudit/events", [admin(1, self.ago(5))])
        client = c.Webex(self.cfg())
        c.run_once(self.cfg(), client=client)
        c.run_once(self.cfg(), client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        req = self.mock.token_requests[0]
        self.assertEqual(req["form"], {"grant_type": ["refresh_token"], "client_id": [CLIENT_ID],
                                       "client_secret": [CLIENT_SECRET], "refresh_token": [REFRESH]})
        self.assertEqual(req["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertTrue(all(r["headers"]["Authorization"] == f"Bearer {self.mock.tokens[0]}" for r in self.mock.requests))
        # Webex handed back the same refresh token, so there was nothing to save.
        self.assertFalse(os.path.exists(self.tokens))
        # A token Webex says expires within the renewal margin is fetched again before each request.
        self.mock.expires_in = 30
        client = c.Webex(self.cfg())
        before = len(self.mock.token_requests)
        c.run_once(self.cfg(), client=client)
        self.assertGreater(len(self.mock.token_requests) - before, 1)

    def test_a_new_refresh_token_is_saved_and_used_from_then_on(self):
        self.mock.rotate = True
        c.run_once(self.cfg(WEBEX_LOGS="cdr"))
        with open(self.tokens) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["refresh_token"], "test-webex-refresh-token-0001-not-real")
        self.assertEqual(stat.S_IMODE(os.stat(self.tokens).st_mode), 0o600)
        # A new process (a new client) uses the saved one, since Webex no longer takes the first.
        c.run_once(self.cfg(WEBEX_LOGS="cdr"))
        self.assertEqual(self.mock.token_requests[1]["form"]["refresh_token"], ["test-webex-refresh-token-0001-not-real"])
        # Setting a new WEBEX_REFRESH_TOKEN starts from that one instead of the saved one.
        self.mock.refresh_tokens.add("test-webex-refresh-token-fresh-not-real")
        c.run_once(self.cfg(WEBEX_LOGS="cdr", WEBEX_REFRESH_TOKEN="test-webex-refresh-token-fresh-not-real"))
        self.assertEqual(self.mock.token_requests[2]["form"]["refresh_token"], ["test-webex-refresh-token-fresh-not-real"])

    def test_a_new_refresh_token_is_saved_in_a_dry_run_too(self):
        self.mock.rotate = True
        out = io.StringIO()
        c.run_once(self.cfg(WEBEX_LOGS="cdr", NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertTrue(os.path.exists(self.tokens))
        self.assertFalse(os.path.exists(self.state))

    def test_a_token_file_that_is_not_json_stops_with_a_plain_error(self):
        with open(self.tokens, "w") as fh:
            fh.write("not json")
        with self.assertRaisesRegex(c.BridgeError, "is not JSON; delete it to start again from WEBEX_REFRESH_TOKEN$"):
            c.run_once(self.cfg())

    def test_a_refresh_token_near_its_expiry_gets_a_warning(self):
        self.mock.refresh_left = 5 * 86400 + 100
        c.run_once(self.cfg(WEBEX_LOGS="cdr"))
        self.assertIn("Webex says the refresh token expires in 5 days", self.logbuf.getvalue())

    def test_an_expired_access_token_is_renewed_once(self):
        self.add("/v1/adminAudit/events", [admin(1, self.ago(5))])
        self.mock.answers = [401]
        self.assertEqual(c.run_once(self.cfg(WEBEX_LOGS="admin_audit")), 1)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.mock.answers = [401, 401]
        with self.assertRaisesRegex(c.BridgeError, r"^Webex refused the admin_audit request \(HTTP 401: test status\); "
                                    r"the app needs the audit:events_read scope, authorized by a Full Admin$"):
            c.run_once(self.cfg(WEBEX_LOGS="admin_audit"))

    def test_a_refused_refresh_token_stops_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(WEBEX_REFRESH_TOKEN="test-webex-refresh-token-wrong-not-real"))
        self.assertEqual(str(cm.exception), "Webex refused the access token request (HTTP 400: The refresh token provided "
                         "is expired, revoked, malformed, or invalid.); check WEBEX_CLIENT_ID and WEBEX_CLIENT_SECRET, or "
                         "authorize the app again and set WEBEX_REFRESH_TOKEN to the new refresh token")
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        for code in (400, 401, 403):
            self.mock.token_answers = [code]
            with self.subTest(code=code), self.assertRaisesRegex(c.BridgeError, rf"HTTP {code}: The refresh token"):
                c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_permission_errors_say_what_each_log_needs(self):
        needs = {"admin_audit": "the audit:events_read scope, authorized by a Full Admin$",
                 "security_audit": "Pro Pack for Control Hub, and Allow user authentication data turned on$",
                 "cdr": "the spark-admin:calling_cdr_read scope and the Webex Calling Detailed Call History API access permission$"}
        for log, need in needs.items():
            self.mock.answers = [403]
            with self.subTest(log=log), self.assertRaisesRegex(c.BridgeError, rf"^Webex refused the {log} request \(HTTP 403: test status\); the app needs .*{need}"):
                c.run_once(self.cfg(WEBEX_LOGS=log))
        self.mock.answers = [400]
        with self.assertRaisesRegex(c.BridgeError, r"^Webex rejected the cdr request \(HTTP 400: test status\)$"):
            c.run_once(self.cfg(WEBEX_LOGS="cdr"))

    def test_call_history_in_another_region_names_the_setting(self):
        self.mock.region_451 = True
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(WEBEX_LOGS="cdr"))
        self.assertIn("HTTP 451: the organization's call history is kept in another region; set WEBEX_CDR_URL", str(cm.exception))
        self.assertTrue(str(cm.exception).endswith("Webex names analytics-calling-au.webexapis.com."), str(cm.exception))
        self.assertEqual(len(self.calls("/v1/cdr_stream")), 1)

    def test_the_org_id_takes_a_uuid_or_the_long_form(self):
        self.assertEqual(c.load_config(base_env())["org_id"], ORG)
        self.assertEqual(c.load_config(base_env(WEBEX_ORG_ID=ORG_UUID.upper()))["org_id"], ORG)
        self.assertEqual(c.load_config(base_env(WEBEX_ORG_ID=ORG))["org_id"], ORG)
        # The call history needs no org ID.
        self.assertIsNone(c.load_config({k: v for k, v in base_env(WEBEX_LOGS="cdr").items() if k != "WEBEX_ORG_ID"})["org_id"])
        for env in ({k: v for k, v in base_env().items() if k != "WEBEX_ORG_ID"}, base_env(WEBEX_ORG_ID="not an id")):
            with self.subTest(env=env), self.assertRaisesRegex(c.BridgeError, "^WEBEX_ORG_ID is required"):
                c.load_config(env)

    def test_call_history_is_read_in_parts_of_two_hours_no_more_than_12_hours_back(self):
        self.add("/v1/cdr_stream", [cdr(1, self.ago(11 * 60)), cdr(2, self.ago(30)), cdr(3, self.now - timedelta(hours=13))])
        self.assertEqual(c.run_once(self.cfg(WEBEX_LOGS="cdr", BRIDGE_LOOKBACK_HOURS="24")), 2)
        reqs = [(parse(r["query"]["startTime"][0]), parse(r["query"]["endTime"][0])) for r in self.calls("/v1/cdr_stream")]
        self.assertEqual(len(reqs), 6)
        self.assertTrue(all(hi - lo <= timedelta(hours=2) for lo, hi in reqs))
        self.assertTrue(all(reqs[i][1] == reqs[i + 1][0] for i in range(5)))
        self.assertGreaterEqual(reqs[0][0], self.now - timedelta(hours=12))
        self.assertLessEqual(reqs[-1][1], datetime.now(timezone.utc) - timedelta(seconds=89))
        # Each part's first request waits a minute after the one before, as Webex's rate limit asks.
        self.assertEqual([round(s) for s in self.slept if s > 30], [61] * 5)
        self.assertAlmostEqual(self.saved()["logs"]["cdr"]["until"], reqs[-1][1].timestamp(), delta=1)

    def test_call_history_pages_wait_for_their_allowance(self):
        self.mock.page_cap = 2
        self.add("/v1/cdr_stream", [cdr(i, self.ago(20 - i)) for i in range(5)])
        self.assertEqual(c.run_once(self.cfg(WEBEX_LOGS="cdr", BRIDGE_LOOKBACK_HOURS="1")), 5)
        self.assertEqual(len(self.calls("/v1/cdr_stream")), 3)
        self.assertEqual([round(s, 1) for s in self.slept if s > 1], [6.5, 6.5])

    def test_call_history_older_than_12_hours_is_skipped_with_a_warning(self):
        old = (self.now - timedelta(hours=20)).timestamp()
        os.makedirs(os.path.dirname(self.state), exist_ok=True)
        with open(self.state, "w") as fh:
            json.dump({"logs": {"cdr": {"until": old, "seen": {}}}}, fh)
        c.run_once(self.cfg(WEBEX_LOGS="cdr"))
        self.assertIn("are past the 12 hours the stream keeps them and can't be read", self.logbuf.getvalue())
        first = parse(self.calls("/v1/cdr_stream")[0]["query"]["startTime"][0])
        self.assertGreaterEqual(first, self.now - timedelta(hours=12))

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.add("/v1/adminAudit/events", [admin(i, self.ago(30 - i)) for i in range(3)])
        self.add("/v1/cdr_stream", [cdr(i, self.ago(30 - i)) for i in range(3)])
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200", WEBEX_LOGS="admin_audit,cdr")
        c.run_once(cfg)
        first_end = parse(self.calls("/v1/adminAudit/events")[0]["query"]["to"][0]).timestamp()
        self.assertAlmostEqual(self.saved()["logs"]["admin_audit"]["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An event Webex listed late, inside the overlap, and a new one; a call record that reached
        # Webex late (inserted now, reported earlier) and one already sent, inserted again.
        self.add("/v1/adminAudit/events", [admin(7, self.ago(15)), admin(8, self.ago(2))])
        self.add("/v1/cdr_stream", [cdr(9, self.ago(40))], inserted=self.ago(3))
        self.add("/v1/cdr_stream", [cdr(1, self.ago(29))], inserted=self.ago(4))
        c.run_once(cfg)
        self.assertEqual(sorted(r.get("id", r.get("Report ID"))[-1] for r in self.sent()), ["7", "8", "9"])
        start = parse(self.calls("/v1/adminAudit/events")[0]["query"]["from"][0]).timestamp()
        self.assertAlmostEqual(start, first_end - 1200, delta=1)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.add("/v1/adminAudit/events", [admin(i, self.ago(10 - i)) for i in range(4)])
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(WEBEX_LOGS="admin_audit"))
        cur = self.saved()["logs"]["admin_audit"]
        self.assertNotIn("until", cur)
        self.assertEqual(len(cur["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(WEBEX_LOGS="admin_audit"))
        self.assertEqual(sorted(r["id"][-1] for r in self.sent()), ["2", "3"])
        self.assertIn("until", self.saved()["logs"]["admin_audit"])

    def test_window_end_never_passes_now(self):
        self.add("/v1/adminAudit/events", [admin(0, self.ago(5)), admin(1, self.now + timedelta(hours=2))])
        c.run_once(self.cfg())
        for cur in self.saved()["logs"].values():
            self.assertLessEqual(cur["until"], datetime.now(timezone.utc).timestamp())
        self.assertEqual([r["id"][-1] for r in self.sent()], ["0"])

    def test_a_next_link_to_another_host_is_refused(self):
        # The token only goes to the configured host, so a next page on another host isn't read.
        self.mock.page_cap = 1
        self.add("/v1/admin/securityAudit/events", [security(i, self.ago(10 - i)) for i in range(2)])
        for link in ("https://webexapis.example.com/v1/admin/securityAudit/events?cursor=1",
                     f"https://127.0.0.1:{self.server.server_address[1]}/v1/admin/securityAudit/events"):
            self.mock.next_link = link
            self.mock.requests.clear()
            with self.subTest(link=link), self.assertRaisesRegex(c.BridgeError, "next page link to another host"):
                c.run_once(self.cfg(WEBEX_LOGS="security_audit"))
            self.assertEqual(len(self.calls("/v1/admin/securityAudit/events")), 1)
        self.assertNotIn("until", self.saved()["logs"]["security_audit"])

    def test_link_headers_are_read_in_the_forms_webex_shows(self):
        msg = c.http.client.HTTPMessage()
        msg["Link"] = '<https://webexapis.com/v1/adminAudit/events?cursor=abc>; rel="next"'
        self.assertEqual(c._next_link(msg), "https://webexapis.com/v1/adminAudit/events?cursor=abc")
        msg = c.http.client.HTTPMessage()
        # The form in the call history docs, with an extra pair of angle brackets.
        msg["Link"] = '<<https://analytics-calling.webexapis.com/v1/cdr_stream?max=5000&startTimeForNextFetch=x>;rel="next">'
        self.assertEqual(c._next_link(msg), "https://analytics-calling.webexapis.com/v1/cdr_stream?max=5000&startTimeForNextFetch=x")
        msg = c.http.client.HTTPMessage()
        msg["Link"] = '<https://webexapis.com/v1/x?cursor=1>; rel="prev"'
        self.assertIsNone(c._next_link(msg))
        self.assertIsNone(c._next_link(c.http.client.HTTPMessage()))

    def test_records_without_an_id_are_skipped(self):
        bad = admin(5, self.ago(5))
        del bad["id"]
        self.add("/v1/adminAudit/events", [bad, admin(6, self.ago(4))])
        self.mock.rows["/v1/adminAudit/events"].append((self.ago(3), "not a record"))
        self.assertEqual(c.run_once(self.cfg(WEBEX_LOGS="admin_audit")), 1)
        self.assertEqual([r["id"][-1] for r in self.sent()], ["6"])

    def test_rate_limit_and_server_errors_are_retried(self):
        self.add("/v1/adminAudit/events", [admin(i, self.ago(10 - i)) for i in range(3)])
        self.mock.answers = [429, 503, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(WEBEX_LOGS="admin_audit"))
        self.assertEqual(len(self.sent()), 3)

    def test_a_retried_status_that_outlasts_the_retries_stays_a_network_error(self):
        self.mock.answers = [503] * c.MAX_ATTEMPTS
        with self.assertRaises(c.NetworkError) as cm:
            c.run_once(self.cfg(WEBEX_LOGS="security_audit"))
        self.assertIsInstance(cm.exception, c.RetriedStatus)
        self.assertEqual(cm.exception.code, 503)

    def test_gzip_batches_and_headers(self):
        self.add("/v1/adminAudit/events", [admin(i, self.ago(30 - i)) for i in range(12)])
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.rotate = True
        self.mock.refresh_left = 86400
        self.add("/v1/adminAudit/events", [admin(0, self.ago(5))])
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(WEBEX_CLIENT_SECRET="another-wrong-secret-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("admin_audit request", logged)
        for secret in (CLIENT_SECRET, INGEST_KEY, REFRESH, "00000000-example-integration", "another-wrong-secret-not-real",
                       self.mock.tokens[0], "test-webex-refresh-token-0001-not-real"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(WEBEX_CLIENT_ID=None),
            base_env(WEBEX_CLIENT_SECRET=None),
            base_env(WEBEX_REFRESH_TOKEN=None),
            base_env(WEBEX_LOGS="admin_audit,meetings"),
            base_env(WEBEX_LOGS=" , "),
            base_env(WEBEX_API_URL="http://webexapis.com"),
            base_env(WEBEX_API_URL="https://webexapis.com/v1"),
            base_env(WEBEX_CDR_URL="https://analytics-calling-au.webexapis.com/v1/cdr_stream"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["logs"], cfg["api_url"], cfg["cdr_url"]),
                         (["admin_audit", "security_audit", "cdr"], "https://webexapis.com", "https://analytics-calling.webexapis.com"))
        self.assertEqual(c.load_config(base_env(WEBEX_LOGS="CDR, Admin_Audit"))["logs"], ["cdr", "admin_audit"])

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("WEBEX_API_URL", "WEBEX_CDR_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_dry_run_prints_and_changes_nothing(self):
        self.add("/v1/admin/securityAudit/events", [security(i, self.ago(10 - i)) for i in range(2)])
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["webex_record"] for x in lines], ["security_audit", "security_audit"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the client secret, token or key to another URL, so the run
        # fails instead, and nothing reaches the redirect's target.
        self.add("/v1/adminAudit/events", [admin(0, self.ago(5))])
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration",
                                             WEBEX_LOGS="admin_audit"),
                     "Webex API": self.cfg(WEBEX_API_URL=r.base, WEBEX_LOGS="admin_audit")}
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
                        held = self.saved().get("logs", {}).get("admin_audit", {}) if os.path.exists(self.state) else {}
                        self.assertNotIn("until", held)
            # The call history host too, after a token from the Webex API.
            r.code = 302
            r.redirected.clear()
            with self.assertRaisesRegex(c.BridgeError, r"answered with a redirect \(HTTP 302\)"):
                c.run_once(self.cfg(WEBEX_CDR_URL=r.base, WEBEX_LOGS="cdr"))
            self.assertEqual((len(r.redirected), r.followed), (1, []))
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

    def test_times_go_out_to_the_millisecond_and_records_are_read_by_created(self):
        self.assertEqual(c._webex_time(1546448316.8459), "2019-01-02T16:58:36.845Z")
        self.assertEqual(c._record_time({"created": "2019-01-02T16:58:36.845Z"}, 5.0), 1546448316.845)
        for bad in ({}, {"created": "yesterday"}, {"created": 5}):
            with self.subTest(record=bad):
                self.assertEqual(c._record_time(bad, 5.0), 5.0)


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

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                c.load_config(base_env(BRIDGE_HTTP_TIMEOUT=value))
        self.assertEqual(c.load_config(base_env(BRIDGE_HTTP_TIMEOUT="0.5"))["timeout"], 0.5)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = c.load_config(base_env(WEBEX_TOKEN_FILE=os.path.join(self.tmp.name, "tokens.json"),
                                          BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "state.json")))
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
        self.tmp.cleanup()

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

    def test_one_client_serves_every_run(self):
        self.run_once_raises(RuntimeError("first"), RuntimeError("second"))
        self.assertEqual(c.main(["--interval", "5"]), 130)
        clients = [call["client"] for call in self.calls]
        self.assertEqual(len(clients), 3)
        self.assertTrue(all(cl is clients[0] for cl in clients))

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
        self.assertRegex(errors[0], r"^ERROR .+ to [a-z0-9.:-]+ failed: URLError; trying again in 5 seconds$")
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
                self.assertRegex(errors[0], rf"^ERROR .+ to [a-z0-9.:-]+ failed with HTTP {code}; trying again in 5 seconds$")
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
        self.assertRegex(errors[0], r"^ERROR .+ to [a-z0-9.:-]+ failed: the host name wasn't found; check the URL setting$")
        self.assertNotRegex(self.log.getvalue(), r"not-?real")

    def test_unknown_host_after_a_run_has_worked_is_logged_and_polling_goes_on(self):
        error = c.HostNotFound("admin_audit request to webexapis.com failed: the host name wasn't found; check the URL setting")
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
