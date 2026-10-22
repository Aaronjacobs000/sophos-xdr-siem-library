"""Unit tests for teams_call_logs_bridge.py against a local mock server.

The mock serves the shapes in Microsoft's Graph reference: POST /<tenant>/oauth2/v2.0/token with the
client credentials form (client_id, client_secret, scope, grant_type), answering {"token_type",
"expires_in", "access_token"} or {"error", "error_description"}; and GET
/v1.0/communications/callRecords/getPstnCalls(fromDateTime=...,toDateTime=...) and
getDirectRoutingCalls(...) with 'Authorization: Bearer <token>', answering {"@odata.context",
"@odata.count", "value": [pstnCallLogRow or directRoutingLogRow], "@odata.nextLink"} or
{"error": {"code", "message"}}. Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/teams-phone-call-logs -p 'test_*.py' -v
"""
import contextlib
import gc
import gzip
import io
import json
import logging
import os
import re
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
import teams_call_logs_bridge as c  # noqa: E402

# The bridge spaces its requests; the tests don't wait, except the one that checks the spacing.
c.PACE_SECONDS = 0

TENANT = "00000000-0000-4000-8000-00000000c0de"
CLIENT_ID = "11111111-2222-4333-8444-555555555555"
CLIENT_SECRET = "test-teams-client-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
FUNC = re.compile(r"^/v1\.0/communications/callRecords/(getPstnCalls|getDirectRoutingCalls)"
                  r"\(fromDateTime=([^,()]+),toDateTime=([^,()]+)\)$")


def iso(dt, digits=7):
    """Graph's timestamps, with 7 fraction digits by default."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0"[:digits] + "Z"


def pstn(i, when):
    return {"id": f"9c4984c7-6c3c-427d-a30c-bd0b2eac{i:04d}", "callId": f"1835317186_{i}@192.0.2.10",
            "userId": "db03c14b-06eb-4189-939b-7cbf3a20ba27", "userPrincipalName": "pat@example.com",
            "userDisplayName": "Pat Example", "startDateTime": iso(when), "endDateTime": iso(when + timedelta(minutes=3)),
            "duration": 180, "charge": 1.25, "callType": "user_out", "currency": "AUD", "calleeNumber": "+442079460123",
            "usageCountryCode": "AU", "tenantCountryCode": "AU", "connectionCharge": 0.0, "callerNumber": "+61255501234",
            "destinationContext": "International", "destinationName": "United Kingdom", "conferenceId": None,
            "licenseCapability": "MCOPSTN2", "inventoryType": "Subscriber", "operator": "Microsoft",
            "callDurationSource": "microsoft"}


def direct(i, when, ok=True):
    return {"id": f"9e8bba57-dc14-533a-a7dd-f0da6575{i:04d}", "correlationId": "c98e1515-a937-4b81-b8a8-3992afde64e0",
            "userId": "db03c14b-06eb-4189-939b-7cbf3a20ba27", "userPrincipalName": "pat@example.com",
            "userDisplayName": "Pat Example", "startDateTime": iso(when, 3), "inviteDateTime": iso(when, 3),
            "failureDateTime": "0001-01-01T00:00:00Z", "endDateTime": iso(when + timedelta(seconds=5), 3), "duration": 5,
            "callType": "ByotOut", "successfulCall": ok, "callerNumber": "+61255501234", "calleeNumber": "+61255509876",
            "mediaPathLocation": "AUEA", "signalingLocation": "AUSE", "finalSipCode": 0 if ok else 403,
            "callEndSubReason": 540000 if ok else 560403, "finalSipCodePhrase": "BYE" if ok else "Forbidden",
            "trunkFullyQualifiedDomainName": "sbc01.example.com", "mediaBypassEnabled": False}


def graph_time(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class Mock:
    def __init__(self):
        # rows[function] = rows
        self.rows = {"getPstnCalls": [], "getDirectRoutingCalls": []}
        self.page_cap = 1000
        self.requests = []
        self.tokens = []
        self.token_requests = []
        self.expires_in = 3599
        # Answers to send instead of the normal one, in order: an HTTP status.
        self.answers = []
        self.token_answers = []
        self.ingest_codes = []
        self.ingested = []
        # A next link to send instead of the normal one.
        self.next_link = None


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path.endswith("/oauth2/v2.0/token"):
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append({"path": url.path, "form": form, "headers": dict(self.headers)})
            if m.token_answers:
                code = m.token_answers.pop(0)
                return self._send(code, {"error": "invalid_request", "error_description":
                                         "AADSTS900144: The request body must contain the following parameter. "
                                         "Trace ID: 0000aaaa-11bb-cccc-dd22-eeeeee333333"})
            if url.path != f"/{TENANT}/oauth2/v2.0/token":
                return self._send(400, {"error": "invalid_request", "error_description": "AADSTS90002: Tenant not found."})
            if form.get("client_id") != [CLIENT_ID] or form.get("client_secret") != [CLIENT_SECRET]:
                return self._send(401, {"error": "invalid_client", "error_description":
                                        "AADSTS7000215: Invalid client secret provided. Trace ID: "
                                        "0000aaaa-11bb-cccc-dd22-eeeeee333333 Correlation ID: aaaa0000-bb11-2222-33cc-444444dddddd"})
            if form.get("grant_type") != ["client_credentials"]:
                return self._send(400, {"error": "unsupported_grant_type", "error_description": "AADSTS70003: test"})
            token = f"eyJ0-test-{len(m.tokens):04d}-not-real"
            m.tokens.append(token)
            return self._send(200, {"token_type": "Bearer", "expires_in": m.expires_in, "ext_expires_in": m.expires_in,
                                    "access_token": token})
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
            return self._send(401, {"error": {"code": "InvalidAuthenticationToken", "message": "Access token is empty."}})
        if m.answers:
            code = m.answers.pop(0)
            return self._send(code, {"error": {"code": "Forbidden" if code == 403 else "BadRequest", "message": "test status"}})
        f = FUNC.match(url.path)
        if not f:
            return self._send(404, {"error": {"code": "BadRequest", "message": "Resource not found for the segment."}})
        func, lo, hi = f.group(1), graph_time(f.group(2)), graph_time(f.group(3))
        if hi - lo > timedelta(days=90):
            return self._send(400, {"error": {"code": "BadRequest", "message": "The date range cannot exceed 90 days."}})
        # A row that isn't an object (as a broken answer might hold) is sent whatever the window.
        rows = [r for r in m.rows[func] if not isinstance(r, dict) or lo <= c._fromisoformat(r["startDateTime"]) <= hi]
        skip = int(query.get("$skip", ["0"])[0])
        chunk = rows[skip:skip + m.page_cap]
        out = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Collection(test)", "@odata.count": len(chunk),
               "value": chunk}
        if skip + m.page_cap < len(rows):
            host = self.headers.get("Host")
            out["@odata.nextLink"] = m.next_link or f"http://{host}{url.path}?$skip={skip + m.page_cap}"
        self._send(200, out)


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
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 21600, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"TEAMS_TENANT_ID": TENANT, "TEAMS_CLIENT_ID": CLIENT_ID, "TEAMS_CLIENT_SECRET": CLIENT_SECRET}
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
                     TEAMS_GRAPH_URL=self.base, TEAMS_LOGIN_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def calls(self, func):
        """The (from, to, $skip) of each request to one function."""
        out = []
        for r in self.mock.requests:
            f = FUNC.match(r["path"])
            if f and f.group(1) == func:
                out.append((graph_time(f.group(2)), graph_time(f.group(3)), r["query"].get("$skip", ["0"])[0]))
        return out

    def test_both_logs_are_read_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.mock.rows["getPstnCalls"] = [pstn(i, self.ago(50 - i)) for i in range(5)]
        self.mock.rows["getDirectRoutingCalls"] = [direct(1, self.ago(20)), direct(2, self.ago(10), ok=False)]
        self.assertEqual(c.run_once(self.cfg()), 7)
        sent = self.sent()
        calls = [r for r in sent if r["teams_record"] == "pstn"]
        self.assertEqual(sorted(r["id"] for r in calls), sorted(r["id"] for r in self.mock.rows["getPstnCalls"]))
        first = calls[0]
        self.assertEqual(list(first)[:2], ["teams_record", "teams_tenant_id"])
        self.assertEqual(first["teams_tenant_id"], TENANT)
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"teams_record":"pstn","teams_tenant_id":"'))
        original = next(r for r in self.mock.rows["getPstnCalls"] if r["id"] == first["id"])
        self.assertEqual({k: v for k, v in first.items() if not k.startswith("teams_")}, original)
        routed = [r for r in sent if r["teams_record"] == "direct_routing"]
        self.assertEqual([(r["successfulCall"], r["finalSipCode"]) for r in routed], [(True, 0), (False, 403)])
        # Five PSTN rows at two a page: three pages through @odata.nextLink, each with the same window.
        reqs = self.calls("getPstnCalls")
        self.assertEqual([r[2] for r in reqs], ["0", "2", "4"])
        self.assertEqual(len({(r[0], r[1]) for r in reqs}), 1)
        lo, hi = reqs[0][0], reqs[0][1]
        self.assertAlmostEqual((hi - lo).total_seconds(), 86400 - 60, delta=10)
        self.assertEqual(len(self.calls("getDirectRoutingCalls")), 1)

    def test_access_token_from_client_credentials_is_kept_until_it_expires(self):
        self.mock.rows["getPstnCalls"] = [pstn(1, self.ago(5))]
        client = c.Graph(self.cfg())
        c.run_once(self.cfg(), client=client)
        c.run_once(self.cfg(), client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        req = self.mock.token_requests[0]
        self.assertEqual(req["path"], f"/{TENANT}/oauth2/v2.0/token")
        self.assertEqual(req["form"], {"client_id": [CLIENT_ID], "client_secret": [CLIENT_SECRET],
                                       "scope": [f"{self.base}/.default"], "grant_type": ["client_credentials"]})
        self.assertEqual(req["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertTrue(all(r["headers"]["Authorization"] == f"Bearer {self.mock.tokens[0]}" for r in self.mock.requests))
        # A token Microsoft says expires within the renewal margin is fetched again before each request.
        self.mock.expires_in = 30
        client = c.Graph(self.cfg())
        before = len(self.mock.token_requests)
        c.run_once(self.cfg(), client=client)
        self.assertGreater(len(self.mock.token_requests) - before, 1)

    def test_the_default_hosts_and_scope_are_microsoft_s(self):
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["graph_url"], cfg["login_url"]), ("https://graph.microsoft.com", "https://login.microsoftonline.com"))
        self.assertEqual(cfg["logs"], ["pstn", "direct_routing"])

    def test_an_expired_token_is_renewed_once(self):
        self.mock.rows["getPstnCalls"] = [pstn(1, self.ago(5))]
        self.mock.answers = [401]
        self.assertEqual(c.run_once(self.cfg(TEAMS_LOGS="pstn")), 1)
        self.assertEqual(len(self.mock.token_requests), 2)
        # Refused again after a new token, the run stops.
        self.mock.answers = [401, 401]
        with self.assertRaisesRegex(c.BridgeError, r"^Microsoft Graph refused the pstn call log request \(HTTP 401: "
                                    r"BadRequest: test status\); the app needs the CallRecords.Read.All"):
            c.run_once(self.cfg(TEAMS_LOGS="pstn"))

    def test_refused_client_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(TEAMS_CLIENT_SECRET="wrong-secret-not-real"))
        self.assertEqual(str(cm.exception), "Microsoft refused the access token request (HTTP 401: invalid_client, "
                         "AADSTS7000215); check TEAMS_TENANT_ID, TEAMS_CLIENT_ID and TEAMS_CLIENT_SECRET, and that the "
                         "secret hasn't expired")
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        for code in (400, 401, 403):
            self.mock.token_answers = [code]
            with self.subTest(code=code), self.assertRaisesRegex(c.BridgeError, rf"HTTP {code}: invalid_request, AADSTS900144\)"):
                c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_a_missing_permission_stops_with_a_clear_error(self):
        self.mock.answers = [403]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertEqual(str(cm.exception), "Microsoft Graph refused the pstn call log request (HTTP 403: Forbidden: "
                         "test status); the app needs the CallRecords.Read.All application permission, with admin consent")
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.assertFalse(os.path.exists(self.state))

    def test_other_graph_errors_stop_with_graph_s_message(self):
        for code in (400, 404):
            self.mock.answers = [code]
            with self.subTest(code=code), self.assertRaisesRegex(
                    c.BridgeError, rf"^Microsoft Graph rejected the pstn call log request \(HTTP {code}: BadRequest: test status\)$"):
                c.run_once(self.cfg())

    def test_logs_setting_limits_what_is_read(self):
        c.run_once(self.cfg(TEAMS_LOGS="direct_routing"))
        self.assertEqual(self.calls("getPstnCalls"), [])
        self.assertEqual(len(self.calls("getDirectRoutingCalls")), 1)

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.rows["getPstnCalls"] = [pstn(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200", TEAMS_LOGS="pstn")
        c.run_once(cfg)
        first_end = self.calls("getPstnCalls")[0][1].timestamp()
        self.assertAlmostEqual(self.saved()["logs"]["pstn"]["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # A call Graph listed late, inside the overlap, and a new one.
        self.mock.rows["getPstnCalls"] += [pstn(7, self.ago(15)), pstn(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["id"][-1] for r in self.sent()), ["7", "8"])
        start = self.calls("getPstnCalls")[0][0].timestamp()
        self.assertAlmostEqual(start, first_end - 1200, delta=1)

    def test_lookback_sets_the_first_window(self):
        self.mock.rows["getPstnCalls"] = [pstn(0, self.now - timedelta(days=3)), pstn(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24", TEAMS_LOGS="pstn"))
        self.assertEqual([r["id"][-1] for r in self.sent()], ["1"])
        end = self.calls("getPstnCalls")[0][1].timestamp()
        self.assertLessEqual(end, datetime.now(timezone.utc).timestamp() - 59)

    def test_a_window_longer_than_graph_takes_is_read_in_parts(self):
        # Graph takes at most 90 days a query; 100 days back is read in two parts of at most 89 days.
        self.mock.rows["getPstnCalls"] = [pstn(0, self.now - timedelta(days=95)), pstn(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="2400", TEAMS_LOGS="pstn"))
        reqs = self.calls("getPstnCalls")
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[0][1], reqs[1][0])
        self.assertTrue(all(hi - lo <= timedelta(days=89) for lo, hi, _ in reqs))
        self.assertEqual(sorted(r["id"][-1] for r in self.sent()), ["0", "1"])
        self.assertAlmostEqual(self.saved()["logs"]["pstn"]["until"], reqs[1][1].timestamp(), delta=1)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.mock.rows["getPstnCalls"] = [pstn(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(TEAMS_LOGS="pstn"))
        cur = self.saved()["logs"]["pstn"]
        self.assertNotIn("until", cur)
        self.assertEqual(len(cur["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(TEAMS_LOGS="pstn"))
        self.assertEqual(sorted(r["id"][-1] for r in self.sent()), ["2", "3"])
        self.assertIn("until", self.saved()["logs"]["pstn"])

    def test_window_end_never_passes_now(self):
        self.mock.rows["getPstnCalls"] = [pstn(0, self.ago(5)), pstn(1, self.now + timedelta(hours=2))]
        c.run_once(self.cfg())
        for cur in self.saved()["logs"].values():
            self.assertLessEqual(cur["until"], datetime.now(timezone.utc).timestamp())
        self.assertEqual([r["id"][-1] for r in self.sent()], ["0"])

    def test_a_next_link_to_another_host_is_refused(self):
        # The token only goes to TEAMS_GRAPH_URL, so a next page on another host isn't read.
        self.mock.page_cap = 1
        self.mock.rows["getPstnCalls"] = [pstn(i, self.ago(10 - i)) for i in range(2)]
        for link in ("https://graph.example.com/v1.0/x?$skip=1", f"https://127.0.0.1:{self.server.server_address[1]}/x"):
            self.mock.next_link = link
            self.mock.requests.clear()
            with self.subTest(link=link), self.assertRaisesRegex(c.BridgeError, "next page link to another host"):
                c.run_once(self.cfg(TEAMS_LOGS="pstn"))
            self.assertEqual(len(self.calls("getPstnCalls")), 1)
        self.assertNotIn("until", self.saved()["logs"]["pstn"])

    def test_rows_without_an_id_are_skipped(self):
        bad = pstn(5, self.ago(5))
        del bad["id"]
        self.mock.rows["getPstnCalls"] = [bad, pstn(6, self.ago(4)), "not a row"]
        self.assertEqual(c.run_once(self.cfg(TEAMS_LOGS="pstn")), 1)
        self.assertEqual([r["id"][-1] for r in self.sent()], ["6"])

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.rows["getPstnCalls"] = [pstn(i, self.ago(10 - i)) for i in range(3)]
        self.mock.answers = [429, 503, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_requests_are_spaced_under_the_rate_budget(self):
        saved, c.PACE_SECONDS = c.PACE_SECONDS, 1.25
        try:
            c.run_once(self.cfg())
        finally:
            c.PACE_SECONDS = saved
        # Two log reads; the second waits.
        self.assertEqual(len(self.slept), 1)
        self.assertTrue(all(0 < s <= 1.25 for s in self.slept), self.slept)

    def test_gzip_batches_and_headers(self):
        self.mock.rows["getPstnCalls"] = [pstn(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.rows["getPstnCalls"] = [pstn(0, self.ago(5))]
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(TEAMS_CLIENT_SECRET="another-wrong-secret-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("pstn call log request", logged)
        for secret in (CLIENT_SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-not-real",
                       self.mock.tokens[0], "Trace ID", "Correlation ID"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(TEAMS_TENANT_ID=None),
            base_env(TEAMS_TENANT_ID="not a tenant"),
            base_env(TEAMS_TENANT_ID="../oauth2"),
            base_env(TEAMS_CLIENT_ID=None),
            base_env(TEAMS_CLIENT_SECRET=None),
            base_env(TEAMS_LOGS="pstn,sms"),
            base_env(TEAMS_LOGS=" , "),
            base_env(TEAMS_GRAPH_URL="http://graph.microsoft.com"),
            base_env(TEAMS_GRAPH_URL="https://graph.microsoft.com/v1.0"),
            base_env(TEAMS_LOGIN_URL="https://login.microsoftonline.com/common"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        self.assertEqual(c.load_config(base_env(TEAMS_TENANT_ID="contoso.onmicrosoft.com"))["tenant_id"], "contoso.onmicrosoft.com")
        self.assertEqual(c.load_config(base_env(TEAMS_LOGS="Direct_Routing, pstn"))["logs"], ["direct_routing", "pstn"])

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("TEAMS_GRAPH_URL", "TEAMS_LOGIN_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.rows["getDirectRoutingCalls"] = [direct(i, self.ago(10 - i)) for i in range(2)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["teams_record"] for x in lines], ["direct_routing", "direct_routing"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the client secret, token or key to another URL, so the run
        # fails instead, and nothing reaches the redirect's target.
        self.mock.rows["getPstnCalls"] = [pstn(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Graph": self.cfg(TEAMS_GRAPH_URL=r.base),
                     "token endpoint": self.cfg(TEAMS_LOGIN_URL=r.base)}
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
                        # The log whose call wasn't sent keeps its window.
                        held = self.saved().get("logs", {}).get("pstn", {}) if os.path.exists(self.state) else {}
                        self.assertNotIn("until", held)
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

    def test_times_are_read_with_seven_fraction_digits_and_sent_to_the_second(self):
        self.assertEqual(c._record_time({"startDateTime": "2019-11-01T00:00:08.2589935Z"}, 5.0), 1572566408.258993)
        self.assertEqual(c._record_time({"startDateTime": "2019-11-01T00:00:25.105Z"}, 5.0), 1572566425.105)
        for bad in ({}, {"startDateTime": "yesterday"}, {"startDateTime": 5}):
            with self.subTest(row=bad):
                self.assertEqual(c._record_time(bad, 5.0), 5.0)
        self.assertEqual(c._graph_time(1572566408.9), "2019-11-01T00:00:08Z")


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
        self.cfg = c.load_config(base_env())
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
        error = c.HostNotFound("pstn call log request to graph.microsoft.com failed: the host name wasn't found; check the URL setting")
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
