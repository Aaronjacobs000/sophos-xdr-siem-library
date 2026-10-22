"""Unit tests for genesys_audit_bridge.py against a local mock server.

The mock serves the shapes in the Genesys Cloud Platform API reference and its Audit pages: the
OAuth token endpoint (POST /oauth/token, 'Authorization: Basic base64(client_id:client_secret)',
form body grant_type=client_credentials; answering {"access_token", "token_type", "expires_in"},
or 400 {"error", "description", "error_description"}), POST /api/v2/audits/query (an
AuditQueryRequest {"interval", "serviceName", "filters", "sort"}; answering 202 with {"id",
"state", "startDate", "interval", "serviceName"}), GET /api/v2/audits/query/{transactionId}
({"id", "state"}, the state Queued or Running until the query has run, then Succeeded, Failed or
Cancelled) and GET /api/v2/audits/query/{transactionId}/results (pageSize up to 500, cursor;
{"id", "pageSize", "cursor", "entities": [AuditLogMessage]}, with no cursor on the last page), and
{"message", "code", "status", "contextId"} on failure, including response.entity.too.large. Plus
a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/genesys-cloud-audit-logs -p 'test_*.py' -v
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
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import genesys_audit_bridge as c  # noqa: E402

CLIENT_ID = "test-genesys-client-id-0001"
SECRET = "test-genesys-client-secret-not-real"
TOKEN = "test-genesys-access-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ORG = "org-home-0001"
USER = "user-0001"
BASE = {"GENESYS_REGION": "mypurecloud.com.au", "GENESYS_CLIENT_ID": CLIENT_ID, "GENESYS_CLIENT_SECRET": SECRET}


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit(i, when, service="PeoplePermissions", entity_type="AuthUser", action="Authenticate", status="SUCCESS"):
    return {"id": f"audit-{i:06d}", "userHomeOrgId": ORG,
            "user": {"id": USER, "name": "Pat Example", "selfUri": f"/api/v2/users/{USER}"}, "client": {"id": ""},
            "remoteIp": ["203.0.113.10"], "serviceName": service, "level": "USER", "eventDate": iso(when),
            "message": {"localizableMessageCode": "", "message": "", "messageWithParams": "", "messageParams": {}},
            "action": action, "entity": {"id": USER, "name": "pat@example.com"}, "entityType": entity_type,
            "status": status, "application": "", "initiatingAction": {}, "transactionInitiator": False,
            "propertyChanges": [], "context": {}, "entityChanges": []}


def interval(text):
    """An ISO 8601 interval, as the bridge sends it, as two epoch seconds."""
    first, last = text.split("/")
    return tuple(datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() for x in (first, last))


def cursor_for(pos):
    # Genesys says a cursor may hold characters that need URL encoding, so this one does.
    return base64.b64encode(f"pos={pos}~>?".encode()).decode()


class Mock:
    def __init__(self):
        self.events = []
        self.codes = []          # statuses the next audit API calls answer with, in turn
        self.ingest_codes = []
        self.ingested = []
        self.created = []        # each query's body as the bridge sent it
        self.queries = {}        # transaction id -> {"body", "polls", "state"}
        self.polls = []
        self.result_calls = []
        self.token_forms = []
        self.refuse_token_once = False
        self.polls_needed = 2    # status checks that answer Queued, then Running, before the end state
        self.final_state = "Succeeded"
        self.require_service = False
        self.busy = False        # another audit query is running in the organization
        self.too_large_above = None
        self.forbidden = False
        self.null_cursor = False
        self.bad_id = None


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

    def _error(self, code, message, kind):
        return self._send(code, {"message": message, "code": kind, "status": code, "contextId": "ctx-0001",
                                 "details": [], "errors": []})

    def _api_refused(self):
        """The checks every audit API call goes through first. Returns True when it answered."""
        m = self.mock
        if self.headers.get("Authorization") != f"Bearer {TOKEN}" or (m.refuse_token_once and len(m.token_forms) < 2):
            self._error(401, "Invalid login credentials.", "bad.credentials")
            return True
        if m.forbidden:
            self._error(403, "Unable to perform the requested action. You are missing the following permission(s): "
                             "audits:audit:view", "missing.permissions")
            return True
        if m.codes:
            code = m.codes.pop(0)
            if code == 429:
                self._send(429, {"message": "Rate limit exceeded the maximum. Retry the request in [3] seconds",
                                 "code": "too.many.requests.retry.after", "status": 429}, {"Retry-After": "3"})
            else:
                self._error(code, "try again", "service.unavailable")
            return True
        return False

    def do_GET(self):
        m = self.mock
        parts = urllib.parse.urlsplit(self.path)
        if self._api_refused():
            return
        segs = parts.path.split("/")
        if not (len(segs) in (6, 7) and segs[:5] == ["", "api", "v2", "audits", "query"]):
            return self._error(404, "Not found", "not.found")
        q = m.queries.get(segs[5])
        if q is None:
            return self._error(404, "The requested query was not found", "not.found")
        if len(segs) == 6:
            m.polls.append(segs[5])
            q["polls"] += 1
            state = ("Queued", "Running")[min(q["polls"] - 1, 1)] if q["polls"] <= m.polls_needed else m.final_state
            q["state"] = state
            return self._send(200 if state not in ("Queued", "Running") else 202,
                              {"id": segs[5], "state": state, "interval": q["body"]["interval"]})
        if segs[6] != "results":
            return self._error(404, "Not found", "not.found")
        params = dict(urllib.parse.parse_qsl(parts.query))
        m.result_calls.append(params)
        if q["state"] != "Succeeded":
            return self._error(400, "The query has not finished", "bad.request")
        size = int(params.get("pageSize", 25))
        if size > 500:
            return self._error(400, "pageSize must be at most 500", "bad.request")
        if m.too_large_above and size > m.too_large_above:
            return self._error(400, "The response is over the size limit. Reduce pageSize or expand list to reduce "
                                    "response size if applicable", "response.entity.too.large")
        pos = 0
        if params.get("cursor"):
            pos = int(base64.b64decode(params["cursor"]).decode().split("=")[1].rstrip("~>?"))
        first, last = interval(q["body"]["interval"])
        service = q["body"].get("serviceName")
        rows = [e for e in m.events if first <= c._parse_time(e["eventDate"]) < last
                and (service is None or e["serviceName"] == service)]
        rows.sort(key=lambda e: e["eventDate"])
        out = {"id": segs[5], "pageSize": size, "entities": rows[pos:pos + size]}
        if pos + size < len(rows):
            out["cursor"] = cursor_for(pos + size)
        elif m.null_cursor:
            out["cursor"] = None
        return self._send(200, out)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/oauth/token":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            m.token_forms.append(form)
            good = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            if self.headers.get("Authorization") != good or form != {"grant_type": "client_credentials"}:
                return self._send(400, {"error": "invalid_client", "description": "authentication failed",
                                        "error_description": "authentication failed"})
            return self._send(200, {"access_token": TOKEN, "token_type": "bearer", "expires_in": 86400})
        if self.path == "/api/v2/audits/query":
            if self._api_refused():
                return
            if self.headers.get("Content-Type") != "application/json":
                return self._error(415, "Unsupported media type", "unsupported.media.type")
            req = json.loads(body)
            m.created.append(req)
            if m.busy:
                return self._error(409, "An audit query is already running for this organization", "conflict")
            if m.require_service and not req.get("serviceName"):
                return self._error(400, "serviceName is required", "bad.request")
            first, last = interval(req["interval"])
            if last - first > 31 * 86400:
                return self._error(400, "You must specify a search interval as part of your query that does not exceed "
                                        "31 days.", "bad.request")
            tid = m.bad_id or f"0a1b2c3d-0000-4000-8000-{len(m.created):012d}"
            m.queries[tid] = {"body": req, "polls": 0, "state": "Queued"}
            return self._send(202, {"id": tid, "state": "Queued", "startDate": iso(datetime.now(timezone.utc)),
                                    "interval": req["interval"], "serviceName": req.get("serviceName")})
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
    ("GENESYS_PAGE_SIZE", "page_size", 500, 100, int, 500),
    ("GENESYS_QUERY_WAIT_SECONDS", "query_wait", 600.0, 120.5, float, 86400),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
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
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration", "NGSIEM_INGEST_KEY": INGEST_KEY,
             "GENESYS_API_URL": self.base, "GENESYS_TOKEN_URL": self.base + "/oauth/token", "BRIDGE_STATE_FILE": self.state, **BASE}
        e.update(extra)
        return c.load_config(e)

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_one_query_reads_every_page_and_tags_events(self):
        m = self.mock
        m.events = [audit(i, self.ago(50 - i)) for i in range(7)]
        self.assertEqual(c.run_once(self.cfg(GENESYS_PAGE_SIZE="3")), 7)
        self.assertTrue(m.ingested[0]["raw"].startswith('{"genesys_record":"audit","id":"audit-000000",'))
        self.assertEqual([{k: v for k, v in r.items() if k != "genesys_record"} for r in self.sent()], m.events)
        # One query for every service, oldest first, with no service name.
        self.assertEqual(len(m.created), 1)
        body = m.created[0]
        self.assertEqual(sorted(body), ["interval", "sort"])
        self.assertEqual(body["sort"], [{"name": "Timestamp", "sortOrder": "ascending"}])
        first, last = interval(body["interval"])
        self.assertAlmostEqual(first, (self.now - timedelta(hours=24)).timestamp(), delta=2)
        self.assertAlmostEqual(last, self.now.timestamp(), delta=2)
        # The state is checked until the query has run, then the results are read page by page.
        self.assertEqual(self.slept, [1.0, 2.0, 4.0])
        self.assertEqual(len(m.polls), 3)
        self.assertEqual([r.get("cursor") for r in m.result_calls], [None, cursor_for(3), cursor_for(6)])
        self.assertEqual({r["pageSize"] for r in m.result_calls}, {"3"})
        self.assertEqual(len(m.token_forms), 1)
        self.assertAlmostEqual(self.saved()["all"]["until"], last, delta=1)

    def test_the_next_run_starts_at_the_last_end_less_the_overlap_and_repeats_are_dropped(self):
        m = self.mock
        m.events = [audit(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        end = interval(m.created[0]["interval"])[1]
        m.ingested.clear()
        m.events.append(audit(9, self.ago(10)))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], ["audit-000009"])
        self.assertEqual(interval(m.created[1]["interval"])[0], end - 900)

    def test_a_late_event_inside_the_overlap_still_goes_on(self):
        # An event that shows up in the query after the window that holds its time was read.
        m = self.mock
        c.run_once(self.cfg())
        end = interval(m.created[0]["interval"])[1]
        m.events = [audit(1, datetime.fromtimestamp(end - 300, timezone.utc))]
        c.run_once(self.cfg())
        self.assertEqual([r["id"] for r in self.sent()], ["audit-000001"])

    def test_a_long_lookback_is_read_in_14_day_intervals_within_retention(self):
        m = self.mock
        m.events = [audit(i, self.now - timedelta(days=d)) for i, d in enumerate((5, 70, 200, 370))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS=str(24 * 400)))
        self.assertEqual(sorted(r["id"] for r in self.sent()), ["audit-000000", "audit-000001", "audit-000002"])
        spans = [interval(b["interval"]) for b in m.created]
        self.assertTrue(all(b - a <= 14 * 86400 for a, b in spans))
        self.assertTrue(all(spans[i][1] == spans[i + 1][0] for i in range(len(spans) - 1)))
        self.assertGreaterEqual(spans[0][0], (self.now - timedelta(days=365)).timestamp())
        self.assertAlmostEqual(spans[-1][1], self.now.timestamp(), delta=2)
        # Only events in the overlap before the last end are kept to drop repeats.
        seen = self.saved()["all"]["seen"]
        self.assertEqual(sorted(seen), [])

    def test_services_are_queried_in_turn_when_named(self):
        m = self.mock
        m.events = [audit(0, self.ago(20)), audit(1, self.ago(15), service="Telephony", entity_type="Trunk", action="Update"),
                    audit(2, self.ago(10), service="Routing", entity_type="Queue", action="Create")]
        self.assertEqual(c.run_once(self.cfg(GENESYS_SERVICES="PeoplePermissions, Telephony,PeoplePermissions")), 2)
        self.assertEqual([b.get("serviceName") for b in m.created], ["PeoplePermissions", "Telephony"])
        self.assertEqual(sorted(r["id"] for r in self.sent()), ["audit-000000", "audit-000001"])
        self.assertEqual(sorted(self.saved()), ["PeoplePermissions", "Telephony"])

    def test_a_service_name_refusal_says_to_set_genesys_services(self):
        self.mock.require_service = True
        with self.assertRaises(c.BridgeError) as caught:
            c.run_once(self.cfg())
        self.assertIn("HTTP 400", str(caught.exception))
        self.assertIn("serviceName is required (bad.request)", str(caught.exception))
        self.assertIn("set GENESYS_SERVICES", str(caught.exception))
        self.assertNotIsInstance(caught.exception, c.NetworkError)
        self.mock.events = [audit(0, self.ago(5))]
        self.assertEqual(c.run_once(self.cfg(GENESYS_SERVICES="PeoplePermissions")), 1)

    def test_a_failed_or_cancelled_query_is_asked_again_next_run(self):
        for state in ("Failed", "Cancelled"):
            with self.subTest(state=state):
                if os.path.exists(self.state):
                    os.remove(self.state)
                self.mock.final_state = state
                self.mock.events = [audit(0, self.ago(5))]
                with self.assertRaises(c.QueryNotDone) as caught:
                    c.run_once(self.cfg())
                self.assertIsInstance(caught.exception, c.NetworkError)
                self.assertIn(f"ended {state.lower()}", str(caught.exception))
                self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("all", {}))
                self.assertEqual(self.mock.result_calls, [])

    def test_a_query_that_runs_too_long_waits_for_the_next_run(self):
        self.mock.polls_needed = 1000
        with self.assertRaises(c.QueryNotDone) as caught:
            c.run_once(self.cfg(GENESYS_QUERY_WAIT_SECONDS="30"))
        self.assertIn("still running after", str(caught.exception))
        self.assertLessEqual(sum(self.slept), 30)
        self.assertEqual(self.slept, [1.0, 2.0, 4.0, 8.0, 10.0])
        self.assertEqual(self.mock.result_calls, [])

    def test_another_running_query_waits_for_the_next_run(self):
        self.mock.busy = True
        with self.assertRaises(c.QueryNotDone) as caught:
            c.run_once(self.cfg())
        self.assertIn("HTTP 409", str(caught.exception))
        self.assertIn("one audit query at a time", str(caught.exception))

    def test_a_page_too_large_is_read_again_at_half_the_size(self):
        self.mock.events = [audit(i, self.ago(200 - i)) for i in range(150)]
        self.mock.too_large_above = 100
        self.assertEqual(c.run_once(self.cfg()), 150)
        self.assertEqual([r["pageSize"] for r in self.mock.result_calls][:4], ["500", "250", "125", "62"])
        self.assertEqual({r["pageSize"] for r in self.mock.result_calls[3:]}, {"62"})
        self.assertIn("reading 62 at a time", self.logbuf.getvalue())
        self.mock.too_large_above = 10
        self.mock.ingested.clear()
        with self.assertRaises(c.BridgeError) as caught:
            c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="2", BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "other.json")))
        self.assertIn("response.entity.too.large", str(caught.exception))

    def test_a_null_cursor_ends_the_results(self):
        self.mock.events = [audit(i, self.ago(10 - i)) for i in range(2)]
        self.mock.null_cursor = True
        self.assertEqual(c.run_once(self.cfg()), 2)
        self.assertEqual(len(self.mock.result_calls), 1)

    def test_an_unusable_transaction_id_stops_the_run(self):
        self.mock.bad_id = "../../users"
        with self.assertRaisesRegex(c.BridgeError, "^the audit query returned no usable transaction id$"):
            c.run_once(self.cfg())
        self.assertEqual(self.mock.polls, [])

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.events = [audit(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(GENESYS_PAGE_SIZE="2"))
        saved = self.saved()["all"]
        self.assertNotIn("until", saved)
        self.assertEqual(sorted(saved["seen"]), ["audit-000000", "audit-000001"])
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(GENESYS_PAGE_SIZE="2"))
        self.assertEqual(sorted(r["id"] for r in self.sent()), ["audit-000002", "audit-000003"])
        self.assertIn("until", self.saved()["all"])

    def test_an_event_without_an_id_is_sent_once(self):
        row = audit(0, self.ago(5))
        del row["id"]
        self.mock.events = [row]
        c.run_once(self.cfg())
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)

    def test_a_refused_access_token_is_renewed_once(self):
        self.mock.events = [audit(0, self.ago(5))]
        self.mock.refuse_token_once = True
        c.run_once(self.cfg())
        self.assertEqual(len(self.mock.token_forms), 2)
        self.assertEqual(len(self.sent()), 1)

    def test_refused_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as caught:
            c.run_once(self.cfg(GENESYS_CLIENT_SECRET="wrong-secret-0000000000"))
        self.assertIn("HTTP 400", str(caught.exception))
        self.assertIn("authentication failed (invalid_client)", str(caught.exception))
        self.assertIn("Client Credentials grant", str(caught.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_a_missing_permission_names_it(self):
        self.mock.forbidden = True
        with self.assertRaises(c.BridgeError) as caught:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403", str(caught.exception))
        self.assertIn("Audits > Audit > View", str(caught.exception))
        self.assertNotIsInstance(caught.exception, c.NetworkError)

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [audit(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["genesys_record"] for x in lines], ["audit"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.events = [audit(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        self.assertIn(3.0, self.slept)  # Retry-After: 3

    def test_gzip_batches_and_headers(self):
        self.mock.events = [audit(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = [audit(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as caught:
            c.run_once(self.cfg(GENESYS_CLIENT_SECRET="another-wrong-secret-000"))
        logged = self.logbuf.getvalue() + str(caught.exception)
        self.assertIn("audit query", logged)
        basic = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
        for secret in (SECRET, TOKEN, INGEST_KEY, basic, "00000000-example-integration", "another-wrong-secret-000"):
            self.assertNotIn(secret, logged)

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("GENESYS_API_URL", "GENESYS_TOKEN_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_the_region_names_both_hosts(self):
        cfg = c.load_config({**BASE, "GENESYS_REGION": "MyPureCloud.com.au"})
        self.assertEqual((cfg["api_url"], cfg["token_url"]),
                         ("https://api.mypurecloud.com.au", "https://login.mypurecloud.com.au/oauth/token"))
        cfg = c.load_config({**BASE, "GENESYS_REGION": "use2.us-gov-pure.cloud"})
        self.assertEqual(cfg["token_url"], "https://login.use2.us-gov-pure.cloud/oauth/token")
        self.assertEqual(len(c.REGIONS), len(set(c.REGIONS)))

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "GENESYS_REGION": "example.com"}, {"GENESYS_CLIENT_ID": CLIENT_ID, "GENESYS_CLIENT_SECRET": SECRET},
                    {**BASE, "GENESYS_API_URL": "http://api.genesys.example"},
                    {**BASE, "GENESYS_TOKEN_URL": "http://login.genesys.example/oauth/token"},
                    {"GENESYS_REGION": "mypurecloud.com", "GENESYS_CLIENT_ID": CLIENT_ID},
                    {**BASE, "GENESYS_CLIENT_ID": "a:b"}, {**BASE, "GENESYS_SERVICES": "People Permissions"},
                    {**BASE, "GENESYS_SERVICES": "../x"}, {**BASE, "GENESYS_PAGE_SIZE": "501"}, {**BASE, "GENESYS_PAGE_SIZE": "0"},
                    {**BASE, "GENESYS_QUERY_WAIT_SECONDS": "0"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "GENESYS_CLIENT_SECRET"}), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["services"], cfg["page_size"], cfg["overlap_seconds"]), ([], 500, 900))
        # Both hosts set by hand need no region, for a region the list doesn't have yet.
        cfg = c.load_config({"GENESYS_CLIENT_ID": CLIENT_ID, "GENESYS_CLIENT_SECRET": SECRET,
                             "GENESYS_API_URL": "https://api.new-region.example", "GENESYS_TOKEN_URL": "https://login.new-region.example/oauth/token"})
        self.assertEqual(cfg["api_url"], "https://api.new-region.example")

    def test_intervals_cover_the_window_once(self):
        start = datetime(2026, 8, 1, 13, tzinfo=timezone.utc).timestamp()
        end = datetime(2026, 9, 2, 2, 30, tzinfo=timezone.utc).timestamp()
        got = c.intervals(start + 0.7, end + 0.2)
        self.assertEqual(got[0][0], start)
        self.assertEqual(got[-1][1], end)
        self.assertEqual([round((b - a) / 86400, 3) for a, b in got], [14.0, 14.0, round((end - start) / 86400 - 28, 3)])
        self.assertEqual(c.intervals(end, end), [])
        self.assertEqual(c._iso(start), "2026-08-01T13:00:00Z")

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2026, 10, 13, 1, 10, 4, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-13T01:10:04Z", want), ("2026-10-13T01:10:04.5Z", want + 0.5),
                               ("2026-10-13T12:10:04.123456789+11:00", want + 0.123456)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))

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
                    self.assertAlmostEqual(c._parse_time(text), expected.timestamp(), places=5)

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.events = [audit(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "token endpoint": self.cfg(GENESYS_TOKEN_URL=r.base + "/oauth/token"),
                     "Audit API": self.cfg(GENESYS_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("all", {}))
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

    def load(self, **extra):
        return c.load_config({**BASE, **extra})

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "501"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^GENESYS_PAGE_SIZE must be between 1 and 500$"):
                self.load(GENESYS_PAGE_SIZE=value)
        self.assertEqual(self.load(GENESYS_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(GENESYS_PAGE_SIZE="500")["page_size"], 500)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config(BASE)
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

    def test_a_query_that_didnt_finish_keeps_polling_too(self):
        self.run_once_raises(c.QueryNotDone("the audit query ended failed on Genesys Cloud's side; the next run asks again"))
        self.assertEqual(c.main(["--interval", "300"]), 130)
        self.assertEqual(len(self.calls), 2)

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
        error = c.HostNotFound("audit query to api.example.com failed: the host name wasn't found; check the URL setting")
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
