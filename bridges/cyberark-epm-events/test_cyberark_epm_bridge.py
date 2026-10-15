"""Unit tests for cyberark_epm_bridge.py against a local mock server.

The mock serves the shapes in CyberArk's EPM web services reference and its ISPSS authentication
guide: POST /oauth2/token/<app id> on the Identity tenant (the service user with Basic
authentication and grant_type=client_credentials, answering {"access_token", "token_type",
"expires_in"}), GET /API/Sets (offset, limit; answering {"SetsCount", "Sets": [{"Id", "Name",
"Description", "IsNPVDI"}]}), and POST /API/Sets/<set id>/Events/Search and
/API/Sets/<set id>/policyaudits/search (nextCursor=start then the returned cursor, limit, and a
{"filter": "arrivalTime GE ... AND arrivalTime LE ..."} body; answering {"events", "filteredCount",
"returnedCount", "nextCursor"}), with [{"ErrorCode", "ErrorMessage"}] on errors. Plus a Sophos
NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/cyberark-epm-events -p 'test_*.py' -v
"""
import base64
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
import cyberark_epm_bridge as c  # noqa: E402

CLIENT_ID = "epm-siem-reader@acme.example.com"
SECRET = "test-cyberark-service-user-password-not-real"
APP_ID = "epmapisiem"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
SET_A = {"Id": "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "Name": "Acme Workstations", "Description": "", "IsNPVDI": False}
SET_B = {"Id": "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d", "Name": "Acme Servers", "Description": "", "IsNPVDI": False}
FILTER = re.compile(r"^arrivalTime GE (\S+) AND arrivalTime LE (\S+)(?: AND eventType IN (\S+))?$")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def raw_event(i, when, event_type="Launch"):
    return {"policyName": None, "hash": f"{i:040X}", "publisher": "Acme Software Pty Ltd", "eventType": event_type,
            "sourceType": "LocalDisk", "sourceName": "Windows Explorer", "lastEventDate": iso(when - timedelta(seconds=20)),
            "firstEventDate": iso(when - timedelta(seconds=20)), "userName": "ACME\\akim", "fileName": f"app{i}.exe",
            "filePath": f"C:\\Program Files\\Acme\\app{i}.exe", "displayName": f"App {i} (app{i}.exe)", "userIsAdmin": False,
            "agentEventCount": 1, "agentId": "78350d3c-5960-4f39-975a-ed07b53924a4", "arrivalTime": iso(when),
            "lastEventComputerName": "FIN-LT-041"}


def policy_audit(i, when):
    return {"hash": f"{i + 500:040X}", "publisher": "Microsoft Windows", "eventType": "Block", "userName": "ACME\\pexample",
            "fileName": "mshta.exe", "filePath": "C:\\Windows\\System32\\mshta.exe", "firstEventDate": iso(when - timedelta(seconds=30)),
            "lastEventDate": iso(when - timedelta(seconds=30)), "policyName": "Block script hosts", "policyAction": "Block",
            "arrivalTime": iso(when), "operatingSystemType": "Windows", "agentId": "5c6d7e8f-9a0b-4c1d-8e2f-3a4b5c6d7e8f",
            "computerName": "OPS-LT-112", "arguments": f"https://payload.example.org/{i}.hta"}


def error_body(message, code="EPM000000E"):
    return [{"ErrorCode": code, "ErrorMessage": message}]


def cursor_for(position):
    return base64.urlsafe_b64encode(json.dumps({"p": position}).encode()).decode()


class Mock:
    def __init__(self):
        self.sets = [SET_A]
        self.events = {}   # set id -> raw events
        self.audits = {}   # set id -> policy audits
        self.page_cap = 1000
        self.access_tokens = []
        self.expired = set()
        self.token_requests = []
        self.requests = []
        self.codes = []
        self.token_codes = []
        self.ingest_codes = []
        self.ingested = []


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

    def _authorized(self):
        m = self.mock
        auth = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
        if auth not in m.access_tokens or auth in m.expired:
            self._send(401, error_body("Your session has expired and your user has been disconnected", "EPM000001E"))
            return False
        if m.codes:
            code = m.codes.pop(0)
            self._send(code, error_body("The user might not have the necessary permissions for the action." if code == 403
                                        else "Too many requests."))
            return False
        return True

    def do_GET(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        m.requests.append({"method": "GET", "path": url.path, "query": query, "raw_query": url.query, "headers": dict(self.headers)})
        if url.path != "/API/Sets":
            return self._send(404, error_body("The requested resource could not be found."))
        if not self._authorized():
            return None
        offset, limit = int(query.get("offset", ["0"])[0]), int(query.get("limit", ["50"])[0])
        return self._send(200, {"SetsCount": len(m.sets), "Sets": m.sets[offset:offset + limit]})

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == f"/oauth2/token/{APP_ID}":
            m.token_requests.append({"headers": dict(self.headers), "form": urllib.parse.parse_qs(body.decode())})
            if m.token_codes:
                return self._send(m.token_codes.pop(0), {"error": "temporarily_unavailable"})
            expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            if self.headers.get("Authorization") != expected:
                return self._send(400, {"error": "invalid_client", "error_description": "Authentication (login or client secret) failed."})
            token = f"access-token-{len(m.access_tokens) + 1}"
            m.access_tokens.append(token)
            return self._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": "all"})
        found = re.fullmatch(r"/API/Sets/([^/]+)/(Events/Search|policyaudits/search)", url.path)
        if found:
            query = urllib.parse.parse_qs(url.query)
            req = json.loads(body)
            m.requests.append({"method": "POST", "path": url.path, "query": query, "raw_query": url.query, "body": req,
                               "headers": dict(self.headers)})
            if not self._authorized():
                return None
            set_id, kind = found.groups()
            if set_id not in [s["Id"] for s in m.sets]:
                return self._send(404, error_body("The wrong SetId or EndpointId was provided in the URL."))
            f = FILTER.match(req.get("filter") or "")
            if not f:
                return self._send(400, error_body("The filter could not be understood."))
            lo, hi, types = c._parse_time(f.group(1)), c._parse_time(f.group(2)), f.group(3)
            rows = (m.events if kind == "Events/Search" else m.audits).get(set_id, [])
            rows = [e for e in rows if lo <= c._parse_time(e["arrivalTime"]) <= hi and (not types or e["eventType"] in types.split(","))]
            rows.sort(key=lambda e: c._parse_time(e["arrivalTime"]))
            cursor = query.get("nextCursor", ["start"])[0]
            position = 0 if cursor == "start" else json.loads(base64.urlsafe_b64decode(cursor))["p"]
            size = min(int(query.get("limit", ["250"])[0]), m.page_cap)
            chunk = rows[position:position + size]
            nxt = cursor_for(position + size) if position + size < len(rows) else ""
            return self._send(200, {"events": chunk, "filteredCount": len(rows), "returnedCount": len(chunk), "nextCursor": nxt})
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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("CYBERARK_EPM_PAGE_SIZE", "page_size", 1000, 500, int, 1000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"CYBERARK_IDENTITY_URL": "https://abc1234.id.cyberark.cloud", "CYBERARK_APP_ID": APP_ID,
         "CYBERARK_CLIENT_ID": CLIENT_ID, "CYBERARK_CLIENT_SECRET": SECRET, "CYBERARK_EPM_API_URL": "https://api-au.epm.cyberark.cloud"}
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
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
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
                     CYBERARK_IDENTITY_URL=self.base, CYBERARK_EPM_API_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self, kind=None):
        rows = [line for post in self.mock.ingested for line in post["lines"]]
        return [r for r in rows if kind is None or r["cyberark_epm_record"] == kind]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def searches(self, kind=None):
        return [r for r in self.mock.requests if r["method"] == "POST" and (kind is None or r["path"].endswith(kind))]

    def test_every_set_and_source_is_read_tagged_and_paged(self):
        self.mock.sets = [SET_A, SET_B]
        self.mock.page_cap = 2
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(50 - i)) for i in range(5)], SET_B["Id"]: [raw_event(9, self.ago(5), "Block")]}
        self.mock.audits = {SET_A["Id"]: [policy_audit(i, self.ago(30 - i)) for i in range(2)]}
        self.assertEqual(c.run_once(self.cfg()), 8)
        raw, audits = self.sent("raw_event"), self.sent("policy_audit")
        self.assertEqual([r["fileName"] for r in raw if r["setId"] == SET_A["Id"]], [f"app{i}.exe" for i in range(5)])
        self.assertEqual([(r["setName"], r["eventType"]) for r in raw if r["setId"] == SET_B["Id"]], [("Acme Servers", "Block")])
        self.assertEqual(len(audits), 2)
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(
            '{"cyberark_epm_record":"raw_event","setId":"0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0","setName":"Acme Workstations","policyName":null'))
        first = {k: v for k, v in raw[0].items() if k not in ("cyberark_epm_record", "setId", "setName")}
        self.assertEqual(first, self.mock.events[SET_A["Id"]][0])
        # Three pages of raw events for set A: start, then the cursors EPM returned.
        a = [r for r in self.searches("Events/Search") if SET_A["Id"] in r["path"]]
        self.assertEqual([r["query"]["nextCursor"][0] for r in a], ["start", c.urllib.parse.unquote(cursor_for(2)), c.urllib.parse.unquote(cursor_for(4))])
        self.assertEqual(a[0]["query"]["limit"], ["1000"])
        f = FILTER.match(a[0]["body"]["filter"])
        self.assertIsNotNone(f)
        self.assertAlmostEqual(c._parse_time(f.group(2)) - c._parse_time(f.group(1)), 86400 - 60, delta=10)
        self.assertEqual(len({r["body"]["filter"] for r in a}), 1)
        sets_call = [r for r in self.mock.requests if r["path"] == "/API/Sets"][0]
        self.assertEqual(sets_call["query"], {"offset": ["0"], "limit": ["1000"]})

    def test_token_request_uses_the_service_user_and_the_web_app(self):
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5))]}
        client = c.Epm(self.cfg())
        c.run_once(self.cfg(), client=client)
        req = self.mock.token_requests[0]
        self.assertEqual(req["headers"]["Authorization"], "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode())
        self.assertEqual(req["form"], {"grant_type": ["client_credentials"]})
        self.assertTrue(all(r["headers"]["Authorization"] == "Bearer access-token-1" for r in self.mock.requests))
        # The same client keeps its token for the next run, so --interval doesn't sign in each time.
        c.run_once(self.cfg(), client=client)
        self.assertEqual(len(self.mock.token_requests), 1)

    def test_an_expired_access_token_is_renewed_once(self):
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(10 - i)) for i in range(3)]}
        client = c.Epm(self.cfg())
        client.token()
        self.mock.expired.add("access-token-1")
        c.run_once(self.cfg(CYBERARK_EPM_SOURCES="raw_events"), client=client)
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.assertEqual(self.mock.requests[-1]["headers"]["Authorization"], "Bearer access-token-2")

    def test_set_ids_limit_the_sets_read(self):
        self.mock.sets = [SET_A, SET_B]
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5))], SET_B["Id"]: [raw_event(1, self.ago(5))]}
        c.run_once(self.cfg(CYBERARK_EPM_SET_IDS=SET_B["Id"]))
        self.assertEqual({r["setId"] for r in self.sent()}, {SET_B["Id"]})
        with self.assertRaisesRegex(c.BridgeError, "names 1 set"):
            c.run_once(self.cfg(CYBERARK_EPM_SET_IDS="0000aaaa-0000-0000-0000-000000000000"))

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(30 - i)) for i in range(3)]}
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200", CYBERARK_EPM_SOURCES="raw_events")
        c.run_once(cfg)
        first_end = c._parse_time(FILTER.match(self.searches()[0]["body"]["filter"]).group(2))
        self.assertAlmostEqual(self.saved()["raw_events"][SET_A["Id"]]["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An event that reached EPM late, inside the overlap, and a new one.
        self.mock.events[SET_A["Id"]] += [raw_event(7, self.ago(15)), raw_event(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["fileName"] for r in self.sent()), ["app7.exe", "app8.exe"])
        start = c._parse_time(FILTER.match(self.searches()[0]["body"]["filter"]).group(1))
        self.assertAlmostEqual(start, first_end - 1200, delta=1)

    def test_lookback_sets_the_first_window(self):
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.now - timedelta(days=3)), raw_event(1, self.ago(60))]}
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24", CYBERARK_EPM_SOURCES="raw_events"))
        self.assertEqual([r["fileName"] for r in self.sent()], ["app1.exe"])
        f = FILTER.match(self.searches()[0]["body"]["filter"])
        self.assertLessEqual(c._parse_time(f.group(2)), datetime.now(timezone.utc).timestamp() - 59)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(10 - i)) for i in range(4)]}
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(CYBERARK_EPM_SOURCES="raw_events"))
        saved = self.saved()["raw_events"][SET_A["Id"]]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(CYBERARK_EPM_SOURCES="raw_events"))
        self.assertEqual([r["fileName"] for r in self.sent()], ["app2.exe", "app3.exe"])
        self.assertIn("until", self.saved()["raw_events"][SET_A["Id"]])

    def test_event_dated_in_the_future_leaves_the_window_end_at_now(self):
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5))]}
        c.run_once(self.cfg(CYBERARK_EPM_SOURCES="raw_events"))
        self.assertLessEqual(self.saved()["raw_events"][SET_A["Id"]]["until"], datetime.now(timezone.utc).timestamp())

    def test_event_types_and_sources_settings(self):
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5)), raw_event(1, self.ago(4), "AttackBlock"), raw_event(2, self.ago(3), "Block")]}
        self.mock.audits = {SET_A["Id"]: [policy_audit(0, self.ago(5))]}
        c.run_once(self.cfg(CYBERARK_EPM_EVENT_TYPES="AttackBlock, Block", CYBERARK_EPM_SOURCES="raw_events"))
        self.assertEqual(sorted(r["eventType"] for r in self.sent()), ["AttackBlock", "Block"])
        self.assertTrue(self.searches()[0]["body"]["filter"].endswith(" AND eventType IN AttackBlock,Block"))
        self.assertEqual(self.searches("policyaudits/search"), [])

    def test_refused_credentials_and_permissions_stop_with_clear_errors(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(CYBERARK_CLIENT_SECRET="wrong-password-0000000000"))
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("Authentication (login or client secret) failed", str(cm.exception))
        self.assertIn("CYBERARK_APP_ID", str(cm.exception))
        self.assertEqual(self.mock.requests, [])
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5))]}
        client = c.Epm(self.cfg())
        client.sets()
        self.mock.codes = [403]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(), client=client)
        self.assertIn("HTTP 403", str(cm.exception))
        self.assertIn("EPM000000E: The user might not have the necessary permissions", str(cm.exception))
        self.assertIn("100,000 events", str(cm.exception))

    def test_a_rejected_filter_shows_the_error(self):
        client = c.Epm(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            client.search("raw_events", SET_A["Id"], "fileName EQ x", "start")
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("The filter could not be understood", str(cm.exception))

    def test_calls_to_epm_are_spaced(self):
        client = c.Epm(self.cfg())
        client.sets()
        client.sets()
        gaps = [s for s in self.slept if 0 < s <= c.MIN_CALL_GAP]
        self.assertEqual(len(gaps), 1)

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(10 - i)) for i in range(2)]}
        self.mock.audits = {SET_A["Id"]: [policy_audit(0, self.ago(5))]}
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["cyberark_epm_record"] for x in lines], ["raw_event", "raw_event", "policy_audit"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(10 - i)) for i in range(3)]}
        self.mock.codes = [429, 503]
        self.mock.token_codes = [503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.events = {SET_A["Id"]: [raw_event(i, self.ago(30 - i)) for i in range(12)]}
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5))]}
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(CYBERARK_CLIENT_SECRET="another-wrong-password-000000"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("sets request", logged)
        for secret in (CLIENT_ID, SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-password-000000", "access-token-1"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(CYBERARK_IDENTITY_URL=None),
            base_env(CYBERARK_IDENTITY_URL="http://abc1234.id.cyberark.example"),
            base_env(CYBERARK_APP_ID=None),
            base_env(CYBERARK_APP_ID="../token"),
            base_env(CYBERARK_CLIENT_ID=None),
            base_env(CYBERARK_CLIENT_SECRET=None),
            base_env(CYBERARK_EPM_API_URL=None),
            base_env(CYBERARK_EPM_API_URL="http://api-au.epm.cyberark.example"),
            base_env(CYBERARK_EPM_SET_IDS="good-set,../bad"),
            base_env(CYBERARK_EPM_SOURCES="raw_events,admin_audit"),
            base_env(CYBERARK_EPM_EVENT_TYPES="Block,Launch OR 1"),
            base_env(CYBERARK_EPM_PAGE_SIZE="0"),
            base_env(CYBERARK_EPM_PAGE_SIZE="1001"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual(cfg["sources"], ["raw_events", "policy_audits"])
        self.assertEqual((cfg["set_ids"], cfg["event_types"], cfg["page_size"]), ([], [], 1000))

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2023, 1, 31, 5, 49, 1, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2023-01-31T05:49:01Z", want), ("2023-01-31T05:49:01.641Z", want + 0.641),
                               ("2023-01-31T05:49:01.7Z", want + 0.7), ("2023-01-31T15:49:01.641+10:00", want + 0.641),
                               ("2023-01-31T05:49:01.123456789Z", want + 0.123456)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))
        self.assertIsNone(c._parse_time(None))
        self.assertEqual(c._epm_time(want + 0.9), "2023-01-31T05:49:01Z")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.events = {SET_A["Id"]: [raw_event(0, self.ago(5))]}
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Identity": self.cfg(CYBERARK_IDENTITY_URL=r.base),
                     "EPM API": self.cfg(CYBERARK_EPM_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("raw_events", {}).get(SET_A["Id"], {}))
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
                    self.assertAlmostEqual(c._parse_time(text), expected.timestamp(), places=5)


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
        return c.load_config(base_env(**extra))

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "1001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^CYBERARK_EPM_PAGE_SIZE must be between 1 and 1,000$"):
                self.load(CYBERARK_EPM_PAGE_SIZE=value)
        self.assertEqual(self.load(CYBERARK_EPM_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(CYBERARK_EPM_PAGE_SIZE="1000")["page_size"], 1000)


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
