"""Unit tests for citrix_cloud_logs_bridge.py against a local mock server.

The mock serves the shapes in Citrix's System Log, DaaS REST API and Monitor OData API references:
POST /cctrustoauth2/<customerId>/tokens/clients with the form fields grant_type, client_id and
client_secret, answering {"token_type": "bearer", "access_token", "expires_in": "3600"}; GET
/systemlog/records with StartDateTime, EndDateTime, Limit and ContinuationToken, answering {"Items",
"Count", "EstimatedTotalItems", "ContinuationToken"}; GET /cvad/manage/me, answering the customer's
sites; GET /cvad/manage/ConfigLog/Operations with Citrix-InstanceId, days, limit and
continuationToken, answering {"Items", "ContinuationToken"} most recent first; and GET
/monitorodata/Connections with $filter, $orderby and $expand, answering {"value", "@odata.nextLink"}.
Every GET takes 'Authorization: CwsAuth Bearer=<token>' and Citrix-CustomerId. Plus a Sophos NG-SIEM
HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/citrix-cloud-logs -p 'test_*.py' -v
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
import citrix_cloud_logs_bridge as c  # noqa: E402

CUSTOMER = "exampleco1x2y"
CLIENT_ID = "0f1e2d3c-test-citrix-client-id-not-real"
CLIENT_SECRET = "test-citrix-client-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
SITE_A = "3061173e-0a1b-4c2d-8e3f-405162738495"
SITE_B = "4172284f-1b2c-4d3e-9f40-516273849506"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z"


def systemlog(i, when):
    """A System Log record in the shape of Citrix's example."""
    return {"RecordId": None if i % 2 else f"a1b2c3d4-0000-4000-8000-{i:012d}", "UtcTimestamp": iso(when), "CustomerId": CUSTOMER,
            "EventType": "platform/administrator/create", "TargetId": f"62336441613649771{i:02d}", "TargetDisplayName": "lee@example.com",
            "TargetEmail": "lee@example.com", "TargetUserId": "a90b4449675f4fcf97e1663623334d74", "TargetType": "administrator",
            "BeforeChanges": None, "AfterChanges": {"AccessType": "Full", "Principal": "lee@example.com"}, "AgentId": "platform",
            "ServiceProfileName": None, "ActorId": "b80c5550786f5adf08f2774734445e85", "ActorDisplayName": "Alex Kim",
            "ActorType": "administrator", "Message": {"en-US": f"Created new administrator user '62336441613649771{i:02d}'."}}


def operation(i, when, site=SITE_A, done=True):
    """A Configuration Logging operation in the shape of Citrix's example and the API reference."""
    local = when.strftime("%m/%d/%Y : %I:%M:%S %p").lstrip("0")
    return {"Id": f"0d96ecf1-4c73-4a0c-9476-{i:012d}", "AdminMachineIP": "192.0.2.15", "EndTime": local if done else None,
            "FormattedEndTime": when.strftime("%Y-%m-%dT%H:%M:%SZ") if done else None, "IsSuccessful": True if done else None,
            "OperationType": "ConfigurationChange", "Parameters": [{"Name": "Name", "Value": "Finance Desktops"}],
            "Source": "Studio", "StartTime": local, "FormattedStartTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "TargetTypes": ["DesktopGroup"], "Text": f"Edit Delivery Group 'Finance Desktops' ({i})", "User": "EXAMPLE\\akim",
            "UserIdentity": "S-1-5-21-1004336348-1177238915-682003330-512", "Labels": [], "Metadata": [], "_site": site}


def connection(i, when):
    """A Monitor connection with its session, user and machine, in the shape of Citrix's example."""
    return {"Id": 408600 + i, "ClientName": "LAPTOP-07", "ClientAddress": "198.51.100.44", "ClientVersion": "24.9.10.28",
            "ClientPlatform": "Windows", "ConnectedViaIPAddress": "192.0.2.36", "LaunchedViaHostName": "Workspace", "IsReconnect": False,
            "IsSecureIca": False, "Protocol": "HDX", "LogOnStartDate": iso(when - timedelta(seconds=13)), "LogOnEndDate": iso(when),
            "SessionKey": f"38502302-78ed-4f02-a3f0-{i:012d}", "CreatedDate": iso(when), "ModifiedDate": iso(when),
            "Session": {"SessionKey": f"38502302-78ed-4f02-a3f0-{i:012d}", "StartDate": iso(when - timedelta(seconds=13)), "EndDate": None,
                        "ConnectionState": 5, "UserId": 1505, "MachineId": "7ff93079-914a-4e6e-b9fe-5ce6e7578684",
                        "User": {"Id": 1505, "Upn": "akim@example.com", "UserName": "akim", "Domain": "EXAMPLE"},
                        "Machine": {"Id": "7ff93079-914a-4e6e-b9fe-5ce6e7578684", "DnsName": "vda-fin-01.corp.example.com",
                                    "Name": "EXAMPLE\\VDA-FIN-01"}}}


class Mock:
    def __init__(self):
        self.systemlog = []
        self.operations = []
        self.connections = []
        self.sites = [SITE_A, SITE_B]
        self.page_cap = 1000
        self.camel = False
        self.stuck_token = False
        self.foreign_next = None
        self.tokens = []
        self.token_requests = []
        self.requests = []
        self.answers = []          # statuses to answer GETs with instead, in order
        self.token_answers = []
        self.expires_in = "3600"
        self.ingest_codes = []
        self.ingested = []
        self.base = ""


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
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path.startswith("/cctrustoauth2/"):
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append({"path": url.path, "form": form, "headers": dict(self.headers)})
            if m.token_answers:
                return self._send(m.token_answers.pop(0), {"error": "test status"})
            if url.path != f"/cctrustoauth2/{CUSTOMER}/tokens/clients" or form.get("grant_type") != ["client_credentials"] \
                    or form.get("client_id") != [CLIENT_ID] or form.get("client_secret") != [CLIENT_SECRET]:
                return self._send(401, {"error": "invalid_client", "error_description": "Invalid client id or secret"})
            token = f"cc-test-token-{len(m.tokens):04d}-not-real"
            m.tokens.append(token)
            return self._send(200, {"token_type": "bearer", "access_token": token, "expires_in": m.expires_in})
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
        m.requests.append({"path": url.path, "query": query, "raw_query": url.query, "headers": dict(self.headers)})
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("CwsAuth Bearer=") or auth[len("CwsAuth Bearer="):] not in m.tokens:
            return self._send(401, {"Error": {"Message": "Missing or invalid authentication details"}})
        if self.headers.get("Citrix-CustomerId") != CUSTOMER:
            return self._send(403, {"Error": {"Message": "Customer not authorized"}})
        if m.answers:
            return self._send(m.answers.pop(0), {"Error": {"Message": "test status"}})
        if url.path == "/systemlog/records":
            lo, hi = c._parse_time(query["StartDateTime"][0]), c._parse_time(query["EndDateTime"][0])
            rows = [r for r in m.systemlog if lo <= c._parse_time(r["UtcTimestamp"]) <= hi]
            rows.sort(key=lambda r: r["UtcTimestamp"], reverse=True)
            first = int(query.get("ContinuationToken", ["0"])[0])
            size = min(int(query.get("Limit", ["50"])[0]), m.page_cap)
            page = rows[first:first + size]
            if m.camel:
                page = [{k[:1].lower() + k[1:]: v for k, v in r.items()} for r in page]
            more = first + size < len(rows)
            token = (query.get("ContinuationToken", ["0"])[0] if m.stuck_token and first else str(first + size)) if more else None
            out = {"Items": page, "Count": len(page), "EstimatedTotalItems": len(rows), "ContinuationToken": token}
            if m.camel:
                out = {"items": page, "count": len(page), "estimatedTotalItems": len(rows), "continuationToken": token}
            return self._send(200, out)
        if url.path == "/cvad/manage/me":
            return self._send(200, {"UserId": "9690c023", "DisplayName": "Bridge", "Customers": [
                {"Id": "othercust", "Sites": [{"Id": "5283395a-2c3d-4e4f-a051-627384950617"}]},
                {"Id": CUSTOMER, "Name": None, "Sites": [{"Id": s, "Name": f"site-{s[:4]}"} for s in m.sites]}]})
        if url.path == "/cvad/manage/ConfigLog/Operations":
            site = self.headers.get("Citrix-InstanceId")
            if site not in m.sites:
                return self._send(404, {"Error": {"Message": "Site not found"}})
            if self.headers.get("X-TimeZone") != "UTC":
                return self._send(400, {"Error": {"Message": "the test mock wants X-TimeZone: UTC"}})
            days = int(query["days"][0])
            floor = datetime.now(timezone.utc).timestamp() - days * 86400
            rows = [{k: v for k, v in r.items() if k != "_site"} for r in m.operations
                    if r["_site"] == site and c._parse_time(r["FormattedStartTime"]) >= floor]
            rows.sort(key=lambda r: r["FormattedStartTime"], reverse=True)
            first = int(query.get("continuationToken", ["0"])[0])
            size = min(int(query.get("limit", ["250"])[0]), m.page_cap)
            more = first + size < len(rows)
            return self._send(200, {"Items": rows[first:first + size], "ContinuationToken": str(first + size) if more else None})
        if url.path == "/monitorodata/Connections":
            f = re.match(r"^CreatedDate ge (\S+) and CreatedDate lt (\S+)$", query["$filter"][0])
            if not f or query.get("$orderby") != ["CreatedDate"] or query.get("$expand") != ["Session($expand=User,Machine)"]:
                return self._send(400, {"error": {"message": "The query specified in the URI is not valid."}})
            lo, hi = c._parse_time(f.group(1)), c._parse_time(f.group(2))
            rows = sorted((r for r in m.connections if lo <= c._parse_time(r["CreatedDate"]) < hi), key=lambda r: r["CreatedDate"])
            skip = int(query.get("$skiptoken", ["0"])[0])
            page = rows[skip:skip + m.page_cap]
            out = {"@odata.context": f"{m.base}/monitorodata/$metadata#Connections", "value": page}
            if skip + m.page_cap < len(rows):
                rest = re.sub(r"&\$skiptoken=\d+", "", url.query)
                out["@odata.nextLink"] = m.foreign_next or f"{m.base}/monitorodata/Connections?{rest}&$skiptoken={skip + m.page_cap}"
            return self._send(200, out)
        self._send(404, {"type": "404", "detail": "resource not found"})


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
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 2160),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"CITRIX_CUSTOMER_ID": CUSTOMER, "CITRIX_CLIENT_ID": CLIENT_ID, "CITRIX_CLIENT_SECRET": CLIENT_SECRET}
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
        self.mock.base = self.base
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
                     CITRIX_API_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self, kind=None):
        return [line for post in self.mock.ingested for line in post["lines"] if kind is None or line["citrix_record"] == kind]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def gets(self, path):
        return [r for r in self.mock.requests if r["path"] == path]

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("CITRIX_API_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_system_log_records_are_read_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.mock.systemlog = [systemlog(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(CITRIX_LOGS="systemlog")), 5)
        sent = self.sent()
        self.assertEqual(sorted(r["TargetId"] for r in sent), sorted(r["TargetId"] for r in self.mock.systemlog))
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(f'{{"citrix_record":"systemlog","citrix_customer_id":"{CUSTOMER}",'
                                                                '"RecordId":'))
        reqs = self.gets("/systemlog/records")
        self.assertEqual(len(reqs), 3)
        self.assertNotIn("ContinuationToken", reqs[0]["query"])
        self.assertEqual([r["query"].get("ContinuationToken") for r in reqs[1:]], [["2"], ["4"]])
        self.assertEqual(reqs[0]["query"]["Limit"], ["200"])
        self.assertRegex(reqs[0]["query"]["StartDateTime"][0], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        headers = {k.lower(): v for k, v in reqs[0]["headers"].items()}
        self.assertEqual((headers["citrix-customerid"], headers["accept"]), (CUSTOMER, "application/json"))

    def test_camel_case_answers_are_read_and_keys_capitalized(self):
        self.mock.page_cap = 2
        self.mock.camel = True
        self.mock.systemlog = [systemlog(i, self.ago(50 - i)) for i in range(3)]
        self.assertEqual(c.run_once(self.cfg(CITRIX_LOGS="systemlog")), 3)
        for r in self.sent():
            self.assertIn("EventType", r)
            self.assertIn("UtcTimestamp", r)
            self.assertNotIn("eventType", r)

    def test_the_same_continuation_token_twice_stops_the_run(self):
        self.mock.page_cap = 1
        self.mock.stuck_token = True
        self.mock.systemlog = [systemlog(i, self.ago(50 - i)) for i in range(4)]
        with self.assertRaisesRegex(c.BridgeError, "the same ContinuationToken twice"):
            c.run_once(self.cfg(CITRIX_LOGS="systemlog"))
        self.assertNotIn("until", self.saved()["logs"]["systemlog"])

    def test_configuration_logging_is_read_for_each_site_most_recent_first(self):
        self.mock.page_cap = 2
        self.mock.operations = [operation(i, self.ago(40 - i)) for i in range(5)] + [operation(9, self.ago(10), SITE_B)]
        self.assertEqual(c.run_once(self.cfg(CITRIX_LOGS="configlog")), 6)
        sent = self.sent()
        self.assertEqual([r["citrix_site_id"] for r in sent], [SITE_A] * 5 + [SITE_B])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(f'{{"citrix_record":"configlog","citrix_customer_id":"{CUSTOMER}",'
                                                                f'"citrix_site_id":"{SITE_A}","Id":'))
        self.assertNotIn("_site", sent[0])
        self.assertEqual(len(self.gets("/cvad/manage/me")), 1)
        reqs = self.gets("/cvad/manage/ConfigLog/Operations")
        self.assertEqual([{k.lower(): v for k, v in r["headers"].items()}["citrix-instanceid"] for r in reqs], [SITE_A] * 3 + [SITE_B])
        self.assertEqual({r["query"]["days"][0] for r in reqs}, {"1"})
        self.assertEqual(reqs[0]["query"]["limit"], ["250"])
        self.assertEqual(sorted(self.saved()["logs"]), [f"configlog/{SITE_A}", f"configlog/{SITE_B}"])

    def test_configuration_logging_stops_at_the_window_start_and_leaves_newer_operations(self):
        self.mock.page_cap = 2
        old = [operation(i, self.ago(60 + i)) for i in range(6)]
        new = [operation(10, self.ago(5)), operation(11, self.ago(4))]
        self.mock.operations = old + new
        with open(self.state, "w") as fh:
            json.dump({"logs": {f"configlog/{SITE_A}": {"until": self.ago(20).timestamp()}}}, fh)
        c.run_once(self.cfg(CITRIX_LOGS="configlog", CITRIX_SITE_IDS=SITE_A, BRIDGE_OVERLAP_SECONDS="600"))
        self.assertEqual(sorted(r["Id"] for r in self.sent()), sorted(o["Id"] for o in new))
        # The first page holds the two new operations and the second the first old one, so it stops there.
        self.assertEqual(len(self.gets("/cvad/manage/ConfigLog/Operations")), 2)
        self.assertEqual(self.gets("/cvad/manage/me"), [])
        # An operation dated past the window's end waits for the next run.
        self.mock.operations.append(operation(12, self.now + timedelta(minutes=5)))
        self.mock.ingested.clear()
        c.run_once(self.cfg(CITRIX_LOGS="configlog", CITRIX_SITE_IDS=SITE_A))
        self.assertEqual(self.sent(), [])

    def test_configuration_logging_asks_for_enough_days(self):
        c.run_once(self.cfg(CITRIX_LOGS="configlog", CITRIX_SITE_IDS=SITE_A, BRIDGE_LOOKBACK_HOURS="100"))
        self.assertEqual(self.gets("/cvad/manage/ConfigLog/Operations")[0]["query"]["days"], ["5"])

    def test_an_operation_that_completes_is_sent_again(self):
        self.mock.operations = [operation(1, self.ago(10), done=False)]
        cfg = self.cfg(CITRIX_LOGS="configlog", CITRIX_SITE_IDS=SITE_A)
        c.run_once(cfg)
        self.mock.operations = [operation(1, self.ago(10))]
        c.run_once(cfg)
        self.assertEqual([r["IsSuccessful"] for r in self.sent()], [None, True])

    def test_configuration_logging_times_without_formatted_start_time(self):
        op = operation(1, datetime(2026, 10, 20, 15, 21, 12, tzinfo=timezone.utc))
        del op["FormattedStartTime"]
        self.assertEqual(op["StartTime"], "10/20/2026 : 03:21:12 PM")
        self.assertEqual(c._configlog_time(op), datetime(2026, 10, 20, 15, 21, 12, tzinfo=timezone.utc).timestamp())
        self.assertEqual(c._configlog_time({"StartTime": "12/21/2020 : 3:21:12 PM"}),
                         datetime(2020, 12, 21, 15, 21, 12, tzinfo=timezone.utc).timestamp())
        self.assertIsNone(c._configlog_time({"StartTime": "yesterday"}))

    def test_a_customer_with_no_site_logs_a_warning(self):
        self.mock.sites = []
        self.assertEqual(c.run_once(self.cfg(CITRIX_LOGS="configlog")), 0)
        self.assertIn("lists no DaaS site", self.logbuf.getvalue())

    def test_monitor_connections_are_read_with_their_session_user_and_machine(self):
        self.mock.page_cap = 2
        self.mock.connections = [connection(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(CITRIX_LOGS="connections")), 5)
        sent = self.sent()
        self.assertEqual([r["Id"] for r in sent], [408600 + i for i in range(5)])
        self.assertEqual(sent[0]["Session"]["User"]["Upn"], "akim@example.com")
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(f'{{"citrix_record":"connection","citrix_customer_id":"{CUSTOMER}","Id":'))
        reqs = self.gets("/monitorodata/Connections")
        self.assertEqual(len(reqs), 3)
        self.assertIn("$filter=CreatedDate%20ge%20", reqs[0]["raw_query"])
        self.assertIn("$expand=Session($expand=User,Machine)", reqs[0]["raw_query"])

    def test_a_connection_is_sent_once_however_it_changes(self):
        conn = connection(1, self.ago(10))
        self.mock.connections = [conn]
        cfg = self.cfg(CITRIX_LOGS="connections")
        c.run_once(cfg)
        self.mock.connections = [{**conn, "ModifiedDate": iso(self.ago(1)), "DisconnectDate": iso(self.ago(1))}]
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 1)

    def test_a_next_page_on_another_host_is_refused(self):
        self.mock.page_cap = 1
        self.mock.connections = [connection(i, self.ago(10 - i)) for i in range(3)]
        self.mock.foreign_next = "https://api.example.com/monitorodata/Connections?$skiptoken=1"
        with self.assertRaisesRegex(c.BridgeError, "next page on another host or path"):
            c.run_once(self.cfg(CITRIX_LOGS="connections"))
        self.mock.foreign_next = f"{self.base}/elsewhere/Connections?$skiptoken=1"
        with self.assertRaisesRegex(c.BridgeError, "next page on another host or path"):
            c.run_once(self.cfg(CITRIX_LOGS="connections"))

    def test_the_token_is_kept_until_it_expires_and_renewed_when_refused(self):
        self.mock.systemlog = [systemlog(0, self.ago(5))]
        cfg = self.cfg()
        client = c.Citrix(cfg)
        c.run_once(cfg, client=client)
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        req = self.mock.token_requests[0]
        self.assertEqual(req["path"], f"/cctrustoauth2/{CUSTOMER}/tokens/clients")
        self.assertEqual(req["form"], {"grant_type": ["client_credentials"], "client_id": [CLIENT_ID], "client_secret": [CLIENT_SECRET]})
        self.mock.tokens.clear()
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 2)
        # expires_in comes as text; a short one is renewed for each request.
        self.mock.expires_in = "30"
        c.run_once(self.cfg(CITRIX_LOGS="systemlog"), client=c.Citrix(cfg))
        c.run_once(self.cfg(CITRIX_LOGS="systemlog"), client=client)
        self.assertEqual(len(self.mock.token_requests), 3)

    def test_refused_client_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(CITRIX_CLIENT_SECRET="wrong-citrix-secret-not-real"))
        self.assertIn("Citrix Cloud refused the token request (HTTP 401: Invalid client id or secret)", str(cm.exception))
        self.assertNotIn("wrong-citrix-secret-not-real", str(cm.exception))

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.systemlog = [systemlog(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(CITRIX_LOGS="systemlog", BRIDGE_OVERLAP_SECONDS="1200")
        c.run_once(cfg)
        first_end = c._parse_time(self.gets("/systemlog/records")[0]["query"]["EndDateTime"][0])
        self.assertAlmostEqual(self.saved()["logs"]["systemlog"]["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        late, new = systemlog(7, self.ago(15)), systemlog(8, self.ago(2))
        self.mock.systemlog += [late, new]
        c.run_once(cfg)
        self.assertEqual(sorted(r["TargetId"] for r in self.sent()), sorted([late["TargetId"], new["TargetId"]]))
        start = c._parse_time(self.gets("/systemlog/records")[0]["query"]["StartDateTime"][0])
        self.assertAlmostEqual(start, first_end - 1200, delta=1)

    def test_lookback_sets_the_first_window(self):
        self.mock.systemlog = [systemlog(0, self.now - timedelta(days=3)), systemlog(1, self.ago(60))]
        c.run_once(self.cfg(CITRIX_LOGS="systemlog", BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["TargetId"] for r in self.sent()], [systemlog(1, self.now)["TargetId"]])

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.mock.systemlog = [systemlog(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(CITRIX_LOGS="systemlog"))
        saved = self.saved()["logs"]["systemlog"]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(CITRIX_LOGS="systemlog"))
        self.assertEqual(len(self.sent()), 2)
        self.assertIn("until", self.saved()["logs"]["systemlog"])

    def test_window_end_never_passes_now(self):
        self.mock.systemlog = [systemlog(0, self.ago(5))]
        c.run_once(self.cfg(CITRIX_LOGS="systemlog"))
        self.assertLessEqual(self.saved()["logs"]["systemlog"]["until"], datetime.now(timezone.utc).timestamp() - 59)

    def test_http_errors_stop_with_clear_errors(self):
        cases = [(403, r"Citrix Cloud refused the System Log request \(HTTP 403: test status\); the service principal needs a role"),
                 (404, "check CITRIX_API_URL, CITRIX_CUSTOMER_ID and CITRIX_SITE_IDS"),
                 (400, r"Citrix Cloud rejected the System Log request \(HTTP 400: test status\)")]
        for code, message in cases:
            with self.subTest(code=code):
                self.mock.answers = [code]
                with self.assertRaisesRegex(c.BridgeError, message):
                    c.run_once(self.cfg(CITRIX_LOGS="systemlog"))
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 404 \(Site not found\)"):
            c.run_once(self.cfg(CITRIX_LOGS="configlog", CITRIX_SITE_IDS="5283395a-2c3d-4e4f-a051-627384950617"))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.systemlog = [systemlog(0, self.ago(10))]
        self.mock.operations = [operation(1, self.ago(9))]
        self.mock.connections = [connection(2, self.ago(8))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["citrix_record"] for x in lines], ["systemlog", "configlog", "connection"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.systemlog = [systemlog(i, self.ago(10 - i)) for i in range(3)]
        self.mock.answers = [429, 500, 503]
        self.mock.token_answers = [503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(CITRIX_LOGS="systemlog"))
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.systemlog = [systemlog(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.systemlog = [systemlog(0, self.ago(5))]
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(CITRIX_CLIENT_SECRET="another-wrong-secret-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("System Log request", logged)
        for secret in (CLIENT_SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-not-real", self.mock.tokens[0]):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(CITRIX_CUSTOMER_ID=None),
            base_env(CITRIX_CUSTOMER_ID="example/../other"),
            base_env(CITRIX_CLIENT_ID=None),
            base_env(CITRIX_CLIENT_SECRET=None),
            base_env(CITRIX_API_URL="http://api.cloud.example"),
            base_env(CITRIX_API_URL="https://api.cloud.com/systemlog"),
            base_env(CITRIX_LOGS="systemlog,sessions"),
            base_env(CITRIX_LOGS=","),
            base_env(CITRIX_SITE_IDS="3061173e,../x"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(BRIDGE_LOOKBACK_HOURS="2161"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["api_url"], cfg["logs"], cfg["site_ids"]),
                         ("https://api.cloud.com", ["systemlog", "configlog", "connections"], []))
        self.assertEqual(c.load_config(base_env(CITRIX_API_URL="https://api.citrixcloud.jp/"))["api_url"], "https://api.citrixcloud.jp")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the token to another URL, so the run fails instead, and
        # nothing reaches the redirect's target.
        self.mock.systemlog = [systemlog(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration",
                                             CITRIX_LOGS="systemlog"),
                     "Citrix Cloud": self.cfg(CITRIX_API_URL=r.base, CITRIX_LOGS="systemlog")}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("logs", {}).get("systemlog", {}))
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
        return c.load_config(base_env(**extra))

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_lookback_is_at_most_the_90_days_citrix_keeps(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 2,160$"):
            self.load(BRIDGE_LOOKBACK_HOURS="2161")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="2160")["lookback_hours"], 2160.0)


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
