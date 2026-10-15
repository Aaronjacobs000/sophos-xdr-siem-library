"""Unit tests for omada_logs_bridge.py against a local mock server.

The mock serves the shapes in TP-Link's Omada Open API reference and Open API Access Guide:
POST /openapi/authorize/token?grant_type=client_credentials with {"omadacId", "client_id",
"client_secret"}, answering {"errorCode": 0, "msg", "result": {"accessToken", "tokenType", "expiresIn",
"refreshToken"}}; GET requests with 'Authorization: AccessToken=<token>' for the site, MSP site and
customer lists and for the event, alert and audit logs of the controller, the MSP view, customers and
sites, each answering {"errorCode": 0, "msg", "result": {"totalRows", "currentPage", "currentSize",
"data": [...]}}, with errors such as -44106, -44112 and -1505 in errorCode. Plus a Sophos NG-SIEM
HTTP Ingest endpoint, and an HTTPS server with a certificate made for the test when openssl is
installed. No real service is called.

  python3 -m unittest discover -s bridges/tp-link-omada-logs -p 'test_*.py' -v
"""
import contextlib
import gc
import gzip
import io
import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import omada_logs_bridge as c  # noqa: E402

# The bridge spaces its requests; the tests don't wait, except the one that checks the spacing.
c.PACE_SECONDS = 0

OMADA_ID = "de382a0e78f4deb681f3128c3e75dbd1"
MSP_ID = "7a51c0de0e5f4c2b9a1b3c4d5e6f7a8b"
CLIENT_ID = "test-omada-client-id-not-real"
CLIENT_SECRET = "test-omada-client-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
SITE_A = "640effd1b3f2ae5b912275ec"
SITE_B = "640effd1b3f2ae5b912275ed"
CUSTOMER = "c0ffee00c0ffee00c0ffee00c0ffee01"


def ms(dt):
    return int(dt.timestamp() * 1000)


def event(i, when, key="OSG_ATK", module="Device"):
    return {"id": f"6705c3a0b1e2c34d5f6a{i:04d}", "key": key, "module": module,
            "content": f"Gateway detected attack from 198.51.100.{i % 250}.", "time": ms(when)}


def alert(i, when):
    return {**event(i, when, "OSG_IPSEC_FL"), "content": "IPsec connection to 203.0.113.1 disconnected.", "level": "Error"}


def audit(i, when, result="Succeed"):
    return {"time": ms(when), "operator": "jsmith", "resource": "WEB", "ip": "192.0.2.10", "auditType": "Network Security",
            "level": "Information", "result": result, "content": f"ACL rule Block-RDP-{i} edited successfully.",
            "label": "MENU.NETWORK_SECURITY", "oldValue": {"status": "true"}, "newValue": {"status": "false"}}


class Mock:
    def __init__(self):
        self.sites = {OMADA_ID: [{"siteId": SITE_A, "name": "Head Office"}, {"siteId": SITE_B, "name": "Branch 01"}]}
        self.customers = [{"customerId": CUSTOMER, "customerName": "Example Customer"}]
        self.msp_sites = [{"siteId": SITE_A, "siteName": "Example Site", "customerId": CUSTOMER, "customerName": "Example Customer"}]
        # logs[(scope path, log)] = rows, where scope path is the URL part before /logs or /audit-logs.
        self.logs = {}
        self.page_cap = 1000
        self.requests = []
        self.tokens = []
        self.token_requests = []
        self.expires_in = 7200
        # Answers to send instead of the normal one, in order: an HTTP status, or ("error", code).
        self.answers = []
        self.token_answers = []
        self.ingest_codes = []
        self.ingested = []


def page_of(rows, query, cap):
    page = int(query.get("page", ["1"])[0])
    size = min(int(query.get("pageSize", ["10"])[0]), cap)
    chunk = rows[(page - 1) * size:page * size]
    return {"totalRows": len(rows), "currentPage": page, "currentSize": size, "data": chunk}


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

    def _ok(self, result):
        self._send(200, {"errorCode": 0, "msg": "Success.", "result": result})

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == "/openapi/authorize/token":
            req = json.loads(body)
            m.token_requests.append({"query": urllib.parse.parse_qs(url.query), "body": req, "headers": dict(self.headers)})
            if m.token_answers:
                answer = m.token_answers.pop(0)
                if isinstance(answer, int):
                    return self._send(answer, {"errorCode": -1, "msg": "test status"})
            if urllib.parse.parse_qs(url.query).get("grant_type") != ["client_credentials"]:
                return self._send(200, {"errorCode": -44111, "msg": "The grant type is invalid."})
            if req.get("client_id") != CLIENT_ID or req.get("client_secret") != CLIENT_SECRET \
                    or req.get("omadacId") not in (OMADA_ID, MSP_ID):
                return self._send(200, {"errorCode": -44106, "msg": "The client id or client secret is invalid."})
            token = f"AT-test{len(m.tokens):04d}notreal"
            m.tokens.append(token)
            return self._send(200, {"errorCode": 0, "msg": "Open API Get Access Token successfully.",
                                    "result": {"accessToken": token, "tokenType": "bearer", "expiresIn": m.expires_in,
                                               "refreshToken": "RT-test-refresh-not-real"}})
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
        if not auth.startswith("AccessToken=") or auth[len("AccessToken="):] not in m.tokens:
            return self._send(200, {"errorCode": -44113, "msg": "The access token is Invalid."})
        if m.answers:
            answer = m.answers.pop(0)
            if isinstance(answer, tuple):
                return self._send(200, {"errorCode": answer[1], "msg": f"test error {answer[1]}"})
            return self._send(answer, {"errorCode": -1, "msg": "test status"})
        parts = url.path.split("/")
        if url.path == f"/openapi/v1/{OMADA_ID}/sites" or (len(parts) == 5 and parts[4] == "sites" and parts[3] in m.sites):
            return self._ok(page_of(m.sites.get(parts[3], []), query, m.page_cap))
        if url.path == f"/openapi/v1/msp/{MSP_ID}/sites":
            return self._ok(page_of(m.msp_sites, query, m.page_cap))
        if url.path == f"/openapi/v1/msp/{MSP_ID}/customers":
            return self._ok(page_of(m.customers, query, m.page_cap))
        for suffix, log in (("/logs/events", "events"), ("/logs/alerts", "alerts"), ("/audit-logs", "audit")):
            if url.path.endswith(suffix):
                scope = url.path[:-len(suffix)]
                rows = m.logs.get((scope, log), [])
                if log == "audit":
                    times = json.loads(query["filters.times"][0])
                    lo, hi = times[0]["timeStart"], times[0]["timeEnd"]
                    rows = sorted((r for r in rows if lo <= r["time"] <= hi), key=lambda r: r["time"])
                else:
                    if "filters.timeStart" not in query or "filters.timeEnd" not in query:
                        return self._send(200, {"errorCode": -1001, "msg": "General error."})
                    lo, hi = int(query["filters.timeStart"][0]), int(query["filters.timeEnd"][0])
                    # Newest first, so the bridge can't count on an order.
                    rows = sorted((r for r in rows if lo <= r["time"] <= hi), key=lambda r: -r["time"])
                return self._ok(page_of(rows, query, m.page_cap))
        self._send(404, {"errorCode": -1, "msg": "Not found"})


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


class Tls:
    """An HTTPS Open API with a self-signed certificate for localhost, made with openssl for the test,
    as a software or hardware controller serves it. It gives a token, no sites, and one event."""

    def __init__(self, folder):
        self.cert = os.path.join(folder, "omada-test.crt")
        key = os.path.join(folder, "omada-test.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", self.cert,
                        "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,digitalSignature,keyCertSign"],
                       check=True, capture_output=True)
        self.requests = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, obj):
                body = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                outer.requests += 1
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self._answer({"errorCode": 0, "result": {"accessToken": "AT-tls-test-not-real", "expiresIn": 7200}})

            def do_GET(self):
                outer.requests += 1
                path = urllib.parse.urlsplit(self.path).path
                rows = [event(1, datetime.now(timezone.utc) - timedelta(minutes=5))] if path.endswith("/logs/events") else []
                self._answer({"errorCode": 0, "result": {"totalRows": len(rows), "currentPage": 1, "currentSize": 1000,
                                                         "data": rows}})

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("OMADA_PAGE_SIZE", "page_size", 1000, 500, int, 1000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"OMADA_URL": "https://omada.example.com:8043", "OMADA_ID": OMADA_ID, "OMADA_CLIENT_ID": CLIENT_ID,
         "OMADA_CLIENT_SECRET": CLIENT_SECRET}
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
                     OMADA_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def log_requests(self, path):
        return [r for r in self.mock.requests if r["path"] == path]

    def site(self, sid=SITE_A):
        return f"/openapi/v1/{OMADA_ID}/sites/{sid}"

    def test_logs_are_read_for_the_controller_and_every_site_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.mock.logs[(self.site(), "events")] = [event(i, self.ago(50 - i)) for i in range(5)]
        self.mock.logs[(self.site(SITE_B), "alerts")] = [alert(10, self.ago(20))]
        self.mock.logs[(f"/openapi/v1/{OMADA_ID}", "events")] = [event(20, self.ago(15), "LOGIN_FL", "Operation")]
        self.mock.logs[(self.site(), "audit")] = [audit(1, self.ago(10))]
        self.assertEqual(c.run_once(self.cfg(OMADA_PAGE_SIZE="2")), 8)
        sent = self.sent()
        events = [r for r in sent if r["omada_record"] == "event" and r["omada_scope"] == "site"]
        self.assertEqual(sorted(r["id"] for r in events), sorted(e["id"] for e in self.mock.logs[(self.site(), "events")]))
        first = events[0]
        self.assertEqual(list(first)[:5], ["omada_record", "omada_scope", "omada_id", "omada_site_id", "omada_site_name"])
        self.assertEqual((first["omada_id"], first["omada_site_id"], first["omada_site_name"]), (OMADA_ID, SITE_A, "Head Office"))
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"omada_record":"'))
        original = next(e for e in self.mock.logs[(self.site(), "events")] if e["id"] == first["id"])
        self.assertEqual({k: v for k, v in first.items() if not k.startswith("omada_")}, original)
        alerts = [r for r in sent if r["omada_record"] == "alert"]
        self.assertEqual([(a["omada_site_id"], a["omada_site_name"], a["level"]) for a in alerts], [(SITE_B, "Branch 01", "Error")])
        controller = [r for r in sent if r["omada_scope"] == "global"]
        self.assertEqual([(r["omada_record"], r["key"]) for r in controller], [("event", "LOGIN_FL")])
        self.assertNotIn("omada_site_id", controller[0])
        self.assertEqual([r["omada_record"] for r in sent if r["omada_record"] == "audit"], ["audit"])
        # Five events at two a page: three pages, each with the same window.
        reqs = self.log_requests(self.site() + "/logs/events")
        self.assertEqual([r["query"]["page"] for r in reqs], [["1"], ["2"], ["3"]])
        self.assertEqual({(r["query"]["filters.timeStart"][0], r["query"]["filters.timeEnd"][0]) for r in reqs}.__len__(), 1)
        lo, hi = int(reqs[0]["query"]["filters.timeStart"][0]), int(reqs[0]["query"]["filters.timeEnd"][0])
        self.assertAlmostEqual((hi - lo) / 1000, 86400 - 60, delta=10)
        # Every log of the controller and of each site is read.
        paths = {r["path"] for r in self.mock.requests}
        for scope in (f"/openapi/v1/{OMADA_ID}", self.site(), self.site(SITE_B)):
            for suffix in ("/logs/events", "/logs/alerts", "/audit-logs"):
                self.assertIn(scope + suffix, paths)

    def test_pages_are_read_to_the_end_when_the_server_sends_fewer_than_asked(self):
        self.mock.page_cap = 2
        self.mock.logs[(self.site(), "events")] = [event(i, self.ago(20 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(OMADA_LOGS="events")), 5)
        reqs = self.log_requests(self.site() + "/logs/events")
        self.assertEqual([(r["query"]["page"], r["query"]["pageSize"]) for r in reqs], [(["1"], ["1000"]), (["2"], ["1000"]), (["3"], ["1000"])])

    def test_access_token_from_client_credentials_is_kept_until_it_expires(self):
        self.mock.logs[(self.site(), "events")] = [event(1, self.ago(5))]
        client = c.Omada(self.cfg())
        c.run_once(self.cfg(), client=client)
        c.run_once(self.cfg(), client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        req = self.mock.token_requests[0]
        self.assertEqual(req["query"], {"grant_type": ["client_credentials"]})
        self.assertEqual(req["body"], {"omadacId": OMADA_ID, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
        self.assertEqual(req["headers"]["Content-Type"], "application/json")
        self.assertTrue(all(r["headers"]["Authorization"] == f"AccessToken={self.mock.tokens[0]}" for r in self.mock.requests))
        # A token Omada says expires within the renewal margin is fetched again before each request.
        self.mock.expires_in = 30
        client = c.Omada(self.cfg())
        before = len(self.mock.token_requests)
        c.run_once(self.cfg(), client=client)
        self.assertGreater(len(self.mock.token_requests) - before, 1)

    def test_an_expired_or_refused_token_is_renewed_once(self):
        self.mock.logs[(self.site(), "events")] = [event(1, self.ago(5))]
        self.mock.answers = [("error", -44112)]
        self.assertEqual(c.run_once(self.cfg()), 1)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.mock.answers = [401]
        os.remove(self.state)
        self.mock.ingested.clear()
        self.assertEqual(c.run_once(self.cfg()), 1)
        self.assertEqual(len(self.mock.token_requests), 4)
        # Refused again after a new token, the run stops.
        self.mock.answers = [("error", -44112), ("error", -44112)]
        with self.assertRaisesRegex(c.BridgeError, r"^Omada refused the site list request: it refused a new access "
                                    r"token too \(error -44112: test error -44112\)$"):
            c.run_once(self.cfg())

    def test_refused_client_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(OMADA_CLIENT_SECRET="wrong-secret-not-real"))
        self.assertIn("error -44106: The client id or client secret is invalid.", str(cm.exception))
        self.assertIn("OMADA_CLIENT_ID", str(cm.exception))
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        for code in (400, 401, 403):
            self.mock.token_answers = [code]
            with self.subTest(code=code), self.assertRaisesRegex(c.BridgeError, rf"HTTP {code}, error -1: test status"):
                c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_msp_mode_reads_the_msp_view_each_customer_and_their_sites(self):
        msp, customer, site = f"/openapi/v1/msp/{MSP_ID}", f"/openapi/v1/{CUSTOMER}", f"/openapi/v1/{CUSTOMER}/sites/{SITE_A}"
        self.mock.logs[(msp, "events")] = [event(1, self.ago(9), "DEV_DISCOVER")]
        self.mock.logs[(customer, "audit")] = [audit(2, self.ago(8))]
        self.mock.logs[(site, "events")] = [event(3, self.ago(7), "OSW_C_1X_FL", "Client")]
        self.assertEqual(c.run_once(self.cfg(OMADA_ID=MSP_ID, OMADA_MSP="1")), 3)
        self.assertEqual(self.mock.token_requests[0]["body"]["omadacId"], MSP_ID)
        rows = {r["omada_scope"]: r for r in self.sent()}
        self.assertEqual(rows["msp"]["omada_id"], MSP_ID)
        self.assertNotIn("omada_customer_id", rows["msp"])
        self.assertEqual((rows["customer"]["omada_id"], rows["customer"]["omada_customer_name"]), (CUSTOMER, "Example Customer"))
        self.assertEqual((rows["site"]["omada_customer_id"], rows["site"]["omada_site_id"], rows["site"]["omada_site_name"]),
                         (CUSTOMER, SITE_A, "Example Site"))
        paths = {r["path"] for r in self.mock.requests}
        self.assertTrue({f"{msp}/customers", f"{msp}/sites", f"{msp}/logs/alerts", f"{customer}/logs/events",
                         f"{site}/audit-logs"} <= paths)
        self.assertNotIn(f"/openapi/v1/{MSP_ID}/sites", paths)

    def test_audit_logs_are_read_by_time_range_and_known_by_their_hash(self):
        self.mock.logs[(self.site(), "audit")] = [audit(1, self.ago(10)), audit(2, self.ago(9), "Failed")]
        c.run_once(self.cfg(OMADA_LOGS="audit"))
        c.run_once(self.cfg(OMADA_LOGS="audit"))
        self.assertEqual([r["result"] for r in self.sent()], ["Succeed", "Failed"])
        req = self.log_requests(self.site() + "/audit-logs")[0]
        self.assertEqual(req["query"]["sorts.time"], ["asc"])
        times = json.loads(req["query"]["filters.times"][0])
        self.assertEqual(list(times[0]), ["timeStart", "timeEnd"])
        seen = self.saved()["logs"][f"site/{OMADA_ID}/{SITE_A}/audit"]["seen"]
        self.assertTrue(all(k.startswith("sha:") for k in seen))
        self.assertEqual(len(seen), 2)

    def test_logs_setting_limits_what_is_read(self):
        c.run_once(self.cfg(OMADA_LOGS="alerts, events"))
        paths = {r["path"] for r in self.mock.requests}
        self.assertFalse(any(p.endswith("/audit-logs") for p in paths))
        self.assertIn(self.site() + "/logs/alerts", paths)

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        scope = (self.site(), "events")
        self.mock.logs[scope] = [event(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200", OMADA_LOGS="events")
        c.run_once(cfg)
        first_end = int(self.log_requests(self.site() + "/logs/events")[0]["query"]["filters.timeEnd"][0]) / 1000
        self.assertAlmostEqual(self.saved()["logs"][f"site/{OMADA_ID}/{SITE_A}/events"]["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An event the controller listed late, inside the overlap, and a new one.
        self.mock.logs[scope] += [event(7, self.ago(15)), event(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["id"][-1] for r in self.sent()), ["7", "8"])
        start = int(self.log_requests(self.site() + "/logs/events")[0]["query"]["filters.timeStart"][0]) / 1000
        self.assertAlmostEqual(start, first_end - 1200, delta=1)

    def test_new_sites_are_picked_up_on_the_next_run(self):
        c.run_once(self.cfg(OMADA_LOGS="events"))
        new = "640effd1b3f2ae5b912275ee"
        self.mock.sites[OMADA_ID].append({"siteId": new, "name": "Branch 02"})
        self.mock.logs[(self.site(new), "events")] = [event(5, self.ago(3))]
        c.run_once(self.cfg(OMADA_LOGS="events"))
        self.assertEqual([(r["omada_site_id"], r["omada_site_name"]) for r in self.sent()], [(new, "Branch 02")])

    def test_lookback_sets_the_first_window(self):
        self.mock.logs[(self.site(), "events")] = [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["id"][-1] for r in self.sent()], ["1"])
        end = int(self.log_requests(self.site() + "/logs/events")[0]["query"]["filters.timeEnd"][0]) / 1000
        self.assertLessEqual(end, datetime.now(timezone.utc).timestamp() - 59)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.mock.logs[(self.site(), "events")] = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(OMADA_PAGE_SIZE="2", OMADA_LOGS="events"))
        cur = self.saved()["logs"][f"site/{OMADA_ID}/{SITE_A}/events"]
        self.assertNotIn("until", cur)
        self.assertEqual(len(cur["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(OMADA_PAGE_SIZE="2", OMADA_LOGS="events"))
        self.assertEqual(sorted(r["id"][-1] for r in self.sent()), ["0", "1"])
        self.assertIn("until", self.saved()["logs"][f"site/{OMADA_ID}/{SITE_A}/events"])

    def test_window_end_never_passes_now(self):
        self.mock.logs[(self.site(), "events")] = [event(0, self.ago(5)), event(1, self.now + timedelta(hours=2))]
        c.run_once(self.cfg())
        for cur in self.saved()["logs"].values():
            self.assertLessEqual(cur["until"], datetime.now(timezone.utc).timestamp())
        self.assertEqual([r["id"][-1] for r in self.sent()], ["0"])

    def test_error_codes_in_the_answer_stop_with_omada_s_message(self):
        self.mock.answers = [("error", -1505)]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("error -1505: test error -1505", str(cm.exception))
        self.assertIn("give the application access", str(cm.exception))
        self.mock.answers = [("error", -1001)]
        with self.assertRaisesRegex(c.BridgeError, r"^Omada answered the site list request with error -1001: test error -1001$"):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_http_errors_stop_with_clear_errors(self):
        cases = [(403, r"HTTP 403, error -1: test status\); the application needs read access"),
                 (404, "HTTP 404; check OMADA_URL and OMADA_ID"),
                 (400, r"HTTP 400, error -1: test status\)$")]
        for code, message in cases:
            # A 401 renews the token first, so it is answered twice.
            self.mock.answers = [code]
            with self.subTest(code=code), self.assertRaisesRegex(c.BridgeError, message) as cm:
                c.run_once(self.cfg())
            self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.mock.answers = [401, 401]
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 401, error -1: test status\); the application needs read access"):
            c.run_once(self.cfg())

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.logs[(self.site(), "events")] = [event(i, self.ago(10 - i)) for i in range(3)]
        self.mock.answers = [429, 503, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_requests_are_spaced_under_the_rate_budget(self):
        saved, c.PACE_SECONDS = c.PACE_SECONDS, 0.15
        try:
            c.run_once(self.cfg(OMADA_LOGS="events"))
        finally:
            c.PACE_SECONDS = saved
        # The token request, the site list and three event reads; each one after the first waits.
        self.assertEqual(len(self.slept), 4)
        self.assertTrue(all(0 < s <= 0.15 for s in self.slept), self.slept)

    def test_gzip_batches_and_headers(self):
        self.mock.logs[(self.site(), "events")] = [event(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.logs[(self.site(), "events")] = [event(0, self.ago(5))]
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(OMADA_CLIENT_SECRET="another-wrong-secret-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("site list request", logged)
        for secret in (CLIENT_SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-not-real",
                       self.mock.tokens[0], "RT-test-refresh-not-real"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cert = os.path.join(self.tmp.name, "omada.pem")
        with open(cert, "w") as fh:
            fh.write("not a certificate\n")
        cases = [
            base_env(OMADA_URL=None),
            base_env(OMADA_URL="http://omada.example.com:8043"),
            base_env(OMADA_URL="https://omada.example.com:8043/openapi"),
            base_env(OMADA_ID=None),
            base_env(OMADA_ID="not/an-id"),
            base_env(OMADA_CLIENT_ID=None),
            base_env(OMADA_CLIENT_SECRET=None),
            base_env(OMADA_LOGS="events,syslog"),
            base_env(OMADA_LOGS=" , "),
            base_env(OMADA_CA_FILE=os.path.join(self.tmp.name, "missing.pem")),
            base_env(OMADA_PAGE_SIZE="0"),
            base_env(OMADA_PAGE_SIZE="1001"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["logs"], cfg["page_size"], cfg["ca_file"], cfg["msp"]), (["events", "alerts", "audit"], 1000, None, False))
        # A file that isn't a certificate stops the bridge when it starts, without its content.
        with self.assertRaisesRegex(c.BridgeError, "^OMADA_CA_FILE couldn't be read as a PEM certificate$"):
            c.Omada(c.load_config(base_env(OMADA_CA_FILE=cert)))

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("OMADA_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.logs[(self.site(), "events")] = [event(i, self.ago(10 - i)) for i in range(2)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["omada_record"] for x in lines], ["event", "event"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the client secret, token or key to another URL, so the run
        # fails instead, and nothing reaches the redirect's target.
        self.mock.logs[(self.site(), "events")] = [event(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Omada": self.cfg(OMADA_URL=r.base)}
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
                        # The log whose event wasn't sent keeps its window.
                        held = self.saved().get("logs", {}).get(f"site/{OMADA_ID}/{SITE_A}/events", {}) if os.path.exists(self.state) else {}
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


    def test_times_are_milliseconds_and_records_without_an_id_are_hashed(self):
        self.assertEqual(c._record_time({"time": 1792055564000}, 5.0), 1792055564.0)
        for bad in ({}, {"time": "1792055564000"}, {"time": True}, {"time": -1}):
            with self.subTest(record=bad):
                self.assertEqual(c._record_time(bad, 5.0), 5.0)
        self.assertEqual(c._key({"id": "abc"}), "id:abc")
        self.assertTrue(c._key({"time": 1, "content": "x"}).startswith("sha:"))
        self.assertEqual(c._key({"time": 1, "content": "x"}), c._key({"content": "x", "time": 1}))


@unittest.skipUnless(shutil.which("openssl"), "openssl makes the test certificate")
class TlsTest(unittest.TestCase):
    """A software or hardware controller's own certificate: refused unless OMADA_CA_FILE trusts it,
    and only for the host name it gives."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = Tls(self.tmp.name)
        self.slept = []
        self.saved_sleep, c.time.sleep = c.time.sleep, self.slept.append

    def tearDown(self):
        c.time.sleep = self.saved_sleep
        self.server.close()
        self.tmp.cleanup()

    def run_dry(self, host, **extra):
        env = base_env(OMADA_URL=f"https://{host}:{self.server.port}", OMADA_LOGS="events",
                       BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "state.json"), **extra)
        out = io.StringIO()
        c.run_once(c.load_config(env), dry_run=True, out=out)
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_the_certificate_named_in_omada_ca_file_is_trusted(self):
        rows = self.run_dry("localhost", OMADA_CA_FILE=self.server.cert)
        self.assertEqual([(r["omada_record"], r["omada_scope"]) for r in rows], [("event", "global")])
        # The token, the site list and the controller's events.
        self.assertEqual(self.server.requests, 3)

    def test_an_untrusted_certificate_stops_the_run_at_once(self):
        with self.assertRaises(c.BridgeError) as caught:
            self.run_dry("localhost")
        self.assertNotIsInstance(caught.exception, c.NetworkError)
        self.assertIn("the server's certificate isn't trusted or doesn't name this host", str(caught.exception))
        self.assertIn("OMADA_CA_FILE", str(caught.exception))
        self.assertEqual((self.server.requests, self.slept), (0, []))

    def test_a_host_name_the_certificate_does_not_give_is_refused(self):
        with self.assertRaisesRegex(c.BridgeError, "certificate isn't trusted or doesn't name this host"):
            self.run_dry("127.0.0.1", OMADA_CA_FILE=self.server.cert)
        self.assertEqual(self.server.requests, 0)

    def test_http_ingest_keeps_the_system_certificates(self):
        # The certificate in OMADA_CA_FILE is trusted for Omada only: HTTP Ingest still uses the
        # system store, through the bridge's default opener.
        client = c.Omada(c.load_config(base_env(OMADA_CA_FILE=self.server.cert)))
        self.assertIsNot(client.opener, c._OPENER)
        self.assertIs(c.Omada(c.load_config(base_env())).opener, c._OPENER)


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
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^OMADA_PAGE_SIZE must be between 1 and 1,000$"):
                self.load(OMADA_PAGE_SIZE=value)
        self.assertEqual(self.load(OMADA_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(OMADA_PAGE_SIZE="1000")["page_size"], 1000)


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
        error = c.HostNotFound("site list request to omada.example.com:8043 failed: the host name wasn't found; check the URL setting")
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
