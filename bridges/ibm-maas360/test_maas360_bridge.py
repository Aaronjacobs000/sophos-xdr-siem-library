"""Unit tests for maas360_bridge.py against a local mock server.

The mock serves the MaaS360 web services shapes from IBM's public authentication page and the
MIT-licensed Cortex XSOAR IBM MaaS360 Security event collector and its test data:
POST /auth-apis/auth/2.0/authenticate/customer/{billingId} ({"authResponse": {"authToken", ...}}, or
HTTP 200 with errorCode on bad credentials), and GET getAdminLoginReports and getAdminChangesAudit
({"loginEvents" | "adminChanges": {"count", "pageNumber", "pageSize", "loginEvent" | "adminChange"}},
pages from 1, a single record as an object), with 'Authorization: MaaS token="..."', plus a Sophos
NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/ibm-maas360 -p 'test_*.py' -v
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
import time
import unittest
import urllib.parse
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import maas360_bridge as c  # noqa: E402

BILLING = "30102000"
APP_ID = "30102000_exampleapp"
ACCESS_KEY = "test-maas360-access-key-not-real"
PASSWORD = "test-maas360-password-not-real"
TOKEN = "test-maas360-auth-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
LOGIN_PATH = f"/account-provisioning/administrator/1.0/getAdminLoginReports/customer/{BILLING}"
CHANGE_PATH = f"/account-provisioning/administrator/1.0/getAdminChangesAudit/customer/{BILLING}"


def login(i, ms, status="Successful"):
    return {"username": f"admin{i}@example.com", "loginAttemptTime": ms, "logoutTime": ms + 60000, "duration": 1.0,
            "operatingSystem": "Windows 11", "browserVersion": "Edge 141.0", "ipAddress": "203.0.113.10", "authStatus": status}


def change(i, ms):
    return {"updateDate": ms, "performedBy": "secadmin@example.com", "operationType": "CHANGE", "ipAddress": "198.51.100.20",
            "administrator": {"email": f"helpdesk{i}@example.com", "username": f"helpdesk{i}@example.com", "firstName": "Pat",
                              "middleName": "", "lastName": "Example", "address": "", "phone": "", "jobTitle": "",
                              "watchSubscription": "N", "accountStatus": "Active", "managedUserGroups": "All groups",
                              "lastLoginTime": "", "rolesAdded": "Help Desk", "rolesDeleted": "", "previousState": ""}}


class Mock:
    def __init__(self):
        self.logins = []
        self.changes = []
        self.page_size = 2
        self.bad_auth = False
        self.expire_once = False
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.auth_bodies = []


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode())

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
        if self.path == f"/auth-apis/auth/2.0/authenticate/customer/{BILLING}":
            req = json.loads(body)["authRequest"]["maaS360AdminAuth"]
            m.auth_bodies.append(req)
            if m.bad_auth or req["appAccessKey"] != ACCESS_KEY or req["password"] != PASSWORD:
                return self._json({"authResponse": {"errorCode": 1007, "errorDesc": "Invalid credentials"}})
            return self._json({"authResponse": {"authToken": TOKEN, "refreshToken": "test-refresh-token-not-real"}})
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._json({}, 401)
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._json({}, code)
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        m.ingested.append({"headers": dict(self.headers), "raw": body.decode(),
                           "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
        self._json({})

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if self.headers.get("Authorization") != f'MaaS token="{TOKEN}"':
            return self._send(401, b"Token invalid")
        if m.expire_once:
            m.expire_once = False
            return self._send(401, b"Token expired.")
        if m.codes:
            return self._json({}, m.codes.pop(0))
        if u.path == LOGIN_PATH:
            rows, key, list_key, ts = m.logins, "loginEvents", "loginEvent", "loginAttemptTime"
        elif u.path == CHANGE_PATH:
            rows, key, list_key, ts = m.changes, "adminChanges", "adminChange", "updateDate"
        else:
            return self._json({}, 404)
        lo, hi = int(q["fromDate"][0]), int(q["toDate"][0])
        size = min(int(q["pageSize"][0]), m.page_size)
        page = int(q["pageNumber"][0])
        hits = sorted((r for r in rows if lo <= r[ts] <= hi), key=lambda r: -r[ts])
        chunk = hits[(page - 1) * size:page * size]
        items = chunk[0] if len(chunk) == 1 else chunk  # one record comes back as an object
        self._json({key: {"count": len(chunk), "pageNumber": page, "pageSize": size, list_key: items}})


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
        self._page = c.PAGE_SIZE
        c.PAGE_SIZE = 2
        self.now = int(time.time() * 1000)

    def tearDown(self):
        c.PAGE_SIZE = self._page
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
             "MAAS360_API_URL": self.base, "MAAS360_BILLING_ID": BILLING, "MAAS360_APP_ID": APP_ID,
             "MAAS360_APP_ACCESS_KEY": ACCESS_KEY, "MAAS360_USERNAME": "api_reader", "MAAS360_PASSWORD": PASSWORD,
             "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def sent(self, kind=None):
        rows = [line for post in self.mock.ingested for line in post["lines"]]
        return [r for r in rows if kind is None or r["maas360_record"] == kind]

    def test_reports_are_paged_tagged_and_oldest_first(self):
        self.mock.logins = [login(i, self.now - 3600000 + i * 1000) for i in range(5)]
        self.mock.changes = [change(i, self.now - 1800000 + i * 1000) for i in range(3)]
        c.run_once(self.cfg())
        logins, changes = self.sent("admin_login"), self.sent("admin_change")
        self.assertEqual([r["username"] for r in logins], [f"admin{i}@example.com" for i in range(5)])
        self.assertEqual(len(changes), 3)
        self.assertEqual({k: v for k, v in logins[0].items() if k != "maas360_record"}, self.mock.logins[0])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"maas360_record":"admin_login"'))
        self.assertEqual(self.mock.auth_bodies[0]["billingID"], BILLING)
        self.assertEqual(self.mock.auth_bodies[0]["platformID"], "3")

    def test_a_single_record_object_is_read(self):
        self.mock.logins = [login(0, self.now - 60000)]
        c.run_once(self.cfg(MAAS360_SOURCES="admin_login"))
        self.assertEqual(len(self.sent()), 1)

    def test_next_run_sends_only_new_records(self):
        self.mock.logins = [login(i, self.now - 600000 + i * 1000) for i in range(3)]
        cfg = self.cfg(MAAS360_SOURCES="admin_login")
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.mock.logins.append(login(9, int(time.time() * 1000)))
        c.run_once(cfg)
        self.assertEqual([r["username"] for r in self.sent()], ["admin9@example.com"])

    def test_lookback_limits_the_first_run(self):
        self.mock.changes = [change(0, self.now - 3 * 86400000), change(1, self.now - 3600000)]
        c.run_once(self.cfg(MAAS360_SOURCES="admin_change"))
        self.assertEqual([r["administrator"]["username"] for r in self.sent()], ["helpdesk1@example.com"])

    def test_auth_error_inside_http_200_stops(self):
        self.mock.bad_auth = True
        self.mock.logins = [login(0, self.now - 60000)]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("1007", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_expired_token_is_renewed_once(self):
        self.mock.logins = [login(0, self.now - 60000)]
        self.mock.expire_once = True
        c.run_once(self.cfg(MAAS360_SOURCES="admin_login"))
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(len(self.mock.auth_bodies), 2)

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.logins = [login(i, self.now - 60000 + i) for i in range(2)]
        self.mock.changes = [change(0, self.now - 60000)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.logins = [login(i, self.now - 60000 + i) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(MAAS360_SOURCES="admin_login"))
        self.assertEqual(len(self.sent()), 3)

    def test_ingest_failure_keeps_the_cursor(self):
        self.mock.logins = [login(0, self.now - 60000)]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_gzip_batches_and_headers(self):
        self.mock.changes = [change(i, self.now - 600000 + i * 1000) for i in range(12)]
        c.run_once(self.cfg(MAAS360_SOURCES="admin_change", BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.logins = [login(0, self.now - 60000)]
        self.mock.expire_once = True
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.logbuf.getvalue()
        self.assertIn("admin_login", logged)
        for secret in (ACCESS_KEY, PASSWORD, TOKEN, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_unknown_sources_and_missing_values(self):
        base = {"MAAS360_BILLING_ID": BILLING, "MAAS360_APP_ID": APP_ID, "MAAS360_APP_ACCESS_KEY": ACCESS_KEY,
                "MAAS360_USERNAME": "api_reader", "MAAS360_PASSWORD": PASSWORD}
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "MAAS360_API_URL": "http://services.example.com"})
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "MAAS360_API_URL": "https://services.example.com", "MAAS360_SOURCES": "devices"})
        with self.assertRaises(c.BridgeError):
            c.load_config({"MAAS360_API_URL": "https://services.example.com"})

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.logins = [login(0, self.now - 60000)]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "MaaS360 API": self.cfg(MAAS360_API_URL=r.base)}
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
