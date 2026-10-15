"""Unit tests for eset_connect_bridge.py against a local mock server.

The mock serves the ESET Connect shapes from ESET's public API reference and OpenAPI specifications:
POST /oauth/token (application/x-www-form-urlencoded, grant_type password or refresh_token, answering
{"access_token", "refresh_token", "token_type", "expires_in"}), and GET /v1/detections
(startTime inclusive and endTime exclusive on occurTime, pageSize, pageToken, answering
{"detections", "nextPageToken", "totalSize"}, or 202 with a response-id header while a query is
pending), with "Authorization: Bearer", plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service
is called.

  python3 -m unittest discover -s bridges/eset-connect -p 'test_*.py' -v
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
import time
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eset_connect_bridge as c  # noqa: E402

USERNAME = "api-reader@example.com"
PASSWORD = "test-eset-password-not-real"
REFRESH = "test-eset-refresh-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def iso(epoch, frac=False):
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if frac else dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(value):
    return c._epoch(value)


def detection(i, epoch, category="DETECTION_CATEGORY_ANTIVIRUS"):
    return {"uuid": f"00000000-0000-4000-8000-{i:012d}", "category": category, "severityLevel": "SEVERITY_LEVEL_MEDIUM",
            "displayName": "Win32/Agent.EXAMPLE", "typeName": "Trojan", "occurTime": iso(epoch, frac=i % 2 == 0),
            "objectName": f"C:\\Users\\jdoe\\Downloads\\invoice_{i}.exe", "objectTypeName": "File",
            "objectUrl": f"file:///C:/Users/jdoe/Downloads/invoice_{i}.exe", "objectHashSha1": "0" * 40,
            "context": {"circumstances": "Event occurred on a newly created file.", "deviceUuid": "11111111-2222-4333-8444-555555555555",
                        "process": {"path": "C:\\Windows\\explorer.exe"}, "userName": "EXAMPLE\\jdoe"},
            "networkCommunication": None,
            "responses": [{"description": "Deleted", "deviceRestartRequired": False, "displayName": "Cleaned by deleting",
                           "protectionName": "Real-time file system protection"}]}


class Mock:
    def __init__(self):
        self.detections = []
        self.page_size = 2
        self.tokens = []
        self.expires_in = 3600
        self.expire_once = False
        self.pending = 0
        self.pending_ids = set()
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.token_forms = []

    def new_token(self):
        tok = f"test-eset-access-token-{len(self.tokens)}-not-real"
        self.tokens.append(tok)
        return tok


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code == 429:
            self.send_header("Retry-After", "0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj).encode(), extra=extra)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
        if self.path == "/oauth/token":
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
            m.token_forms.append(form)
            if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
                return self._json({"error": "invalid_request"}, 400)
            ok = (form.get("grant_type") == "password" and form.get("username") == USERNAME and form.get("password") == PASSWORD) \
                or (form.get("grant_type") == "refresh_token" and form.get("refresh_token") == REFRESH)
            if not ok:
                return self._json({"error": "invalid_grant"}, 400)
            return self._json({"access_token": m.new_token(), "refresh_token": REFRESH, "token_type": "Bearer", "expires_in": m.expires_in})
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
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if not m.tokens or self.headers.get("Authorization") != f"Bearer {m.tokens[-1]}":
            return self._json({"code": 16, "message": "unauthenticated"}, 401)
        if m.expire_once:
            m.expire_once = False
            return self._json({"code": 16, "message": "token expired"}, 401)
        if m.codes:
            return self._json({}, m.codes.pop(0))
        if u.path != "/v1/detections":
            return self._json({}, 404)
        rid = self.headers.get("response-id")
        if m.pending:
            m.pending -= 1
            new_id = rid or f"resp-{len(m.requests)}"
            m.pending_ids.add(new_id)
            return self._send(202, b"", extra={"response-id": new_id})
        if rid and rid not in m.pending_ids:
            return self._json({}, 404)
        lo, hi = parse(q["startTime"]), parse(q["endTime"])
        size = min(int(q.get("pageSize") or 50), m.page_size)
        offset = int(q.get("pageToken") or 0)
        hits = [d for d in m.detections if lo <= parse(d["occurTime"]) < hi
                and (not q.get("deviceUuid") or d["context"]["deviceUuid"] == q["deviceUuid"])]
        hits.sort(key=lambda d: -parse(d["occurTime"]))  # newest first, so the bridge has to sort
        chunk = hits[offset:offset + size]
        nxt = str(offset + size) if offset + size < len(hits) else ""
        self._json({"detections": chunk, "nextPageToken": nxt, "totalSize": len(hits)})


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
    partway through it, as a dropped connection would."""

    def __init__(self, code=200):
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
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b'100\r\n{"partial":')
                self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("ESET_CONNECT_PAGE_SIZE", "page_size", 500, 100, int, 1000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 3600, 600, int, 10 ** 9),
    ("BRIDGE_PENDING_WAIT_SECONDS", "pending_wait", 15.0, 7.5, float, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 150.0, 30.5, float, 10 ** 9),
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
        warnings.showwarning = lambda m, cat, *a, **k: self.leaks.append(str(m)) if issubclass(cat, ResourceWarning) else show(m, cat, *a, **k)
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
        self.now = time.time()

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
             "ESET_CONNECT_TOKEN_URL": self.base, "ESET_CONNECT_API_URL": self.base,
             "ESET_CONNECT_USERNAME": USERNAME, "ESET_CONNECT_PASSWORD": PASSWORD, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def queries(self):
        return [urllib.parse.parse_qs(urllib.parse.urlsplit(p).query) for m, p, h in self.mock.requests if m == "GET"]

    def test_detections_are_paged_tagged_and_oldest_first(self):
        self.mock.detections = [detection(i, self.now - 3600 + i * 60) for i in range(5)]
        n = c.run_once(self.cfg())
        rows = self.sent()
        self.assertEqual(n, 5)
        self.assertEqual([r["uuid"] for r in rows], [d["uuid"] for d in self.mock.detections])
        self.assertEqual({k: v for k, v in rows[0].items() if k != "eset_connect_record"}, self.mock.detections[0])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"eset_connect_record":"detection"'))
        self.assertEqual(len(self.queries()), 3)
        self.assertEqual(self.mock.token_forms[0], {"grant_type": "password", "username": USERNAME, "password": PASSWORD})

    def test_query_window_page_size_and_device_filter(self):
        self.mock.detections = [detection(1, self.now - 60)]
        c.run_once(self.cfg(ESET_CONNECT_PAGE_SIZE="250", ESET_CONNECT_DEVICE_UUID="11111111-2222-4333-8444-555555555555",
                            BRIDGE_LOOKBACK_HOURS="2", BRIDGE_OVERLAP_SECONDS="600"))
        q = self.queries()[0]
        self.assertEqual(q["pageSize"], ["250"])
        self.assertEqual(q["deviceUuid"], ["11111111-2222-4333-8444-555555555555"])
        self.assertRegex(q["startTime"][0], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertAlmostEqual(parse(q["startTime"][0]), self.now - 7200 - 600, delta=5)
        self.assertAlmostEqual(parse(q["endTime"][0]), self.now, delta=5)
        self.assertEqual(len(self.sent()), 1)

    def test_next_run_sends_only_new_detections(self):
        self.mock.detections = [detection(i, self.now - 600 + i * 10) for i in range(3)]
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        late = detection(9, time.time() - 1)
        self.mock.detections.append(late)
        # The second run's window starts an overlap before the first run's end, so it reads the
        # first three again; only the new one is sent.
        with open(self.state, encoding="utf-8") as fh:
            state = json.load(fh)
        state["detections"]["since"] -= 5
        with open(self.state, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        c.run_once(cfg)
        self.assertEqual([r["uuid"] for r in self.sent()], [late["uuid"]])

    def test_a_late_detection_inside_the_overlap_is_sent_once(self):
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="3600")
        self.mock.detections = [detection(1, self.now - 300)]
        c.run_once(cfg)
        # A detection that happened 20 minutes ago reaches ESET Connect only now (the device was
        # offline). Its occurTime is before the last run's end but inside the overlap.
        self.mock.detections.append(detection(2, self.now - 1200))
        self.mock.ingested.clear()
        c.run_once(cfg)
        c.run_once(cfg)
        self.assertEqual([r["uuid"] for r in self.sent()], [detection(2, 0)["uuid"]])

    def test_lookback_limits_the_first_run(self):
        self.mock.detections = [detection(0, self.now - 3 * 86400), detection(1, self.now - 3600)]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24", BRIDGE_OVERLAP_SECONDS="0"))
        self.assertEqual([r["uuid"] for r in self.sent()], [detection(1, 0)["uuid"]])

    def test_bad_credentials_stop_and_save_nothing(self):
        self.mock.detections = [detection(0, self.now - 60)]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(ESET_CONNECT_PASSWORD="wrong-password-000"))
        self.assertIn("ESET Connect sign-in failed with HTTP 400", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))
        self.assertEqual(self.mock.ingested, [])

    def test_a_rejected_token_is_refreshed_once(self):
        self.mock.detections = [detection(0, self.now - 60)]
        self.mock.expire_once = True
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual([f["grant_type"] for f in self.mock.token_forms], ["password", "refresh_token"])

    def test_the_token_is_renewed_before_it_expires(self):
        self.mock.detections = [detection(0, self.now - 60)]
        cfg = self.cfg()
        client = c.EsetConnect(cfg)
        c.run_once(cfg, client=client)
        client.expires_at = time.time() - 1
        c.run_once(cfg, client=client)
        self.assertEqual([f["grant_type"] for f in self.mock.token_forms], ["password", "refresh_token"])
        gets = [h["Authorization"] for m, p, h in self.mock.requests if m == "GET"]
        self.assertEqual(gets, [f"Bearer {self.mock.tokens[0]}", f"Bearer {self.mock.tokens[1]}"])

    def test_a_pending_query_is_collected_with_its_response_id(self):
        self.mock.detections = [detection(i, self.now - 600 + i) for i in range(3)]
        self.mock.pending = 2
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        gets = [(p, {k.lower(): v for k, v in h.items()}.get("response-id")) for m, p, h in self.mock.requests if m == "GET"]
        # The first ask has no response-id; the next two repeat the same query with it.
        self.assertIsNone(gets[0][1])
        self.assertTrue(gets[1][1] and gets[2][1] == gets[1][1])
        self.assertEqual(gets[0][0], gets[1][0])
        self.assertEqual(gets[1][0], gets[2][0])

    def test_a_query_pending_too_long_stops_without_saving(self):
        self.mock.detections = [detection(0, self.now - 60)]
        self.mock.pending = c.PENDING_ATTEMPTS + 5
        with self.assertRaisesRegex(c.BridgeError, "still preparing"):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.detections = [detection(i, self.now - 60 + i) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0])["eset_connect_record"], "detection")
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.detections = [detection(i, self.now - 60 + i) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_ingest_failure_keeps_the_cursor(self):
        self.mock.detections = [detection(0, self.now - 60)]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_gzip_batches_and_headers(self):
        self.mock.detections = [detection(i, self.now - 600 + i) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="2500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.detections = [detection(0, self.now - 60)]
        self.mock.expire_once = True
        self.mock.pending = 1
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.logbuf.getvalue()
        self.assertIn("detections", logged)
        for secret in (PASSWORD, REFRESH, INGEST_KEY, "00000000-example-integration", *self.mock.tokens):
            self.assertNotIn(secret, logged)

    def test_config_regions_https_and_required_values(self):
        base = {"ESET_CONNECT_USERNAME": USERNAME, "ESET_CONNECT_PASSWORD": PASSWORD}
        cfg = c.load_config({**base, "ESET_CONNECT_REGION": "JPN"})
        self.assertEqual(cfg["token_url"], "https://jpn.business-account.iam.eset.systems")
        self.assertEqual(cfg["api_url"], "https://jpn.incident-management.eset.systems")
        self.assertEqual(c.load_config(base)["api_url"], "https://eu.incident-management.eset.systems")
        for bad in ({"ESET_CONNECT_REGION": "au"}, {"ESET_CONNECT_API_URL": "http://incident-management.example.com"},
                    {"ESET_CONNECT_TOKEN_URL": "http://iam.example.com"}, {"NGSIEM_INGEST_URL": "http://ingest.example.com/x"},
                    {"ESET_CONNECT_PAGE_SIZE": "5000"}, {"ESET_CONNECT_PAGE_SIZE": "many"}):
            with self.subTest(bad=bad), self.assertRaises(c.BridgeError):
                c.load_config({**base, **bad})
        with self.assertRaises(c.BridgeError):
            c.load_config({"ESET_CONNECT_USERNAME": USERNAME})

    def test_occur_time_formats(self):
        self.assertEqual(c._epoch("2026-10-13T01:02:03Z"), datetime(2026, 10, 13, 1, 2, 3, tzinfo=timezone.utc).timestamp())
        self.assertAlmostEqual(c._epoch("2026-10-13T01:02:03.250Z"), datetime(2026, 10, 13, 1, 2, 3, tzinfo=timezone.utc).timestamp() + 0.25)
        self.assertEqual(c._epoch("2026-10-13T11:02:03+10:00"), c._epoch("2026-10-13T01:02:03Z"))
        self.assertIsNone(c._epoch("not a time"))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the password, token or key to another URL, so the run
        # fails instead, and nothing reaches the redirect's target.
        self.mock.detections = [detection(0, self.now - 60)]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "ESET token URL": self.cfg(ESET_CONNECT_TOKEN_URL=r.base),
                     "ESET API URL": self.cfg(ESET_CONNECT_API_URL=r.base)}
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


class RangeTest(unittest.TestCase):
    """A number outside its range stops the bridge with an error that gives the range."""

    def load(self, **extra):
        env = {"ESET_CONNECT_USERNAME": USERNAME, "ESET_CONNECT_PASSWORD": PASSWORD}
        env.update(extra)
        return c.load_config(env)

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "1001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^ESET_CONNECT_PAGE_SIZE must be between 1 and 1,000$"):
                self.load(ESET_CONNECT_PAGE_SIZE=value)
        self.assertEqual(self.load(ESET_CONNECT_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(ESET_CONNECT_PAGE_SIZE="1000")["page_size"], 1000)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config({"ESET_CONNECT_USERNAME": USERNAME, "ESET_CONNECT_PASSWORD": PASSWORD})
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
        self.assertIsInstance(first, c.EsetConnect)
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
