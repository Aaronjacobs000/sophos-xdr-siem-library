"""Unit tests for netwrix_auditor_bridge.py against a local mock server.

The mock serves the shapes in Netwrix's Auditor Integration API reference:
POST /netwrix/api/v1/activity_records/search?format=json&count=<n> with Basic authentication and a
{"FilterList": {"When": {"From", "To"}, "DataSource": [...]}, "ContinuationMark": "..."} body,
answering {"ActivityRecordList": [{"Action", "MonitoringPlan": {"ID", "Name"}, "DataSource",
"Item": {"Name"}, "ObjectType", "RID", "What", "When", "Where", "Who", "Workstation",
"DetailList"}], "ContinuationMark": "..."}, an empty list after the last record, and
{"ErrorList": [{"Category", "Description"}]} on errors. Plus a Sophos NG-SIEM HTTP Ingest endpoint,
and an HTTPS server with a certificate made for the test when openssl is installed. No real service
is called.

  python3 -m unittest discover -s bridges/netwrix-auditor-activity-records -p 'test_*.py' -v
"""
import base64
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
import netwrix_auditor_bridge as c  # noqa: E402

USERNAME = "ACME\\svc-nwx-siem"
PASSWORD = "test-netwrix-reader-password-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
SEARCH = "/netwrix/api/v1/activity_records/search"
PLAN = {"ID": "{42F64379-163E-4A43-A9C5-4514C5A23798}", "Name": "AD Monitoring"}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def record(i, when, source="Active Directory", rid=True):
    r = {"Action": "Added", "MonitoringPlan": PLAN, "DataSource": source, "Item": {"Name": "corp.example.com (Domain)"},
         "ObjectType": "user", "RID": f"20261014011244{i:035d}", "What": f"\\com\\example\\corp\\Users\\User {i}",
         "When": iso(when), "Where": "dc01.corp.example.com", "Who": "ACME\\jsmith", "Workstation": "ws-jsmith.corp.example.com",
         "DetailList": [{"PropertyName": "description", "Before": None, "After": f"Account {i}"}]}
    if not rid:
        del r["RID"]
    return r


def error_body(description, category="InputError"):
    return {"ErrorList": [{"Category": category, "Description": description}]}


def mark_for(position, filters):
    return base64.b64encode(json.dumps({"p": position, "f": filters}, sort_keys=True).encode()).decode()


class Mock:
    def __init__(self):
        self.records = []
        self.page_cap = 1000
        self.requests = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        # Netwrix's docs name the array ActivityRecordSearch for the pages after the first.
        self.later_name = "ActivityRecordList"


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
        if url.path == SEARCH:
            query = urllib.parse.parse_qs(url.query)
            m.requests.append({"path": url.path, "query": query, "body": json.loads(body), "headers": dict(self.headers)})
            expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
            if self.headers.get("Authorization") != expected:
                return self._send(401, None)
            if m.codes:
                code = m.codes.pop(0)
                return self._send(code, error_body("0x80040C0A SQL Server cannot be contacted", "ServerError") if code == 500
                                  else None if code in (401, 404, 405) else error_body("Too many requests"))
            if query.get("format") != ["json"]:
                return self._send(400, error_body("XML expected"))
            req = json.loads(body)
            flt = req.get("FilterList") or {}
            when = flt.get("When") or {}
            lo, hi = c._parse_time(when.get("From")), c._parse_time(when.get("To"))
            if lo is None or hi is None:
                return self._send(400, error_body("Invalid When filter"))
            sources = flt.get("DataSource")
            rows = [r for r in m.records if lo <= c._parse_time(r["When"]) <= hi
                    and (not sources or r["DataSource"] in sources)]
            mark = req.get("ContinuationMark")
            if mark:
                state = json.loads(base64.b64decode(mark))
                if state["f"] != flt:
                    return self._send(400, error_body("The continuation mark doesn't match the filters"))
                position = state["p"]
            else:
                position = 0
            size = min(int(query.get("count", ["1000"])[0]), m.page_cap)
            chunk = rows[position:position + size]
            name = "ActivityRecordList" if not mark else m.later_name
            return self._send(200, {name: chunk, "ContinuationMark": mark_for(position + len(chunk), flt)})
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



class Tls:
    """An HTTPS search endpoint with a self-signed certificate for localhost, made with openssl for
    the test. It answers every search with one record and an empty page after it."""

    def __init__(self, folder):
        self.cert = os.path.join(folder, "nwx-test.crt")
        key = os.path.join(folder, "nwx-test.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", self.cert,
                        "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,digitalSignature,keyCertSign"],
                       check=True, capture_output=True)
        self.requests = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.requests += 1
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                rows = [] if req.get("ContinuationMark") else [record(1, datetime.now(timezone.utc) - timedelta(minutes=5))]
                body = json.dumps({"ActivityRecordList": rows, "ContinuationMark": "bWFyaw=="}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("NETWRIX_PAGE_SIZE", "page_size", 1000, 500, int, 5000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 3600, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 120.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"NETWRIX_API_URL": "https://nwx01.corp.example.com:9699", "NETWRIX_USERNAME": USERNAME, "NETWRIX_PASSWORD": PASSWORD}
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
                     NETWRIX_API_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def window(self, request):
        when = request["body"]["FilterList"]["When"]
        return c._parse_time(when["From"]), c._parse_time(when["To"])

    def test_records_are_searched_by_time_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.mock.records = [record(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg()), 5)
        sent = self.sent()
        self.assertEqual([r["What"] for r in sent], [f"\\com\\example\\corp\\Users\\User {i}" for i in range(5)])
        self.assertTrue(all(r["netwrix_auditor_record"] == "activity_record" for r in sent))
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"netwrix_auditor_record":"activity_record","Action":"Added"'))
        self.assertEqual({k: v for k, v in sent[0].items() if k != "netwrix_auditor_record"}, self.mock.records[0])
        # Three pages of records and the empty page that ends the search, each with the same filters.
        reqs = self.mock.requests
        self.assertEqual(len(reqs), 4)
        self.assertNotIn("ContinuationMark", reqs[0]["body"])
        self.assertEqual([r["body"].get("ContinuationMark") for r in reqs[1:]],
                         [mark_for(p, reqs[0]["body"]["FilterList"]) for p in (2, 4, 5)])
        self.assertEqual(len({json.dumps(r["body"]["FilterList"], sort_keys=True) for r in reqs}), 1)
        self.assertEqual(reqs[0]["query"], {"format": ["json"], "count": ["1000"]})
        self.assertEqual(reqs[0]["headers"]["Content-Type"], "application/json; charset=utf-8")
        start, end = self.window(reqs[0])
        self.assertAlmostEqual(end - start, 86400 - 60, delta=10)
        self.assertEqual(list(reqs[0]["body"]["FilterList"]), ["When"])

    def test_basic_authentication_with_the_domain_account(self):
        self.mock.records = [record(0, self.ago(5))]
        c.run_once(self.cfg())
        auth = self.mock.requests[0]["headers"]["Authorization"]
        self.assertEqual(base64.b64decode(auth.removeprefix("Basic ")).decode(), f"{USERNAME}:{PASSWORD}")

    def test_later_pages_named_activity_record_search_are_read(self):
        self.mock.page_cap = 1
        self.mock.later_name = "ActivityRecordSearch"
        self.mock.records = [record(i, self.ago(10 - i)) for i in range(3)]
        self.assertEqual(c.run_once(self.cfg()), 3)

    def test_data_sources_setting_filters_the_search(self):
        self.mock.records = [record(0, self.ago(5)), record(1, self.ago(4), "Exchange Online"), record(2, self.ago(3), "File Servers")]
        c.run_once(self.cfg(NETWRIX_DATA_SOURCES="Active Directory, Exchange Online"))
        self.assertEqual(sorted(r["DataSource"] for r in self.sent()), ["Active Directory", "Exchange Online"])
        self.assertEqual(self.mock.requests[0]["body"]["FilterList"]["DataSource"], ["Active Directory", "Exchange Online"])

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.records = [record(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200")
        c.run_once(cfg)
        first_end = self.window(self.mock.requests[0])[1]
        self.assertAlmostEqual(self.saved()["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # A record Netwrix collected late, inside the overlap, and a new one.
        self.mock.records += [record(7, self.ago(15)), record(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["RID"][-1] for r in self.sent()), ["7", "8"])
        self.assertAlmostEqual(self.window(self.mock.requests[0])[0], first_end - 1200, delta=1)

    def test_records_without_a_rid_are_known_by_their_hash(self):
        self.mock.records = [record(0, self.ago(10), rid=False), record(1, self.ago(9), rid=False)]
        c.run_once(self.cfg())
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 2)
        self.assertTrue(all(k.startswith("sha:") for k in self.saved()["seen"]))

    def test_lookback_sets_the_first_window(self):
        self.mock.records = [record(0, self.now - timedelta(days=3)), record(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["RID"][-1] for r in self.sent()], ["1"])
        self.assertLessEqual(self.window(self.mock.requests[0])[1], datetime.now(timezone.utc).timestamp() - 59)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.mock.records = [record(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg())
        saved = self.saved()
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual([r["RID"][-1] for r in self.sent()], ["2", "3"])
        self.assertIn("until", self.saved())

    def test_window_end_never_passes_now(self):
        self.mock.records = [record(0, self.ago(5)), record(1, self.now + timedelta(hours=2))]
        c.run_once(self.cfg())
        self.assertLessEqual(self.saved()["until"], datetime.now(timezone.utc).timestamp())

    def test_refused_account_and_missing_role_stop_with_clear_errors(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(NETWRIX_PASSWORD="wrong-password-0000000000"))
        self.assertIn("HTTP 401", str(cm.exception))
        self.assertIn("Basic authentication", str(cm.exception))
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.mock.codes = [403]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403", str(cm.exception))
        self.assertIn("Global reviewer", str(cm.exception))
        for code in (404, 405):
            self.mock.codes = [code]
            with self.subTest(code=code), self.assertRaisesRegex(c.BridgeError, f"HTTP {code}; check NETWRIX_API_URL"):
                c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_a_rejected_search_shows_the_netwrix_error(self):
        client = c.Netwrix(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            client.search({"When": {"From": "yesterday", "To": "today"}}, None)
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("InputError: Invalid When filter", str(cm.exception))

    def test_server_error_past_the_retries_is_a_network_error_with_netwrix_s_reason(self):
        self.mock.records = [record(0, self.ago(5))]
        self.mock.codes = [500] * c.MAX_ATTEMPTS
        with self.assertRaises(c.NetworkError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 500: ServerError: 0x80040C0A SQL Server cannot be contacted", str(cm.exception))
        self.assertIn("expired license", str(cm.exception))
        self.assertEqual(self.sent(), [])

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.records = [record(i, self.ago(10 - i)) for i in range(2)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["netwrix_auditor_record"] for x in lines], ["activity_record", "activity_record"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.records = [record(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [429, 503, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.records = [record(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.records = [record(0, self.ago(5))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(NETWRIX_PASSWORD="another-wrong-password-000000"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("activity records search", logged)
        basic = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        for secret in ("svc-nwx-siem", PASSWORD, INGEST_KEY, "00000000-example-integration", "another-wrong-password-000000", basic):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cert = os.path.join(self.tmp.name, "nwx.pem")
        with open(cert, "w") as fh:
            fh.write("not a certificate\n")
        cases = [
            base_env(NETWRIX_API_URL=None),
            base_env(NETWRIX_API_URL="http://nwx01.corp.example.com:9699"),
            base_env(NETWRIX_API_URL="https://nwx01.corp.example.com:9699/netwrix/api/v1"),
            base_env(NETWRIX_API_URL="https://user:pw@nwx01.corp.example.com:9699"),
            base_env(NETWRIX_USERNAME=None),
            base_env(NETWRIX_PASSWORD=None),
            base_env(NETWRIX_USERNAME="ACME\\svc:nwx"),
            base_env(NETWRIX_CA_FILE=os.path.join(self.tmp.name, "missing.pem")),
            base_env(NETWRIX_PAGE_SIZE="0"),
            base_env(NETWRIX_PAGE_SIZE="5001"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["data_sources"], cfg["page_size"], cfg["ca_file"]), ([], 1000, None))
        # A file that isn't a certificate stops the bridge when it starts, without its content.
        with self.assertRaisesRegex(c.BridgeError, "^NETWRIX_CA_FILE couldn't be read as a PEM certificate$"):
            c.Netwrix(c.load_config(base_env(NETWRIX_CA_FILE=cert)))

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2017, 2, 14, 15, 42, 34, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2017-02-14T15:42:34Z", want), ("2017-02-14T15:42:34.641Z", want + 0.641),
                               ("2017-02-15T02:42:34+11:00", want), ("2017-02-14T10:42:34-05:00", want),
                               ("2017-02-14T15:42:34", want)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))
        self.assertIsNone(c._parse_time(None))
        self.assertEqual(c._netwrix_time(want + 0.9), "2017-02-14T15:42:34Z")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the password or key to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.records = [record(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Netwrix": self.cfg(NETWRIX_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved())
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


@unittest.skipUnless(shutil.which("openssl"), "openssl makes the test certificate")
class TlsTest(unittest.TestCase):
    """Netwrix Auditor Server's own certificate: refused unless NETWRIX_CA_FILE trusts it, and only
    for the host name it gives."""

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
        env = base_env(NETWRIX_API_URL=f"https://{host}:{self.server.port}",
                       BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "state.json"), **extra)
        out = io.StringIO()
        c.run_once(c.load_config(env), dry_run=True, out=out)
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_the_certificate_named_in_netwrix_ca_file_is_trusted(self):
        rows = self.run_dry("localhost", NETWRIX_CA_FILE=self.server.cert)
        self.assertEqual([r["netwrix_auditor_record"] for r in rows], ["activity_record"])
        self.assertEqual(self.server.requests, 2)

    def test_an_untrusted_certificate_stops_the_run_at_once(self):
        with self.assertRaises(c.BridgeError) as caught:
            self.run_dry("localhost")
        self.assertNotIsInstance(caught.exception, c.NetworkError)
        self.assertIn("the server's certificate isn't trusted or doesn't name this host", str(caught.exception))
        self.assertEqual((self.server.requests, self.slept), (0, []))

    def test_a_host_name_the_certificate_does_not_give_is_refused(self):
        with self.assertRaisesRegex(c.BridgeError, "certificate isn't trusted or doesn't name this host"):
            self.run_dry("127.0.0.1", NETWRIX_CA_FILE=self.server.cert)
        self.assertEqual(self.server.requests, 0)

    def test_http_ingest_keeps_the_system_certificates(self):
        # The certificate in NETWRIX_CA_FILE is trusted for Netwrix only: HTTP Ingest still uses the
        # system store, through the bridge's default opener.
        client = c.Netwrix(c.load_config(base_env(NETWRIX_CA_FILE=self.server.cert)))
        self.assertIsNot(client.opener, c._OPENER)
        self.assertIs(c.Netwrix(c.load_config(base_env())).opener, c._OPENER)


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
        for value in ("-1", "0", "5001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^NETWRIX_PAGE_SIZE must be between 1 and 5,000$"):
                self.load(NETWRIX_PAGE_SIZE=value)
        self.assertEqual(self.load(NETWRIX_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(NETWRIX_PAGE_SIZE="5000")["page_size"], 5000)


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
        error = c.HostNotFound("activity records search to nwx01.corp.example.com:9699 failed: the host name wasn't found; check the URL setting")
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
