"""Unit tests for snowflake_login_history_bridge.py against a local mock server.

The mock serves the shapes in Snowflake's SQL API reference: POST /api/v2/statements (a JSON body
with statement, timeout, bindings, warehouse and role; answering 200 with a ResultSet of
resultSetMetaData {numRows, format, rowType, partitionInfo}, data, code, statementHandle and
statementStatusUrl, or 202 with a QueryStatus {code, message, statementHandle, statementStatusUrl}
while the statement runs, or 422 with a QueryFailureStatus), GET /api/v2/statements/{handle}
(the same answers) and GET /api/v2/statements/{handle}?partition=N (the rows of a later partition,
gzip compressed with Content-Encoding: gzip and no metadata), and POST
/api/v2/statements/{handle}/cancel. Rows are LOGIN_HISTORY rows as the SQL API returns them: every
value a string or null, TIMESTAMP_LTZ as seconds since the epoch with nine decimals. It runs the
bridge's statement and bind variables on its own rows. Plus a Sophos NG-SIEM HTTP Ingest endpoint.
No real service is called.

  python3 -m unittest discover -s bridges/snowflake-login-history -p 'test_*.py' -v
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
import snowflake_login_history_bridge as c  # noqa: E402

TOKEN = "test-snowflake-pat-not-real-7f3a9c2e"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ACCOUNT = "myorg-myaccount"
BASE = {"SNOWFLAKE_ACCOUNT_URL": f"https://{ACCOUNT}.snowflakecomputing.com", "SNOWFLAKE_TOKEN": TOKEN}
STATEMENTS = "/api/v2/statements"
HANDLE = "01b7c1f2-0000-4d3b-0000-0004a1b2c3d4"
COLUMNS = [("EVENT_ID", "fixed"), ("EVENT_TIMESTAMP", "timestamp_ltz"), ("EVENT_TYPE", "text"), ("USER_NAME", "text"),
           ("CLIENT_IP", "text"), ("REPORTED_CLIENT_TYPE", "text"), ("REPORTED_CLIENT_VERSION", "text"),
           ("FIRST_AUTHENTICATION_FACTOR", "text"), ("SECOND_AUTHENTICATION_FACTOR", "text"), ("IS_SUCCESS", "text"),
           ("ERROR_CODE", "fixed"), ("ERROR_MESSAGE", "text"), ("RELATED_EVENT_ID", "fixed"), ("CONNECTION", "text"),
           ("CLIENT_PRIVATE_LINK_ID", "text"), ("FIRST_AUTHENTICATION_FACTOR_ID", "text"),
           ("SECOND_AUTHENTICATION_FACTOR_ID", "text"), ("LOGIN_DETAILS", "text"), ("AUTHORIZING_INTEGRATION_NAME", "text")]
NAMES = [n for n, _ in COLUMNS]
STATEMENT_RE = re.compile(r"SELECT \* FROM SNOWFLAKE\.ACCOUNT_USAGE\.LOGIN_HISTORY WHERE EVENT_TIMESTAMP < \? AND "
                          r"\(EVENT_TIMESTAMP > \? OR \(EVENT_TIMESTAMP = \? AND EVENT_ID > \?\)\) "
                          r"ORDER BY EVENT_TIMESTAMP, EVENT_ID LIMIT (\d+)")


def epoch(dt, nanos=0):
    """A TIMESTAMP_LTZ value as the SQL API returns it: seconds since the epoch with nine decimals."""
    seconds = int(dt.replace(microsecond=0).timestamp())
    return f"{seconds}.{dt.microsecond * 1000 + nanos:09d}"


def login(i, when, success=True, nanos=0, **extra):
    """One LOGIN_HISTORY row, as the SQL API's data array holds it."""
    rec = {"EVENT_ID": str(9007199254740993 + i), "EVENT_TIMESTAMP": epoch(when, nanos), "EVENT_TYPE": "LOGIN",
           "USER_NAME": f"USER{i}", "CLIENT_IP": "203.0.113.40", "REPORTED_CLIENT_TYPE": "SNOWFLAKE_UI",
           "REPORTED_CLIENT_VERSION": "9.30.1", "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
           "SECOND_AUTHENTICATION_FACTOR": "MFA_TOKEN" if success else None, "IS_SUCCESS": "YES" if success else "NO",
           "ERROR_CODE": None if success else "390100", "ERROR_MESSAGE": None if success else "INCORRECT_USERNAME_PASSWORD",
           "RELATED_EVENT_ID": "0", "CONNECTION": None, "CLIENT_PRIVATE_LINK_ID": None,
           "FIRST_AUTHENTICATION_FACTOR_ID": None, "SECOND_AUTHENTICATION_FACTOR_ID": None, "LOGIN_DETAILS": None,
           "AUTHORIZING_INTEGRATION_NAME": None}
    rec.update(extra)
    return [rec[n] for n in NAMES]


def ns(value):
    whole, _, frac = value.partition(".")
    return int(whole) * c.NS + int(frac.ljust(9, "0"))


class Mock:
    def __init__(self):
        self.rows = []
        self.codes = []
        self.status_codes = []
        self.ingest_codes = []
        self.ingested = []
        self.statements = []
        self.headers = []
        self.gets = []
        self.cancels = []
        self.running = 0
        self.poll_wait = 0.0
        self.partition_size = 1000
        self.pending = None
        self.wrong_count = False
        self.code = "090001"


def run_statement(rows, body):
    """The bridge's statement on the mock's rows: the bind variables, the order and the limit."""
    m = STATEMENT_RE.fullmatch(body["statement"])
    assert m, body["statement"]
    b = body["bindings"]
    assert [b[k]["type"] for k in ("1", "2", "3", "4")] == ["TIMESTAMP_LTZ", "TIMESTAMP_LTZ", "TIMESTAMP_LTZ", "FIXED"], b
    assert b["2"]["value"] == b["3"]["value"], b
    end, start, after = int(b["1"]["value"]), int(b["2"]["value"]), int(b["4"]["value"])
    out = []
    for r in rows:
        t, eid = ns(r[1]), int(r[0])
        if t < end and (t > start or (t == start and eid > after)):
            out.append(r)
    out.sort(key=lambda r: (ns(r[1]), int(r[0])))
    return out[:int(m.group(1))]


def result_set(rows, size, code="090001", wrong_count=False):
    parts = [rows[i:i + size] for i in range(0, len(rows), size)] or [[]]
    info = [{"rowCount": len(p) + (1 if wrong_count and i == 0 else 0), "uncompressedSize": 1000 * len(p)}
            for i, p in enumerate(parts)]
    return parts, {"resultSetMetaData": {"numRows": len(rows), "format": "jsonv2",
                                         "rowType": [{"name": n, "database": "SNOWFLAKE", "schema": "ACCOUNT_USAGE",
                                                      "table": "LOGIN_HISTORY", "type": t, "nullable": True}
                                                     for n, t in COLUMNS],
                                         "partitionInfo": info},
                   "data": parts[0], "code": code, "statementStatusUrl": f"{STATEMENTS}/{HANDLE}?requestId=x",
                   "sqlState": "00000", "statementHandle": HANDLE, "message": "Statement executed successfully.",
                   "createdOn": 1792040000000}


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None, raw=None):
        body = raw if raw is not None else (b"" if obj is None else json.dumps(obj).encode())
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        self.mock.headers.append(dict(self.headers))
        return (self.headers.get("Authorization") == f"Bearer {TOKEN}"
                and self.headers.get("X-Snowflake-Authorization-Token-Type") == "PROGRAMMATIC_ACCESS_TOKEN")

    def _error(self, code):
        if isinstance(code, tuple):
            return self._send(code[0], code[1])
        if code == 429:
            return self._send(429, {"code": "390505", "message": "Too many requests."}, {"Retry-After": "1"})
        return self._send(code, {"code": "000000", "message": "try again"})

    def _refused(self):
        # Snowflake's message for a refused token shows its last characters.
        return self._send(401, {"code": "390303", "message": f"Invalid OAuth access token. ...{TOKEN[-8:]}"})

    def _running(self):
        return self._send(202, {"code": "333334", "message": "Asynchronous execution in progress. Use provided query id "
                                "to perform query monitoring and management.", "statementHandle": HANDLE,
                                "statementStatusUrl": f"{STATEMENTS}/{HANDLE}"})

    def do_GET(self):
        m = self.mock
        parts = urllib.parse.urlsplit(self.path)
        if parts.path != f"{STATEMENTS}/{HANDLE}" or m.pending is None:
            return self._send(404, {"code": "000709", "message": "Statement not found"})
        if not self._authorized():
            return self._refused()
        q = dict(urllib.parse.parse_qsl(parts.query))
        m.gets.append(q)
        if m.status_codes:
            return self._error(m.status_codes.pop(0))
        if "partition" in q:
            data = json.dumps({"data": m.pending[0][int(q["partition"])]}).encode()
            return self._send(200, None, {"Content-Encoding": "gzip"}, raw=gzip.compress(data))
        if m.running > 0:
            m.running -= 1
            # The tests replace time.sleep, so the wait for an answer uses an event instead.
            threading.Event().wait(m.poll_wait)
            return self._running()
        return self._send(200, m.pending[1])

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == f"{STATEMENTS}/{HANDLE}/cancel":
            m.cancels.append(parts.path)
            return self._send(200, {"code": "000604", "sqlState": "57014", "message": "SQL execution canceled",
                                    "statementHandle": HANDLE, "statementStatusUrl": f"{STATEMENTS}/{HANDLE}"})
        if parts.path == STATEMENTS:
            if not self._authorized():
                return self._refused()
            if m.codes:
                return self._error(m.codes.pop(0))
            req = json.loads(body)
            m.statements.append(req)
            m.pending = result_set(run_statement(m.rows, req), m.partition_size, m.code, m.wrong_count)
            if m.running > 0:
                return self._running()
            return self._send(200, m.pending[1])
        if not parts.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
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
    ("SNOWFLAKE_PAGE_SIZE", "page_size", 10000, 500, int, 100000),
    ("SNOWFLAKE_QUERY_TIMEOUT", "query_timeout", 300, 120, int, 3600),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 8760),
    ("BRIDGE_DELAY_SECONDS", "delay_seconds", 10800, 7200, int, 86400),
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
             "SNOWFLAKE_ACCOUNT_URL": self.base, "SNOWFLAKE_TOKEN": TOKEN, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        cfg = c.load_config(e)
        # The mock runs on 127.0.0.1, so name the account as a real account URL would.
        cfg["account"] = ACCOUNT
        return cfg

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("SNOWFLAKE_ACCOUNT_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_rows_are_tagged_and_sent_oldest_first(self):
        self.mock.rows = [login(i, self.ago(400 - i), success=i != 2) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(SNOWFLAKE_PAGE_SIZE="2", SNOWFLAKE_WAREHOUSE="NGSIEM_WH",
                                             SNOWFLAKE_ROLE="NGSIEM_LOGIN_READER")), 5)
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"snowflake_record":"login_history","snowflake_account":"'
                                                                + ACCOUNT + '","EVENT_ID":"9007199254740993","EVENT_TIMESTAMP":"'))
        sent = self.sent()
        self.assertEqual([r["USER_NAME"] for r in sent], [f"USER{i}" for i in range(5)])
        # Every value stays the string (or null) the SQL API returned, so IDs keep every digit; the
        # time becomes RFC 3339 in UTC.
        want = dict(zip(NAMES, login(2, self.ago(398), success=False)))
        want["EVENT_TIMESTAMP"] = c._iso(ns(want["EVENT_TIMESTAMP"]))
        self.assertEqual({k: v for k, v in sent[2].items() if k not in ("snowflake_record", "snowflake_account")}, want)
        self.assertEqual((sent[2]["EVENT_ID"], sent[2]["ERROR_CODE"], sent[2]["SECOND_AUTHENTICATION_FACTOR"]),
                         ("9007199254740995", "390100", None))
        self.assertRegex(sent[0]["EVENT_TIMESTAMP"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,9}Z$")
        # Pages of two; each page starts after the last one's final row.
        self.assertEqual(len(self.mock.statements), 3)
        first, second = self.mock.statements[0], self.mock.statements[1]
        self.assertEqual((first["timeout"], first["warehouse"], first["role"]), (300, "NGSIEM_WH", "NGSIEM_LOGIN_READER"))
        self.assertTrue(first["statement"].endswith(" LIMIT 2"))
        self.assertEqual(first["bindings"]["4"], {"type": "FIXED", "value": "-1"})
        self.assertEqual(second["bindings"]["2"]["value"], str(ns(self.mock.rows[1][1])))
        self.assertEqual(second["bindings"]["4"], {"type": "FIXED", "value": "9007199254740994"})
        for h in self.mock.headers:
            self.assertEqual((h["Authorization"], h["X-Snowflake-Authorization-Token-Type"], h["Accept"], h["Content-Type"]),
                             (f"Bearer {TOKEN}", "PROGRAMMATIC_ACCESS_TOKEN", "application/json", "application/json"))
            self.assertTrue(h["User-Agent"].startswith("sophos-xdr-siem-library-snowflake-login-history-bridge/"))

    def test_without_a_warehouse_or_role_the_users_defaults_are_used(self):
        self.mock.rows = [login(0, self.ago(400))]
        c.run_once(self.cfg())
        self.assertNotIn("warehouse", self.mock.statements[0])
        self.assertNotIn("role", self.mock.statements[0])

    def test_the_window_ends_the_delay_before_now(self):
        # LOGIN_HISTORY fills with up to two hours of latency, so the default window ends three hours ago.
        self.mock.rows = [login(0, self.ago(200)), login(1, self.ago(100))]
        c.run_once(self.cfg())
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER0"])
        end = int(self.mock.statements[0]["bindings"]["1"]["value"])
        expected = int((self.now - timedelta(seconds=10800)).timestamp() * c.NS)
        self.assertLess(abs(end - expected), 5 * c.NS)
        self.assertEqual(self.saved()[ACCOUNT], {"cursor_ns": end, "cursor_id": None})
        self.mock.ingested.clear()
        c.run_once(self.cfg(BRIDGE_DELAY_SECONDS="0"))
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER1"])

    def test_the_first_run_starts_the_lookback_before_now(self):
        self.mock.rows = [login(0, self.now - timedelta(hours=30)), login(1, self.now - timedelta(hours=20))]
        c.run_once(self.cfg())
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER1"])

    def test_the_next_run_starts_where_the_last_ended_without_repeats(self):
        self.mock.rows = [login(i, self.ago(300 - i)) for i in range(3)]
        c.run_once(self.cfg())
        self.mock.ingested.clear()
        # The first window ended three hours ago, so this row is in the next one.
        self.mock.rows.append(login(7, self.ago(3)))
        cfg = self.cfg(BRIDGE_DELAY_SECONDS="0")
        c.run_once(cfg)
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER7"])
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])

    def test_rows_that_share_a_time_across_pages_are_each_sent_once(self):
        when = self.ago(250)
        self.mock.rows = [login(0, self.ago(260))] + [login(i, when, nanos=123) for i in (1, 2, 3, 4)] + [login(9, self.ago(200))]
        c.run_once(self.cfg(SNOWFLAKE_PAGE_SIZE="2"))
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER0", "USER1", "USER2", "USER3", "USER4", "USER9"])
        # Within one time, each page goes on after the last EVENT_ID it sent.
        self.assertEqual([s["bindings"]["4"]["value"] for s in self.mock.statements],
                         ["-1", "9007199254740994", "9007199254740996", "9007199254741002"])

    def test_the_position_moves_only_after_ingest_accepts(self):
        self.mock.rows = [login(i, self.ago(300 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(SNOWFLAKE_PAGE_SIZE="2"))
        self.assertEqual(self.saved()[ACCOUNT], {"cursor_ns": ns(self.mock.rows[1][1]), "cursor_id": self.mock.rows[1][0]})
        self.mock.ingested.clear()
        c.run_once(self.cfg(SNOWFLAKE_PAGE_SIZE="2"))
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER2", "USER3"])

    def test_a_running_statement_is_checked_until_it_finishes(self):
        self.mock.rows = [login(i, self.ago(300 - i)) for i in range(3)]
        self.mock.running = 6
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.mock.gets, [{}] * 7)
        # The wait between checks grows, to five seconds at most.
        self.assertEqual(self.slept, [0.5, 1.0, 2.0, 4.0, 5.0, 5.0, 5.0])

    def test_a_statement_past_its_time_limit_is_cancelled_and_the_window_kept(self):
        self.mock.rows = [login(0, self.ago(300))]
        self.mock.running = 1000
        self.mock.poll_wait = 0.3
        saved, c.POLL_GRACE_SECONDS = c.POLL_GRACE_SECONDS, 0
        try:
            with self.assertRaisesRegex(c.NetworkError, "didn't finish within 1 seconds, so it was cancelled"):
                c.run_once(self.cfg(SNOWFLAKE_QUERY_TIMEOUT="1"))
        finally:
            c.POLL_GRACE_SECONDS = saved
        self.assertEqual(self.mock.cancels, [f"{STATEMENTS}/{HANDLE}/cancel"])
        self.assertLess(len(self.mock.gets), 10)
        self.assertEqual(self.sent(), [])
        self.assertFalse(os.path.exists(self.state))

    def test_a_statement_snowflake_timed_out_is_a_network_error(self):
        self.mock.rows = [login(0, self.ago(300))]
        failure = (422, {"code": "000630", "sqlState": "57014", "statementHandle": HANDLE,
                         "message": "Statement reached its statement or warehouse timeout of 300 second(s) and was canceled."})
        self.mock.codes = [failure]
        with self.assertRaisesRegex(c.NetworkError, "reached its timeout of 300 seconds in Snowflake"):
            c.run_once(self.cfg())
        self.mock.running, self.mock.status_codes = 1, [failure]
        with self.assertRaisesRegex(c.NetworkError, "reached its timeout"):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_a_refused_statement_stops_with_snowflakes_message(self):
        self.mock.rows = [login(0, self.ago(300))]
        self.mock.codes = [(422, {"code": "002003", "sqlState": "02000", "statementHandle": HANDLE,
                                  "message": "SQL compilation error:\nObject 'SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY' does not "
                                             "exist or not authorized."})]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.assertIn("refused the query request (HTTP 422, code 002003): SQL compilation error:", str(cm.exception))
        self.assertIn("does not exist or not authorized", str(cm.exception))
        self.mock.codes = [(400, {"code": "390142", "message": "Incoming request does not contain a valid payload."})]
        with self.assertRaisesRegex(c.BridgeError, r"\(HTTP 400, code 390142\): Incoming request does not contain"):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_a_refused_token_stops_at_once_without_any_of_the_token(self):
        self.mock.rows = [login(0, self.ago(300))]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(SNOWFLAKE_TOKEN="wrong-token-value-not-real"))
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.assertIn("refused the token on the query request (HTTP 401, code 390303); check SNOWFLAKE_TOKEN", str(cm.exception))
        self.assertNotIn(TOKEN[-8:], str(cm.exception) + self.logbuf.getvalue())
        self.assertEqual(len(self.mock.headers), 1)

    def test_every_partition_is_read(self):
        # The first partition comes with the answer; the rest are fetched one by one, gzip compressed.
        self.mock.rows = [login(i, self.ago(400 - i)) for i in range(7)]
        self.mock.partition_size = 3
        c.run_once(self.cfg())
        self.assertEqual([r["USER_NAME"] for r in self.sent()], [f"USER{i}" for i in range(7)])
        self.assertEqual(self.mock.gets, [{"partition": "1"}, {"partition": "2"}])
        self.assertEqual(self.saved()[ACCOUNT]["cursor_id"], None)

    def test_a_partition_with_the_wrong_row_count_sends_nothing(self):
        self.mock.rows = [login(i, self.ago(400 - i)) for i in range(4)]
        self.mock.partition_size = 2
        self.mock.wrong_count = True
        with self.assertRaisesRegex(c.BridgeError, "^partition 0 of the result has 2 rows, but Snowflake said 3$"):
            c.run_once(self.cfg())
        self.assertEqual(self.sent(), [])
        self.assertFalse(os.path.exists(self.state))

    def test_a_result_too_large_to_return_whole_stops_with_advice(self):
        self.mock.rows = [login(0, self.ago(300))]
        self.mock.code = "391908"
        with self.assertRaisesRegex(c.BridgeError, "lower SNOWFLAKE_PAGE_SIZE"):
            c.run_once(self.cfg())

    def test_a_partition_that_unpacks_past_the_cap_is_refused(self):
        client = c.Snowflake(self.cfg())
        saved, c.MAX_RESPONSE_BYTES = c.MAX_RESPONSE_BYTES, 1024 * 1024
        try:
            bomb = gzip.compress(b'{"data": [' + b" " * (2 * 1024 * 1024) + b"]}")
            with self.assertRaisesRegex(c.BridgeError, "unpacks to more than 1 MB"):
                client._partition(bomb)
            with self.assertRaisesRegex(c.BridgeError, "ends partway"):
                client._partition(gzip.compress(b'{"data": []}')[:-8])
            self.assertEqual(client._partition(gzip.compress(b'{"data": [["1"]]}')), [["1"]])
            self.assertEqual(client._partition(b'{"data": []}'), [])
        finally:
            c.MAX_RESPONSE_BYTES = saved

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.rows = [login(i, self.ago(300 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["snowflake_record"] for x in lines], ["login_history"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.rows = [login(i, self.ago(300 - i)) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.slept[0], 1.0)

    def test_gzip_batches_and_headers(self):
        self.mock.rows = [login(i, self.ago(400 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.rows = [login(0, self.ago(300))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(SNOWFLAKE_TOKEN="another-wrong-token-000"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("query request", logged)
        for secret in (TOKEN, TOKEN[-8:], INGEST_KEY, "00000000-example-integration", "another-wrong-token-000"):
            self.assertNotIn(secret, logged)

    def test_state_is_kept_per_account(self):
        self.mock.rows = [login(0, self.ago(300))]
        cfg = self.cfg()
        c.run_once(cfg)
        cfg["account"] = "myorg-otheraccount"
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(set(self.saved()), {ACCOUNT, "myorg-otheraccount"})

    def test_a_saved_position_older_than_a_year_starts_at_the_retention_limit(self):
        old = int((self.now - timedelta(days=500)).timestamp()) * c.NS
        with open(self.state, "w") as fh:
            json.dump({ACCOUNT: {"cursor_ns": old, "cursor_id": "123"}}, fh)
        self.mock.rows = [login(0, self.now - timedelta(days=400)), login(1, self.now - timedelta(days=300))]
        c.run_once(self.cfg())
        self.assertEqual([r["USER_NAME"] for r in self.sent()], ["USER1"])
        self.assertEqual(self.mock.statements[0]["bindings"]["4"]["value"], "-1")

    def test_a_saved_position_past_the_window_end_counts_as_the_end(self):
        # The clock went back: the window starts at its end, and the saved EVENT_ID no longer applies.
        future = int((self.now + timedelta(hours=1)).timestamp()) * c.NS
        with open(self.state, "w") as fh:
            json.dump({ACCOUNT: {"cursor_ns": future, "cursor_id": "123"}}, fh)
        self.assertEqual(c.run_once(self.cfg()), 0)
        self.assertEqual(self.mock.statements, [])

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "SNOWFLAKE_ACCOUNT_URL": f"http://{ACCOUNT}.snowflakecomputing.com"},
                    {**BASE, "SNOWFLAKE_ACCOUNT_URL": f"https://{ACCOUNT}.snowflakecomputing.com/api/v2"},
                    {**BASE, "SNOWFLAKE_ACCOUNT_URL": f"https://{ACCOUNT}.snowflakecomputing.com?x=1"},
                    {"SNOWFLAKE_TOKEN": TOKEN}, {"SNOWFLAKE_ACCOUNT_URL": BASE["SNOWFLAKE_ACCOUNT_URL"]},
                    {**BASE, "NGSIEM_INGEST_URL": "http://ingest.example/http-endpoint/v1/x"},
                    {**BASE, "SNOWFLAKE_PAGE_SIZE": "0"}, {**BASE, "BRIDGE_LOOKBACK_HOURS": "8761"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "SNOWFLAKE_TOKEN"}), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["account_url"], cfg["account"], cfg["warehouse"], cfg["role"]),
                         (f"https://{ACCOUNT}.snowflakecomputing.com", ACCOUNT, None, None))
        self.assertEqual((cfg["page_size"], cfg["delay_seconds"], cfg["lookback_hours"], cfg["query_timeout"]),
                         (10000, 10800, 24.0, 300))
        self.assertEqual(c.load_config({**BASE, "SNOWFLAKE_ACCOUNT_URL": f"https://{ACCOUNT}.snowflakecomputing.com/"})["account_url"],
                         f"https://{ACCOUNT}.snowflakecomputing.com")
        self.assertEqual(c.load_config({**BASE, "SNOWFLAKE_ACCOUNT_URL": f"https://{ACCOUNT}.privatelink.snowflakecomputing.com"})["account"],
                         ACCOUNT)

    def test_times_keep_nanoseconds(self):
        want = int(datetime(2026, 10, 14, 16, 12, 44, tzinfo=timezone.utc).timestamp()) * c.NS
        secs = want // c.NS
        for text, expected in [(f"{secs}.000000000", want), (f"{secs}.123000000", want + 123000000),
                               (f"{secs}.5", want + 500000000), (f"{secs}.123456789", want + 123456789), (f"{secs}", want),
                               (" 1.000000001 ", c.NS + 1), ("-1.500000000", -c.NS - 500000000)]:
            with self.subTest(text=text):
                self.assertEqual(c._epoch_ns(text), expected)
        for bad in ("yesterday", "", None, 1792000000, "1792000000.1234567891", "1616173619.000000000 1500", "1e9"):
            with self.subTest(bad=bad):
                self.assertIsNone(c._epoch_ns(bad))
        self.assertEqual(c._iso(want), "2026-10-14T16:12:44.000Z")
        self.assertEqual(c._iso(want + 123000000), "2026-10-14T16:12:44.123Z")
        self.assertEqual(c._iso(want + 123456789), "2026-10-14T16:12:44.123456789Z")
        self.assertEqual(c._iso(want + 120000), "2026-10-14T16:12:44.00012Z")
        self.assertEqual(c._value("timestamp_ltz", f"{secs}.123000000"), "2026-10-14T16:12:44.123Z")
        self.assertEqual(c._value("TIMESTAMP_NTZ".lower(), f"{secs}.1"), "2026-10-14T16:12:44.100Z")
        self.assertEqual((c._value("fixed", "9007199254740993"), c._value("text", None)), ("9007199254740993", None))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.rows = [login(0, self.ago(300))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": lambda: self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "SQL API": lambda: self.cfg(SNOWFLAKE_ACCOUNT_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, make in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaisesRegex(c.BridgeError, rf"answered with a redirect \(HTTP {code}\), which the bridge refuses"):
                            c.run_once(make())
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state) and self.saved().get(ACCOUNT, {}).get("cursor_ns"))
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
        for value in ("-1", "0", "100001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^SNOWFLAKE_PAGE_SIZE must be between 1 and 100,000$"):
                self.load(SNOWFLAKE_PAGE_SIZE=value)
        self.assertEqual(self.load(SNOWFLAKE_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(SNOWFLAKE_PAGE_SIZE="100000")["page_size"], 100000)

    def test_query_timeout_out_of_range_gives_its_range(self):
        for value in ("0", "-5", "3601"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^SNOWFLAKE_QUERY_TIMEOUT must be between 1 and 3,600$"):
                self.load(SNOWFLAKE_QUERY_TIMEOUT=value)
        self.assertEqual(self.load(SNOWFLAKE_QUERY_TIMEOUT="3600")["query_timeout"], 3600)

    def test_lookback_is_at_most_a_year(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 8,760$"):
            self.load(BRIDGE_LOOKBACK_HOURS="8761")
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be above 0$"):
            self.load(BRIDGE_LOOKBACK_HOURS="0")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="8760")["lookback_hours"], 8760.0)

    def test_delay_is_at_most_a_day(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_DELAY_SECONDS must be between 0 and 86,400$"):
            self.load(BRIDGE_DELAY_SECONDS="86401")
        self.assertEqual(self.load(BRIDGE_DELAY_SECONDS="0")["delay_seconds"], 0)


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

    def test_a_query_that_ran_too_long_keeps_polling_too(self):
        self.run_once_raises(c.NetworkError("the query didn't finish within 300 seconds, so it was cancelled; the next run "
                                            "tries the same window again"))
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
