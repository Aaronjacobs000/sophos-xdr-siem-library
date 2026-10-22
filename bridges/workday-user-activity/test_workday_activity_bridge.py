"""Unit tests for workday_activity_bridge.py against a local mock server.

The mock serves the shapes in Workday's Privacy API reference: POST /ccx/oauth2/<tenant>/token
with the refresh_token grant and the API client in HTTP Basic, answering {"access_token",
"token_type", "refresh_token"} (and OAuth's {"error", "error_description"} when it refuses), and
GET /ccx/api/privacy/v1/<tenant>/activityLogging with the from, to, limit, offset and
instancesReturned query parameters, answering {"total": ..., "data": [...]} and
{"error", "errors": [...]} on errors. One query returns at most instancesReturned times
c.INSTANCES entries, which the tests lower so they need few entries. Plus a Sophos NG-SIEM HTTP
Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/workday-user-activity -p 'test_*.py' -v
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
import workday_activity_bridge as c  # noqa: E402

TENANT = "acme_test"
CLIENT_ID = "test-workday-client-id-not-real"
CLIENT_SECRET = "test-workday-client-secret-not-real"
REFRESH = "test-workday-refresh-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
TOKEN_PATH = f"/ccx/oauth2/{TENANT}/token"
ACTIVITY_PATH = f"/ccx/api/privacy/v1/{TENANT}/activityLogging"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def entry(i, when, action="READ"):
    """A user activity entry in the shape of the Privacy API reference's userActivityTracking."""
    return {"activityAction": action, "systemAccount": f"user{i}@example.com", "requestTime": iso(when),
            "taskDisplayName": "View Worker", "taskId": f"{i:032x}", "sessionId": f"{i:06x}",
            "target": {"descriptor": f"Worker {i}", "id": f"{i + 1:032x}"},
            "ipAddress": "203.0.113.10", "deviceType": "Desktop", "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}


class Mock:
    def __init__(self):
        self.entries = []
        self.codes = []           # (status, body) answered on activityLogging before any page
        self.token_codes = []     # (status, body) answered on the token endpoint
        self.requests = []
        self.token_requests = []
        self.ingest_codes = []
        self.ingested = []
        self.issued = 0
        self.valid = set()
        self.expires_in = 3600
        self.no_total = False


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        if url.path != ACTIVITY_PATH:
            return self._send(404, {"error": "Resource not found"})
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        m.requests.append({"query": q, "headers": dict(self.headers)})
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] not in m.valid:
            return self._send(401, {"error": "invalid access token", "errors": [{"error": "Unauthorized"}]})
        if m.codes:
            code, body = m.codes.pop(0)
            return self._send(code, body)
        lo, hi = c._parse_time(q["from"]), c._parse_time(q["to"])
        rows = sorted((e for e in m.entries if lo <= c._parse_time(e["requestTime"]) <= hi), key=lambda e: e["requestTime"])
        cap = int(q.get("instancesReturned", "25")) * c.INSTANCES
        offset, limit = int(q.get("offset", "0")), int(q.get("limit", "20"))
        page = rows[:cap][offset:offset + limit]
        answer = {"data": page} if m.no_total else {"total": len(rows), "data": page}
        return self._send(200, answer)

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == TOKEN_PATH:
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
            m.token_requests.append({"form": form, "headers": dict(self.headers)})
            if m.token_codes:
                code, answer = m.token_codes.pop(0)
                return self._send(code, answer)
            basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            if self.headers.get("Authorization") != f"Basic {basic}":
                return self._send(401, {"error": "invalid_client"})
            if form.get("grant_type") != "refresh_token" or form.get("refresh_token") != REFRESH:
                return self._send(400, {"error": "invalid_grant", "error_description": "Invalid refresh token"})
            m.issued += 1
            token = f"access-{m.issued}"
            m.valid.add(token)
            answer = {"access_token": token, "token_type": "Bearer", "refresh_token": REFRESH}
            if m.expires_in is not None:
                answer["expires_in"] = m.expires_in
            return self._send(200, answer)
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
    ("WORKDAY_PAGE_LIMIT", "page_limit", 1000, 500, int, 1000),
    ("WORKDAY_INSTANCES_RETURNED", "instances", 1, 5, int, 25),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 720),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_WINDOW_MINUTES", "window_minutes", 60, 15, int, 1440),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 180.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"WORKDAY_HOST_URL": "https://wd2-impl-services1.workday.example", "WORKDAY_TENANT": TENANT,
         "WORKDAY_CLIENT_ID": CLIENT_ID, "WORKDAY_CLIENT_SECRET": CLIENT_SECRET, "WORKDAY_REFRESH_TOKEN": REFRESH}
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
        # The cap tests lower it further, so they need few entries.
        self._instances = c.INSTANCES
        c.INSTANCES = 100

    def tearDown(self):
        c.INSTANCES = self._instances
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
                     WORKDAY_HOST_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})


    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("WORKDAY_HOST_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_entries_are_read_tagged_and_paged(self):
        self.mock.entries = [entry(i, self.ago(50 - i)) for i in range(4)] + [entry(9, self.ago(5), "WRITE")]
        self.assertEqual(c.run_once(self.cfg(WORKDAY_PAGE_LIMIT="2", BRIDGE_WINDOW_MINUTES="1440")), 5)
        self.assertEqual([r["sessionId"] for r in self.sent()], [e["sessionId"] for e in self.mock.entries])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(
            '{"workday_record":"user_activity","workday_tenant":"acme_test","activityAction":"READ"'))
        first = {k: v for k, v in self.sent()[0].items() if k not in ("workday_record", "workday_tenant")}
        self.assertEqual(first, self.mock.entries[0])
        # Three pages of 2, by offset, with the same window, until offset reaches total.
        reqs = self.mock.requests
        self.assertEqual([r["query"]["offset"] for r in reqs], ["0", "2", "4"])
        q = reqs[0]["query"]
        self.assertEqual((q["limit"], q["instancesReturned"]), ("2", "1"))
        self.assertRegex(q["from"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertRegex(q["to"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertAlmostEqual(c._parse_time(q["to"]) - c._parse_time(q["from"]), 86400 - 180 + 1, delta=5)
        self.assertAlmostEqual(c._parse_time(q["to"]), self.now.timestamp() - 180, delta=5)
        self.assertEqual({(r["query"]["from"], r["query"]["to"]) for r in reqs}, {(q["from"], q["to"])})
        headers = {k.lower(): v for k, v in reqs[0]["headers"].items()}
        self.assertEqual(headers["authorization"], "Bearer access-1")
        self.assertEqual(headers["accept"], "application/json")
        # One token for the whole run, from the refresh token grant with the client in HTTP Basic.
        self.assertEqual(len(self.mock.token_requests), 1)
        token = self.mock.token_requests[0]
        self.assertEqual(token["form"], {"grant_type": "refresh_token", "refresh_token": REFRESH})
        self.assertEqual(token["headers"]["Authorization"], "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode())
        self.assertEqual(token["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertIn("until", self.saved()["activity"])

    def test_windows_of_the_window_setting_each_start_a_second_early_and_save_their_end(self):
        self.mock.entries = [entry(0, self.ago(150)), entry(1, self.ago(100)), entry(2, self.ago(30))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="3", BRIDGE_WINDOW_MINUTES="60"))
        reqs = [r["query"] for r in self.mock.requests]
        self.assertEqual(len(reqs), 3)
        for before, after in zip(reqs, reqs[1:]):
            self.assertEqual(c._parse_time(after["from"]), c._parse_time(before["to"]) - 1)
        self.assertEqual(c._parse_time(reqs[1]["to"]) - c._parse_time(reqs[1]["from"]), 3601)
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.saved()["activity"]["until"], c._parse_time(reqs[-1]["to"]))

    def test_a_short_page_is_not_the_end_but_total_or_an_empty_page_is(self):
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(3)]
        c.run_once(self.cfg(WORKDAY_PAGE_LIMIT="3", BRIDGE_WINDOW_MINUTES="1440"))
        # Three entries fill a page of 3 and reach total, so there is no second request.
        self.assertEqual(len(self.mock.requests), 1)
        # Without total, the bridge reads until a page comes back empty.
        os.remove(self.state)
        self.mock.requests.clear()
        self.mock.no_total = True
        c.run_once(self.cfg(WORKDAY_PAGE_LIMIT="2", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertEqual([r["query"]["offset"] for r in self.mock.requests], ["0", "2", "3"])

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.entries = [entry(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200")
        c.run_once(cfg)
        first_end = c._parse_time(self.mock.requests[-1]["query"]["to"])
        self.assertEqual(self.saved()["activity"]["until"], first_end)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An entry that Workday wrote late, inside the overlap, and a new one. The window ends
        # three minutes before now, so the new one is four minutes old.
        self.mock.entries += [entry(7, self.ago(15), "DOWNLOAD"), entry(8, self.ago(4))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["sessionId"] for r in self.sent()), [entry(7, self.now)["sessionId"], entry(8, self.now)["sessionId"]])
        self.assertEqual(c._parse_time(self.mock.requests[0]["query"]["from"]), first_end - 1200 - 1)

    def test_lookback_sets_the_first_window(self):
        self.mock.entries = [entry(0, self.now - timedelta(days=3)), entry(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["sessionId"] for r in self.sent()], [entry(1, self.now)["sessionId"]])

    def test_window_never_starts_before_the_30_days_workday_keeps(self):
        with open(self.state, "w") as fh:
            json.dump({"activity": {"until": self.now.timestamp() - 60 * 86400}}, fh)
        c.run_once(self.cfg(BRIDGE_WINDOW_MINUTES="1440"))
        start = c._parse_time(self.mock.requests[0]["query"]["from"])
        self.assertGreaterEqual(start, self.now.timestamp() - 30 * 86400 - 5)

    def test_window_end_moves_only_after_ingest_accepts_its_window(self):
        self.mock.entries = [entry(0, self.ago(100)), entry(1, self.ago(30))]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="2", BRIDGE_WINDOW_MINUTES="60"))
        reqs = [r["query"] for r in self.mock.requests]
        self.assertEqual(self.saved()["activity"]["until"], c._parse_time(reqs[0]["to"]))
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="2", BRIDGE_WINDOW_MINUTES="60"))
        self.assertEqual([r["sessionId"] for r in self.sent()], [self.mock.entries[1]["sessionId"]])

    def test_window_end_stays_before_now(self):
        self.mock.entries = [entry(0, self.ago(5))]
        c.run_once(self.cfg())
        self.assertLessEqual(self.saved()["activity"]["until"], datetime.now(timezone.utc).timestamp() - 179)
        with open(self.state, "w") as fh:
            json.dump({"activity": {"until": self.now.timestamp() + 7200}}, fh)
        self.mock.requests.clear()
        c.run_once(self.cfg(BRIDGE_OVERLAP_SECONDS="600"))
        q = self.mock.requests[0]["query"]
        self.assertEqual(c._parse_time(q["to"]) - c._parse_time(q["from"]), 601)

    # The cap tests run collect with a fixed now on a whole minute, so where the windows start, and
    # which window each entry falls in, never depends on the clock. With run_once, entries a few
    # milliseconds apart could straddle a window's end and arrive in two windows.
    NOW = 1792620000.0  # 2026-10-21T22:00:00Z

    def collect_at_now(self, **extra):
        cfg = self.cfg(**extra)
        sink = c.Sink(cfg, False)
        return c.collect(cfg, {}, sink, lambda: None, c.Workday(cfg), self.NOW)

    def at(self, seconds_before):
        return datetime.fromtimestamp(self.NOW - seconds_before, timezone.utc)

    def test_a_window_that_reaches_the_cap_is_read_in_halves(self):
        # One query returns at most instancesReturned times INSTANCES (5 here) entries. The 12
        # entries, 4 minutes apart, sit in the hour from 2 hours to 1 hour before NOW.
        c.INSTANCES = 5
        self.mock.entries = [entry(i, self.at(7200 - 300 - 240 * i)) for i in range(12)]
        self.assertEqual(self.collect_at_now(BRIDGE_LOOKBACK_HOURS="3", BRIDGE_WINDOW_MINUTES="60"), 12)
        self.assertEqual(sorted(r["sessionId"] for r in self.sent()), sorted(e["sessionId"] for e in self.mock.entries))
        self.assertEqual(len(self.sent()), 12)
        self.assertIn("reading it in halves", self.logbuf.getvalue())
        self.assertEqual({r["query"]["instancesReturned"] for r in self.mock.requests}, {"1"})

    def test_a_shortest_window_that_reaches_the_cap_uses_the_most_instances(self):
        # The entries are a few milliseconds apart, 20 seconds into the one-minute window that
        # starts 10 minutes before NOW, so they all fall in that window and no other.
        c.INSTANCES = 5
        when = self.at(600 - 20)
        self.mock.entries = [entry(i, when + timedelta(milliseconds=i)) for i in range(7)]
        self.assertEqual(self.collect_at_now(BRIDGE_LOOKBACK_HOURS="1", BRIDGE_WINDOW_MINUTES="1"), 7)
        self.assertEqual(len(self.sent()), 7)
        self.assertIn("25", {r["query"]["instancesReturned"] for r in self.mock.requests})
        # At 25 already, the most one query returns is all there is: the rest is logged as lost.
        self.mock.requests.clear()
        self.mock.ingested.clear()
        self.mock.entries = [entry(i, when + timedelta(milliseconds=i)) for i in range(130)]
        self.assertEqual(self.collect_at_now(BRIDGE_LOOKBACK_HOURS="1", BRIDGE_WINDOW_MINUTES="1",
                                             WORKDAY_INSTANCES_RETURNED="25"), 125)
        self.assertEqual(len(self.sent()), 125)
        self.assertIn("matched 130 entries, and Workday returns at most 125", self.logbuf.getvalue())

    def test_repeats_are_known_by_the_hash_of_the_whole_entry(self):
        e = entry(0, self.ago(5))
        twin = dict(e, activityAction="WRITE")
        self.mock.entries = [e, dict(e), twin]
        c.run_once(self.cfg())
        c.run_once(self.cfg())
        self.assertEqual(sorted(r["activityAction"] for r in self.sent()), ["READ", "WRITE"])

    def test_token_is_renewed_before_it_expires_and_once_when_refused(self):
        self.mock.entries = [entry(0, self.ago(5))]
        client = c.Workday(self.cfg())
        clock = [1000.0]
        saved, c.time.monotonic = c.time.monotonic, lambda: clock[0]
        try:
            self.assertEqual(client.token(), "access-1")
            clock[0] += 3600 - 61
            self.assertEqual(client.token(), "access-1")
            clock[0] += 2
            self.assertEqual(client.token(), "access-2")
            # Without expires_in, or with -1, a token counts as an hour.
            for value in (None, -1):
                self.mock.expires_in = value
                first = client.token(renew=True)
                clock[0] += 3500
                self.assertEqual(client.token(), first)
                clock[0] += 100
                self.assertNotEqual(client.token(), first)
        finally:
            c.time.monotonic = saved
        # A token Workday refuses is renewed once, then the request goes through.
        client.token(renew=True)
        self.mock.valid.clear()
        self.mock.requests.clear()
        self.assertEqual(client.activity({"from": c._wd_time(self.now.timestamp() - 600), "to": c._wd_time(self.now.timestamp())})["total"], 1)
        self.assertEqual(len(self.mock.requests), 2)
        self.assertIn("getting a new one", self.logbuf.getvalue())

    def test_a_token_refused_twice_stops_the_run(self):
        self.mock.codes = [(401, {"error": "invalid access token"})]
        saved = c.Workday._new_token

        def stale(client):
            saved(client)
            self.mock.valid.clear()
            return "stale"
        c.Workday._new_token = stale
        try:
            with self.assertRaisesRegex(c.BridgeError, r"Workday refused the access token \(HTTP 401\)"):
                c.run_once(self.cfg())
        finally:
            c.Workday._new_token = saved

    def test_refused_credentials_and_permissions_stop_with_clear_errors(self):
        for code, body, words in ((400, {"error": "invalid_grant", "error_description": "Invalid refresh token"}, "Invalid refresh token"),
                                  (400, {"error": "invalid_request"}, "invalid_request"),
                                  (401, {"error": "invalid_client"}, "invalid_client")):
            with self.subTest(code=code, body=body):
                self.mock.token_codes = [(code, body)]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertNotIsInstance(cm.exception, c.NetworkError)
                self.assertIn(f"Workday refused the token request (HTTP {code}): {words}", str(cm.exception))
                self.assertIn("WORKDAY_REFRESH_TOKEN", str(cm.exception))
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 401\): invalid_client"):
            c.run_once(self.cfg(WORKDAY_CLIENT_SECRET="wrong-secret-not-real"))
        for code, body, words in ((403, {"error": "Insufficient permissions", "errors": [{"error": "No access to System Auditing"}]},
                                   "Insufficient permissions: No access to System Auditing; the API client needs the System scope"),
                                  (404, {"error": "Resource not found"}, "Resource not found; check WORKDAY_HOST_URL (the services host) and WORKDAY_TENANT"),
                                  (400, {"error": "Invalid request", "errors": [{"error": "limit must be at most 100", "field": "limit"}]},
                                   "Invalid request: limit must be at most 100; the reference gives 100")):
            with self.subTest(code=code):
                self.mock.codes = [(code, body)]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertNotIsInstance(cm.exception, c.NetworkError)
                self.assertIn(f"(HTTP {code}): {words}", str(cm.exception))
        self.assertNotIn("until", self.saved().get("activity", {}) if os.path.exists(self.state) else {})

    def test_an_answer_that_is_not_the_documented_shape_stops_the_run(self):
        for answer, words in (([], "JSON that is not an object"), ({"total": 1, "data": {"a": 1}}, "data that is not a list")):
            with self.subTest(answer=answer):
                self.mock.codes = [(200, answer)]
                with self.assertRaisesRegex(c.BridgeError, words):
                    c.run_once(self.cfg())
        self.mock.token_codes = [(200, {"token_type": "Bearer"})]
        with self.assertRaisesRegex(c.BridgeError, "token request returned no access_token"):
            c.run_once(self.cfg())

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([(x["workday_record"], x["workday_tenant"]) for x in lines], [("user_activity", TENANT)] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [(429, {"error": "Too many requests"}), (500, {}), (503, {})]
        self.mock.token_codes = [(503, {})]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.entries = [entry(i, self.ago(30 - i)) for i in range(4)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1000"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 4)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.entries = [entry(0, self.ago(5))]
        self.mock.codes = [(503, {})]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        self.mock.valid.clear()
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(WORKDAY_REFRESH_TOKEN="another-refresh-token-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("token request", logged)
        for secret in (CLIENT_ID, CLIENT_SECRET, REFRESH, INGEST_KEY, "access-1", "00000000-example-integration",
                       "another-refresh-token-not-real", base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [base_env(**{name: None}) for name in ("WORKDAY_HOST_URL", "WORKDAY_TENANT", "WORKDAY_CLIENT_ID",
                                                       "WORKDAY_CLIENT_SECRET", "WORKDAY_REFRESH_TOKEN")]
        cases += [
            base_env(WORKDAY_HOST_URL="http://wd2-impl-services1.workday.example"),
            base_env(WORKDAY_HOST_URL="https://wd2-impl-services1.workday.example/ccx/api/v1/acme_test"),
            base_env(WORKDAY_HOST_URL="https://wd2-impl-services1.workday.example?x=1"),
            base_env(WORKDAY_TENANT="acme/../other"),
            base_env(WORKDAY_TENANT="acme test"),
            base_env(WORKDAY_PAGE_LIMIT="0"),
            base_env(WORKDAY_PAGE_LIMIT="1001"),
            base_env(WORKDAY_INSTANCES_RETURNED="0"),
            base_env(WORKDAY_INSTANCES_RETURNED="26"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(BRIDGE_LOOKBACK_HOURS="721"),
            base_env(BRIDGE_WINDOW_MINUTES="0"),
            base_env(BRIDGE_WINDOW_MINUTES="1441"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        with self.assertRaisesRegex(c.BridgeError, "^WORKDAY_CLIENT_SECRET, WORKDAY_REFRESH_TOKEN are required"):
            c.load_config(base_env(WORKDAY_CLIENT_SECRET="", WORKDAY_REFRESH_TOKEN=" "))
        cfg = c.load_config(base_env(WORKDAY_HOST_URL="https://wd2-impl-services1.workday.example/"))
        self.assertEqual(cfg["token_url"], f"https://wd2-impl-services1.workday.example/ccx/oauth2/{TENANT}/token")
        self.assertEqual(cfg["activity_url"], f"https://wd2-impl-services1.workday.example/ccx/api/privacy/v1/{TENANT}/activityLogging")
        self.assertEqual((cfg["page_limit"], cfg["instances"], cfg["window_minutes"], cfg["lookback_hours"]), (1000, 1, 60, 24.0))

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2026, 10, 3, 7, 0, 0, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-03T07:00:00.000Z", want), ("2026-10-03T07:00:00Z", want),
                               ("2026-10-03T07:00:00.655Z", want + 0.655), ("2026-10-03T06:00:00-01:00", want),
                               ("2026-10-03T07:00:00", want)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))
        self.assertIsNone(c._parse_time(None))
        self.assertEqual(c._wd_time(want + 0.9), "2026-10-03T07:00:00Z")

    def test_total_reads_numbers_and_ignores_the_rest(self):
        for value, expected in ((5, 5), ("7", 7), (" 8 ", 8), (None, None), (True, None), ("many", None), (2.5, None)):
            with self.subTest(value=value):
                self.assertEqual(c._total({"total": value}), expected)

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the token or key to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.entries = [entry(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration",
                                             BRIDGE_WINDOW_MINUTES="1440"),
                     "Workday": self.cfg(WORKDAY_HOST_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("activity", {}))
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

    def test_page_limit_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "1001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^WORKDAY_PAGE_LIMIT must be between 1 and 1,000$"):
                self.load(WORKDAY_PAGE_LIMIT=value)
        self.assertEqual(self.load(WORKDAY_PAGE_LIMIT="100")["page_limit"], 100)

    def test_lookback_is_at_most_the_30_days_workday_keeps(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 720$"):
            self.load(BRIDGE_LOOKBACK_HOURS="721")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="720")["lookback_hours"], 720.0)


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
