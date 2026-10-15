"""Unit tests for ondmarc_bridge.py against a local mock server.

The mock serves the OnDMARC API v2 shapes from Red Sift's public OpenAPI specification
(https://docs.redsift.com/ondmarc.yaml): GET /dmarc-guardian, /dns-history and /domains/flat
({"data": [...], "pagination": {"page_size", "page", "page_count", "count"}}, pages from 0) and
GET /reports/aggregate/analyst ({"mode": "flat", "data": [...], "rowCount"}, 402 without the DMARC
Analyst feature), with "Authorization: Api-Key", plus a Sophos NG-SIEM HTTP Ingest endpoint.
No real service is called.

  python3 -m unittest discover -s bridges/red-sift-ondmarc -p 'test_*.py' -v
"""
import contextlib
import gc
import gzip
import io
import json
import logging
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ondmarc_bridge as c  # noqa: E402

API_KEY = "test-ondmarc-api-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
PREFIX = "/api/ondmarc/v2"


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def issue(i, updated, severity="high"):
    return {"issue": {"issueId": 4000 + i, "issueType": "dangling-cname", "definitionId": "dangling-cname-v2",
                      "subjectDomain": f"app{i}.example.com", "causeDomain": f"host{i}.example.net",
                      "title": "Dangling CNAME", "severity": severity, "createdOn": iso(updated), "lastUpdated": iso(updated),
                      "details": {"@type": "dangling", "status": "NXDOMAIN", "rrType": "CNAME"},
                      "affectedRecord": {"name": f"app{i}.example.com", "type": "CNAME", "value": f"host{i}.example.net"}},
            "dns": {"a": [], "aaaa": [], "mx": [], "spf": [], "dmarc": "", "hasPublicIp": False},
            "notes": "", "relatedTo": "example.com", "imageUrl": "https://images.example.com/shot.png?sig=abc",
            "emails": {"list": [{"domain": "example.com", "score": 5}], "badReputationCount": 1, "avgReputationCount": 2},
            "domain": "example.com"}


def change(i, observed):
    return {"id": f"dh-{i:05d}", "domain": "example.com", "observedAt": iso(observed), "protocol": "dmarc", "recordType": "TXT",
            "value": "v=DMARC1; p=none", "previousValue": "v=DMARC1; p=reject", "changeTypes": ["policy_downgrade"],
            "severity": "high", "diff": "p=reject changed to p=none",
            "diffSegments": [{"value": "p=none", "added": True, "removed": False, "count": 1}]}


def agg_row(domain, day, ip):
    return {"report_id": f"rpt-{day}-{ip}", "receiver": "Example Receiver", "source": "unknown", "source_display_name": "Unknown",
            "source_ip": ip, "email_volume": 3, "disposition": "reject", "dkim_result": "fail", "spf_result": "fail",
            "dmarc_result": "fail", "header_from": domain, "date": day, "classification": "unknown"}


class Mock:
    def __init__(self):
        self.issues = []
        self.changes = []
        self.domains = ["example.com", "example.org"]
        self.agg = {}             # (domain, day) -> rows
        self.analyst_enabled = True
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.page_size_cap = 2    # small pages so paging is exercised


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _page(self, rows, q):
        size = min(int(q.get("page_size", ["100"])[0]), self.mock.page_size_cap)
        page = int(q.get("page", ["0"])[0])
        count = len(rows)
        pages = max(1, -(-count // size)) if count else 0
        return {"data": rows[page * size:(page + 1) * size], "pagination": {"page_size": size, "page": page, "page_count": pages, "count": count}}

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not u.path.startswith(PREFIX):
            return self._json({"message": "not found"}, 404)
        if self.headers.get("Authorization") != f"Api-Key {API_KEY}":
            return self._json({"message": "Unauthorized"}, 401)
        if m.codes:
            return self._json({"message": "busy"}, m.codes.pop(0))
        path = u.path[len(PREFIX):]
        if path == "/dmarc-guardian":
            return self._json(self._page(m.issues, q))
        if path == "/dns-history":
            assert q["sort"] == ["observedAt::asc"]
            start = q["from_date"][0]
            rows = sorted((r for r in m.changes if r["observedAt"][:10] >= start), key=lambda r: r["observedAt"])
            return self._json({**self._page(rows, q), "lastChecked": 0})
        if path == "/domains/flat":
            return self._json(self._page(m.domains, q))
        if path == "/reports/aggregate/analyst":
            if not m.analyst_enabled:
                return self._json({"message": "DMARC Analyst is not enabled"}, 402)
            assert q["from_date"] == q["to_date"]
            pm = json.loads(q["pagination_model"][0])
            rows = m.agg.get((q["domain"][0], q["from_date"][0]), [])
            size = min(pm["pageSize"], m.page_size_cap)
            return self._json({"mode": "flat", "data": rows[pm["page"] * size:(pm["page"] + 1) * size], "rowCount": len(rows)})
        return self._json({"message": "not found"}, 404)

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
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


# Every numeric setting: its name, config key, default, a normal value, type, and highest value.
NUMBERS = [
    ("ONDMARC_AGGREGATE_LOOKBACK_DAYS", "aggregate_lookback_days", 7, 14, int, 36500),
    ("ONDMARC_AGGREGATE_SETTLE_DAYS", "aggregate_settle_days", 2, 3, int, 36500),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 3600, 600, int, 10 ** 9),
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
             "ONDMARC_API_URL": f"{self.base}{PREFIX}", "ONDMARC_API_KEY": API_KEY, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_guardian_issues_are_tagged_and_trimmed(self):
        self.mock.issues = [issue(i, self.now - timedelta(hours=1)) for i in range(5)]
        c.run_once(self.cfg(ONDMARC_SOURCES="guardian"))
        sent = self.sent()
        self.assertEqual(len(sent), 5)
        self.assertTrue(all(r["ondmarc_record"] == "dmarc_guardian_issue" for r in sent))
        self.assertNotIn("imageUrl", sent[0])
        self.assertNotIn("list", sent[0]["emails"])
        self.assertEqual(sent[0]["issue"], self.mock.issues[0]["issue"])
        # The record key comes first, which the library parser's confirm string expects.
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"ondmarc_record":"dmarc_guardian_issue"'))

    def test_guardian_resends_only_updated_issues(self):
        self.mock.issues = [issue(i, self.now - timedelta(hours=1)) for i in range(3)]
        cfg = self.cfg(ONDMARC_SOURCES="guardian")
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.mock.issues[1] = issue(1, self.now, severity="critical")
        c.run_once(cfg)
        self.assertEqual([r["issue"]["issueId"] for r in self.sent()], [4001])

    def test_dns_history_pages_oldest_first_then_only_new(self):
        self.mock.changes = [change(i, self.now - timedelta(hours=5) + timedelta(minutes=i)) for i in range(5)]
        cfg = self.cfg(ONDMARC_SOURCES="dns_history")
        c.run_once(cfg)
        sent = self.sent()
        self.assertEqual([r["id"] for r in sent], [f"dh-{i:05d}" for i in range(5)])
        self.assertTrue(all("diffSegments" not in r and r["ondmarc_record"] == "dns_history" for r in sent))
        self.mock.ingested.clear()
        self.mock.changes.append(change(5, self.now - timedelta(minutes=1)))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], ["dh-00005"])

    def test_dns_history_lookback_limits_the_first_run(self):
        self.mock.changes = [change(0, self.now - timedelta(days=3)), change(1, self.now - timedelta(hours=2))]
        c.run_once(self.cfg(ONDMARC_SOURCES="dns_history"))
        self.assertEqual([r["id"] for r in self.sent()], ["dh-00001"])

    def test_aggregate_is_off_by_default(self):
        c.run_once(self.cfg())
        self.assertFalse(any("/reports/aggregate" in r[1] for r in self.mock.requests))

    def test_aggregate_reads_each_settled_day_once_per_domain(self):
        settle = 2
        days = [(self.now.date() - timedelta(days=d)).isoformat() for d in range(settle, settle + 3)]
        for dom in self.mock.domains:
            for day in days:
                self.mock.agg[(dom, day)] = [agg_row(dom, day, f"203.0.113.{n}") for n in range(3)]
        cfg = self.cfg(ONDMARC_SOURCES="aggregate", ONDMARC_AGGREGATE_LOOKBACK_DAYS="3", ONDMARC_AGGREGATE_SETTLE_DAYS=str(settle))
        c.run_once(cfg)
        sent = self.sent()
        self.assertEqual(len(sent), 2 * 3 * 3)
        self.assertTrue(all(r["ondmarc_record"] == "aggregate_record" and r["ondmarc_domain"] == r["header_from"] for r in sent))
        self.assertEqual(sorted({r["date"] for r in sent}), sorted(days))
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])

    def test_aggregate_without_the_feature_stops_with_a_clear_error(self):
        self.mock.analyst_enabled = False
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(ONDMARC_SOURCES="aggregate", ONDMARC_AGGREGATE_DOMAINS="example.com"))
        self.assertIn("402", str(cm.exception))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.issues = [issue(i, self.now) for i in range(2)]
        self.mock.changes = [change(0, self.now - timedelta(minutes=5))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_bad_key_stops(self):
        self.mock.issues = [issue(0, self.now)]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(ONDMARC_API_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.issues = [issue(i, self.now) for i in range(3)]
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(ONDMARC_SOURCES="guardian"))
        self.assertEqual(len(self.sent()), 3)

    def test_ingest_failure_keeps_the_cursor(self):
        self.mock.issues = [issue(0, self.now)]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_gzip_batches_and_headers(self):
        self.mock.changes = [change(i, self.now - timedelta(hours=2) + timedelta(seconds=i)) for i in range(20)]
        c.run_once(self.cfg(ONDMARC_SOURCES="dns_history", BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.issues = [issue(0, self.now)]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.logbuf.getvalue()
        self.assertIn("DMARC Guardian", logged)
        for secret in (API_KEY, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_unknown_sources_and_missing_key(self):
        with self.assertRaises(c.BridgeError):
            c.load_config({"ONDMARC_API_URL": "http://ondmarc.example.com/api/ondmarc/v2", "ONDMARC_API_KEY": API_KEY})
        with self.assertRaises(c.BridgeError):
            c.load_config({"ONDMARC_API_KEY": API_KEY, "ONDMARC_SOURCES": "guardian,forensic"})
        with self.assertRaises(c.BridgeError):
            c.load_config({})

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.issues = [issue(0, self.now)]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "OnDMARC API": self.cfg(ONDMARC_API_URL=f"{r.base}{PREFIX}")}
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

    def test_a_record_dated_in_the_future_leaves_the_cursor_at_now(self):
        # A wrong clock can date a record years ahead. The cursor stays at the run's time, so the
        # next run still asks for everything after it.
        class Client:
            def __init__(self, rows):
                self.rows, self.asked = rows, []

            def paged(self, path, params, what):
                self.asked.append(params["from_date"])
                return self.rows

        class Sink:
            def send(self, records):
                pass

        cfg, state = self.cfg(), {}
        future = {"id": "d1", "observedAt": "2099-01-01T00:00:00Z"}
        c.collect_dns_history(cfg, state, Sink(), lambda: None, Client([future]))
        self.assertLessEqual(c._parse_time(state["dns_history"]["since"]), datetime.now(timezone.utc))
        again = Client([future])
        self.assertEqual(c.collect_dns_history(cfg, state, Sink(), lambda: None, again), 0)
        self.assertLessEqual(again.asked[0], datetime.now(timezone.utc).date().isoformat())

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


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config({"ONDMARC_API_KEY": API_KEY})
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

    def test_negative_interval_is_refused(self):
        self.run_once_raises()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            c.main(["--interval", "-1"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
