"""Unit tests for kaseya_vsa95_bridge.py against a local mock server.

The mock serves the Data Warehouse API datasets the bridge reads, in the shape the Kaseya
Data Warehouse API reference (R95) gives: GET /api/odata/1.0/<dataset> with OData $filter,
$orderby, $top and $skip, an OData "value" array, and HTTP Basic with user name and user token.
It also serves a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/kaseya-vsa95-data-warehouse -p 'test_*.py' -v
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
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kaseya_vsa95_bridge as c  # noqa: E402

USER = "dwapi.reader"
TOKEN = "test-vsa95-user-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def rc_session(i, when):
    return {"AgentId": "118551706373495", "PartitionId": "1", "SessionId": f"3fa85f64-5717-4562-b3fc-{i:012d}",
            "SessionStartTime": ts(when), "RemoteControlAdministratorName": "tech.akim", "SessionLastActiveTime": ts(when),
            "SessionTypeDescription": "Kaseya Remote Control", "SessionStatus": "Ended", "Duration": "00:05:00",
            "SessionDate": ts(when), "SessionNotes": ""}


def change_event(i, when):
    return {"AgentId": "118551706373495", "PartitionId": "1", "EventId": 1000 + i, "ChangeEventDateTime": ts(when),
            "ChangeDescription": f"Example change {i}"}


class Mock:
    def __init__(self):
        self.data = {name: [] for name in c.DATASETS}
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.reject_unquoted = False


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

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        name = u.path.rsplit("/", 1)[-1]
        if not u.path.startswith("/api/odata/1.0/") or name not in m.data:
            return self._json({"error": "not found"}, 404)
        basic = base64.b64encode(f"{USER}:{TOKEN}".encode()).decode()
        if self.headers.get("Authorization") != f"Basic {basic}":
            return self._json({"error": "unauthorized"}, 401)
        if m.codes:
            return self._json({}, m.codes.pop(0))
        q = urllib.parse.parse_qs(u.query)
        field = c.DATASETS[name][0]
        mm = re.fullmatch(rf"{field} gt ('?)(\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}Z)\1", q["$filter"][0])
        if not mm or (m.reject_unquoted and not mm.group(1)):
            return self._json({"error": {"message": "invalid filter"}}, 400)
        after = c._parse_time(mm.group(2))
        assert q["$orderby"] == [f"{field} asc"]
        rows = sorted((r for r in m.data[name] if c._parse_time(r[field]) > after), key=lambda r: r[field])
        top, skip = int(q["$top"][0]), int(q.get("$skip", ["0"])[0])
        self._json({"@odata.context": f"https://vsa.example.com/api/odata/1.0/$metadata#{name}", "value": rows[skip:skip + top]})

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
        m.ingested.append({"headers": dict(self.headers), "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
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
    ("VSA95_PAGE_SIZE", "page_size", 1000, 100, int, 10 ** 9),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 300, 600, int, 10 ** 9),
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
             "VSA95_API_URL": f"{self.base}/api/odata/1.0", "VSA95_USERNAME": USER, "VSA95_USER_TOKEN": TOKEN,
             "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def add(self, maker, dataset, n, minutes_ago=120):
        now = datetime.now(timezone.utc)
        start = len(self.mock.data[dataset])
        self.mock.data[dataset].extend([maker(start + i, now - timedelta(minutes=minutes_ago) + timedelta(seconds=i)) for i in range(n)])

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def test_reads_each_dataset_and_tags_records(self):
        self.add(rc_session, "RemoteControlSessions", 3)
        self.add(change_event, "ConfigurationChangeEvents", 2)
        c.run_once(self.cfg())
        sent = self.sent()
        self.assertEqual([r["Dataset"] for r in sent], ["RemoteControlSessions"] * 3 + ["ConfigurationChangeEvents"] * 2)
        self.assertEqual(list(sent[0])[0], "Dataset")
        self.assertEqual({k: v for k, v in sent[0].items() if k != "Dataset"}, self.mock.data["RemoteControlSessions"][0])
        gets = [r for r in self.mock.requests if r[0] == "GET"]
        self.assertEqual(len(gets), len(c.DATASETS))

    def test_skip_paging(self):
        self.add(rc_session, "RemoteControlSessions", 25)
        c.run_once(self.cfg(VSA95_PAGE_SIZE="10", VSA95_DATASETS="RemoteControlSessions"))
        self.assertEqual(len(self.sent()), 25)
        skips = [urllib.parse.parse_qs(urllib.parse.urlsplit(r[1]).query)["$skip"][0] for r in self.mock.requests if r[0] == "GET"]
        self.assertEqual(skips, ["0", "10", "20"])

    def test_next_run_sends_only_new_records(self):
        self.add(change_event, "ConfigurationChangeEvents", 5, minutes_ago=3)
        cfg = self.cfg(VSA95_DATASETS="ConfigurationChangeEvents")
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.add(change_event, "ConfigurationChangeEvents", 1, minutes_ago=1)
        c.run_once(cfg)
        self.assertEqual([r["EventId"] for r in self.sent()], [1005])

    def test_quoted_times_option(self):
        self.add(rc_session, "RemoteControlSessions", 2)
        self.mock.reject_unquoted = True
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(VSA95_DATASETS="RemoteControlSessions"))
        c.run_once(self.cfg(VSA95_DATASETS="RemoteControlSessions", VSA95_QUOTE_TIMES="1"))
        self.assertEqual(len(self.sent()), 2)

    def test_dry_run_prints_and_changes_nothing(self):
        self.add(rc_session, "RemoteControlSessions", 4)
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 4)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_bad_token_stops(self):
        self.add(rc_session, "RemoteControlSessions", 2)
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(VSA95_USER_TOKEN="wrong-token-0000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.add(rc_session, "RemoteControlSessions", 4)
        self.mock.codes = [429, 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(VSA95_DATASETS="RemoteControlSessions"))
        self.assertEqual(len(self.sent()), 4)

    def test_ingest_failure_keeps_the_cursor(self):
        self.add(rc_session, "RemoteControlSessions", 4)
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_secrets_never_logged(self):
        self.add(rc_session, "RemoteControlSessions", 4)
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.logbuf.getvalue()
        self.assertIn("RemoteControlSessions", logged)
        basic = base64.b64encode(f"{USER}:{TOKEN}".encode()).decode()
        for secret in (TOKEN, basic, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_bad_values(self):
        base = {"VSA95_USERNAME": USER, "VSA95_USER_TOKEN": TOKEN}
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "VSA95_API_URL": "http://vsa.example.com/api/odata/1.0"})
        with self.assertRaises(c.BridgeError):
            c.load_config({**base, "VSA95_API_URL": "https://vsa.example.com/api/odata/1.0", "VSA95_DATASETS": "Agents"})
        with self.assertRaises(c.BridgeError):
            c.load_config({"VSA95_API_URL": "https://vsa.example.com/api/odata/1.0", "VSA95_USERNAME": USER})

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.add(rc_session, "RemoteControlSessions", 4)
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Data Warehouse API": self.cfg(VSA95_API_URL=f"{r.base}/api/odata/1.0")}
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

            def page(self, dataset, time_field, after, skip):
                self.asked.append(after)
                return self.rows if skip == 0 else []

        class Sink:
            def send(self, records):
                pass

        cfg, state = self.cfg(VSA95_DATASETS="ConfigurationChangeEvents"), {}
        future = {"AgentId": "1", "EventId": "e1", "ChangeEventDateTime": "2099-01-01T00:00:00Z"}
        c.collect(cfg, state, Sink(), lambda: None, Client([future]))
        self.assertLessEqual(c._parse_time(state["ConfigurationChangeEvents"]["since"]), datetime.now(timezone.utc))
        again = Client([future])
        self.assertEqual(c.collect(cfg, state, Sink(), lambda: None, again), 0)
        self.assertLess(again.asked[0], datetime.now(timezone.utc))

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


class TimeTest(unittest.TestCase):
    """Times with and without fractional seconds and offsets read the same on Python 3.9 to 3.13."""

    def test_fractions_and_offsets(self):
        at = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        ms, us = timedelta(milliseconds=123), timedelta(microseconds=123456)
        cases = {
            "2026-10-15T10:00:00Z": at,
            "2026-10-15T10:00:00": at,
            "2026-10-15T20:00:00+10:00": at,
            "2026-10-15T10:00:00.123Z": at + ms,
            "2026-10-15T10:00:00.123": at + ms,
            "2026-10-15T20:00:00.123+10:00": at + ms,
            "2026-10-15T05:30:00.123-04:30": at + ms,
            "2026-10-15T10:00:00.5+00:00": at + timedelta(milliseconds=500),
            "2026-10-15T10:00:00.1234567Z": at + us,
            "2026-10-15T20:00:00.1234567+10:00": at + us,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(c._parse_time(text), expected)


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
        self.cfg = c.load_config({"VSA95_API_URL": "https://vsa.example.com/api/odata/1.0", "VSA95_USERNAME": USER,
                                  "VSA95_USER_TOKEN": TOKEN})
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
