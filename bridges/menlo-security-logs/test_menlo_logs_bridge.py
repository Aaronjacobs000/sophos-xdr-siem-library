"""Unit tests for menlo_logs_bridge.py against a local mock server.

The mock serves the shapes in Menlo's own Microsoft Sentinel connector and the Cortex XSOAR Menlo
Security pack: POST /api/rep/v2/fetch/client_select with format, limit, start and end in the
query and {"token", "log_type", "pagingIdentifiers"} as the JSON body. It answers a list of
wrappers, {"timestamp", "result": {"events": [{"event": {...}}], "pagingIdentifiers":
{"next_time", "hashes", "last_iteration"}}}, oldest first, an empty answer when there is no data,
and {"reason": ...} on errors. Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is
called.

  python3 -m unittest discover -s bridges/menlo-security-logs -p 'test_*.py' -v
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
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import menlo_logs_bridge as c  # noqa: E402

TOKEN = "test-menlo-log-api-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def naive(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")


def event(i, when, log_type="web"):
    """An event in the shape of the XSOAR pack's web response and Menlo's connector schemas."""
    if log_type == "audit":
        return {"event_time": naive(when), "name": "admin_audit", "uid": "admin@example.com", "audit_actions": "policy_update",
                "sub_event_type": "web_policy", "details": json.dumps({"rule": f"rule {i}"}), "additional_info": "{}",
                "rev_id": str(1000 + i), "severity": "5", "version": "2.0", "product": "MSIP", "vendor": "Menlo Security"}
    return {"top_url": "http://example.com", "domain": "example.com", "protocol": "http", "risk_tally": "-1",
            "origin_ip": "198.51.100.8", "event_time": naive(when), "dst": "198.51.100.8", "name": "page_request",
            "url": f"http://example.com/page/{i}", "response_code": "200", "userid": "akim@example.com",
            "pe_action": "allow", "x-client-ip": "203.0.113.10", "tab_id": str(i), "severity": "5", "version": "2.0",
            "product": "MSIP", "vendor": "Menlo Security"}


class Mock:
    def __init__(self):
        self.events = {}           # log type -> events
        self.page_cap = 10000
        self.codes = []            # (status, body) answered before any page
        self.requests = []
        self.ingest_codes = []
        self.ingested = []
        self.last_in = "result"    # where last_iteration goes: "result", "paging", or "none"
        self.empty_when_none = True
        self.wrappers = 1          # how many wrappers an answer splits its events into
        self.stuck = False
        self.answer = None         # a JSON answer to send as it is, for shapes that aren't documented


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == c.FETCH_PATH:
            q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                req = json.loads(body)
            except ValueError:
                return self._send(400, {"reason": "Error parsing JSON request body for API token"})
            m.requests.append({"query": q, "body": req, "headers": dict(self.headers)})
            if req.get("token") != TOKEN:
                return self._send(401, {"reason": "Invalid Auth Token or unauthorized to fetch the logs"})
            if m.codes:
                code, answer = m.codes.pop(0)
                return self._send(code, answer)
            if m.answer is not None:
                return self._send(200, m.answer)
            lo, hi = int(q["start"]), int(q["end"])
            rows = sorted((e for e in m.events.get(req.get("log_type"), []) if lo <= c._parse_time(e["event_time"]) <= hi),
                          key=lambda e: e["event_time"])
            offset = ((req.get("pagingIdentifiers") or {}).get("hashes") or {}).get("offset", 0)
            if m.stuck:
                offset = 0
            limit = min(int(q.get("limit", "1000")), m.page_cap)
            page = rows[offset:offset + limit]
            if not page and m.empty_when_none:
                return self._send(200, None)
            last = offset + limit >= len(rows)
            paging = {"next_time": page[-1]["event_time"] + "Z" if page else "", "hashes": {"offset": 0 if m.stuck else offset + limit}}
            result = {"events": [{"event": e} for e in page], "pagingIdentifiers": paging}
            if m.last_in == "result":
                result["last_iteration"] = last
            elif m.last_in == "paging":
                paging["last_iteration"] = last
            elif last:
                del result["pagingIdentifiers"]
            n = max(1, m.wrappers)
            parts = [page[i::n] for i in range(n)] if n > 1 else [page]
            answer = [{"timestamp": "2026-10-21T00:00:00.000Z", "result": dict(result, events=[{"event": e} for e in part])} for part in parts]
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
    ("MENLO_PAGE_LIMIT", "page_limit", 1000, 500, int, 10000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 720),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 300, 600, int, 10 ** 9),
    ("BRIDGE_WINDOW_MINUTES", "window_minutes", 5, 15, int, 1440),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 120.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"MENLO_TOKEN": TOKEN}
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
                     MENLO_API_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})


    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("MENLO_API_URL", "NGSIEM_INGEST_URL"):
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

    def test_events_are_read_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.mock.events = {"web": [event(i, self.ago(50 - i)) for i in range(5)]}
        self.assertEqual(c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440")), 5)
        self.assertEqual([r["tab_id"] for r in self.sent()], ["0", "1", "2", "3", "4"])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"menlo_record":"web","top_url":"http://example.com"'))
        first = {k: v for k, v in self.sent()[0].items() if k != "menlo_record"}
        self.assertEqual(first, self.mock.events["web"][0])
        # Three pages: the first without pagingIdentifiers, then each sending back the last ones.
        reqs = self.mock.requests
        self.assertEqual(len(reqs), 3)
        self.assertNotIn("pagingIdentifiers", reqs[0]["body"])
        self.assertEqual([r["body"]["pagingIdentifiers"]["hashes"] for r in reqs[1:]], [{"offset": 2}, {"offset": 4}])
        self.assertEqual(reqs[0]["body"], {"token": TOKEN, "log_type": "web"})
        q = reqs[0]["query"]
        self.assertEqual((q["format"], q["limit"]), ("JSON", "1000"))
        self.assertEqual(int(q["end"]) - int(q["start"]), 86400 - 180 + 1)
        self.assertAlmostEqual(int(q["end"]), self.now.timestamp() - 180, delta=5)
        self.assertEqual({(r["query"]["start"], r["query"]["end"]) for r in reqs}, {(q["start"], q["end"])})
        headers = {k.lower(): v for k, v in reqs[0]["headers"].items()}
        self.assertEqual(headers["content-type"], "application/json")
        self.assertNotIn("authorization", headers)
        self.assertIn("until", self.saved()["logs"]["web"])

    def test_every_way_menlo_marks_the_last_page_ends_the_window(self):
        for last_in in ("result", "paging", "none"):
            with self.subTest(last_in=last_in):
                if os.path.exists(self.state):
                    os.remove(self.state)
                self.mock.requests.clear()
                self.mock.ingested.clear()
                self.mock.page_cap, self.mock.last_in = 2, last_in
                self.mock.events = {"web": [event(i, self.ago(10 - i)) for i in range(4)]}
                c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
                self.assertEqual(len(self.mock.requests), 2)
                self.assertEqual(len(self.sent()), 4)
        # A page with no events ends it too, and so does the empty answer Menlo gives for no data.
        for empty in (True, False):
            with self.subTest(empty_answer=empty):
                os.remove(self.state)
                self.mock.requests.clear()
                self.mock.events, self.mock.empty_when_none = {"web": []}, empty
                c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
                self.assertEqual(len(self.mock.requests), 1)
                self.assertIn("until", self.saved()["logs"]["web"])

    def test_events_from_every_wrapper_of_an_answer_are_read(self):
        self.mock.wrappers = 3
        self.mock.events = {"web": [event(i, self.ago(10 - i)) for i in range(7)]}
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertEqual(sorted(int(r["tab_id"]) for r in self.sent()), list(range(7)))

    def test_each_log_type_is_read_on_its_own(self):
        self.mock.events = {"web": [event(0, self.ago(7))], "audit": [event(1, self.ago(6), "audit"), event(2, self.ago(5), "audit")],
                            "email": [{"event_time": naive(self.ago(8)), "name": "url-rewrite", "domain": "example.com"}]}
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual([r["menlo_record"] for r in self.sent()], ["web", "audit", "audit"])
        self.assertEqual(sorted(self.saved()["logs"]), ["audit", "web"])
        self.mock.ingested.clear()
        c.run_once(self.cfg(MENLO_LOG_TYPES="email, AUDIT"))
        self.assertEqual([r["menlo_record"] for r in self.sent()], ["email"])

    def test_windows_of_the_window_setting_each_start_a_second_early_and_save_their_end(self):
        self.mock.events = {"web": [event(0, self.ago(50)), event(1, self.ago(25)), event(2, self.ago(5))]}
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_LOOKBACK_HOURS="1", BRIDGE_WINDOW_MINUTES="20"))
        reqs = [r["query"] for r in self.mock.requests]
        self.assertEqual(len(reqs), 3)
        for before, after in zip(reqs, reqs[1:]):
            self.assertEqual(int(after["start"]), int(before["end"]) - 1)
        self.assertEqual(int(reqs[1]["end"]) - int(reqs[1]["start"]), 1201)
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(self.saved()["logs"]["web"]["until"], int(reqs[-1]["end"]))

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.events = {"web": [event(i, self.ago(30 - i)) for i in range(3)]}
        cfg = self.cfg(MENLO_LOG_TYPES="web", BRIDGE_OVERLAP_SECONDS="1200", BRIDGE_WINDOW_MINUTES="1440")
        c.run_once(cfg)
        first_end = int(self.mock.requests[-1]["query"]["end"])
        self.assertEqual(self.saved()["logs"]["web"]["until"], first_end)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An event that Menlo listed late, inside the overlap, and a new one. The window ends three
        # minutes before now, so the new one is four minutes old.
        self.mock.events["web"] += [event(7, self.ago(15)), event(8, self.ago(4))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["tab_id"] for r in self.sent()), ["7", "8"])
        self.assertEqual(int(self.mock.requests[0]["query"]["start"]), first_end - 1200 - 1)

    def test_lookback_sets_the_first_window_and_never_more_than_30_days(self):
        self.mock.events = {"web": [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]}
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_LOOKBACK_HOURS="24", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertEqual([r["tab_id"] for r in self.sent()], ["1"])
        with open(self.state, "w") as fh:
            json.dump({"logs": {"web": {"until": self.now.timestamp() - 60 * 86400}}}, fh)
        self.mock.requests.clear()
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertGreaterEqual(int(self.mock.requests[0]["query"]["start"]), self.now.timestamp() - 30 * 86400 - 5)

    def test_window_end_moves_only_after_ingest_accepts_its_window(self):
        self.mock.events = {"web": [event(0, self.ago(100)), event(1, self.ago(30))]}
        self.mock.ingest_codes = [200, 400]
        cfg = self.cfg(MENLO_LOG_TYPES="web", BRIDGE_LOOKBACK_HOURS="2", BRIDGE_WINDOW_MINUTES="60")
        with self.assertRaises(c.BridgeError):
            c.run_once(cfg)
        reqs = [r["query"] for r in self.mock.requests]
        self.assertEqual(self.saved()["logs"]["web"]["until"], int(reqs[0]["end"]))
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual([r["tab_id"] for r in self.sent()], ["1"])

    def test_window_end_stays_before_now(self):
        self.mock.events = {"web": [event(0, self.ago(5))]}
        c.run_once(self.cfg(MENLO_LOG_TYPES="web"))
        self.assertLessEqual(self.saved()["logs"]["web"]["until"], datetime.now(timezone.utc).timestamp() - 179)
        with open(self.state, "w") as fh:
            json.dump({"logs": {"web": {"until": self.now.timestamp() + 7200}}}, fh)
        self.mock.requests.clear()
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_OVERLAP_SECONDS="240"))
        q = self.mock.requests[0]["query"]
        self.assertEqual(int(q["end"]) - int(q["start"]), 241)

    def test_repeats_are_known_by_the_hash_of_the_whole_event(self):
        e = event(0, self.ago(5))
        self.mock.events = {"web": [e, dict(e), dict(e, pe_action="block")]}
        c.run_once(self.cfg(MENLO_LOG_TYPES="web"))
        c.run_once(self.cfg(MENLO_LOG_TYPES="web"))
        self.assertEqual(sorted(r["pe_action"] for r in self.sent()), ["allow", "block"])

    def test_stuck_paging_or_an_odd_answer_stops_the_run(self):
        self.mock.page_cap = 2
        self.mock.events = {"web": [event(i, self.ago(10 - i)) for i in range(5)]}
        self.mock.stuck = True
        with self.assertRaisesRegex(c.BridgeError, "the same pagingIdentifiers twice"):
            c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertNotIn("until", self.saved()["logs"]["web"])
        self.mock.stuck = False
        for answer, words in (("text", "JSON that is not an object or a list"),
                              ([{"result": {"events": {"event": {}}}}], "events that are not a list")):
            with self.subTest(answer=answer):
                self.mock.answer = answer
                with self.assertRaisesRegex(c.BridgeError, words):
                    c.run_once(self.cfg(MENLO_LOG_TYPES="web"))
        # A single wrapper, not in a list, is read like a list of one.
        self.mock.answer = {"result": {"events": [{"event": event(9, self.ago(5))}], "last_iteration": True}}
        self.mock.ingested.clear()
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertEqual([r["tab_id"] for r in self.sent()], ["9"])

    def test_refused_token_and_requests_stop_with_clear_errors(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(MENLO_TOKEN="wrong-token-not-real"))
        self.assertEqual(str(cm.exception), "Menlo refused the web logs request (HTTP 401): Invalid Auth Token or unauthorized "
                         "to fetch the logs; check MENLO_TOKEN, and that the token has the Log Export API permission and can "
                         "read web logs")
        for code, body, words in ((403, {"reason": "Forbidden"}, "Menlo refused the web logs request (HTTP 403): Forbidden"),
                                  (400, {"reason": "Invalid log_type"}, "Menlo rejected the web logs request (HTTP 400): Invalid log_type"),
                                  (404, None, "with HTTP 404; check MENLO_API_URL"),
                                  (405, None, "with HTTP 405; check MENLO_API_URL")):
            with self.subTest(code=code):
                self.mock.codes = [(code, body)]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertNotIsInstance(cm.exception, c.NetworkError)
                self.assertIn(words, str(cm.exception))
        self.assertNotIn("web", self.saved().get("logs", {}) if os.path.exists(self.state) else {})

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = {"web": [event(i, self.ago(10 - i)) for i in range(2)], "audit": [event(5, self.ago(5), "audit")]}
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["menlo_record"] for x in lines], ["web", "web", "audit"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events = {"web": [event(i, self.ago(10 - i)) for i in range(3)]}
        self.mock.codes = [(429, {}), (500, {}), (503, {})]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.events = {"web": [event(i, self.ago(30 - i)) for i in range(8)]}
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_BATCH_BYTES="1000"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 8)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = {"web": [event(0, self.ago(5))]}
        self.mock.codes = [(503, {})]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg(MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"))
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(MENLO_TOKEN="another-wrong-token-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("web logs request", logged)
        for secret in (TOKEN, INGEST_KEY, "00000000-example-integration", "another-wrong-token-not-real"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(MENLO_TOKEN=None),
            base_env(MENLO_API_URL="http://logs.menlo.example"),
            base_env(MENLO_LOG_TYPES="web,audit logs"),
            base_env(MENLO_LOG_TYPES="web&limit=1"),
            base_env(MENLO_LOG_TYPES=","),
            base_env(MENLO_PAGE_LIMIT="0"),
            base_env(MENLO_PAGE_LIMIT="10001"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(BRIDGE_LOOKBACK_HOURS="721"),
            base_env(BRIDGE_WINDOW_MINUTES="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["api_url"], cfg["log_types"], cfg["page_limit"], cfg["window_minutes"], cfg["overlap_seconds"]),
                         ("https://logs.menlosecurity.com", ["web", "audit"], 1000, 5, 300))
        self.assertEqual(c.load_config(base_env(MENLO_LOG_TYPES="Web, dlp,web"))["log_types"], ["web", "dlp"])

    def test_times_with_and_without_fractions_and_zones(self):
        want = datetime(2026, 10, 21, 21, 2, 11, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-21T21:02:11.218000", want + 0.218), ("2026-10-21T21:02:11.218", want + 0.218),
                               ("2026-10-21T21:02:11", want), ("2026-10-21T21:02:11.218Z", want + 0.218)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("NA"))
        self.assertIsNone(c._parse_time(None))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the token or key to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.events = {"web": [event(0, self.ago(5))]}
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration",
                                             MENLO_LOG_TYPES="web", BRIDGE_WINDOW_MINUTES="1440"),
                     "Menlo": self.cfg(MENLO_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("logs", {}).get("web", {}))
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
        for value in ("-1", "0", "10001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^MENLO_PAGE_LIMIT must be between 1 and 10,000$"):
                self.load(MENLO_PAGE_LIMIT=value)
        self.assertEqual(self.load(MENLO_PAGE_LIMIT="10000")["page_limit"], 10000)

    def test_lookback_is_at_most_30_days(self):
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
