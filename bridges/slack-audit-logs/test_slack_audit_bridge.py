"""Unit tests for slack_audit_bridge.py against a local mock server.

The mock serves the shapes in Slack's Audit Logs API reference: GET /audit/v1/logs with the user
token in Authorization: Bearer, and the oldest, latest (both inclusive), limit, action and cursor
query parameters. It answers {"ok": true, "entries": [...], "response_metadata": {"next_cursor":
...}} with the newest entries first, an empty next_cursor on the last page, and {"ok": false,
"error": ...} with Slack's error codes. Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service
is called.

  python3 -m unittest discover -s bridges/slack-audit-logs -p 'test_*.py' -v
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
import time
import unittest
import urllib.parse
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import slack_audit_bridge as c  # noqa: E402

TOKEN = "test-slack-user-token-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def entry(i, when, action="user_login"):
    """An audit log entry in the shape of the Audit Logs API reference's examples."""
    user = {"id": f"W0TEST{i:04d}", "name": "Alex Kim", "email": "akim@example.com", "team": "T0EXMPL02"}
    e = {"id": f"0123a45b-6c7d-8900-e12f-{i:012x}", "date_create": int(when), "action": action,
         "actor": {"type": "user", "user": user}, "entity": {"type": "user", "user": user},
         "context": {"location": {"type": "enterprise", "id": "E0EXMPL01", "name": "Example Org", "domain": "example-org"},
                     "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "session_id": "847288190092",
                     "ip_address": "203.0.113.10"}}
    if action == "file_downloaded":
        e["entity"] = {"type": "file", "file": {"id": f"F0TEST{i:04d}", "name": "plan.pdf", "filetype": "pdf", "title": "Plan"}}
    if action == "anomaly":
        e["details"] = {"action_timestamp": int(when) * 1000000, "location": "Sydney, New South Wales",
                        "previous_ip_address": "198.51.100.4", "reason": ["ip_address"], "ip_address_details": ["new-asn"]}
    return e


UNSET = object()


def cursor_for(offset):
    """Slack's cursors are opaque; these are base64 with = padding, which a URL must encode."""
    return base64.b64encode(f"next:{offset:03d}".encode()).decode()


def offset_of(cursor):
    return int(base64.b64decode(cursor).decode().split(":")[1])


class Mock:
    def __init__(self):
        self.entries = []
        self.page_cap = 9999
        self.codes = []          # (HTTP status, Slack error code or None) answered before any page
        self.requests = []
        self.ingest_codes = []
        self.ingested = []
        self.stuck_cursor = False
        self.cursor_value = UNSET  # a next_cursor to send in place of the real one
        self.metadata = "whole"    # or "no next_cursor", or "none" to leave out response_metadata
        self.answer = None       # a JSON answer to send as it is, for shapes that aren't documented


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
        if url.path != c.LOGS_PATH:
            return self._send(404, {"ok": False, "error": "bad_endpoint"})
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        m.requests.append({"query": q, "headers": dict(self.headers), "raw": url.query})
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, {"ok": False, "error": "invalid_authentication"})
        if m.codes:
            code, error = m.codes.pop(0)
            return self._send(code, {"ok": False, "error": error} if error else {"ok": False})
        if m.answer is not None:
            return self._send(200, m.answer)
        oldest, latest = int(q.get("oldest", 0)), int(q.get("latest", 2 ** 40))
        if oldest < c.EARLIEST or latest > time.time() + 5:
            return self._send(200, {"ok": False, "error": "invalid_range"})
        actions = q["action"].split(",") if q.get("action") else None
        rows = [e for e in m.entries if oldest <= e["date_create"] <= latest and (actions is None or e["action"] in actions)]
        rows.sort(key=lambda e: (-e["date_create"], e.get("id", "")))
        start = offset_of(q["cursor"]) if q.get("cursor") else 0
        limit = min(int(q.get("limit") or 100), m.page_cap)
        page = rows[start:start + limit]
        following = cursor_for(start + limit) if start + limit < len(rows) else ""
        if m.stuck_cursor and q.get("cursor"):
            following = q["cursor"]
        if m.cursor_value is not UNSET and following:
            following = m.cursor_value
        answer = {"ok": True, "entries": page, "response_metadata": {"next_cursor": following}}
        if m.metadata == "no next_cursor":
            answer["response_metadata"] = {}
        elif m.metadata == "none":
            del answer["response_metadata"]
        return self._send(200, answer)

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
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
    ("SLACK_PAGE_LIMIT", "page_limit", 1000, 500, int, 9999),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"SLACK_TOKEN": TOKEN}
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
        e = base_env(NGSIEM_INGEST_URL=f"{self.base}/http-endpoint/v1/00000000-example-integration", NGSIEM_INGEST_KEY=INGEST_KEY,
                     SLACK_API_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("SLACK_API_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def ago(self, minutes):
        return self.now - minutes * 60

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_entries_are_read_tagged_and_paged(self):
        self.mock.page_cap = 2
        self.mock.entries = [entry(i, self.ago(50 - i)) for i in range(4)] + [entry(9, self.ago(5), "file_downloaded")]
        self.assertEqual(c.run_once(self.cfg()), 5)
        # Slack lists the newest first; each page goes out oldest first.
        self.assertEqual([r["id"] for r in self.sent()],
                         [entry(i, 0)["id"] for i in (3, 9)] + [entry(i, 0)["id"] for i in (1, 2)] + [entry(0, 0)["id"]])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(
            '{"slack_record":"audit","id":"0123a45b-6c7d-8900-e12f-000000000003","date_create":'))
        first = {k: v for k, v in self.sent()[-1].items() if k != "slack_record"}
        self.assertEqual(first, self.mock.entries[0])
        # Three pages: the first, then each with the next_cursor of the page before, the same
        # oldest and latest, and the cursor's = padding encoded.
        reqs = self.mock.requests
        self.assertEqual(len(reqs), 3)
        self.assertNotIn("cursor", reqs[0]["query"])
        self.assertEqual([offset_of(r["query"]["cursor"]) for r in reqs[1:]], [2, 4])
        self.assertIn("cursor=" + urllib.parse.quote(cursor_for(2), safe=""), reqs[1]["raw"])
        q = reqs[0]["query"]
        self.assertEqual(q["limit"], "1000")
        self.assertNotIn("action", q)
        self.assertEqual(int(q["latest"]) - int(q["oldest"]), 86400 - 60)
        self.assertAlmostEqual(int(q["latest"]), self.now - 60, delta=5)
        self.assertEqual({(r["query"]["oldest"], r["query"]["latest"]) for r in reqs}, {(q["oldest"], q["latest"])})
        headers = {k.lower(): v for k, v in reqs[0]["headers"].items()}
        self.assertEqual(headers["authorization"], f"Bearer {TOKEN}")
        self.assertEqual(headers["accept"], "application/json")
        self.assertIn("until", self.saved()["logs"])

    def test_an_empty_or_missing_next_cursor_is_the_last_page(self):
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(3)]
        c.run_once(self.cfg(SLACK_PAGE_LIMIT="3"))
        # A full page with an empty next_cursor is the last; Slack's paging is by cursor, not count.
        self.assertEqual(len(self.mock.requests), 1)
        # Slack says an empty, null or missing next_cursor means no more results.
        self.mock.page_cap = 1
        for value, metadata in ((None, "whole"), ("", "whole"), (UNSET, "no next_cursor"), (UNSET, "none")):
            with self.subTest(next_cursor=value, metadata=metadata):
                os.remove(self.state)
                self.mock.requests.clear()
                self.mock.ingested.clear()
                self.mock.cursor_value, self.mock.metadata = value, metadata
                c.run_once(self.cfg())
                self.assertEqual(len(self.mock.requests), 1)
                self.assertEqual(len(self.sent()), 1)
                self.assertIn("until", self.saved()["logs"])

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.entries = [entry(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1200")
        c.run_once(cfg)
        first_end = int(self.mock.requests[0]["query"]["latest"])
        self.assertEqual(self.saved()["logs"]["until"], first_end)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An entry that Slack listed late, inside the overlap, and a new one. The window ends a
        # minute before now, so the new one is two minutes old.
        self.mock.entries += [entry(7, self.ago(15), "file_downloaded"), entry(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["id"] for r in self.sent()), sorted([entry(7, 0)["id"], entry(8, 0)["id"]]))
        self.assertEqual(int(self.mock.requests[0]["query"]["oldest"]), first_end - 1200)

    def test_lookback_sets_the_first_window(self):
        self.mock.entries = [entry(0, self.now - 3 * 86400), entry(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["id"] for r in self.sent()], [entry(1, 0)["id"]])
        self.assertLessEqual(int(self.mock.requests[0]["query"]["latest"]), time.time() - 59)

    def test_window_never_starts_before_march_2018(self):
        # Slack's audit logs start in March 2018, and an earlier oldest is an invalid_range error.
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="1000000"))
        self.assertEqual(int(self.mock.requests[0]["query"]["oldest"]), c.EARLIEST)
        self.assertIn("until", self.saved()["logs"])

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.page_cap = 2
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg())
        saved = self.saved()["logs"]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual(sorted(r["id"] for r in self.sent()), sorted(e["id"] for e in self.mock.entries[:2]))
        self.assertIn("until", self.saved()["logs"])

    def test_window_end_stays_before_now(self):
        self.mock.entries = [entry(0, self.ago(5))]
        c.run_once(self.cfg())
        self.assertLessEqual(self.saved()["logs"]["until"], time.time() - 59)
        # A saved end later than now, from a clock that went back, counts as now.
        with open(self.state, "w") as fh:
            json.dump({"logs": {"until": self.now + 7200}}, fh)
        self.mock.requests.clear()
        c.run_once(self.cfg(BRIDGE_OVERLAP_SECONDS="600"))
        q = self.mock.requests[0]["query"]
        self.assertEqual(int(q["latest"]) - int(q["oldest"]), 600)

    def test_actions_setting(self):
        self.mock.entries = [entry(0, self.ago(5)), entry(1, self.ago(4), "file_downloaded"), entry(2, self.ago(3), "anomaly")]
        c.run_once(self.cfg(SLACK_ACTIONS="anomaly, file_downloaded"))
        self.assertEqual(sorted(r["action"] for r in self.sent()), ["anomaly", "file_downloaded"])
        self.assertEqual(self.mock.requests[0]["query"]["action"], "anomaly,file_downloaded")

    def test_entry_without_an_id_is_known_by_its_hash(self):
        e = entry(0, self.ago(5))
        del e["id"]
        self.mock.entries = [e]
        c.run_once(self.cfg())
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)

    def test_entry_times(self):
        now = 1792620000.0
        for value, expected in ((1792616531, 1792616531.0), (1792616531.0, 1792616531.0), ("1792616531", 1792616531.0),
                                (" 1792616531 ", 1792616531.0), (None, now), ("yesterday", now), (True, now),
                                (float("nan"), now), (1e15, now), ({"t": 1}, now)):
            with self.subTest(value=value):
                self.assertEqual(c._entry_time({"date_create": value}, now), expected)
        self.assertEqual(c._entry_time({}, now), now)

    def test_refused_token_and_permissions_stop_with_clear_errors(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(SLACK_TOKEN="wrong-token-not-real"))
        self.assertEqual(str(cm.exception), "Slack refused the logs request (HTTP 401, invalid_authentication: Slack refused "
                         "the token; SLACK_TOKEN must be the user token (xoxp-) of an app with the auditlogs:read scope "
                         "that an Org Owner installed on the Enterprise organization)")
        for code, error, words in ((403, "user_not_authorized", "is not an Owner of the Enterprise organization"),
                                   (200, "team_not_authorized", "install it on the Enterprise organization itself"),
                                   (200, "feature_not_enabled", "needs an Enterprise plan"),
                                   (400, "invalid_action", "SLACK_ACTIONS"),
                                   (400, "something_new", "something_new"),
                                   (200, None, "no error code")):
            with self.subTest(error=error):
                self.mock.codes = [(code, error)]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertNotIsInstance(cm.exception, c.NetworkError)
                self.assertIn(words, str(cm.exception))
                self.assertEqual(f"HTTP {code}" in str(cm.exception), code != 200)
        self.assertNotIn("until", self.saved().get("logs", {}) if os.path.exists(self.state) else {})

    def test_a_stuck_or_odd_cursor_stops_the_run(self):
        self.mock.page_cap = 2
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(5)]
        self.mock.stuck_cursor = True
        with self.assertRaisesRegex(c.BridgeError, "the same next_cursor twice"):
            c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 4)
        self.assertNotIn("until", self.saved()["logs"])
        self.mock.stuck_cursor = False
        self.mock.cursor_value = 12345
        with self.assertRaisesRegex(c.BridgeError, "a next_cursor that is not text"):
            c.run_once(self.cfg())
        self.mock.cursor_value = UNSET
        c.run_once(self.cfg())
        self.assertEqual(sorted(r["id"] for r in self.sent()), sorted(e["id"] for e in self.mock.entries))
        self.assertIn("until", self.saved()["logs"])

    def test_an_answer_that_is_not_the_documented_shape_stops_the_run(self):
        for answer, words in (([], "JSON that is not an object"), ({"ok": True, "entries": {"id": "x"}}, "entries that are not a list")):
            with self.subTest(answer=answer):
                self.mock.answer = answer
                with self.assertRaisesRegex(c.BridgeError, words):
                    c.run_once(self.cfg())
        self.assertNotIn("until", self.saved().get("logs", {}) if os.path.exists(self.state) else {})

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(2)] + [entry(5, self.ago(5), "anomaly")]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["slack_record"] for x in lines], ["audit"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.entries = [entry(i, self.ago(10 - i)) for i in range(3)]
        self.mock.codes = [(429, "rate_limited"), (500, None), (503, None)]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(len(self.mock.requests), 4)

    def test_rate_limit_past_the_retries_is_a_network_error(self):
        self.mock.codes = [(429, "rate_limited")] * c.MAX_ATTEMPTS
        with self.assertRaises(c.NetworkError) as cm:
            c.run_once(self.cfg())
        self.assertTrue(str(cm.exception).endswith("failed with HTTP 429"), str(cm.exception))

    def test_gzip_batches_and_headers(self):
        self.mock.entries = [entry(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")
        os.remove(self.state)
        self.mock.ingested.clear()
        c.run_once(self.cfg(BRIDGE_GZIP="0"))
        self.assertNotIn("Content-Encoding", self.mock.ingested[0]["headers"])
        self.assertEqual(len(self.sent()), 12)

    def test_secrets_never_logged(self):
        self.mock.entries = [entry(0, self.ago(5))]
        self.mock.page_cap = 1
        self.mock.entries.append(entry(1, self.ago(4)))
        self.mock.codes = [(503, None)]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(SLACK_TOKEN="another-wrong-token-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("logs request", logged)
        for secret in (TOKEN, INGEST_KEY, "00000000-example-integration", "another-wrong-token-not-real", cursor_for(1)):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(SLACK_TOKEN=None),
            base_env(SLACK_API_URL="http://api.slack.example"),
            base_env(SLACK_ACTIONS="user_login,file downloaded"),
            base_env(SLACK_ACTIONS="user_login&limit=1"),
            base_env(SLACK_ACTIONS="User_Login"),
            base_env(SLACK_ACTIONS=",".join(f"action_{i}" for i in range(31))),
            base_env(SLACK_PAGE_LIMIT="0"),
            base_env(SLACK_PAGE_LIMIT="10000"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["api_url"], cfg["actions"], cfg["page_limit"], cfg["lookback_hours"], cfg["overlap_seconds"]),
                         ("https://api.slack.com", [], 1000, 24.0, 900))
        self.assertEqual(c.load_config(base_env(SLACK_API_URL="https://api.slack.com/"))["api_url"], "https://api.slack.com")
        self.assertEqual(len(c.load_config(base_env(SLACK_ACTIONS=",".join(f"action_{i}" for i in range(30))))["actions"]), 30)
        self.assertEqual(c.load_config(base_env(SLACK_ACTIONS="pref.sso_setting_changed, user_login,user_login"))["actions"],
                         ["pref.sso_setting_changed", "user_login"])

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the token to another URL, so the run fails instead, and
        # nothing reaches the redirect's target.
        self.mock.entries = [entry(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Audit Logs API": self.cfg(SLACK_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("logs", {}))
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

    def test_page_limit_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "10000"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^SLACK_PAGE_LIMIT must be between 1 and 9,999$"):
                self.load(SLACK_PAGE_LIMIT=value)
        self.assertEqual(self.load(SLACK_PAGE_LIMIT="1")["page_limit"], 1)
        self.assertEqual(self.load(SLACK_PAGE_LIMIT="9999")["page_limit"], 9999)

    def test_lookback_has_a_wide_range_since_slack_gives_no_retention(self):
        # Slack documents no retention for audit logs, only that they start in March 2018.
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 1,000,000$"):
            self.load(BRIDGE_LOOKBACK_HOURS="1000001")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="8760")["lookback_hours"], 8760.0)


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
        error = c.HostNotFound("logs request to api.example.com failed: the host name wasn't found; check the URL setting")
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
