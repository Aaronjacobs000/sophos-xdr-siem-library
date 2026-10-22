"""Unit tests for goto_admin_jobs_bridge.py against a local mock server.

The mock serves the shapes in GoTo's Admin API spec and authentication guides: POST /oauth/token with
Basic client authentication and grant_type=personal_access_token&pat=... or
grant_type=refresh_token&refresh_token=..., answering {"access_token", "token_type", "expires_in",
"scope", "principal"} (with a new "refresh_token" when GoTo replaces it) or {"error",
"error_description"}; GET /admin/rest/v1/me answering {"key", "accountKey", "accounts": [...]}; and GET
/admin/rest/v1/accounts/{accountKey}/jobs with fromDate, toDate and metadata, answering the job
records. GoTo documents no body for that answer, so the mock sends either a JSON array or {"results",
"fromIndex", "toIndex", "total"} as GoTo's other lists do, and can hold back jobs to test the split.
A refused access token gets the 403 GoTo's gateway sends ({"int_err_code": "InvalidToken"}), and other
errors {"incidentId", "errors": [{"code"}]}. Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real
service is called.

  python3 -m unittest discover -s bridges/goto-admin-jobs -p 'test_*.py' -v
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
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import goto_admin_jobs_bridge as c  # noqa: E402

# The bridge spaces its requests; the tests don't wait, except the one that checks the spacing.
c.PACE_SECONDS = 0

CLIENT_ID = "test-goto-client-id-not-real"
CLIENT_SECRET = "test-goto-client-secret-not-real"
PAT = "test-goto-pat-not-real"
REFRESH = "RT-test-first-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
ACCOUNT = 1234567890123456789012


def ms(dt):
    return int(dt.timestamp() * 1000)


def job(i, when, status="COMPLETED", jtype="updateuser"):
    return {"system": "ea", "id": f"j{i:05d}abc", "type": jtype, "submitTime": ms(when), "startTime": ms(when) + 40,
            "endTime": ms(when) + 900, "status": status,
            "admin": {"key": 5550001, "email": "jsmith@example.com", "firstName": "Jane", "lastName": "Smith",
                      "systemUser": False, "syncUser": False},
            "request": {"method": "PUT", "uri": f"/ext-admin/rest/accounts/{ACCOUNT}/users/7770{i:03d}",
                        "content": "{\"adminRoles\":[\"MANAGE_SEATS\"]}"},
            "response": {"status": 204},
            "metadata": {"users": [{"key": 7770000 + i, "email": f"user{i}@example.com", "firstName": "Sam", "lastName": "Lee"}]}}


class Mock:
    def __init__(self):
        self.jobs = []
        self.shape = "results"
        # The most jobs one answer holds; with results, total still counts them all.
        self.cap = 10000
        self.requests = []
        self.me_requests = 0
        self.tokens = []
        self.token_requests = []
        self.expires_in = 3600
        self.refresh_valid = {REFRESH}
        # The refresh token to send with the next token answer, which invalidates the old one.
        self.rotate_to = None
        self.answers = []
        self.ingest_codes = []
        self.ingested = []


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == "/oauth/token":
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append({"form": form, "headers": dict(self.headers)})
            basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            if self.headers.get("Authorization") != f"Basic {basic}":
                return self._send(401, {"error": "invalid_client", "error_description": "Bad client credentials"})
            grant = form.get("grant_type", [""])[0]
            reply = {}
            if grant == "personal_access_token" and form.get("pat") == [PAT]:
                pass
            elif grant == "refresh_token" and form.get("refresh_token", [""])[0] in m.refresh_valid:
                if m.rotate_to:
                    m.refresh_valid = {m.rotate_to}
                    reply["refresh_token"] = m.rotate_to
                    m.rotate_to = None
            else:
                return self._send(400, {"error": "invalid_grant", "error_description": "Invalid grant"})
            token = f"AT-test{len(m.tokens):04d}notreal"
            m.tokens.append(token)
            return self._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": m.expires_in,
                                    "scope": "identity:", "principal": "jsmith@example.com", **reply})
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
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] not in m.tokens:
            return self._send(403, {"int_err_code": "InvalidToken", "msg": "Invalid token passed"},
                              {"WWW-Authenticate": 'error="invalid_token",error_description="The access token is invalid"'})
        if url.path == "/admin/rest/v1/me":
            m.me_requests += 1
            return self._send(200, {"key": 5550001, "accountKey": ACCOUNT, "email": "jsmith@example.com",
                                    "accounts": [{"key": ACCOUNT, "name": "Example Account"}]})
        m.requests.append({"path": url.path, "query": query, "headers": dict(self.headers)})
        if m.answers:
            answer = m.answers.pop(0)
            if isinstance(answer, tuple):
                return self._send(200, answer[1])
            return self._send(answer, {"incidentId": 123, "errors": [{"code": "test.status"}]})
        if url.path == f"/admin/rest/v1/accounts/{ACCOUNT}/jobs":
            lo, hi = int(query["fromDate"][0]), int(query["toDate"][0])
            rows = sorted((j for j in m.jobs if lo <= j["submitTime"] <= hi), key=lambda j: -j["submitTime"])
            held = rows[:m.cap]
            if m.shape == "list":
                return self._send(200, held)
            return self._send(200, {"results": held, "fromIndex": 0, "toIndex": max(0, len(held) - 1), "total": len(rows)})
        self._send(404, {"incidentId": 124, "errors": [{"code": "not.found"}]})


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
    ("GOTO_WINDOW_MINUTES", "window_minutes", 60, 30, int, 1440),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"GOTO_CLIENT_ID": CLIENT_ID, "GOTO_CLIENT_SECRET": CLIENT_SECRET, "GOTO_PAT": PAT}
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
        self.token_file = os.path.join(self.tmp.name, "token.json")
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
                     GOTO_API_URL=self.base, GOTO_AUTH_URL=self.base, BRIDGE_STATE_FILE=self.state,
                     BRIDGE_TOKEN_FILE=self.token_file)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def refresh_cfg(self, **extra):
        return self.cfg(**{"GOTO_PAT": None, "GOTO_REFRESH_TOKEN": REFRESH, **extra})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def held_back(self, when):
        """True when no saved window end has reached the job submitted at `when`: earlier windows
        with nothing to send may have moved on."""
        cur = self.saved().get("accounts", {}).get(str(ACCOUNT), {}) if os.path.exists(self.state) else {}
        return cur.get("until") is None or cur["until"] < when.timestamp()

    def ranges(self):
        return [(int(r["query"]["fromDate"][0]), int(r["query"]["toDate"][0])) for r in self.mock.requests]

    def test_jobs_are_read_for_the_account_from_me_and_tagged(self):
        self.mock.jobs = [job(i, self.ago(50 - i)) for i in range(3)]
        c.run_once(self.cfg(GOTO_WINDOW_MINUTES="1440"))
        rows = self.sent()
        self.assertEqual(sorted(r["id"] for r in rows), ["j00000abc", "j00001abc", "j00002abc"])
        for r in rows:
            self.assertEqual(list(r)[:2], ["goto_record", "goto_account_key"])
            self.assertEqual((r["goto_record"], r["goto_account_key"]), ("admin_job", str(ACCOUNT)))
        self.assertEqual(rows[0]["admin"]["email"], "jsmith@example.com")
        self.assertEqual(self.mock.me_requests, 1)
        q = self.mock.requests[0]["query"]
        self.assertEqual(q["metadata"], ["true"])
        lo, hi = self.ranges()[0]
        self.assertAlmostEqual(self.now.timestamp() * 1000 - lo, 24 * 3600 * 1000, delta=5000)
        self.assertAlmostEqual(self.now.timestamp() * 1000 - hi, 60 * 1000, delta=5000)

    def test_a_set_account_key_skips_me_and_metadata_can_be_left_out(self):
        self.mock.jobs = [job(0, self.ago(5))]
        c.run_once(self.cfg(GOTO_ACCOUNT_KEY=str(ACCOUNT), GOTO_METADATA="0"))
        self.assertEqual(self.mock.me_requests, 0)
        self.assertNotIn("metadata", self.mock.requests[0]["query"])
        self.assertEqual(len(self.sent()), 1)

    def test_a_json_array_answer_is_read_too(self):
        self.mock.shape = "list"
        self.mock.jobs = [job(i, self.ago(30 - i)) for i in range(4)]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 4)

    def test_an_answer_of_another_shape_stops_with_a_plain_error(self):
        for body in ({"jobs": []}, {"results": "x"}, "text"):
            with self.subTest(body=body):
                self.mock.answers = [("body", body)]
                with self.assertRaisesRegex(c.BridgeError, r"neither a JSON array nor \{\"results\": \[\.\.\.\]\}"):
                    c.run_once(self.cfg())

    def test_an_answer_short_of_its_total_splits_the_window(self):
        self.mock.cap = 2
        self.mock.jobs = [job(i, self.ago(50 - i * 5)) for i in range(7)]
        c.run_once(self.cfg(GOTO_WINDOW_MINUTES="1440"))
        self.assertEqual(sorted(r["id"] for r in self.sent()), sorted(f"j{i:05d}abc" for i in range(7)))
        # Each half is read on its own until every answer holds its total, and the halves meet exactly.
        done = [r for r in self.ranges()]
        self.assertGreater(len(done), 1)
        leaves = sorted({rg for rg in done if not any(o != rg and o[0] <= rg[0] and rg[1] <= o[1] for o in done)})
        self.assertTrue(all(b[0] == a[1] + 1 for a, b in zip(leaves, leaves[1:])), leaves)

    def test_jobs_in_one_millisecond_over_an_answer_stop_the_run(self):
        self.mock.cap = 1
        when = self.ago(5)
        self.mock.jobs = [job(0, when), job(1, when)]
        with self.assertRaisesRegex(c.BridgeError, r"for one millisecond held 1 of 2 jobs"):
            c.run_once(self.cfg())
        self.assertTrue(self.held_back(when))

    def test_windows_follow_window_minutes_with_no_gap_or_overlap(self):
        self.mock.jobs = [job(i, self.ago(170 - i * 30)) for i in range(6)]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="3", GOTO_WINDOW_MINUTES="60"))
        r = self.ranges()
        self.assertEqual(len(r), 3)
        self.assertTrue(all(b - a == 60 * 60000 - 1 for a, b in r[:-1]), r)
        self.assertTrue(all(nxt[0] == cur[1] + 1 for cur, nxt in zip(r, r[1:])), r)
        self.assertEqual(len(self.sent()), 6)
        self.assertAlmostEqual(self.saved()["accounts"][str(ACCOUNT)]["until"], r[-1][1] / 1000.0)

    def test_pat_grant_with_basic_client_auth_and_the_token_is_kept(self):
        cfg = self.cfg()
        client = c.GoTo(cfg)
        c.run_once(cfg, client=client)
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        tr = self.mock.token_requests[0]
        self.assertEqual(tr["form"], {"grant_type": ["personal_access_token"], "pat": [PAT]})
        self.assertEqual(tr["headers"]["Authorization"], "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode())
        self.assertEqual(tr["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(self.mock.me_requests, 1)
        self.assertFalse(os.path.exists(self.token_file))

    def test_a_token_near_its_expiry_is_renewed(self):
        self.mock.expires_in = 30
        cfg = self.cfg()
        client = c.GoTo(cfg)
        saved = c.time.monotonic
        try:
            c.run_once(cfg, client=client)
            start = saved()
            c.time.monotonic = lambda: start + 61
            c.run_once(cfg, client=client)
        finally:
            c.time.monotonic = saved
        self.assertEqual(len(self.mock.token_requests), 2)

    def test_a_refused_token_is_renewed_once(self):
        cfg = self.cfg()
        client = c.GoTo(cfg)
        c.run_once(cfg, client=client)
        self.mock.tokens.clear()  # GoTo no longer takes it: its gateway answers 403 InvalidToken
        self.mock.jobs = [job(0, self.ago(5))]
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.assertEqual(len(self.sent()), 1)

    def test_refresh_token_grant_saves_a_replaced_refresh_token(self):
        self.mock.rotate_to = "RT-test-second-not-real"
        c.run_once(self.refresh_cfg())
        self.assertEqual(self.mock.token_requests[0]["form"], {"grant_type": ["refresh_token"], "refresh_token": [REFRESH]})
        with open(self.token_file) as fh:
            self.assertEqual(json.load(fh), {"refresh_token": "RT-test-second-not-real"})
        self.assertEqual(stat.S_IMODE(os.stat(self.token_file).st_mode), 0o600)
        # The next start reads the saved token, since GoTo invalidated the one in the environment.
        c.run_once(self.refresh_cfg())
        self.assertEqual(self.mock.token_requests[1]["form"]["refresh_token"], ["RT-test-second-not-real"])
        self.assertNotIn("RT-test-second-not-real", self.logbuf.getvalue())
        self.assertIn("saved it to BRIDGE_TOKEN_FILE", self.logbuf.getvalue())

    def test_a_refresh_token_that_cant_be_saved_stops_with_a_clear_error(self):
        self.mock.rotate_to = "RT-test-second-not-real"
        with self.assertRaisesRegex(c.BridgeError, r"BRIDGE_TOKEN_FILE couldn't be written"):
            c.run_once(self.refresh_cfg(BRIDGE_TOKEN_FILE=os.path.join(self.tmp.name, "missing", "token.json")))
        with open(self.token_file, "w") as fh:
            fh.write("not json")
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_TOKEN_FILE couldn't be read"):
            c.GoTo(self.refresh_cfg())

    def test_refused_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(GOTO_PAT="another-wrong-pat-not-real"))
        self.assertIn("GoTo refused the personal access token (HTTP 400: invalid_grant; Invalid grant)", str(cm.exception))
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.assertNotIn("another-wrong-pat-not-real", str(cm.exception))
        with self.assertRaisesRegex(c.BridgeError, r"GoTo refused the refresh token \(HTTP 400"):
            c.run_once(self.refresh_cfg(GOTO_REFRESH_TOKEN="RT-test-stale-not-real"))
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 401: invalid_client; Bad client credentials\); check GOTO_CLIENT_ID"):
            c.run_once(self.cfg(GOTO_CLIENT_SECRET="wrong-secret-not-real"))
        self.assertFalse(os.path.exists(self.state))

    def test_a_job_is_sent_again_only_when_its_status_changes(self):
        started = job(0, self.ago(10), status="STARTED")
        self.mock.jobs = [started]
        c.run_once(self.cfg())
        c.run_once(self.cfg())
        self.mock.jobs = [{**started, "status": "COMPLETED"}]
        c.run_once(self.cfg())
        self.assertEqual([r["status"] for r in self.sent()], ["STARTED", "COMPLETED"])

    def test_next_run_reads_from_the_last_window_less_the_overlap(self):
        self.mock.jobs = [job(0, self.ago(10))]
        c.run_once(self.cfg())
        until = self.saved()["accounts"][str(ACCOUNT)]["until"]
        self.mock.jobs.append(job(1, self.ago(5)))
        self.mock.requests.clear()
        c.run_once(self.cfg(BRIDGE_OVERLAP_SECONDS="900"))
        self.assertEqual([r["id"] for r in self.sent()], ["j00000abc", "j00001abc"])
        self.assertEqual(self.ranges()[0][0], int((until - 900) * 1000))

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.jobs = [job(0, self.ago(5))]
        self.mock.ingest_codes = [400]
        with self.assertRaises(c.HttpStatus):
            c.run_once(self.cfg())
        self.assertTrue(self.held_back(self.ago(5)))
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)

    def test_window_end_never_passes_now(self):
        with open(self.state, "w") as fh:
            json.dump({"accounts": {str(ACCOUNT): {"until": (self.now + timedelta(hours=5)).timestamp()}}}, fh)
        self.mock.jobs = [job(0, self.ago(5))]
        c.run_once(self.cfg())
        self.assertLessEqual(self.saved()["accounts"][str(ACCOUNT)]["until"], datetime.now(timezone.utc).timestamp())
        self.assertEqual(len(self.sent()), 1)

    def test_http_errors_stop_with_clear_errors(self):
        cases = [(403, r"HTTP 403: test.status\); the token needs the identity: scope"),
                 (404, r"HTTP 404 \(test.status\); check GOTO_ACCOUNT_KEY"),
                 (400, r"HTTP 400: test.status\)$")]
        for code, message in cases:
            self.mock.answers = [code]
            with self.subTest(code=code), self.assertRaisesRegex(c.BridgeError, message) as cm:
                c.run_once(self.cfg())
            self.assertNotIsInstance(cm.exception, c.NetworkError)
        # A 401 renews the token first, so it is answered twice.
        self.mock.answers = [401, 401]
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 401: test.status\); the token needs"):
            c.run_once(self.cfg())

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.jobs = [job(i, self.ago(10 - i)) for i in range(3)]
        self.mock.answers = [429, 503, 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_requests_are_spaced_under_the_rate_limit(self):
        saved, c.PACE_SECONDS = c.PACE_SECONDS, 0.15
        try:
            c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="3", GOTO_WINDOW_MINUTES="60"))
        finally:
            c.PACE_SECONDS = saved
        # /me and three job windows; each one after the first waits.
        self.assertEqual(len(self.slept), 3)
        self.assertTrue(all(0 < s <= 0.15 for s in self.slept), self.slept)

    def test_gzip_batches_and_headers(self):
        self.mock.jobs = [job(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.jobs = [job(0, self.ago(5))]
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        self.mock.rotate_to = "RT-test-second-not-real"
        c.run_once(self.refresh_cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(GOTO_PAT="another-wrong-pat-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("jobs request", logged)
        for secret in (CLIENT_SECRET, PAT, REFRESH, "RT-test-second-not-real", INGEST_KEY, "00000000-example-integration",
                       "another-wrong-pat-not-real", self.mock.tokens[0]):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(GOTO_API_URL="http://api.getgo.com"),
            base_env(GOTO_API_URL="https://api.getgo.com/admin/rest/v1"),
            base_env(GOTO_AUTH_URL="authentication.logmeininc.com"),
            base_env(GOTO_CLIENT_ID=None),
            base_env(GOTO_CLIENT_SECRET=None),
            base_env(GOTO_PAT=None),
            base_env(GOTO_REFRESH_TOKEN=REFRESH),
            base_env(GOTO_ACCOUNT_KEY="acct-123"),
            base_env(GOTO_WINDOW_MINUTES="0"),
            base_env(GOTO_WINDOW_MINUTES="1441"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["api_url"], cfg["auth_url"], cfg["window_minutes"], cfg["metadata"], cfg["account_key"]),
                         ("https://api.getgo.com", "https://authentication.logmeininc.com", 60, True, None))
        self.assertEqual(c.load_config(base_env(GOTO_PAT=None, GOTO_REFRESH_TOKEN=REFRESH))["refresh_token"], REFRESH)

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("GOTO_API_URL", "GOTO_AUTH_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.jobs = [job(i, self.ago(10 - i)) for i in range(2)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["goto_record"] for x in lines], ["admin_job", "admin_job"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_still_saves_a_replaced_refresh_token(self):
        # GoTo invalidates the old refresh token when it sends a new one, so even a dry run keeps it.
        self.mock.rotate_to = "RT-test-second-not-real"
        c.run_once(self.refresh_cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=io.StringIO())
        with open(self.token_file) as fh:
            self.assertEqual(json.load(fh)["refresh_token"], "RT-test-second-not-real")
        self.assertFalse(os.path.exists(self.state))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the client secret, a token or the key to another URL, so the
        # run fails instead, and nothing reaches the redirect's target.
        self.mock.jobs = [job(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "GoTo API": self.cfg(GOTO_API_URL=r.base), "GoTo authentication": self.cfg(GOTO_AUTH_URL=r.base)}
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
                        # The window that holds the job that wasn't sent keeps its place.
                        self.assertTrue(self.held_back(self.ago(5)))
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

    def test_times_keys_and_error_text(self):
        self.assertEqual(c._job_time({"submitTime": 1791966764000}, 5.0), 1791966764.0)
        for bad in ({}, {"submitTime": "1791966764000"}, {"submitTime": True}, {"submitTime": -1}):
            with self.subTest(job=bad):
                self.assertEqual(c._job_time(bad, 5.0), 5.0)
        self.assertEqual(c._key({"id": "abc", "status": "FAILED"}), "id:abc:FAILED")
        self.assertTrue(c._key({"type": "x"}).startswith("sha:"))
        self.assertEqual(c._key({"a": 1, "b": 2}), c._key({"b": 2, "a": 1}))
        self.assertEqual(c._goto_error(b'{"incidentId":123,"errors":[{"code":"group.name.maxlength","field":"name"}]}'),
                         "group.name.maxlength; name")
        self.assertEqual(c._goto_error(b'{"code":"user.email.conflict","field":"email"}'), "user.email.conflict; email")
        self.assertEqual(c._goto_error(b'{"error":"invalid_grant","error_description":"Invalid grant"}'), "invalid_grant; Invalid grant")
        self.assertEqual(c._goto_error(b'{"int_err_code":"InvalidToken","msg":"Invalid token passed"}'), "InvalidToken; Invalid token passed")
        for body in (b"", b"[]", b"not json", b'{"x": 1}'):
            self.assertEqual(c._goto_error(body), "no message")
        self.assertTrue(c._token_refused(c.HttpStatus("x", "https://a.example.com", 403, b'{"int_err_code":"InvalidToken"}')))
        self.assertFalse(c._token_refused(c.HttpStatus("x", "https://a.example.com", 403, b'{"errors":[{"code":"insufficient.permissions"}]}')))


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

    def test_window_minutes_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "1441"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^GOTO_WINDOW_MINUTES must be between 1 and 1,440$"):
                self.load(GOTO_WINDOW_MINUTES=value)
        self.assertEqual(self.load(GOTO_WINDOW_MINUTES="1")["window_minutes"], 1)
        self.assertEqual(self.load(GOTO_WINDOW_MINUTES="1440")["window_minutes"], 1440)


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
        error = c.HostNotFound("jobs request to api.getgo.com failed: the host name wasn't found; check the URL setting")
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
