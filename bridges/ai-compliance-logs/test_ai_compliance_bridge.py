"""Unit tests for ai_compliance_bridge.py against a local mock server.

The mock serves the response shapes documented by OpenAI (Compliance Logs Platform, audit
logs) and Anthropic (Compliance API Activity Feed), plus a Sophos NG-SIEM HTTP Ingest
endpoint. No real service is called.

  python3 -m unittest discover -s bridges/ai-compliance-logs -p 'test_*.py' -v
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
import ai_compliance_bridge as c  # noqa: E402

CLP_KEY = "test-openai-compliance-key-not-real"
OPENAI_ADMIN_KEY = "test-openai-admin-key-not-real"
ANTHROPIC_KEY = "test-anthropic-compliance-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
WS = "4f1c2a3b-0d5e-4c7f-9a8b-1e2d3c4b5a69"
SIGNATURE = "test-signed-url-signature-not-real"


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def clp_auth(eid, ts, action="login_success"):
    return {"event_id": eid, "type": "AUTH_LOG", "timestamp": ts, "principal": {"id": WS, "type": "CHATGPT_WORKSPACE"},
            "actor": {"type": "ACCOUNT_USER", "user_id": "user-example1", "user_email": "alice@example.com"},
            "request_metadata": {"client_ip": "203.0.113.24", "client_user_agent": "Mozilla/5.0"},
            "action_data": {"action": action, "auth_provider_name": "password"}}


def clp_message(eid, ts, text="Summarize the example plan."):
    return {"event_id": eid, "type": "CONVERSATION_MESSAGE", "timestamp": ts,
            "principal": {"id": WS, "type": "CHATGPT_WORKSPACE"},
            "actor": {"type": "ACCOUNT_USER", "user_id": "user-example1", "user_email": "alice@example.com"},
            "message": {"id": "msg-1", "author": {"type": "assistant", "model": "gpt-5-2-pro", "applied_custom_instructions": "Be brief."},
                        "content": {"type": "text", "value": text, "annotations": [{"type": "url_citation", "urls": ["https://www.example.com/a"]}]},
                        "files": [{"id": "file-1", "name": "plan.pdf"}]},
            "conversation": {"id": "convo-1", "title": "Example plan", "mode": "chat", "is_temporary_chat": False}}


def clp_codex(eid, ts):
    return {"event_id": eid, "type": "CODEX_LOG", "timestamp": ts, "principal": {"id": WS, "type": "CHATGPT_WORKSPACE"},
            "actor": {"type": "ACCOUNT_USER", "user_id": "user-example1", "user_email": "alice@example.com"},
            "codex": {"task_id": "task-1", "prompt": "fix the build", "model": "codex-1", "output": {"text": "done", "status": "completed"}}}


class Mock:
    """State for one test: vendor data, ingest responses, and everything the server saw."""

    def __init__(self):
        self.clp_files = []          # [{"id", "event_type", "end_time", "records"}]
        self.audit = []              # OpenAI audit log objects
        self.activities = []         # Anthropic activities
        self.ingest_codes = []       # response codes to return before 200
        self.ingested = []           # [{"headers", "lines"}]
        self.requests = []           # [(method, path, headers)]
        self.download_location = None  # Location for the download redirect, instead of /signed/...
        self.signed_redirect = None    # a redirect the signed URL answers with
        self.signed_short = 0          # signed file answers to cut short after their first line


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="application/json", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode())

    def do_GET(self):
        m = self.mock
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        m.requests.append(("GET", self.path, dict(self.headers)))
        parts = u.path.strip("/").split("/")
        if u.path.startswith(f"/v1/compliance/workspaces/{WS}/logs"):
            if self.headers.get("Authorization") != f"Bearer {CLP_KEY}":
                return self._json({"error": "unauthorized"}, 401)
            if len(parts) == 6:  # download: 307 to a signed URL
                f = next((f for f in m.clp_files if f["id"] == parts[5]), None)
                if not f:
                    return self._json({}, 404)
                return self._send(307, b"", headers={"Location": m.download_location or f"/signed/{f['id']}?sig={SIGNATURE}"})
            after = q["after"][0]
            limit = int(q.get("limit", ["100"])[0])
            types = set(",".join(q["event_type"]).split(","))
            files = sorted((f for f in m.clp_files if f["event_type"] in types and c._parse_time(f["end_time"]) > c._parse_time(after)),
                           key=lambda f: f["end_time"])
            page = files[:limit]
            return self._json({"data": [{"id": f["id"], "event_type": f["event_type"], "end_time": f["end_time"],
                                         "file_name": f["id"] + ".jsonl", "file_size": 1, "file_sha256": "00"} for f in page],
                               "has_more": len(files) > limit, "last_end_time": page[-1]["end_time"] if page else None})
        if u.path.startswith("/signed/"):
            if self.headers.get("Authorization"):
                return self._json({"error": "signed URLs reject an Authorization header"}, 400)
            if q.get("sig") != [SIGNATURE]:
                return self._json({}, 403)
            if m.signed_redirect:
                return self._send(302, b"", headers={"Location": m.signed_redirect})
            f = next(f for f in m.clp_files if f["id"] == parts[1])
            body = "".join(json.dumps(r) + "\n" for r in f["records"]).encode()
            if m.signed_short:
                # The connection closes at a line break, so what arrives still reads as whole
                # JSON lines; only the Content-Length shows that records are missing.
                m.signed_short -= 1
                self.send_response(200)
                self.send_header("Content-Type", "application/jsonl")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body[:body.index(b"\n") + 1])
                return
            return self._send(200, body, "application/jsonl")
        if u.path == "/v1/organization/audit_logs":
            if self.headers.get("Authorization") != f"Bearer {OPENAI_ADMIN_KEY}":
                return self._json({"error": "unauthorized"}, 401)
            gte = int(q["effective_at[gte]"][0])
            limit = int(q.get("limit", ["20"])[0])
            rows = sorted((r for r in m.audit if r["effective_at"] >= gte), key=lambda r: (-r["effective_at"], r["id"]))
            if "after" in q:
                idx = [r["id"] for r in rows].index(q["after"][0])
                rows = rows[idx + 1:]
            page = rows[:limit]
            return self._json({"object": "list", "data": page, "first_id": page[0]["id"] if page else None,
                               "last_id": page[-1]["id"] if page else None, "has_more": len(rows) > limit})
        if u.path == "/v1/compliance/activities":
            if self.headers.get("x-api-key") != ANTHROPIC_KEY or not self.headers.get("anthropic-version"):
                return self._json({"error": {"type": "authentication_error"}}, 401)
            gte = c._parse_time(q["created_at.gte"][0])
            lt = c._parse_time(q["created_at.lt"][0])
            assert q["order"] == ["asc"]
            limit = int(q.get("limit", ["100"])[0])
            rows = sorted((r for r in m.activities if gte <= c._parse_time(r["created_at"]) < lt),
                          key=lambda r: (r["created_at"], r["id"]))
            if "after_id" in q:
                idx = [r["id"] for r in rows].index(q["after_id"][0])
                rows = rows[idx + 1:]
            page = rows[:limit]
            return self._json({"data": page, "has_more": len(rows) > limit,
                               "first_id": page[0]["id"] if page else None, "last_id": page[-1]["id"] if page else None})
        self._json({}, 404)

    def do_POST(self):
        m = self.mock
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        m.requests.append(("POST", self.path, dict(self.headers)))
        if not self.path.startswith("/http-endpoint/v1/"):
            return self._json({}, 404)
        if self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._json({}, 401)
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._send(code, b"{}", headers={"Retry-After": "0"})
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        lines = [json.loads(x) for x in body.decode().splitlines() if x.strip()]
        m.ingested.append({"headers": dict(self.headers), "lines": lines})
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
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 300, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
    ("ANTHROPIC_SETTLE_SECONDS", "anthropic.settle_seconds", 60, 30, int, 10 ** 9),
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
        handler = type("H", (Handler,), {"mock": self.mock})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state.json")
        self.log = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log)
        c.LOG.addHandler(self.log_handler)
        c.LOG.setLevel(logging.DEBUG)
        self._sleep = c.time.sleep
        c.time.sleep = lambda s: None

    def tearDown(self):
        c.time.sleep = self._sleep
        c.LOG.removeHandler(self.log_handler)
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()
        gc.collect()
        self._warnings.__exit__(None, None, None)
        self.assertEqual(self.leaks, [], "a socket or file was left open")

    def env(self, **extra):
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration",
             "NGSIEM_INGEST_KEY": INGEST_KEY, "BRIDGE_STATE_FILE": self.state,
             "OPENAI_CLP_BASE_URL": f"{self.base}/v1", "OPENAI_API_BASE_URL": f"{self.base}/v1",
             "ANTHROPIC_BASE_URL": self.base}
        e.update(extra)
        return e

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    # ------------------------------------------------------------ OpenAI Compliance Logs Platform

    def clp_env(self, **extra):
        return self.env(BRIDGE_SOURCES="openai_clp", OPENAI_COMPLIANCE_API_KEY=CLP_KEY,
                        OPENAI_CLP_PRINCIPAL_ID=WS, **extra)

    def add_clp_files(self):
        now = datetime.now(timezone.utc)
        t1, t2 = now - timedelta(minutes=30), now - timedelta(minutes=20)
        self.mock.clp_files = [
            {"id": "clf-1", "event_type": "AUTH_LOG", "end_time": iso(t1),
             "records": [clp_auth("e1", iso(t1 - timedelta(minutes=5))), clp_auth("e2", iso(t1 - timedelta(minutes=1)))]},
            # e2 repeats: the platform is at least once and repeats events across files.
            {"id": "clf-2", "event_type": "AUTH_LOG", "end_time": iso(t2),
             "records": [clp_auth("e2", iso(t1 - timedelta(minutes=1))), clp_auth("e3", iso(t2 - timedelta(minutes=2)), "logout_success")]},
            {"id": "clf-3", "event_type": "CONVERSATION_MESSAGE", "end_time": iso(t2),
             "records": [clp_message("m1", iso(t2 - timedelta(minutes=3)))]},
            {"id": "clf-4", "event_type": "CODEX_LOG", "end_time": iso(t2), "records": [clp_codex("x1", iso(t2))]},
        ]
        return t2

    def test_clp_pages_redirect_dedupe_and_cursor(self):
        t2 = self.add_clp_files()
        cfg = c.load_config(self.clp_env())
        c.run_once(cfg)
        ids = [r["event_id"] for r in self.sent()]
        self.assertEqual(ids, ["e1", "e2", "e3"])
        # The download followed the 307 to the signed URL without the API key.
        signed = [r for r in self.mock.requests if r[1].startswith("/signed/")]
        self.assertEqual(len(signed), 2)
        self.assertTrue(all("Authorization" not in h for _, _, h in signed))
        st = self.saved()["openai_clp"]["AUTH_LOG"]
        self.assertEqual(c._parse_time(st["after"]), c._parse_time(iso(t2)))
        # A second run finds no newer files and sends nothing.
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])

    def test_signed_url_and_its_redirects_must_be_https(self):
        # The signed URL is a credential, so it only goes out over https (plain http to this
        # machine is allowed for these tests), and so does any redirect it answers with.
        self.add_clp_files()
        for first, second in (("ftp://127.0.0.1:1/clf-1.jsonl", None), (None, "ftp://127.0.0.1:1/clf-1.jsonl")):
            with self.subTest(first=first, second=second):
                self.mock.download_location, self.mock.signed_redirect = first, second
                with self.assertRaisesRegex(c.BridgeError, "https"):
                    c.run_once(c.load_config(self.clp_env()))
                self.assertEqual(self.sent(), [])
                self.assertNotIn(SIGNATURE, self.log.getvalue())

    def test_signed_file_cut_short_is_retried_and_never_moves_the_cursor(self):
        # A log file cut short at a line break reads as whole JSON lines with records missing. The
        # download is retried until it arrives whole, so every record is sent.
        t2 = self.add_clp_files()
        cfg = c.load_config(self.clp_env(OPENAI_CLP_EVENT_TYPES="AUTH_LOG"))
        self.mock.signed_short = 2
        c.run_once(cfg)
        self.assertEqual([r["event_id"] for r in self.sent()], ["e1", "e2", "e3"])
        self.assertEqual(c._parse_time(self.saved()["openai_clp"]["AUTH_LOG"]["after"]), c._parse_time(iso(t2)))
        # Cut short on every try: the run stops with a network error, nothing from the file is
        # sent, and the cursor stays where the last whole file left it.
        t3 = t2 + timedelta(minutes=10)
        self.mock.clp_files.append({"id": "clf-5", "event_type": "AUTH_LOG", "end_time": iso(t3),
                                    "records": [clp_auth("e4", iso(t3 - timedelta(minutes=2))), clp_auth("e5", iso(t3))]})
        self.mock.ingested.clear()
        self.mock.signed_short = 10 ** 6
        with self.assertRaises(c.NetworkError) as caught:
            c.run_once(cfg)
        self.assertEqual(self.sent(), [])
        self.assertEqual(c._parse_time(self.saved()["openai_clp"]["AUTH_LOG"]["after"]), c._parse_time(iso(t2)))
        self.assertTrue(str(caught.exception).startswith("signed file download to "), str(caught.exception))
        self.assertNotIn(SIGNATURE, self.log.getvalue() + str(caught.exception))

    def test_signed_url_failures_name_the_api_redirect_not_a_url_setting(self):
        # The signed file URL comes from the API's redirect, not from a setting, so its errors don't
        # say to check the URL setting: a host name that doesn't resolve says where the name came
        # from, and a 501 or 505 says what the code means.
        self.add_clp_files()
        self.mock.download_location = f"https://files.example.com/signed/clf-1?sig={SIGNATURE}"
        cfg = c.load_config(self.clp_env(OPENAI_CLP_EVENT_TYPES="AUTH_LOG"))
        failures = (
            (lambda url: c.urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "test lookup failure")), c.HostNotFound,
             "signed file download to files.example.com failed: the host name in the signed URL the API redirected to wasn't found"),
            (lambda url: c.urllib.error.HTTPError(url, 501, "test status", c.http.client.HTTPMessage(), io.BytesIO(b"{}")), c.BridgeError,
             "signed file download to files.example.com failed with HTTP 501: the server doesn't support this request, "
             "and a retry won't change that"),
        )
        for error, kind, message in failures:
            with self.subTest(message=message):
                def fail(req, *args, **kwargs):
                    raise error(req.full_url)
                c._HTTPS_REDIRECT.open = fail
                try:
                    with self.assertRaises(kind) as caught:
                        c.run_once(cfg)
                finally:
                    del c._HTTPS_REDIRECT.open
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(self.sent(), [])
                self.assertNotIn(SIGNATURE, self.log.getvalue())

    def test_clp_conversation_redacted_by_default(self):
        self.add_clp_files()
        c.run_once(c.load_config(self.clp_env(OPENAI_CLP_EVENT_TYPES="CONVERSATION_MESSAGE,CODEX_LOG")))
        msg, codex = self.sent()
        self.assertEqual(msg["message"]["content"]["value"], c.REDACTED)
        self.assertEqual(msg["message"]["content"]["type"], "text")
        self.assertEqual(msg["message"]["content"]["annotations"][0]["urls"], [c.REDACTED])
        self.assertEqual(msg["message"]["files"], [{"id": "file-1", "name": c.REDACTED}])
        self.assertEqual(msg["message"]["author"]["applied_custom_instructions"], c.REDACTED)
        self.assertEqual(msg["message"]["author"]["model"], "gpt-5-2-pro")
        self.assertEqual(msg["conversation"]["title"], c.REDACTED)
        self.assertEqual(msg["conversation"]["id"], "convo-1")
        # Other log types keep the envelope and IDs; every other string is redacted.
        self.assertEqual(codex["actor"]["user_email"], "alice@example.com")
        self.assertEqual(codex["codex"]["task_id"], "task-1")
        self.assertEqual(codex["codex"]["prompt"], c.REDACTED)
        self.assertEqual(codex["codex"]["output"]["text"], c.REDACTED)
        self.assertEqual(codex["codex"]["output"]["status"], "completed")
        self.assertNotIn("Summarize", json.dumps(self.mock.ingested))

    def test_clp_redaction_off(self):
        self.add_clp_files()
        c.run_once(c.load_config(self.clp_env(OPENAI_CLP_EVENT_TYPES="CONVERSATION_MESSAGE", BRIDGE_REDACT="0")))
        (msg,) = self.sent()
        self.assertEqual(msg["message"]["content"]["value"], "Summarize the example plan.")
        self.assertEqual(msg["conversation"]["title"], "Example plan")

    def test_clp_audit_instructions_redacted(self):
        now = datetime.now(timezone.utc)
        rec = {"event_id": "a1", "type": "AUDIT_LOG", "timestamp": iso(now), "principal": {"id": WS, "type": "CHATGPT_WORKSPACE"},
               "actor": {"type": "ACCOUNT_USER", "user_id": "user-admin", "user_email": "bob@example.com"},
               "action": "WORKSPACE_SET_SYSTEM_INSTRUCTION", "action_result": "SUCCESS", "action_privilege": "ADMIN",
               "action_data": {"system_instruction": "Internal prompt text"}}
        self.mock.clp_files = [{"id": "clf-a", "event_type": "AUDIT_LOG", "end_time": iso(now), "records": [rec]}]
        c.run_once(c.load_config(self.clp_env(OPENAI_CLP_EVENT_TYPES="AUDIT_LOG")))
        (out,) = self.sent()
        self.assertEqual(out["action_data"]["system_instruction"], c.REDACTED)
        self.assertEqual(out["action"], "WORKSPACE_SET_SYSTEM_INSTRUCTION")

    def test_clp_list_pagination(self):
        now = datetime.now(timezone.utc)
        self.mock.clp_files = [{"id": f"clf-{i:03d}", "event_type": "AUTH_LOG", "end_time": iso(now - timedelta(minutes=300 - i)),
                                "records": [clp_auth(f"p{i}", iso(now - timedelta(minutes=301 - i)))]} for i in range(150)]
        c.run_once(c.load_config(self.clp_env()))
        self.assertEqual(len(self.sent()), 150)
        lists = [r for r in self.mock.requests if r[1].startswith(f"/v1/compliance/workspaces/{WS}/logs?event_type=AUTH_LOG")]
        self.assertEqual(len(lists), 2)

    # ------------------------------------------------------------ OpenAI API Platform audit logs

    def test_openai_audit_paging_and_overlap_dedupe(self):
        now = int(datetime.now(timezone.utc).timestamp())
        def ev(i, t):
            return {"id": f"audit_log-{i:04d}", "type": "api_key.created", "effective_at": t,
                    "actor": {"type": "session", "session": {"user": {"id": "user-1", "email": "alice@example.com"}, "ip_address": "203.0.113.24"}},
                    "api_key.created": {"id": f"key_{i}", "data": {"scopes": ["api.model.read"]}}}
        self.mock.audit = [ev(i, now - 3600 + i * 10) for i in range(250)]
        cfg = c.load_config(self.env(BRIDGE_SOURCES="openai_audit", OPENAI_ADMIN_KEY=OPENAI_ADMIN_KEY))
        c.run_once(cfg)
        sent = self.sent()
        self.assertEqual(len(sent), 250)
        self.assertEqual([r["effective_at"] for r in sent], sorted(r["effective_at"] for r in sent))
        # A later run re-reads the overlap window but sends only the new event.
        self.mock.ingested.clear()
        self.mock.audit.append(ev(999, now - 3600 + 2500))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], ["audit_log-0999"])

    # ------------------------------------------------------------ Anthropic Activity Feed

    def act(self, i, when, typ="claude_chat_created", **fields):
        d = {"id": f"activity_{i:06d}", "created_at": iso(when), "organization_id": "org_example", "organization_uuid": WS,
             "actor": {"type": "user_actor", "email_address": "alice@example.com", "user_id": "user_1", "ip_address": "203.0.113.24", "user_agent": "Mozilla/5.0"},
             "type": typ}
        d.update(fields)
        return d

    def test_anthropic_window_paging_dedupe_and_redaction(self):
        now = datetime.now(timezone.utc)
        self.mock.activities = [self.act(i, now - timedelta(minutes=120) + timedelta(seconds=i)) for i in range(1500)]
        self.mock.activities.append(self.act(5000, now - timedelta(minutes=30), "compliance_api_accessed",
                                             request_method="GET", status_code=200, url="/v1/compliance/activities", request_body="{\"q\":1}"))
        # Inside the next run's overlap window, so it is read twice but must be sent once.
        self.mock.activities.append(self.act(7000, now - timedelta(seconds=100)))
        # Not queryable yet: inside the settle window, so the first run must leave it.
        self.mock.activities.append(self.act(6000, now - timedelta(seconds=5)))
        cfg = c.load_config(self.env(BRIDGE_SOURCES="anthropic", ANTHROPIC_COMPLIANCE_KEY=ANTHROPIC_KEY))
        c.run_once(cfg)
        sent = self.sent()
        self.assertEqual(len(sent), 1502)
        api = next(r for r in sent if r["type"] == "compliance_api_accessed")
        self.assertEqual(api["request_body"], c.REDACTED)
        self.assertNotIn("activity_006000", [r["id"] for r in sent])
        pages = [r for r in self.mock.requests if r[1].startswith("/v1/compliance/activities")]
        self.assertEqual(len(pages), 2)
        # The next run re-reads the overlap and sends only the activity it has not sent.
        self.mock.ingested.clear()
        cfg = c.load_config(self.env(BRIDGE_SOURCES="anthropic", ANTHROPIC_COMPLIANCE_KEY=ANTHROPIC_KEY,
                                     ANTHROPIC_SETTLE_SECONDS="0"))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], ["activity_006000"])

    # ------------------------------------------------------------ HTTP Ingest

    def test_dry_run_prints_and_changes_nothing(self):
        self.add_clp_files()
        out = io.StringIO()
        cfg = c.load_config(self.clp_env(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""))
        c.run_once(cfg, dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([r["event_id"] for r in lines], ["e1", "e2", "e3"])
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_ingest_retries_429_then_succeeds(self):
        self.add_clp_files()
        self.mock.ingest_codes = [429, 503]
        c.run_once(c.load_config(self.clp_env()))
        self.assertEqual([r["event_id"] for r in self.sent()], ["e1", "e2", "e3"])

    def test_ingest_401_stops_without_moving_the_cursor(self):
        self.add_clp_files()
        cfg = c.load_config(self.clp_env(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        with self.assertRaises(c.BridgeError):
            c.run_once(cfg)
        self.assertFalse(os.path.exists(self.state))
        posts = [r for r in self.mock.requests if r[0] == "POST"]
        self.assertEqual(len(posts), 1)

    def test_ingest_format_gzip_and_batches(self):
        self.add_clp_files()
        c.run_once(c.load_config(self.clp_env(BRIDGE_BATCH_BYTES="500")))
        self.assertEqual(len(self.mock.ingested), 3)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Type"], "application/json")
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Authorization"], f"Bearer {INGEST_KEY}")
        c.run_once(c.load_config(self.clp_env(BRIDGE_GZIP="0", BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "s2.json"))))
        self.assertNotIn("Content-Encoding", self.mock.ingested[-1]["headers"])

    def test_secrets_never_logged(self):
        self.add_clp_files()
        self.mock.ingest_codes = [429]
        now = int(datetime.now(timezone.utc).timestamp())
        self.mock.audit = [{"id": "audit_log-1", "type": "login.succeeded", "effective_at": now - 60, "actor": {"type": "session"}, "login.succeeded": {}}]
        c.run_once(c.load_config(self.env(OPENAI_COMPLIANCE_API_KEY=CLP_KEY, OPENAI_CLP_PRINCIPAL_ID=WS,
                                          OPENAI_ADMIN_KEY=OPENAI_ADMIN_KEY, ANTHROPIC_COMPLIANCE_KEY=ANTHROPIC_KEY)))
        logged = self.log.getvalue()
        self.assertIn("openai_clp AUTH_LOG", logged)
        for secret in (CLP_KEY, OPENAI_ADMIN_KEY, ANTHROPIC_KEY, INGEST_KEY, SIGNATURE, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_missing_values(self):
        with self.assertRaises(c.BridgeError):
            c.load_config({"NGSIEM_INGEST_URL": "http://ingest.example.com/http-endpoint/v1/x", "ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY})
        with self.assertRaises(c.BridgeError):
            c.load_config({"ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY, "ANTHROPIC_BASE_URL": "http://api.example.com"})
        with self.assertRaises(c.BridgeError):
            c.load_config({"OPENAI_COMPLIANCE_API_KEY": CLP_KEY})
        with self.assertRaises(c.BridgeError):
            c.Sink(c.load_config({"ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY}), dry_run=False)
        self.assertEqual(c.load_config({"OPENAI_ADMIN_KEY": OPENAI_ADMIN_KEY})["sources"], ["openai_audit"])

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.add_clp_files()
        r = Redirects()
        try:
            cases = {"HTTP Ingest": c.load_config(self.clp_env(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration")),
                     "OpenAI Compliance Logs Platform": c.load_config(self.clp_env(OPENAI_CLP_BASE_URL=f"{r.base}/v1")),
                     "OpenAI audit logs": c.load_config(self.env(BRIDGE_SOURCES="openai_audit", OPENAI_ADMIN_KEY=OPENAI_ADMIN_KEY, OPENAI_API_BASE_URL=f"{r.base}/v1")),
                     "Anthropic Compliance API": c.load_config(self.env(BRIDGE_SOURCES="anthropic", ANTHROPIC_COMPLIANCE_KEY=ANTHROPIC_KEY, ANTHROPIC_BASE_URL=r.base))}
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

    def test_openai_audit_event_dated_in_the_future_leaves_the_cursor_at_now(self):
        # A wrong clock can date an event years ahead. The cursor stays at the run's time, so a
        # later run still collects the events that come after it.
        now = int(datetime.now(timezone.utc).timestamp())
        def ev(i, t):
            return {"id": f"audit_log-{i:04d}", "type": "login.succeeded", "effective_at": t,
                    "actor": {"type": "session"}, "login.succeeded": {}}
        self.mock.audit = [ev(1, now + 10 * 365 * 86400)]
        cfg = c.load_config(self.env(BRIDGE_SOURCES="openai_audit", OPENAI_ADMIN_KEY=OPENAI_ADMIN_KEY))
        c.run_once(cfg)
        self.assertLessEqual(self.saved()["openai_audit"]["since"], int(datetime.now(timezone.utc).timestamp()))
        self.mock.ingested.clear()
        self.mock.audit.append(ev(2, now + 5))
        c.run_once(cfg)
        self.assertEqual([r["id"] for r in self.sent()], ["audit_log-0002"])

    def request_sized(self, size, code=200, **kwargs):
        """_request against a server whose answer has a body of `size` bytes, with the cap at 1 MB.
        Fails if the bridge hasn't closed the connection by the time _request returns or raises."""
        saved, c.MAX_RESPONSE_BYTES = c.MAX_RESPONSE_BYTES, 1024 * 1024
        server = Sized(size, code)
        try:
            return c._request("GET", f"{server.base}/x", {}, None, 5.0, what="test request", **kwargs)
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

    def test_redirect_response_over_the_limit_stops_the_run(self):
        # The one error body this bridge reads is a redirect it hands back to the caller.
        for size in (1024 * 1024 + 1, 2 * 1024 * 1024):
            with self.subTest(size=size), self.assertRaisesRegex(c.BridgeError, "sent more than 1 MB"):
                self.request_sized(size, code=307, redirects="return")

    def test_signed_file_download_has_its_own_larger_limit(self):
        # Log files can be much larger than an API page, so only the signed download may go up to
        # MAX_FILE_BYTES; every other request keeps MAX_RESPONSE_BYTES.
        now = datetime.now(timezone.utc)
        big = dict(clp_auth("big-1", iso(now)), padding=" " * (1536 * 1024))
        self.mock.clp_files = [{"id": "clf-big", "event_type": "AUTH_LOG", "end_time": iso(now), "records": [big]}]
        url = f"{self.base}/v1/compliance/workspaces/{WS}/logs/clf-big"
        auth = {"Authorization": f"Bearer {CLP_KEY}"}
        saved = c.MAX_RESPONSE_BYTES, c.MAX_FILE_BYTES
        c.MAX_RESPONSE_BYTES, c.MAX_FILE_BYTES = 1024 * 1024, 2 * 1024 * 1024
        try:
            self.assertEqual(c._download_clp_file(url, auth, 5.0), [big])
            with self.assertRaisesRegex(c.BridgeError, "sent more than 1 MB"):
                c._get_json(f"{self.base}/signed/clf-big?sig={SIGNATURE}", {}, 5.0, "test request")
            c.MAX_FILE_BYTES = 1024 * 1024
            with self.assertRaisesRegex(c.BridgeError, "^signed file download to .* sent more than 1 MB"):
                c._download_clp_file(url, auth, 5.0)
        finally:
            c.MAX_RESPONSE_BYTES, c.MAX_FILE_BYTES = saved

    def test_bad_numbers_stop_with_one_plain_error(self):
        for name, _, _, _, cast, high in NUMBERS:
            for value in ["abc", "nan", "inf", "-1", str(high + 1)] + (["1.5"] if cast is int else []):
                with self.subTest(name=name, value=value), self.assertRaisesRegex(c.BridgeError, f"^{name} "):
                    c.load_config(self.env(**{name: value}))

    def test_numbers_still_load(self):
        for name, key, default, normal, cast, _ in NUMBERS:
            for extra, expected in (({}, default), ({name: str(normal)}, normal)):
                with self.subTest(name=name, extra=extra):
                    value = c.load_config(self.env(**extra))
                    for part in key.split("."):
                        value = value[part]
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
        env = {"ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY}
        env.update(extra)
        return c.load_config(env)

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config({"ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY})
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

    def test_no_source_still_stops_the_bridge(self):
        self.cfg = dict(self.cfg, sources=[])
        self.run_once_raises()
        self.assertEqual(c.main(["--interval", "5"]), 1)
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
