"""Unit tests for ai_compliance_collector.py against a local mock server.

The mock serves the response shapes documented by OpenAI (Compliance Logs Platform, audit
logs) and Anthropic (Compliance API Activity Feed), plus a Sophos NG-SIEM HTTP Ingest
endpoint. No real service is called.

  python3 -m unittest discover -s collectors/ai-compliance-logs -p 'test_*.py' -v
"""
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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ai_compliance_collector as c  # noqa: E402

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
                return self._send(307, b"", headers={"Location": f"/signed/{f['id']}?sig={SIGNATURE}"})
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
            f = next(f for f in m.clp_files if f["id"] == parts[1])
            return self._send(200, "".join(json.dumps(r) + "\n" for r in f["records"]).encode(), "application/jsonl")
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


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.mock = Mock()
        handler = type("H", (Handler,), {"mock": self.mock})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
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

    def env(self, **extra):
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration",
             "NGSIEM_INGEST_KEY": INGEST_KEY, "COLLECTOR_STATE_FILE": self.state,
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
        return self.env(COLLECTOR_SOURCES="openai_clp", OPENAI_COMPLIANCE_API_KEY=CLP_KEY,
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
        c.run_once(c.load_config(self.clp_env(OPENAI_CLP_EVENT_TYPES="CONVERSATION_MESSAGE", COLLECTOR_REDACT="0")))
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
        cfg = c.load_config(self.env(COLLECTOR_SOURCES="openai_audit", OPENAI_ADMIN_KEY=OPENAI_ADMIN_KEY))
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
        cfg = c.load_config(self.env(COLLECTOR_SOURCES="anthropic", ANTHROPIC_COMPLIANCE_KEY=ANTHROPIC_KEY))
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
        cfg = c.load_config(self.env(COLLECTOR_SOURCES="anthropic", ANTHROPIC_COMPLIANCE_KEY=ANTHROPIC_KEY,
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
        with self.assertRaises(c.CollectorError):
            c.run_once(cfg)
        self.assertFalse(os.path.exists(self.state))
        posts = [r for r in self.mock.requests if r[0] == "POST"]
        self.assertEqual(len(posts), 1)

    def test_ingest_format_gzip_and_batches(self):
        self.add_clp_files()
        c.run_once(c.load_config(self.clp_env(COLLECTOR_BATCH_BYTES="500")))
        self.assertEqual(len(self.mock.ingested), 3)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Type"], "application/json")
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Authorization"], f"Bearer {INGEST_KEY}")
        c.run_once(c.load_config(self.clp_env(COLLECTOR_GZIP="0", COLLECTOR_STATE_FILE=os.path.join(self.tmp.name, "s2.json"))))
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
        with self.assertRaises(c.CollectorError):
            c.load_config({"NGSIEM_INGEST_URL": "http://ingest.example.com/http-endpoint/v1/x", "ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY})
        with self.assertRaises(c.CollectorError):
            c.load_config({"ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY, "ANTHROPIC_BASE_URL": "http://api.example.com"})
        with self.assertRaises(c.CollectorError):
            c.load_config({"OPENAI_COMPLIANCE_API_KEY": CLP_KEY})
        with self.assertRaises(c.CollectorError):
            c.Sink(c.load_config({"ANTHROPIC_COMPLIANCE_KEY": ANTHROPIC_KEY}), dry_run=False)
        self.assertEqual(c.load_config({"OPENAI_ADMIN_KEY": OPENAI_ADMIN_KEY})["sources"], ["openai_audit"])


if __name__ == "__main__":
    unittest.main()
