"""Unit tests for webhook_relay.py against a local mock of HTTP Ingest.

Deliveries are signed the way each vendor documents it: Svix for Huntress (HMAC-SHA256 over
"<id>.<timestamp>.<body>", base64, "v1," prefix), X-Hook-Signature for Autotask (HMAC-SHA1 over
the body, base64, "sha1=" prefix), X-Mist-Signature-v2 for Juniper Mist (HMAC-SHA256 over the
body, hex), and a secret in the path for Hudu, ScreenConnect and FortiCNAPP. The bodies are lines
from the library entries' samples.log, Mist batches in the shape of Mist's webhook samples, and a
FortiCNAPP alert indented as in Fortinet's example. No real service is called.

  python3 -m unittest discover -s bridges/webhook-relay -p 'test_*.py' -v
"""
import base64
import contextlib
import gc
import hashlib
import hmac
import http.client
import io
import json
import logging
import os
import socket
import sys
import threading
import time
import unittest
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webhook_relay as r  # noqa: E402

HUNTRESS_KEY = b"test-huntress-signing-key-not-real"
HUNTRESS_SECRET = "whsec_" + base64.b64encode(HUNTRESS_KEY).decode()
AUTOTASK_KEY = "test-autotask-secret-key-not-real-000000"
HUDU_SECRET = "test-hudu-path-secret-not-real-0000000000"
SCREENCONNECT_SECRET = "test-screenconnect-path-secret-not-real-00"
MIST_SECRET = "test-mist-webhook-secret-not-real-000000"
FORTICNAPP_SECRET = "test-forticnapp-path-secret-not-real-000"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
INGEST_PATH = "/http-endpoint/v1/00000000-example-integration"

HUNTRESS_BODY = (b'{"event_type":"incident_report.created","id":1820044,"account":{"id":4821,"name":"Example MSP"},'
                 b'"organization":{"id":91234,"name":"Acme Dental"},"agent_id":5520317,"platform":"windows",'
                 b'"severity":"critical","status":"sent","subject":"CRITICAL - Incident on ACME-WS-014 (Acme Dental)",'
                 b'"summary":"Huntress detected hands-on-keyboard activity.","body":"<p>Remote access tool.</p>",'
                 b'"indicator_counts":{"footholds":1},"api_url":"https://api.example.com/v1/incident_reports/1820044",'
                 b'"created_at":"2026-10-12T11:38:52Z","sent_at":"2026-10-12T11:40:11Z","updated_at":"2026-10-12T11:40:11Z",'
                 b'"status_updated_at":"2026-10-12T11:40:11Z","closed_at":null}')
AUTOTASK_BODY = (b'{"Action":"Update","Guid":"0a7c3e91-2b5d-4f8e-a6c1-9d4b2e7f1a08","EntityType":"Contact","Id":30544120,'
                 b'"Fields":{"EMailAddress":"billing@example.com","Phone":"02 5550 1234"},"EventTime":"2026-10-12T11:42:05Z",'
                 b'"SequenceNumber":149,"PersonID":29682885}')
HUDU_BODY = (b'{"source":"Hudu","alert":"record","action":"update","record_type":"AssetPassword",'
             b'"record_name":"Acme Dental - Domain Admin","record_id":"4412","company_name":"Acme Dental","company_id":"31",'
             b'"user":"Alex Kim","url":"https://docs.example.com/a/4412","asset_layout_id":""}')
MIST_EVENTS = [
    {"admin_name": "Sam Admin sam.admin@example.com", "id": "8e00dd48-b918-4d9b-9a1c-000000000001", "message": "Update Site Settings",
     "org_id": "2818e386-8dec-2562-9a1c-000000000001", "site_id": "4ac1dcf4-9d8b-7211-9a1c-000000000001", "src_ip": "203.0.113.20",
     "timestamp": 1791853804.201053},
    {"admin_name": "Sam Admin sam.admin@example.com", "id": "8e00dd48-b918-4d9b-9a1c-000000000002", "message": "Update Device \"Reception\"",
     "org_id": "2818e386-8dec-2562-9a1c-000000000001", "device_id": "00000000-0000-0000-1000-5c5b35000001",
     "src_ip": "203.0.113.20", "timestamp": 1791853806.5},
]
MIST_BATCH = json.dumps({"topic": "audits", "events": MIST_EVENTS}).encode()
MIST_ONE = json.dumps({"topic": "audits", "events": MIST_EVENTS[:1]}, separators=(",", ":")).encode()
SCREENCONNECT_BODY = (b"ScreenConnect|category=Security|event=LoginAttempt|result=PasswordInvalid|time=10/12/2026 10:41:02 PM"
                      b"|user=admin|source=Internal|address=203.0.113.45")
# FortiCNAPP posts one alert per request; Fortinet's example shows it indented over several lines.
FORTICNAPP_ALERT = {
    "event_title": "Unauthorized API Call", "event_link": "https://example.lacework.net/ui/investigate/Event/120885?startTime=1792008000000&endTime=1792011600000",
    "lacework_account": "example", "event_source": "AWS",
    "event_description": "User jsmith made an unauthorized call to ec2:DescribeInstances from 203.0.113.50",
    "event_timestamp": "14 Oct 2026 09:05 GMT", "event_type": "CloudActivity", "event_id": "120885", "event_severity": "3"}
FORTICNAPP_BODY = json.dumps(FORTICNAPP_ALERT, indent=1).encode() + b"\n"


def svix_headers(body, key=HUNTRESS_KEY, msg_id="msg_2Qx7example000000000000", stamp=None, prefix="svix-", extra_sigs=()):
    stamp = str(int(time.time()) if stamp is None else stamp)
    sig = base64.b64encode(hmac.new(key, f"{msg_id}.{stamp}.".encode() + body, hashlib.sha256).digest()).decode()
    return {f"{prefix}id": msg_id, f"{prefix}timestamp": stamp, f"{prefix}signature": " ".join([*extra_sigs, f"v1,{sig}"])}


def mist_headers(body, key=MIST_SECRET):
    return {"Content-Type": "application/json", "User-Agent": "Mist-webhook",
            "X-Mist-Signature-v2": hmac.new(key.encode(), body, hashlib.sha256).hexdigest(),
            "X-Mist-Signature": hmac.new(key.encode(), body, hashlib.sha1).hexdigest()}


def autotask_headers(body, key=AUTOTASK_KEY):
    return {"X-Hook-Signature": "sha1=" + base64.b64encode(hmac.new(key.encode(), body, hashlib.sha1).digest()).decode()}


class Ingest:
    """Records what reaches the mock HTTP Ingest endpoint and answers with scripted codes."""

    def __init__(self):
        self.codes = []
        self.retry_after = "0"
        self.received = []
        self.other = []
        self.short = 0  # replies to cut short of their Content-Length after taking the delivery


class IngestHandler(BaseHTTPRequestHandler):
    ingest: Ingest = None

    def log_message(self, *a):
        pass

    def _send(self, code, headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        m = self.ingest
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != INGEST_PATH:
            m.other.append(("POST", self.path, dict(self.headers)))
            return self._send(404)
        if self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._send(401)
        if m.codes:
            code = m.codes.pop(0)
            if code == 302:
                return self._send(302, {"Location": "/elsewhere"})
            if code != 200:
                return self._send(code, {"Retry-After": m.retry_after})
        m.received.append({"headers": dict(self.headers), "body": body})
        if m.short:
            # The connection closes before the reply reaches its Content-Length.
            m.short -= 1
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self._send(200)

    def do_GET(self):
        self.ingest.other.append(("GET", self.path, dict(self.headers)))
        self._send(404)


class RelayTest(unittest.TestCase):
    def setUp(self):
        # A test that leaves a socket or file open fails: tearDown collects garbage and checks
        # for ResourceWarnings. Other warnings print as usual.
        self.leaks = []
        self._warnings = warnings.catch_warnings()
        self._warnings.__enter__()
        warnings.simplefilter("always", ResourceWarning)
        show = warnings.showwarning
        warnings.showwarning = lambda m, c, *a, **k: self.leaks.append(str(m)) if issubclass(c, ResourceWarning) else show(m, c, *a, **k)
        self.ingest = Ingest()
        self.ingest_server = ThreadingHTTPServer(("127.0.0.1", 0), type("H", (IngestHandler,), {"ingest": self.ingest}))
        threading.Thread(target=self.ingest_server.serve_forever, args=(0.05,), daemon=True).start()
        self.ingest_url = f"http://127.0.0.1:{self.ingest_server.server_address[1]}{INGEST_PATH}"
        self.log = io.StringIO()
        self.handler = logging.StreamHandler(self.log)
        r.LOG.addHandler(self.handler)
        r.LOG.setLevel(logging.DEBUG)
        self._sleep = r.time.sleep
        r.time.sleep = lambda s: None
        self.relay = None

    def tearDown(self):
        r.time.sleep = self._sleep
        r.LOG.removeHandler(self.handler)
        if self.relay:
            self.relay.shutdown()
            self.relay.server_close()
        self.ingest_server.shutdown()
        self.ingest_server.server_close()
        gc.collect()
        self._warnings.__exit__(None, None, None)
        self.assertEqual(self.leaks, [], "a socket or file was left open")

    def env(self, **extra):
        e = {"NGSIEM_INGEST_URL": self.ingest_url, "NGSIEM_INGEST_KEY": INGEST_KEY, "BRIDGE_LISTEN_PORT": "0",
             "HUNTRESS_SIGNING_SECRET": HUNTRESS_SECRET, "AUTOTASK_SECRET_KEY": AUTOTASK_KEY,
             "HUDU_PATH_SECRET": HUDU_SECRET, "SCREENCONNECT_PATH_SECRET": SCREENCONNECT_SECRET,
             "MIST_WEBHOOK_SECRET": MIST_SECRET, "FORTICNAPP_PATH_SECRET": FORTICNAPP_SECRET}
        e.update(extra)
        return {k: v for k, v in e.items() if v is not None}

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The relay stops at startup and doesn't show them.
        for name in ("NGSIEM_INGEST_URL",):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(r.RelayError) as caught:
                        r.load_config(self.env(**{name: url}))
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the relay can't use; remove it")

    def start(self, dry_run=False, out=None, **extra):
        self.relay = r.make_server(r.load_config(self.env(**extra)), dry_run, out)
        threading.Thread(target=self.relay.serve_forever, args=(0.05,), daemon=True).start()

    def post(self, path, body=b"", headers=None, length=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.relay.server_address[1], timeout=10)
        try:
            conn.putrequest("POST", path, skip_accept_encoding=True)
            for k, v in (headers or {}).items():
                conn.putheader(k, v)
            if length is True:
                conn.putheader("Content-Length", str(len(body)))
            elif length is not None:
                conn.putheader("Content-Length", str(length))
            conn.endheaders()
            if body:
                try:
                    conn.send(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            resp = conn.getresponse()
            return resp.status, resp.read().decode()
        finally:
            conn.close()

    def bodies(self):
        return [x["body"] for x in self.ingest.received]

    # -------------------------------------------------------------- Huntress (Svix)

    def test_huntress_valid_signature_forwards_body_unchanged_with_bearer(self):
        self.start()
        status, _ = self.post("/huntress", HUNTRESS_BODY, {"Content-Type": "application/json", **svix_headers(HUNTRESS_BODY)})
        self.assertEqual(status, 200)
        self.assertEqual(self.bodies(), [HUNTRESS_BODY])
        sent = self.ingest.received[0]["headers"]
        self.assertEqual(sent["Authorization"], f"Bearer {INGEST_KEY}")
        self.assertEqual(sent["Content-Type"], "application/json")
        # Svix headers stay with the relay.
        self.assertFalse(any(k.lower().startswith("svix-") for k in sent))

    def test_huntress_webhook_prefix_and_several_signatures(self):
        self.start()
        h = svix_headers(HUNTRESS_BODY, prefix="webhook-", extra_sigs=("v1,bm90LXRoZS1zaWduYXR1cmU=", "v1a,ignored"))
        self.assertEqual(self.post("/huntress", HUNTRESS_BODY, h)[0], 200)
        self.assertEqual(self.bodies(), [HUNTRESS_BODY])

    def test_huntress_rejects_unverified_deliveries(self):
        self.start()
        good = svix_headers(HUNTRESS_BODY)
        cases = {
            "wrong key": svix_headers(HUNTRESS_BODY, key=b"some-other-signing-key-000000000"),
            "tampered body": svix_headers(HUNTRESS_BODY.replace(b"critical", b"low")),
            "stale timestamp": svix_headers(HUNTRESS_BODY, stamp=int(time.time()) - 600),
            "future timestamp": svix_headers(HUNTRESS_BODY, stamp=int(time.time()) + 600),
            "other id": {**good, "svix-id": "msg_other"},
            "no signature": {k: v for k, v in good.items() if k != "svix-signature"},
            "no headers": {},
            "bad timestamp": {**good, "svix-timestamp": "yesterday"},
            "unknown version": {**good, "svix-signature": good["svix-signature"].replace("v1,", "v2,")},
        }
        for name, headers in cases.items():
            with self.subTest(name):
                self.assertEqual(self.post("/huntress", HUNTRESS_BODY, headers)[0], 401)
        self.assertEqual(self.bodies(), [])
        self.assertIn("timestamp is more than 5 minutes", self.log.getvalue())

    def test_huge_timestamp_and_deeply_nested_json_get_a_4xx_and_one_log_line(self):
        # Neither may end the request with a traceback and no answer.
        self.start()
        errors = io.StringIO()
        stderr, sys.stderr = sys.stderr, errors
        try:
            for stamp in ("9" * 400, "-" + "9" * 400):
                with self.subTest(stamp=stamp[:5]):
                    self.assertEqual(self.post("/huntress", HUNTRESS_BODY, svix_headers(HUNTRESS_BODY, stamp=stamp))[0], 401)
            deep = b"[" * 100000 + b"]" * 100000
            deliveries = {
                "huntress": ("/huntress", svix_headers(deep)),
                "autotask": ("/autotask", autotask_headers(deep)),
                "hudu": (f"/hudu/{HUDU_SECRET}", {}),
            }
            for name, (path, headers) in deliveries.items():
                with self.subTest(name):
                    self.assertEqual(self.post(path, deep, headers), (400, "body can't be read\n"))
        finally:
            sys.stderr = stderr
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(self.bodies(), [])
        lines = self.log.getvalue().splitlines()
        self.assertEqual(len([l for l in lines if "timestamp is more than 5 minutes" in l]), 2)
        self.assertEqual(len([l for l in lines if "nested too deeply" in l]), 3)

    def test_json_one_level_past_the_depth_limit_is_refused(self):
        # A depth every Python parses, so the 400 comes from the relay's limit, not RecursionError.
        self.start()
        limit = r.MAX_JSON_DEPTH
        at_limit = b'{"a":' * (limit - 1) + b"[1]" + b"}" * (limit - 1)
        past = b'{"a":' * limit + b"[1]" + b"}" * limit
        path = f"/hudu/{HUDU_SECRET}"
        self.assertEqual(self.post(path, past), (400, "body can't be read\n"))
        self.assertEqual(self.post(path, at_limit)[0], 200)
        self.assertEqual(self.bodies(), [at_limit])
        self.assertEqual(len([l for l in self.log.getvalue().splitlines() if "nested too deeply" in l]), 1)
        batch = json.dumps({"topic": "audits", "events": [json.loads(past), {"a": 1}]}).encode()
        with self.assertRaises(r.BodyError):
            r.split_batch(batch)

    # -------------------------------------------------------------- Autotask

    def test_autotask_valid_signature_forwards(self):
        self.start()
        self.assertEqual(self.post("/autotask", AUTOTASK_BODY, autotask_headers(AUTOTASK_BODY))[0], 200)
        self.assertEqual(self.bodies(), [AUTOTASK_BODY])
        self.assertEqual(self.ingest.received[0]["headers"]["Content-Type"], "application/json")

    def test_autotask_rejects_unverified_deliveries(self):
        self.start()
        hexsig = "sha1=" + hmac.new(AUTOTASK_KEY.encode(), AUTOTASK_BODY, hashlib.sha1).hexdigest()
        cases = {
            "wrong key": autotask_headers(AUTOTASK_BODY, key="another-autotask-secret-key-0000000000"),
            "tampered body": autotask_headers(AUTOTASK_BODY.replace(b"Update", b"Delete")),
            "hex digest": {"X-Hook-Signature": hexsig},
            "missing": {},
            "empty": {"X-Hook-Signature": "sha1="},
        }
        for name, headers in cases.items():
            with self.subTest(name):
                self.assertEqual(self.post("/autotask", AUTOTASK_BODY, headers)[0], 401)
        self.assertEqual(self.bodies(), [])

    # -------------------------------------------------------------- Hudu and ScreenConnect (path secret)

    def test_hudu_path_secret_forwards(self):
        self.start()
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY, {"Content-Type": "application/json"})[0], 200)
        self.assertEqual(self.bodies(), [HUDU_BODY])

    def test_wrong_or_missing_path_secret_is_404(self):
        self.start()
        for path in ("/hudu", "/hudu/", f"/hudu/{HUDU_SECRET[:-1]}", f"/hudu/{HUDU_SECRET}x", f"/hudu/{SCREENCONNECT_SECRET}",
                     f"/hudu/{HUDU_SECRET}/extra", "/screenconnect", f"/screenconnect/{HUDU_SECRET}", "/forticnapp",
                     f"/forticnapp/{HUDU_SECRET}", f"/forticnapp/{FORTICNAPP_SECRET}x", f"/forticnapp?api-token={FORTICNAPP_SECRET}",
                     f"/forticnapp/?api-token={FORTICNAPP_SECRET}"):
            with self.subTest(path):
                self.assertEqual(self.post(path, HUDU_BODY)[0], 404)
        self.assertEqual(self.bodies(), [])

    def test_screenconnect_text_body_and_multiline_data_on_one_line(self):
        self.start()
        path = f"/screenconnect/{SCREENCONNECT_SECRET}"
        self.assertEqual(self.post(path, SCREENCONNECT_BODY, {"Content-Type": "text/plain"})[0], 200)
        multi = (b"ScreenConnect|category=Session|event=RanCommand|time=10/12/2026 10:46:05 PM|session_type=Access|data=line one\r\n"
                 b"line two\nline three\r\n")
        self.assertEqual(self.post(path, multi, {"Content-Type": "text/plain"})[0], 200)
        self.assertEqual(self.bodies()[0], SCREENCONNECT_BODY)
        self.assertEqual(self.bodies()[1], b"ScreenConnect|category=Session|event=RanCommand|time=10/12/2026 10:46:05 PM"
                                           b"|session_type=Access|data=line one\\nline two\\nline three")
        for post in self.ingest.received:
            self.assertEqual(post["headers"]["Content-Type"], "text/plain")

    def test_forticnapp_path_secret_forwards_an_indented_alert_on_one_line(self):
        self.start()
        status, _ = self.post(f"/forticnapp/{FORTICNAPP_SECRET}", FORTICNAPP_BODY, {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        sent = self.bodies()[0]
        self.assertNotIn(b"\n", sent)
        self.assertEqual(json.loads(sent), FORTICNAPP_ALERT)
        self.assertEqual(list(json.loads(sent)), list(FORTICNAPP_ALERT))
        headers = self.ingest.received[0]["headers"]
        self.assertEqual((headers["Authorization"], headers["Content-Type"]), (f"Bearer {INGEST_KEY}", "application/json"))
        # A query string after the path secret, such as a token FortiCNAPP's form suggests, changes nothing.
        self.assertEqual(self.post(f"/forticnapp/{FORTICNAPP_SECRET}?api-token=unused", FORTICNAPP_BODY)[0], 200)
        self.assertEqual(self.bodies()[1], sent)
        self.assertIn("forticnapp: forwarded", self.log.getvalue())

    def test_pretty_printed_json_goes_on_one_line_with_the_same_data(self):
        self.start()
        pretty = json.dumps(json.loads(HUNTRESS_BODY), indent=2).encode() + b"\n"
        self.assertEqual(self.post("/huntress", pretty, svix_headers(pretty))[0], 200)
        sent = self.bodies()[0]
        self.assertNotIn(b"\n", sent)
        self.assertEqual(json.loads(sent), json.loads(HUNTRESS_BODY))
        self.assertEqual(list(json.loads(sent)), list(json.loads(HUNTRESS_BODY)))
        # A trailing line break alone doesn't count as a second record, so the body goes on as is.
        self.assertEqual(r.one_record(HUDU_BODY + b"\r\n"), (HUDU_BODY + b"\r\n", "application/json"))

    # -------------------------------------------------------------- Juniper Mist

    def test_mist_valid_signature_forwards_a_batch_unchanged_by_default(self):
        self.start()
        self.assertEqual(self.post("/mist", MIST_BATCH, mist_headers(MIST_BATCH))[0], 200)
        self.assertEqual(self.bodies(), [MIST_BATCH])
        sent = self.ingest.received[0]["headers"]
        self.assertEqual((sent["Authorization"], sent["Content-Type"]), (f"Bearer {INGEST_KEY}", "application/json"))
        self.assertFalse(any(k.lower().startswith("x-mist") for k in sent))

    def test_mist_batch_is_split_into_one_record_per_event_when_turned_on(self):
        self.start(BRIDGE_SPLIT_BATCHES="1")
        self.assertEqual(self.post("/mist", MIST_BATCH, mist_headers(MIST_BATCH))[0], 200)
        self.assertEqual(len(self.ingest.received), 1)
        lines = self.bodies()[0].split(b"\n")
        self.assertEqual([json.loads(x) for x in lines], [{"topic": "audits", "events": [e]} for e in MIST_EVENTS])
        self.assertEqual(self.ingest.received[0]["headers"]["Content-Type"], "application/json")
        # The numbers go on exactly as Mist sent them.
        self.assertIn(b'"timestamp":1791853804.201053', lines[0])
        # A body with one event already is one record, and goes on byte for byte.
        self.assertEqual(self.post("/mist", MIST_ONE, mist_headers(MIST_ONE))[0], 200)
        self.assertEqual(self.bodies()[1], MIST_ONE)
        self.assertIn("mist: split a batch of 2 events", self.log.getvalue())

    def test_splitting_leaves_other_vendors_alone(self):
        self.start(BRIDGE_SPLIT_BATCHES="1")
        hudu = json.dumps({"events": [{"a": 1}, {"a": 2}]}).encode()
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", hudu)[0], 200)
        self.assertEqual(self.bodies(), [hudu])

    def test_split_batch_only_takes_a_batch_of_two_or_more(self):
        for body in (b"not json", b"[1, 2]", b'{"topic": "audits"}', b'{"topic": "audits", "events": {"a": 1}}',
                     b'{"topic": "audits", "events": []}', MIST_ONE):
            with self.subTest(body=body[:30]):
                self.assertIsNone(r.split_batch(body))
        self.assertEqual(r.split_batch(MIST_BATCH)[1], 2)
        with self.assertRaises(r.BodyError):
            r.split_batch(b"[" * 100000 + b"]" * 100000)

    def test_mist_rejects_unverified_deliveries(self):
        self.start(BRIDGE_SPLIT_BATCHES="1")
        good = mist_headers(MIST_BATCH)
        cases = {
            "wrong key": mist_headers(MIST_BATCH, key="another-mist-webhook-secret-00000000000"),
            "tampered body": mist_headers(MIST_BATCH.replace(b"Reception", b"Lobby")),
            "sha1 only": {"X-Mist-Signature": good["X-Mist-Signature"]},
            "base64 digest": {"X-Mist-Signature-v2": base64.b64encode(hmac.new(MIST_SECRET.encode(), MIST_BATCH, hashlib.sha256).digest()).decode()},
            "missing": {},
        }
        for name, headers in cases.items():
            with self.subTest(name):
                self.assertEqual(self.post("/mist", MIST_BATCH, headers)[0], 401)
        self.assertEqual(self.bodies(), [])
        # An upper-case hex digest is the same digest.
        self.assertEqual(self.post("/mist", MIST_BATCH, {**good, "X-Mist-Signature-v2": good["X-Mist-Signature-v2"].upper()})[0], 200)

    def test_mist_dry_run_prints_each_event(self):
        out = io.StringIO()
        self.start(dry_run=True, out=out, NGSIEM_INGEST_URL=None, NGSIEM_INGEST_KEY=None, BRIDGE_SPLIT_BATCHES="1")
        self.assertEqual(self.post("/mist", MIST_BATCH, mist_headers(MIST_BATCH))[0], 200)
        self.assertEqual([json.loads(x)["events"][0]["id"] for x in out.getvalue().splitlines()], [e["id"] for e in MIST_EVENTS])
        self.assertEqual(self.bodies(), [])

    # -------------------------------------------------------------- requests the relay refuses

    def test_unconfigured_vendor_and_unknown_path_are_404(self):
        self.start(HUNTRESS_SIGNING_SECRET=None)
        self.assertEqual(self.post("/huntress", HUNTRESS_BODY, svix_headers(HUNTRESS_BODY))[0], 404)
        self.assertEqual(self.post("/", HUDU_BODY)[0], 404)
        self.assertEqual(self.post("/other", HUDU_BODY)[0], 404)
        self.assertEqual(self.post("/autotask/extra", AUTOTASK_BODY, autotask_headers(AUTOTASK_BODY))[0], 404)
        self.assertEqual(self.bodies(), [])

    def test_pingone_has_no_route(self):
        # PingOne posts NDJSON straight to HTTP Ingest with the header, so the relay has no route for it,
        # and a PingOne token setting turns nothing on.
        token = "p" * 40
        self.start(PINGONE_WEBHOOK_TOKEN=token)
        batch = b'[{"id":"1","action":{"type":"USER.CREATED"}},{"id":"2","action":{"type":"USER.UPDATED"}}]'
        self.assertEqual(self.post("/pingone", batch, {"Authorization": f"Bearer {token}"})[0], 404)
        self.assertEqual(self.bodies(), [])
        with self.assertRaises(r.RelayError) as caught:
            r.load_config({"NGSIEM_INGEST_URL": self.ingest_url, "NGSIEM_INGEST_KEY": INGEST_KEY, "PINGONE_WEBHOOK_TOKEN": token})
        self.assertNotIn("PINGONE", str(caught.exception))

    def test_oversize_body_is_413_before_it_is_read(self):
        self.start(BRIDGE_MAX_BODY_BYTES="2048")
        big = b'{"source":"Hudu","pad":"' + b"x" * 4000 + b'"}'
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", big)[0], 413)
        # The relay answers from the header alone; no body is sent here.
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", b"", length=10_000_000)[0], 413)
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 200)
        self.assertEqual(self.bodies(), [HUDU_BODY])

    def test_missing_length_chunked_empty_and_get_are_refused(self):
        self.start()
        path = f"/hudu/{HUDU_SECRET}"
        self.assertEqual(self.post(path, b"", length=None)[0], 411)
        self.assertEqual(self.post(path, b"5\r\nhello\r\n0\r\n\r\n", {"Transfer-Encoding": "chunked"}, length=None)[0], 411)
        self.assertEqual(self.post(path, b"\r\n")[0], 400)
        conn = http.client.HTTPConnection("127.0.0.1", self.relay.server_address[1], timeout=10)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 405)
            self.assertEqual(resp.getheader("Allow"), "POST")
        finally:
            conn.close()
        self.assertEqual(self.bodies(), [])

    # -------------------------------------------------------------- HTTP Ingest answers

    def test_ingest_429_and_5xx_are_retried(self):
        self.start()
        self.ingest.codes = [429, 503, 500]
        self.assertEqual(self.post("/autotask", AUTOTASK_BODY, autotask_headers(AUTOTASK_BODY))[0], 200)
        self.assertEqual(self.bodies(), [AUTOTASK_BODY])
        self.assertEqual(self.log.getvalue().count("retrying in"), 3)

    def test_ingest_that_stays_down_gets_503_for_the_sender_to_retry(self):
        self.start()
        self.ingest.codes = [503] * 10
        self.assertEqual(self.post("/autotask", AUTOTASK_BODY, autotask_headers(AUTOTASK_BODY))[0], 503)
        self.assertEqual(len(self.ingest.codes), 10 - r.MAX_ATTEMPTS)
        self.assertEqual(self.bodies(), [])

    def test_ingest_reply_cut_short_is_retried_and_the_sender_always_gets_an_answer(self):
        # HTTP Ingest took the delivery, but its reply closed before its Content-Length. The relay
        # treats that like any connection that fails partway: it tries again, and if every reply
        # is cut short, it answers 503 so the sender retries. Either way the sender gets an answer
        # and the log gets one line per try, with no traceback.
        self.start()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.ingest.short = 1
            self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY), (200, "forwarded\n"))
            self.assertEqual(self.bodies(), [HUDU_BODY, HUDU_BODY])
            self.ingest.received.clear()
            self.ingest.short = 100
            self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 503)
            self.assertEqual(len(self.bodies()), r.MAX_ATTEMPTS)
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertIn("failed (IncompleteRead); retrying in", self.log.getvalue())
        self.assertIn("did not take the delivery in time; answered 503", self.log.getvalue())

    def test_retry_after_past_the_deadline_answers_503_at_once(self):
        self.start(BRIDGE_FORWARD_DEADLINE="8")
        self.ingest.codes = [429, 429]
        self.ingest.retry_after = "120"
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 503)
        self.assertEqual(self.ingest.codes, [429])

    def test_ingest_refusal_is_not_retried_and_answers_502(self):
        self.start()
        for code in (400, 401, 403, 413):
            with self.subTest(code):
                self.ingest.codes = [code, 200]
                self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 502)
                self.assertEqual(self.ingest.codes, [200])
        self.ingest.codes = []
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 200)
        # A wrong key is refused by HTTP Ingest the same way.
        self.relay.shutdown()
        self.relay.server_close()
        self.start(NGSIEM_INGEST_KEY="wrong-key-000000000")
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 502)

    def test_ingest_501_and_505_are_not_retried_and_say_why(self):
        # 501 and 505 say HTTP Ingest will never take the request as it is sent, so a retry can't
        # help: the sender gets 502 at once, and the log says what the code means.
        self.start()
        for code, meaning in ((501, "the server doesn't support this request"),
                              (505, "the server doesn't support HTTP/1.1, the version the relay uses")):
            with self.subTest(code=code):
                self.ingest.codes = [code, 200]
                self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 502)
                self.assertEqual(self.ingest.codes, [200])
                self.assertIn(f"answered HTTP {code}: {meaning}, and a retry won't change that; check NGSIEM_INGEST_URL. "
                              "Not retried", self.log.getvalue())

    def test_user_info_in_the_ingest_url_stays_out_of_the_log(self):
        # A user name or password in NGSIEM_INGEST_URL is a credential: log lines show the host and
        # port with the user info redacted.
        self.assertEqual(r._host("https://user:secret@ingest.example.com:8443/services/x"), "[redacted]@ingest.example.com:8443")
        self.assertEqual(r._host("https://ingest.example.com/services/x"), "ingest.example.com")

    def test_ingest_redirect_is_not_followed(self):
        self.start()
        self.ingest.codes = [302]
        self.assertEqual(self.post(f"/hudu/{HUDU_SECRET}", HUDU_BODY)[0], 502)
        self.assertEqual(self.ingest.other, [])
        self.assertIn("answered with a redirect (HTTP 302), which the relay refuses", self.log.getvalue())

    # -------------------------------------------------------------- dry run, logging, configuration

    def test_dry_run_prints_and_forwards_nothing(self):
        out = io.StringIO()
        self.start(dry_run=True, out=out, NGSIEM_INGEST_URL=None, NGSIEM_INGEST_KEY=None)
        self.assertEqual(self.post("/autotask", AUTOTASK_BODY, autotask_headers(AUTOTASK_BODY))[0], 200)
        self.assertEqual(self.post("/autotask", AUTOTASK_BODY, {"X-Hook-Signature": "sha1=AAAA"})[0], 401)
        self.assertEqual(out.getvalue(), AUTOTASK_BODY.decode() + "\n")
        self.assertEqual(self.bodies(), [])

    def test_secrets_and_payloads_never_logged(self):
        self.start()
        marker = "payload-marker-should-not-be-logged"
        hudu = HUDU_BODY.replace(b"Alex Kim", marker.encode())
        self.ingest.codes = [503]
        self.post(f"/hudu/{HUDU_SECRET}", hudu)
        self.post(f"/hudu/{HUDU_SECRET}x", hudu)
        self.post(f"/screenconnect/{SCREENCONNECT_SECRET}", SCREENCONNECT_BODY.replace(b"admin", marker.encode()))
        self.post("/huntress", HUNTRESS_BODY, svix_headers(HUNTRESS_BODY))
        self.post("/huntress", HUNTRESS_BODY, svix_headers(HUNTRESS_BODY, key=b"some-other-signing-key-000000000"))
        self.post("/autotask", AUTOTASK_BODY, autotask_headers(AUTOTASK_BODY))
        self.post("/autotask", AUTOTASK_BODY, {"X-Hook-Signature": "sha1=AAAA"})
        self.post("/mist", MIST_BATCH, mist_headers(MIST_BATCH))
        self.post("/mist", MIST_BATCH, mist_headers(MIST_BATCH, key="another-mist-webhook-secret-00000000000"))
        self.post(f"/forticnapp/{FORTICNAPP_SECRET}", FORTICNAPP_BODY.replace(b"jsmith", marker.encode()))
        self.post(f"/forticnapp/{FORTICNAPP_SECRET[:-1]}", FORTICNAPP_BODY)
        self.ingest.codes = [401]
        self.post(f"/hudu/{HUDU_SECRET}", hudu)
        logged = self.log.getvalue()
        self.assertIn("forwarded", logged)
        self.assertIn("msg_2Qx7example000000000000", logged)
        autotask_sig = autotask_headers(AUTOTASK_BODY)["X-Hook-Signature"][5:]
        for secret in (HUNTRESS_SECRET, base64.b64encode(HUNTRESS_KEY).decode(), AUTOTASK_KEY, HUDU_SECRET,
                       SCREENCONNECT_SECRET, INGEST_KEY, INGEST_PATH, "00000000-example-integration", marker,
                       "Acme Dental", "billing@example.com", autotask_sig, MIST_SECRET, "sam.admin@example.com",
                       mist_headers(MIST_BATCH)["X-Mist-Signature-v2"], FORTICNAPP_SECRET, FORTICNAPP_SECRET[:-1],
                       "ec2:DescribeInstances"):
            self.assertNotIn(secret, logged)

    def test_ingest_key_with_a_line_break_is_refused_without_showing_it(self):
        with self.assertRaises(r.RelayError) as caught:
            r.load_config(self.env(NGSIEM_INGEST_KEY="key-part-one\nkey-part-two"))
        self.assertNotIn("key-part", str(caught.exception))

    # -------------------------------------------------------------- slow and many connections

    def slow_client(self):
        """Opens a connection that sends part of a request and stops."""
        s = socket.create_connection(("127.0.0.1", self.relay.server_address[1]), timeout=5)
        s.sendall(b"POST /hudu/" + HUDU_SECRET.encode() + b" HTTP/1.1\r\nX-Slow: a")
        return s

    def test_connections_past_the_limit_get_503_and_slots_come_back(self):
        self._connections_past_the_limit()

    def test_connections_past_the_limit_when_the_relay_logs_late(self):
        # On a busy machine the relay's thread can write its "in use" line well after the 503 reaches
        # the sender. Holding that line up 0.3 s checks the test above allows for it.
        warning, sleep = r.LOG.warning, self._sleep

        def late(msg, *args, **kwargs):
            if "connections are in use" in msg:
                sleep(0.3)
            return warning(msg, *args, **kwargs)

        r.LOG.warning = late
        try:
            self._connections_past_the_limit()
        finally:
            del r.LOG.warning

    def _connections_past_the_limit(self):
        self.start(BRIDGE_MAX_CONNECTIONS="2")
        slow = [self.slow_client() for _ in range(2)]
        try:
            self._sleep(0.3)
            extra = socket.create_connection(("127.0.0.1", self.relay.server_address[1]), timeout=3)
            try:
                self.assertTrue(extra.recv(64).startswith(b"HTTP/1.0 503"))
            finally:
                extra.close()
        finally:
            for s in slow:
                s.close()
        # The relay's own thread writes this line after it answers 503, so the answer can arrive
        # before the line does.
        deadline = time.monotonic() + 5
        while "all 2 connections are in use" not in self.log.getvalue():
            self.assertLess(time.monotonic(), deadline, "the relay never logged that its connections were in use")
            self._sleep(0.02)
        deadline = time.monotonic() + 5
        while self.post(f"/hudu/{HUDU_SECRET}", b'{"a": 1}')[0] != 200:
            self.assertLess(time.monotonic(), deadline, "the slots never came back")
            self._sleep(0.1)
        self.assertEqual(self.bodies(), [b'{"a": 1}'])

    def test_a_slow_sender_gets_a_fixed_time_in_all(self):
        # Each read has its own 30-second timeout, so a sender that trickles bytes would keep a
        # connection forever. REQUEST_SECONDS bounds the whole request instead.
        saved = getattr(r, "REQUEST_SECONDS", None)
        r.REQUEST_SECONDS = 1
        try:
            self.start()
            s = self.slow_client()
            s.settimeout(0.3)
            began, ended = time.monotonic(), None
            try:
                while time.monotonic() - began < 4:
                    try:
                        s.sendall(b"a")
                        if s.recv(64) is not None:
                            ended = time.monotonic()
                            break
                    except socket.timeout:
                        continue
                    except OSError:
                        ended = time.monotonic()
                        break
            finally:
                s.close()
        finally:
            if saved is None:
                del r.REQUEST_SECONDS
            else:
                r.REQUEST_SECONDS = saved
        self.assertIsNotNone(ended, "the relay kept the slow connection open")
        self.assertLess(ended - began, 2.5)

    def test_max_connections_is_checked(self):
        for bad in ("0", "1001", "many"):
            with self.subTest(bad):
                with self.assertRaises(r.RelayError):
                    r.load_config(self.env(BRIDGE_MAX_CONNECTIONS=bad))
        self.assertEqual(r.load_config(self.env())["max_connections"], 32)

    def test_config_is_checked(self):
        bad = {
            "plain http ingest": {"NGSIEM_INGEST_URL": "http://ingest.example.com/http-endpoint/v1/x"},
            "short path secret": {"HUDU_PATH_SECRET": "too-short"},
            "short Autotask key": {"AUTOTASK_SECRET_KEY": "0123456789"},
            "long Autotask key": {"AUTOTASK_SECRET_KEY": "k" * 65},
            "secret with a space": {"SCREENCONNECT_PATH_SECRET": "with a space " * 4},
            "not a signing secret": {"HUNTRESS_SIGNING_SECRET": "whsec_not base64!"},
            "short Mist secret": {"MIST_WEBHOOK_SECRET": "too-short"},
            "short FortiCNAPP secret": {"FORTICNAPP_PATH_SECRET": "too-short"},
            "port": {"BRIDGE_LISTEN_PORT": "eighty"},
            "deadline": {"BRIDGE_FORWARD_DEADLINE": "0"},
            "nothing to relay": {"HUNTRESS_SIGNING_SECRET": None, "AUTOTASK_SECRET_KEY": None, "HUDU_PATH_SECRET": None,
                                 "SCREENCONNECT_PATH_SECRET": None, "MIST_WEBHOOK_SECRET": None, "FORTICNAPP_PATH_SECRET": None},
        }
        for name, extra in bad.items():
            with self.subTest(name):
                with self.assertRaises(r.RelayError):
                    r.load_config(self.env(**extra))
        cfg = r.load_config(self.env(NGSIEM_INGEST_URL=None))
        self.assertEqual(sorted(cfg["vendors"]), ["autotask", "forticnapp", "hudu", "huntress", "mist", "screenconnect"])
        self.assertFalse(cfg["split_batches"])
        self.assertTrue(r.load_config(self.env(BRIDGE_SPLIT_BATCHES="1"))["split_batches"])
        self.assertEqual(cfg["vendors"]["huntress"], HUNTRESS_KEY)
        self.assertEqual((cfg["host"], cfg["max_body"]), ("127.0.0.1", 524288))
        with self.assertRaises(r.RelayError):
            r.Relay(cfg, dry_run=False)
        r.Relay(cfg, dry_run=True)


class LegacyNameTest(unittest.TestCase):
    """Bridges were called collectors: a setup that still sets the COLLECTOR_ names keeps working."""

    def test_collector_names_still_work(self):
        self.assertEqual(r._env({"COLLECTOR_LOG_LEVEL": "DEBUG"}, "BRIDGE_LOG_LEVEL", "INFO"), "DEBUG")
        self.assertEqual(r._env({"COLLECTOR_LOG_LEVEL": "DEBUG", "BRIDGE_LOG_LEVEL": "WARNING"}, "BRIDGE_LOG_LEVEL", "INFO"), "WARNING")
        self.assertEqual(r._env({}, "BRIDGE_LOG_LEVEL", "INFO"), "INFO")
        self.assertTrue(r._flag({"COLLECTOR_DRY_RUN": "1"}, "BRIDGE_DRY_RUN", False))
        self.assertFalse(r._flag({"COLLECTOR_DRY_RUN": "1", "BRIDGE_DRY_RUN": "0"}, "BRIDGE_DRY_RUN", False))


if __name__ == "__main__":
    unittest.main()
