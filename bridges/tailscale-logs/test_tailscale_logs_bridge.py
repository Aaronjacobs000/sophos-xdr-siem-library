"""Unit tests for tailscale_logs_bridge.py against a local mock server.

The mock serves the shapes in Tailscale's API reference (its OpenAPI document) and its logging and
OAuth client docs: POST /api/v2/oauth/token with the form fields client_id and client_secret,
answering {"access_token", "token_type": "Bearer", "expires_in": 3600, "scope"}; GET
/api/v2/tailnet/<tailnet>/logging/configuration and /logging/network with start and end in RFC 3339
and 'Authorization: Bearer', answering {"version": "1.1", "tailnetId", "logs": [...]} and
{"logs": [...]}, oldest first, and {"message": ...} on errors. Plus a Sophos NG-SIEM HTTP Ingest
endpoint. No real service is called.

  python3 -m unittest discover -s bridges/tailscale-logs -p 'test_*.py' -v
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
import tailscale_logs_bridge as c  # noqa: E402

CLIENT_ID = "test-tailscale-oauth-client-id-not-real"
CLIENT_SECRET = "tskey-client-test-secret-not-real"
API_KEY = "tskey-api-test-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
TAILNET_ID = "T1a2b3c4d5CNTRL"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}123Z"


def audit(i, when, action="UPDATE", target_type="NODE", prop="KEY_EXPIRY_TIME"):
    """A configuration audit log in the shape of the docs' example."""
    return {"action": action, "actor": {"displayName": "Alex Kim", "id": f"u{i:04d}ExampleCNTRL", "loginName": "akim@example.com", "type": "USER"},
            "deferredAt": "0001-01-01T00:00:00Z", "eventGroupID": f"0378d8f57300d172ef7ae3826e09{i:04x}", "eventTime": iso(when),
            "new": "2027-04-18T20:13:30.134350003Z", "old": "0001-01-01T00:00:00Z", "origin": "ADMIN_CONSOLE",
            "target": {"id": f"n{i:04d}ExampleCNTRL", "name": "web-01.example.ts.net", "property": prop, "type": target_type},
            "type": "CONFIG"}


def flow(when, node="nBcdef1CNTRL"):
    """A network flow log in the shape of the docs' example: virtual and physical traffic, the
    source node and the destination nodes."""
    start = when - timedelta(seconds=5)
    return {"start": iso(start), "end": iso(when), "logged": iso(when + timedelta(seconds=3)), "nodeId": node,
            "srcNode": {"nodeId": node, "addresses": ["100.100.22.33", "fd7a:115c:a1e0::c034:c374"], "os": "linux",
                        "name": "build-01.example.ts.net", "user": "akim@example.com"},
            "dstNodes": [{"nodeId": "n22daC8CNTRL", "addresses": ["100.100.44.55", "fd7a:115c:a1e0::abcd:123"], "os": "windows",
                          "name": "laptop-07.example.ts.net", "user": "jsmith@example.com"},
                         {"nodeId": "nX8fDaxCNTRL", "addresses": ["100.100.66.77"], "os": "linux", "name": "db-01.example.ts.net",
                          "tags": ["tag:prod"]}],
            "virtualTraffic": [{"proto": 6, "src": "100.100.22.33:21291", "dst": "100.100.44.55:3389", "txPkts": 2, "txBytes": 108,
                                "rxPkts": 2, "rxBytes": 112},
                               {"proto": 6, "src": "[fd7a:115c:a1e0::c034:c374]:864", "dst": "[fd7a:115c:a1e0::abcd:123]:22",
                                "txPkts": 6, "txBytes": 900, "rxPkts": 3, "rxBytes": 728}],
            "subnetTraffic": [{"proto": 17, "src": "100.100.22.33:5353", "dst": "192.0.2.53:53", "txPkts": 1, "txBytes": 64}],
            "physicalTraffic": [{"src": "100.100.66.77:0", "dst": "198.51.100.20:41641", "txPkts": 4, "txBytes": 384,
                                 "rxPkts": 4, "rxBytes": 384}]}


class Mock:
    def __init__(self):
        self.audit = []
        self.flows = []
        self.tokens = []
        self.token_requests = []
        self.requests = []
        self.answers = []        # statuses to answer log requests with instead, in order
        self.token_answers = []
        self.expires_in = 3600
        self.null_logs = False
        self.ingest_codes = []
        self.ingested = []


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        m = self.mock
        url = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.path == c.TOKEN_PATH:
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append({"form": form, "headers": dict(self.headers)})
            if m.token_answers:
                return self._send(m.token_answers.pop(0), {"message": "test status"})
            if form.get("client_id") != [CLIENT_ID] or form.get("client_secret") != [CLIENT_SECRET]:
                return self._send(401, {"message": "invalid client credentials"})
            token = f"tskey-test-oauth-token-{len(m.tokens):04d}-not-real"
            m.tokens.append(token)
            return self._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": m.expires_in,
                                    "scope": "logs:configuration:read logs:network:read"})
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
        m.requests.append({"path": url.path, "query": query, "headers": dict(self.headers)})
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] not in m.tokens + [API_KEY]:
            return self._send(401, {"message": "API token invalid"})
        if m.answers:
            return self._send(m.answers.pop(0), {"message": "test status"})
        parts = url.path.split("/")
        if len(parts) != 7 or parts[:4] != ["", "api", "v2", "tailnet"] or parts[5] != "logging" or parts[6] not in ("configuration", "network"):
            return self._send(404, {"message": "not found"})
        if "start" not in query or "end" not in query:
            return self._send(400, {"message": "start and end are required"})
        lo, hi = c._parse_time(query["start"][0]), c._parse_time(query["end"][0])
        if parts[6] == "configuration":
            rows = sorted((r for r in m.audit if lo <= c._parse_time(r["eventTime"]) <= hi), key=lambda r: r["eventTime"])
            out = {"version": "1.1", "tailnetId": "example.com", "logs": None if m.null_logs else rows}
        else:
            rows = sorted((r for r in m.flows if lo <= c._parse_time(r["logged"]) <= hi), key=lambda r: r["logged"])
            out = {"logs": None if m.null_logs else rows}
        self._send(200, out)


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
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 2160),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 900, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"TAILSCALE_OAUTH_CLIENT_ID": CLIENT_ID, "TAILSCALE_OAUTH_CLIENT_SECRET": CLIENT_SECRET}
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
                     TAILSCALE_API_URL=self.base, BRIDGE_STATE_FILE=self.state, TAILSCALE_WINDOW_MINUTES="1440")
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def log_requests(self, log):
        return [r for r in self.mock.requests if r["path"].endswith("/logging/" + log)]

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("TAILSCALE_API_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_configuration_logs_are_read_and_tagged(self):
        self.mock.audit = [audit(i, self.ago(50 - i)) for i in range(3)] + [audit(9, self.ago(5), "LOGIN", "ADMIN_CONSOLE", "")]
        self.assertEqual(c.run_once(self.cfg(TAILSCALE_LOGS="configuration")), 4)
        self.assertEqual([r["action"] for r in self.sent()], ["UPDATE"] * 3 + ["LOGIN"])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"tailscale_record":"configuration","tailscale_tailnet":"example.com",'
                                                                '"action":"UPDATE"'))
        first = {k: v for k, v in self.sent()[0].items() if k not in ("tailscale_record", "tailscale_tailnet")}
        self.assertEqual(first, self.mock.audit[0])
        (req,) = self.log_requests("configuration")
        self.assertEqual(req["path"], "/api/v2/tailnet/-/logging/configuration")
        start, end = c._parse_time(req["query"]["start"][0]), c._parse_time(req["query"]["end"][0])
        self.assertRegex(req["query"]["start"][0], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertAlmostEqual(end - start, 86400 - 60, delta=2)
        self.assertEqual(req["headers"]["Authorization"], f"Bearer {self.mock.tokens[0]}")

    def test_network_flow_logs_are_sent_one_record_per_connection(self):
        self.mock.flows = [flow(self.ago(10))]
        self.assertEqual(c.run_once(self.cfg(TAILSCALE_LOGS="network")), 4)
        recs = self.sent()
        self.assertEqual([(r["traffic"], r["src"], r["dst"]) for r in recs], [
            ("virtual", "100.100.22.33:21291", "100.100.44.55:3389"),
            ("virtual", "[fd7a:115c:a1e0::c034:c374]:864", "[fd7a:115c:a1e0::abcd:123]:22"),
            ("subnet", "100.100.22.33:5353", "192.0.2.53:53"),
            ("physical", "100.100.66.77:0", "198.51.100.20:41641")])
        log = self.mock.flows[0]
        for r in recs:
            self.assertEqual((r["tailscale_record"], r["tailscale_tailnet"], r["nodeId"], r["start"], r["end"], r["logged"]),
                             ("network", "-", log["nodeId"], log["start"], log["end"], log["logged"]))
            self.assertEqual(r["srcNode"]["name"], "build-01.example.ts.net")
            self.assertNotIn("dstNodes", r)
            self.assertNotIn("virtualTraffic", r)
        self.assertEqual(recs[0]["dstNode"]["name"], "laptop-07.example.ts.net")
        self.assertEqual(recs[1]["dstNode"]["name"], "laptop-07.example.ts.net")
        self.assertNotIn("dstNode", recs[2])
        self.assertEqual(recs[3]["peerNode"]["name"], "db-01.example.ts.net")
        # Counters Tailscale leaves out (zero) stay out.
        self.assertEqual((recs[2].get("rxPkts"), recs[3].get("proto")), (None, None))
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"tailscale_record":"network","tailscale_tailnet":"-","nodeId":'))

    def test_addresses_of_both_forms(self):
        self.assertEqual(c._address("100.64.0.1:443"), "100.64.0.1")
        self.assertEqual(c._address("[fd7a:115c:a1e0::1]:443"), "fd7a:115c:a1e0::1")
        self.assertEqual(c._address("fd7a:115c:a1e0::1"), "fd7a:115c:a1e0::1")
        self.assertEqual(c._address(None), "")

    def test_the_oauth_token_is_kept_until_it_expires_and_renewed_when_refused(self):
        self.mock.audit = [audit(0, self.ago(5))]
        cfg = self.cfg()
        client = c.Tailscale(cfg)
        c.run_once(cfg, client=client)
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 1)
        self.assertEqual(self.mock.token_requests[0]["form"], {"client_id": [CLIENT_ID], "client_secret": [CLIENT_SECRET]})
        self.assertEqual(self.mock.token_requests[0]["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        # Tailscale refuses the token: the bridge gets a new one and asks once more.
        self.mock.tokens.clear()
        c.run_once(cfg, client=client)
        self.assertEqual(len(self.mock.token_requests), 2)
        # A token that lives under the renewal margin is renewed for each request.
        self.mock.expires_in = 30
        c.run_once(cfg, client=c.Tailscale(cfg))
        self.assertEqual(len(self.mock.token_requests), 4)

    def test_refused_client_credentials_stop_with_a_clear_error(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(TAILSCALE_OAUTH_CLIENT_SECRET="tskey-client-wrong-not-real"))
        self.assertIn("Tailscale refused the OAuth token request (HTTP 401: invalid client credentials)", str(cm.exception))
        self.assertNotIn("wrong-not-real", str(cm.exception))

    def test_an_api_access_token_is_sent_as_it_is(self):
        self.mock.audit = [audit(0, self.ago(5))]
        c.run_once(self.cfg(TAILSCALE_OAUTH_CLIENT_ID=None, TAILSCALE_OAUTH_CLIENT_SECRET=None, TAILSCALE_API_KEY=API_KEY))
        self.assertEqual(self.mock.token_requests, [])
        self.assertTrue(all(r["headers"]["Authorization"] == f"Bearer {API_KEY}" for r in self.mock.requests))
        self.mock.tokens.clear()
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 401: API token invalid\); check the OAuth client or TAILSCALE_API_KEY"):
            c.run_once(self.cfg(TAILSCALE_OAUTH_CLIENT_ID=None, TAILSCALE_OAUTH_CLIENT_SECRET=None,
                                TAILSCALE_API_KEY="tskey-api-expired-not-real"))

    def test_the_tailnet_goes_in_the_path(self):
        c.run_once(self.cfg(TAILSCALE_TAILNET="T1a2b3c4d5CNTRL"))
        self.assertEqual({r["path"] for r in self.mock.requests},
                         {f"/api/v2/tailnet/{TAILNET_ID}/logging/configuration", f"/api/v2/tailnet/{TAILNET_ID}/logging/network"})

    def test_a_backlog_is_read_a_window_at_a_time_and_each_window_saved(self):
        self.mock.audit = [audit(i, self.ago(300 - 60 * i)) for i in range(5)]
        cfg = self.cfg(TAILSCALE_LOGS="configuration", TAILSCALE_WINDOW_MINUTES="90", BRIDGE_LOOKBACK_HOURS="6")
        self.assertEqual(c.run_once(cfg), 5)
        reqs = self.log_requests("configuration")
        self.assertEqual(len(reqs), 4)
        bounds = [(c._parse_time(r["query"]["start"][0]), c._parse_time(r["query"]["end"][0])) for r in reqs]
        for (s1, e1), (s2, e2) in zip(bounds, bounds[1:]):
            self.assertEqual(e1, s2)
        self.assertTrue(all(e - s <= 90 * 60 for s, e in bounds))
        self.assertLessEqual(bounds[-1][1], datetime.now(timezone.utc).timestamp() - 59)

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.audit = [audit(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(TAILSCALE_LOGS="configuration", BRIDGE_OVERLAP_SECONDS="1200")
        c.run_once(cfg)
        first_end = c._parse_time(self.log_requests("configuration")[0]["query"]["end"][0])
        self.assertAlmostEqual(self.saved()["logs"]["configuration"]["until"], first_end, delta=1)
        self.mock.ingested.clear()
        self.mock.requests.clear()
        # An event that Tailscale listed late, inside the overlap, and a new one.
        late, new = audit(7, self.ago(15), "DELETE"), audit(8, self.ago(2), "CREATE", "API_KEY", "")
        self.mock.audit += [late, new]
        c.run_once(cfg)
        self.assertEqual([r["eventGroupID"] for r in self.sent()], [late["eventGroupID"], new["eventGroupID"]])
        start = c._parse_time(self.log_requests("configuration")[0]["query"]["start"][0])
        self.assertAlmostEqual(start, first_end - 1200, delta=1)

    def test_the_lookback_never_passes_what_tailscale_keeps(self):
        with open(self.state, "w") as fh:
            json.dump({"logs": {"configuration": {"until": self.now.timestamp() - 200 * 86400},
                                "network": {"until": self.now.timestamp() - 200 * 86400}}}, fh)
        c.run_once(self.cfg(TAILSCALE_WINDOW_MINUTES="1440"))
        first = {log: c._parse_time(self.log_requests(log)[0]["query"]["start"][0]) for log in ("configuration", "network")}
        self.assertAlmostEqual(first["configuration"], self.now.timestamp() - 90 * 86400, delta=5)
        self.assertAlmostEqual(first["network"], self.now.timestamp() - 30 * 86400, delta=5)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.audit = [audit(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(TAILSCALE_LOGS="configuration"))
        self.assertFalse(os.path.exists(self.state) and "until" in self.saved()["logs"].get("configuration", {}))
        self.mock.ingest_codes = []
        c.run_once(self.cfg(TAILSCALE_LOGS="configuration"))
        self.assertEqual(len(self.sent()), 4)
        self.assertIn("until", self.saved()["logs"]["configuration"])

    def test_window_end_never_passes_now(self):
        self.mock.audit = [audit(0, self.ago(5))]
        c.run_once(self.cfg())
        self.assertLessEqual(self.saved()["logs"]["configuration"]["until"], datetime.now(timezone.utc).timestamp() - 59)

    def test_null_logs_count_as_none(self):
        self.mock.audit = [audit(0, self.ago(5))]
        self.mock.null_logs = True
        self.assertEqual(c.run_once(self.cfg()), 0)
        self.assertEqual(self.sent(), [])

    def test_http_errors_stop_with_clear_errors(self):
        cases = [(403, "the logs:configuration:read scope"), (404, "check TAILSCALE_TAILNET, and for network flow logs"),
                 (400, r"Tailscale rejected the configuration logs request \(HTTP 400: test status\)")]
        for code, message in cases:
            with self.subTest(code=code):
                self.mock.answers = [code]
                with self.assertRaisesRegex(c.BridgeError, message):
                    c.run_once(self.cfg(TAILSCALE_LOGS="configuration"))
        self.mock.answers = [403]
        with self.assertRaisesRegex(c.BridgeError, "the logs:network:read scope"):
            c.run_once(self.cfg(TAILSCALE_LOGS="network"))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.audit = [audit(i, self.ago(10 - i)) for i in range(2)]
        self.mock.flows = [flow(self.ago(5))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["tailscale_record"] for x in lines], ["configuration"] * 2 + ["network"] * 4)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.audit = [audit(i, self.ago(10 - i)) for i in range(3)]
        self.mock.answers = [429, 500, 503]
        self.mock.token_answers = [503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg(TAILSCALE_LOGS="configuration"))
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.audit = [audit(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.audit = [audit(0, self.ago(5))]
        self.mock.answers = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(TAILSCALE_OAUTH_CLIENT_SECRET="tskey-client-another-wrong-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("configuration logs request", logged)
        for secret in (CLIENT_SECRET, INGEST_KEY, "00000000-example-integration", "tskey-client-another-wrong-not-real",
                       self.mock.tokens[0]):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(TAILSCALE_OAUTH_CLIENT_ID=None, TAILSCALE_OAUTH_CLIENT_SECRET=None),
            base_env(TAILSCALE_OAUTH_CLIENT_SECRET=None),
            base_env(TAILSCALE_API_KEY=API_KEY),
            base_env(TAILSCALE_API_URL="http://api.tailscale.example"),
            base_env(TAILSCALE_API_URL="https://api.tailscale.com/api/v2"),
            base_env(TAILSCALE_TAILNET="example.com/../other"),
            base_env(TAILSCALE_TAILNET="exa mple"),
            base_env(TAILSCALE_LOGS="configuration,devices"),
            base_env(TAILSCALE_LOGS=","),
            base_env(TAILSCALE_WINDOW_MINUTES="0"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(BRIDGE_LOOKBACK_HOURS="2161"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual((cfg["api_url"], cfg["tailnet"], cfg["logs"], cfg["window_minutes"]),
                         ("https://api.tailscale.com", "-", ["configuration", "network"], 60))
        self.assertEqual(c.load_config(base_env(TAILSCALE_TAILNET="example.com"))["tailnet"], "example.com")
        self.assertEqual(c.load_config({"TAILSCALE_API_KEY": API_KEY})["api_key"], API_KEY)

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2025, 10, 28, 22, 39, 51, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2025-10-28T22:39:51Z", want), ("2025-10-28T22:39:51.890385065Z", want + 0.890385),
                               ("2025-10-29T08:39:51.5+10:00", want + 0.5)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertEqual(c._ts_time(want + 0.9), "2025-10-28T22:39:51Z")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key to another URL, so the run fails instead, and
        # nothing reaches the redirect's target.
        self.mock.audit = [audit(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Tailscale API": self.cfg(TAILSCALE_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("logs", {}).get("configuration", {}))
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

    def test_window_minutes_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "1441"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^TAILSCALE_WINDOW_MINUTES must be between 1 and 1,440$"):
                self.load(TAILSCALE_WINDOW_MINUTES=value)
        self.assertEqual(self.load(TAILSCALE_WINDOW_MINUTES="1440")["window_minutes"], 1440)

    def test_lookback_is_at_most_the_90_days_tailscale_keeps(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 2,160$"):
            self.load(BRIDGE_LOOKBACK_HOURS="2161")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="2160")["lookback_hours"], 2160.0)


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
