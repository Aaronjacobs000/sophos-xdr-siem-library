"""Unit tests for cortex_xpanse_bridge.py against a local mock server.

The mock serves the shapes in Palo Alto's Cortex Xpanse REST API reference: POST
/public_api/v2/alerts/get_alerts_multi_events/ with {"request_data": {"filters", "search_from",
"search_to", "use_page_token", "next_page_token"}}, answering {"reply": {"total_count",
"result_count", "alerts", "next_page_token"}}, with the standard key (Authorization and
x-xdr-auth-id) and the advanced key (x-xdr-nonce, x-xdr-timestamp and the SHA-256 of the key, nonce
and time as Authorization), errors as {"reply": {"err_code", "err_msg", "err_extra"}}, and a Sophos
NG-SIEM HTTP Ingest endpoint. Alerts don't carry server_creation_time, so the mock files each alert
by its local_insert_ts, the time Xpanse wrote it, which is what the filter reads. No real service is
called.

  python3 -m unittest discover -s bridges/cortex-xpanse-alerts -p 'test_*.py' -v
"""
import contextlib
import gc
import gzip
import hashlib
import io
import json
import logging
import os
import re
import socket
import sys
import tempfile
import threading
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cortex_xpanse_bridge as c  # noqa: E402

API_KEY = "test-xpanse-api-key-not-real"
KEY_ID = "17"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
TENANT = "example.crtx.au.paloaltonetworks.com"
BASE = {"XPANSE_API_URL": f"https://api-{TENANT}", "XPANSE_API_KEY": API_KEY, "XPANSE_API_KEY_ID": KEY_ID}
ALERTS = "/public_api/v2/alerts/get_alerts_multi_events/"


def ms(dt):
    return int(dt.timestamp() * 1000)


def alert(i, inserted, severity="high", **extra):
    a = {"alert_id": str(113700 + i), "external_id": f"6b51f815-982e-365c-8aed-9d94442355{i:02d}-0", "name":
         f"Insecure TLS at 192.0.2.{i}:443", "description": "This issue flags services with an insecure TLS configuration.",
         "severity": severity, "source": "ASM", "alert_type": "Unclassified", "resolution_status": "STATUS_010_NEW",
         "local_insert_ts": inserted, "last_modified_ts": inserted, "detection_timestamp": inserted - 60000,
         "ipv4_addresses": [f"192.0.2.{i}"], "domain_names": [f"host{i}.example.com"], "port_number": 443,
         "port_protocol": "TCP", "attack_surface_rule_id": "InsecureTLS", "attack_surface_rule_name": "Insecure TLS",
         "asset_ids": ["3aa22188-b754-3b7d-8ab9-e6a716590d16"], "tags": ["AR:Registered to You"]}
    a.update(extra)
    return a


class Mock:
    def __init__(self):
        self.alerts = []
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []
        self.headers = []
        self.nonces = []
        self.tokens = {}
        self.answer = None
        self.refuse_token = False
        self.repeat_token = False


def matches(a, filters):
    for f in filters:
        if f["field"] == "alert_source":
            assert f["operator"] == "in"
            if a["source"] not in f["value"]:
                return False
        elif f["field"] == "server_creation_time":
            if f["operator"] == "gte" and a["local_insert_ts"] < f["value"]:
                return False
            if f["operator"] == "lte" and a["local_insert_ts"] > f["value"]:
                return False
        elif f["field"] == "severity":
            assert f["operator"] == "in"
            if a["severity"] not in f["value"]:
                return False
        else:
            raise AssertionError(f"unexpected filter {f}")
    return True


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        body = b"" if obj is None else (obj if isinstance(obj, bytes) else json.dumps(obj).encode())
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        m, h = self.mock, self.headers
        if h.get("x-xdr-auth-id") != KEY_ID:
            return False
        nonce, stamp = h.get("x-xdr-nonce"), h.get("x-xdr-timestamp")
        if nonce is None:
            return h.get("Authorization") == API_KEY
        if not re.fullmatch(r"[A-Za-z0-9]{64}", nonce) or nonce in m.nonces or not (stamp or "").isdigit():
            return False
        m.nonces.append(nonce)
        # The server's clock agrees with the bridge's, which some tests move on.
        if abs(int(stamp) - int(c.time.time() * 1000)) > 5 * 60 * 1000:
            return False
        return h.get("Authorization") == hashlib.sha256(f"{API_KEY}{nonce}{stamp}".encode()).hexdigest()

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == ALERTS:
            m.headers.append({k.lower(): v for k, v in self.headers.items()})
            if not self._authorized():
                return self._send(401, b"", {"X-Public-Api-Body": "1"})
            if m.codes:
                code = m.codes.pop(0)
                if isinstance(code, tuple):
                    return self._send(*code)
                return self._send(code, {"reply": {"err_code": str(code), "err_msg": "An error occurred", "err_extra": None}})
            req = json.loads(body)["request_data"]
            m.requests.append(req)
            if m.answer is not None:
                return self._send(200, m.answer)
            token = req.get("next_page_token")
            if token:
                if m.refuse_token or token not in m.tokens:
                    m.refuse_token = False
                    return self._send(400, {"reply": {"err_code": "400", "err_msg": "Invalid page token",
                                                                       "err_extra": None}})
                sig, offset = m.tokens[token]
                assert sig == json.dumps(req["filters"], sort_keys=True), "a page token with other filters"
            else:
                offset = 0
            rows = sorted((a for a in m.alerts if matches(a, req["filters"])), key=lambda a: a["local_insert_ts"])
            size = req.get("search_to", 100)
            assert size <= 100
            page = rows[offset:offset + size]
            reply = {"total_count": min(len(rows), 9999), "result_count": len(page),
                     "alerts": [{k: v for k, v in a.items()} for a in page]}
            if req.get("use_page_token") and offset + size < len(rows):
                nxt = f"token-{offset + size}" if not m.repeat_token else token
                m.tokens[nxt] = (json.dumps(req["filters"], sort_keys=True), offset + size)
                reply["next_page_token"] = nxt
            return self._send(200, {"reply": reply})
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
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
    ("XPANSE_PAGE_SIZE", "page_size", 100, 50, int, 100),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 8760),
    ("BRIDGE_DELAY_SECONDS", "delay_seconds", 300, 60, int, 86400),
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
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

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
             "XPANSE_API_URL": self.base, "XPANSE_API_KEY": API_KEY, "XPANSE_API_KEY_ID": KEY_ID, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        cfg = c.load_config(e)
        # The mock runs on 127.0.0.1, so name the tenant as a real API URL would.
        cfg["tenant"] = TENANT
        return cfg

    def ago(self, minutes):
        return ms(self.now - timedelta(minutes=minutes))

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("XPANSE_API_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_alerts_are_tagged_and_sent_as_xpanse_returns_them(self):
        self.mock.alerts = [alert(i, self.ago(50 - i)) for i in range(3)] + [alert(9, self.ago(40), source="XDR")]
        self.assertEqual(c.run_once(self.cfg()), 3)
        raw = self.mock.ingested[0]["raw"]
        self.assertTrue(raw.startswith('{"xpanse_record":"alert","xpanse_tenant":"' + TENANT + '","alert_id":"113700"'), raw[:120])
        sent = self.sent()
        self.assertEqual([r["alert_id"] for r in sent], ["113700", "113701", "113702"])
        self.assertEqual({k: v for k, v in sent[1].items() if k not in ("xpanse_record", "xpanse_tenant")}, alert(1, self.ago(49)))
        req = self.mock.requests[0]
        end = req["filters"][2]["value"]
        self.assertEqual(req["filters"], [{"field": "alert_source", "operator": "in", "value": ["ASM"]},
                                          {"field": "server_creation_time", "operator": "gte", "value": req["filters"][1]["value"]},
                                          {"field": "server_creation_time", "operator": "lte", "value": end}])
        self.assertEqual((req["search_from"], req["search_to"], req["use_page_token"]), (0, 100, True))
        self.assertNotIn("next_page_token", req)
        self.assertNotIn("sort", req)
        self.assertLess(abs(end + 1 - (ms(datetime.now(timezone.utc)) - 300000)), 5000)
        self.assertLess(abs(req["filters"][1]["value"] - (ms(datetime.now(timezone.utc)) - 24 * 3600000)), 5000)
        self.assertEqual(self.saved()[TENANT]["cursor_ms"], end + 1)

    def test_the_advanced_key_signs_each_request_with_a_new_nonce(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        self.mock.codes = [503]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)
        # The retry was signed again: two requests, two nonces, and the key itself never sent.
        self.assertEqual(len(self.mock.nonces), 2)
        self.assertNotEqual(self.mock.nonces[0], self.mock.nonces[1])
        for h in self.mock.headers:
            self.assertEqual(h["x-xdr-auth-id"], KEY_ID)
            self.assertNotIn(API_KEY, json.dumps(h))
            self.assertEqual(h["authorization"], hashlib.sha256(f"{API_KEY}{h['x-xdr-nonce']}{h['x-xdr-timestamp']}".encode()).hexdigest())

    def test_a_standard_key_goes_as_authorization(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        c.run_once(self.cfg(XPANSE_API_KEY_TYPE="standard"))
        self.assertEqual(len(self.sent()), 1)
        h = self.mock.headers[0]
        self.assertEqual((h["authorization"], h["x-xdr-auth-id"]), (API_KEY, KEY_ID))
        self.assertNotIn("x-xdr-nonce", h)

    def test_a_key_of_the_wrong_type_is_refused_with_a_hint(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        self.mock.codes = []
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(XPANSE_API_KEY_ID="18"))
        self.assertEqual(str(cm.exception), "Xpanse refused the alerts request (HTTP 401: the key or its ID is wrong, or the key "
                         "type doesn't match XPANSE_API_KEY_TYPE): no message")
        self.assertFalse(os.path.exists(self.state))

    def test_other_refusals_stop_with_xpanses_message(self):
        cases = [((402, {"reply": {"err_code": "402", "err_msg": "User does not have the required license type to run this API", "err_extra": None}}),
                  "(HTTP 402: the tenant's license doesn't include the API): User does not have the required license type to run this API"),
                 ((403, {"reply": {"err_code": "403", "err_msg": "Forbidden", "err_extra": "Missing permission: Public API"}}),
                  "(HTTP 403: the key's role can't read alerts): Forbidden (Missing permission: Public API)"),
                 ((400, {"reply": {"err_code": "400", "err_msg": "Got an invalid JSON.", "err_extra": None}}),
                  "refused the alerts request (HTTP 400): Got an invalid JSON."),
                 ((422, {"code": 422, "status": "Unprocessable Entity", "message": "bad filter"}), "(HTTP 422): no message")]
        for answer, message in cases:
            with self.subTest(code=answer[0]):
                self.mock.alerts = [alert(0, self.ago(30))]
                self.mock.codes = [answer]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertNotIsInstance(cm.exception, c.NetworkError)
                self.assertIn(message, str(cm.exception))
        self.assertEqual(self.slept, [])
        self.assertFalse(os.path.exists(self.state))

    def test_severities_filter_the_request(self):
        self.mock.alerts = [alert(0, self.ago(30), severity="low"), alert(1, self.ago(20), severity="critical")]
        c.run_once(self.cfg(XPANSE_SEVERITIES="High, critical"))
        self.assertEqual(self.mock.requests[0]["filters"][3], {"field": "severity", "operator": "in", "value": ["high", "critical"]})
        self.assertEqual([r["alert_id"] for r in self.sent()], ["113701"])

    def test_windows_meet_without_a_gap_or_an_overlap(self):
        cfg = self.cfg(BRIDGE_DELAY_SECONDS="0")
        saved, c.time.time = c.time.time, lambda: self.now.timestamp()
        try:
            self.mock.alerts = [alert(0, self.ago(30))]
            c.run_once(cfg)
            first_end = self.saved()[TENANT]["cursor_ms"]
            self.assertEqual(first_end, ms(self.now))
            # An alert written at exactly the first window's end belongs to the next window only.
            self.mock.alerts.append(alert(1, first_end))
            c.time.time = lambda: self.now.timestamp() + 60
            c.run_once(cfg)
        finally:
            c.time.time = saved
        self.assertEqual([r["alert_id"] for r in self.sent()], ["113700", "113701"])
        second = self.mock.requests[1]["filters"]
        self.assertEqual((second[1]["value"], second[2]["value"]), (first_end, first_end + 59999))

    def test_no_new_window_until_the_delay_has_passed(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        cfg = self.cfg()
        saved, c.time.time = c.time.time, lambda: self.now.timestamp()
        try:
            c.run_once(cfg)
            self.assertEqual(c.run_once(cfg), 0)
        finally:
            c.time.time = saved
        self.assertEqual(len(self.mock.requests), 1)
        self.assertIn("no new window yet", self.logbuf.getvalue())

    def test_pages_follow_the_token_and_a_stopped_window_goes_on_from_its_next_page(self):
        self.mock.alerts = [alert(i, self.ago(50 - i)) for i in range(5)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(XPANSE_PAGE_SIZE="2"))
        state = self.saved()[TENANT]
        self.assertEqual(state["pending"]["token"], "token-2")
        self.assertNotIn("cursor_ms", state)
        first = self.mock.requests[0]
        self.assertEqual(self.mock.requests[1]["next_page_token"], "token-2")
        self.assertEqual(self.mock.requests[1]["filters"], first["filters"])
        self.mock.ingested.clear()
        self.mock.requests.clear()
        saved, c.time.time = c.time.time, lambda: self.now.timestamp() + 3600
        try:
            c.run_once(self.cfg(XPANSE_PAGE_SIZE="2"))
        finally:
            c.time.time = saved
        # The same window, from the third alert: the same bounds, an hour later.
        self.assertEqual([r["filters"] for r in self.mock.requests], [first["filters"]] * 2)
        self.assertEqual([r.get("next_page_token") for r in self.mock.requests], ["token-2", "token-4"])
        self.assertEqual([r["alert_id"] for r in self.sent()], ["113702", "113703", "113704"])
        state = self.saved()[TENANT]
        self.assertNotIn("pending", state)
        self.assertEqual(state["cursor_ms"], first["filters"][2]["value"] + 1)

    def test_a_refused_saved_token_reads_the_window_again_from_its_first_page(self):
        self.mock.alerts = [alert(i, self.ago(50 - i)) for i in range(3)]
        end = self.ago(5)
        with open(self.state, "w") as fh:
            json.dump({TENANT: {"pending": {"start_ms": self.ago(60), "end_ms": end, "token": "stale-token"}}}, fh)
        c.run_once(self.cfg(XPANSE_PAGE_SIZE="2"))
        self.assertEqual([r["alert_id"] for r in self.sent()], ["113700", "113701", "113702"])
        self.assertIn("refused the saved page token", self.logbuf.getvalue())
        self.assertNotIn("next_page_token", self.mock.requests[1])
        self.assertEqual(self.saved()[TENANT]["cursor_ms"], end)

    def test_a_token_that_doesnt_move_on_stops_the_run(self):
        self.mock.alerts = [alert(i, self.ago(50 - i)) for i in range(5)]
        self.mock.repeat_token = True
        with open(self.state, "w") as fh:
            json.dump({TENANT: {"pending": {"start_ms": self.ago(60), "end_ms": self.ago(5), "token": "token-2"}}}, fh)
        self.mock.tokens["token-2"] = (json.dumps([{"field": "alert_source", "operator": "in", "value": ["ASM"]},
                                                   {"field": "server_creation_time", "operator": "gte", "value": self.ago(60)},
                                                   {"field": "server_creation_time", "operator": "lte", "value": self.ago(5) - 1}],
                                                  sort_keys=True), 2)
        with self.assertRaisesRegex(c.BridgeError, "next page token is the one it was sent"):
            c.run_once(self.cfg(XPANSE_PAGE_SIZE="2"))

    def test_an_answer_with_no_alerts_list_stops_the_run(self):
        for answer in ({"reply": {"total_count": 0}}, {"reply": []}, {"alerts": []}, [1]):
            with self.subTest(answer=answer):
                self.mock.answer = answer
                with self.assertRaisesRegex(c.BridgeError, r"returned JSON with no reply\.alerts list"):
                    c.run_once(self.cfg())
        self.mock.answer = b"<html>maintenance</html>"
        with self.assertRaisesRegex(c.BridgeError, "not JSON"):
            c.run_once(self.cfg())

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.alerts = [alert(i, self.ago(30 - i)) for i in range(2)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["xpanse_record"] for x in lines], ["alert"] * 2)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        self.mock.codes = [(429, {"reply": {"err_code": "429", "err_msg": "Exceeded 10 requests in a 60-second window"}}, {"Retry-After": "1"}), 500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.slept[0], 1.0)

    def test_gzip_batches_and_headers(self):
        self.mock.alerts = [alert(i, self.ago(40 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(XPANSE_API_KEY="another-wrong-key-000", BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "other.json")))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("alerts request", logged)
        for secret in (API_KEY, INGEST_KEY, "00000000-example-integration", "another-wrong-key-000"):
            self.assertNotIn(secret, logged)

    def test_state_is_kept_per_tenant(self):
        self.mock.alerts = [alert(0, self.ago(30))]
        cfg = self.cfg()
        c.run_once(cfg)
        cfg["tenant"] = "other.crtx.eu.paloaltonetworks.com"
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.sent()[0]["xpanse_tenant"], "other.crtx.eu.paloaltonetworks.com")
        self.assertEqual(set(self.saved()), {TENANT, "other.crtx.eu.paloaltonetworks.com"})

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "XPANSE_API_URL": ""}, {**BASE, "XPANSE_API_URL": f"http://api-{TENANT}"},
                    {**BASE, "XPANSE_API_URL": f"https://api-{TENANT}/public_api/v1"}, {**BASE, "XPANSE_API_KEY": ""},
                    {**BASE, "XPANSE_API_KEY_ID": ""}, {**BASE, "XPANSE_API_KEY_ID": "abc"}, {**BASE, "XPANSE_API_KEY_TYPE": "basic"},
                    {**BASE, "XPANSE_SEVERITIES": "urgent"}, {**BASE, "XPANSE_SEVERITIES": ","},
                    {**BASE, "NGSIEM_INGEST_URL": "http://ingest.example/http-endpoint/v1/x"},
                    {**BASE, "XPANSE_PAGE_SIZE": "0"}, {**BASE, "XPANSE_PAGE_SIZE": "101"}, {**BASE, "BRIDGE_LOOKBACK_HOURS": "8761"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "XPANSE_API_KEY"}), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["api_url"], cfg["tenant"], cfg["key_type"], cfg["severities"]),
                         (f"https://api-{TENANT}", TENANT, "advanced", None))
        self.assertEqual((cfg["page_size"], cfg["delay_seconds"], cfg["lookback_hours"]), (100, 300, 24.0))
        self.assertEqual(c.load_config({**BASE, "XPANSE_API_URL": "https://xpanse.example.com/"})["tenant"], "xpanse.example.com")
        self.assertEqual(c.load_config({**BASE, "XPANSE_API_KEY_TYPE": "Standard"})["key_type"], "standard")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.alerts = [alert(0, self.ago(30))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": lambda: self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Xpanse API": lambda: self.cfg(XPANSE_API_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, make in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaisesRegex(c.BridgeError, rf"answered with a redirect \(HTTP {code}\), which the bridge refuses"):
                            c.run_once(make())
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state) and self.saved().get(TENANT, {}).get("cursor_ms"))
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
        host_port = f"127.0.0.1:{listener.getsockname()[1]}"
        slept = []
        saved, c.time.sleep = c.time.sleep, slept.append
        try:
            with self.assertRaises(c.NetworkError) as caught:
                c._request("GET", f"http://{host_port}/x", {}, None, 0.05, what="test request")
        finally:
            c.time.sleep = saved
            listener.close()
        self.assertEqual(len(slept), c.MAX_ATTEMPTS - 1)
        self.assertRegex(str(caught.exception), rf"^test request to {host_port} failed: (timeout|TimeoutError)$")

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
        return c.load_config({**BASE, **extra})

    def test_http_timeout_must_be_more_than_zero(self):
        for value in ("0", "0.0", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    c.BridgeError, r"^BRIDGE_HTTP_TIMEOUT must be between 0\.001 and 1,000,000,000$"):
                self.load(BRIDGE_HTTP_TIMEOUT=value)
        self.assertEqual(self.load(BRIDGE_HTTP_TIMEOUT="0.5")["timeout"], 0.5)

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "101"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^XPANSE_PAGE_SIZE must be between 1 and 100$"):
                self.load(XPANSE_PAGE_SIZE=value)
        self.assertEqual(self.load(XPANSE_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(XPANSE_PAGE_SIZE="100")["page_size"], 100)

    def test_lookback_is_at_most_a_year(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be between 0 and 8,760$"):
            self.load(BRIDGE_LOOKBACK_HOURS="8761")
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_LOOKBACK_HOURS must be above 0$"):
            self.load(BRIDGE_LOOKBACK_HOURS="0")
        self.assertEqual(self.load(BRIDGE_LOOKBACK_HOURS="8760")["lookback_hours"], 8760.0)


class IntervalTest(unittest.TestCase):
    """main with --interval: an unexpected error is logged by type and line, never its message,
    and polling goes on. A BridgeError still stops the bridge, and a single run still raises."""

    def setUp(self):
        self.cfg = c.load_config(BASE)
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
        tmp = tempfile.TemporaryDirectory()
        self.cfg["state_file"] = os.path.join(tmp.name, "state.json")
        try:
            self.assertEqual(c.main(["--interval", "5", "--dry-run"]), 130)
        finally:
            opener.open = saved_open
            tmp.cleanup()
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
        tmp = tempfile.TemporaryDirectory()
        self.cfg["state_file"] = os.path.join(tmp.name, "state.json")
        try:
            return c.main(argv), len(runs)
        finally:
            opener.open = saved_open
            tmp.cleanup()

    @staticmethod
    def status(code, body=b"{}"):
        return lambda url: c.urllib.error.HTTPError(url, code, "test status", c.http.client.HTTPMessage(), io.BytesIO(body))

    def errors(self):
        return [line for line in self.log.getvalue().splitlines() if line.startswith("ERROR")]

    def test_retried_status_past_the_retries_is_logged_by_host_and_polling_goes_on(self):
        for code, body in ((429, b"{}"), (503, b"{}")):
            with self.subTest(code=code):
                self.log.seek(0)
                self.log.truncate()
                del self.slept[:]
                self.assertEqual(self.every_request_fails(self.status(code, body), ["--interval", "5", "--dry-run"]), (130, 2))
                self.assertEqual(len(self.slept), c.MAX_ATTEMPTS)
                self.assertEqual(self.slept[-1], 5)
                errors = self.errors()
                self.assertEqual(len(errors), 1)
                self.assertRegex(errors[0], rf"^ERROR .+ to [a-z0-9.-]+ failed with HTTP {code}; trying again in 5 seconds$")
                self.assertNotRegex(self.log.getvalue(), r"not-?real")

    def test_other_statuses_and_redirects_still_stop_the_bridge(self):
        for code in (302, 400, 401, 402, 403, 404):
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
        error = c.HostNotFound("alerts request to api-example.crtx.au.paloaltonetworks.com failed: the host name wasn't found; check the URL setting")
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
