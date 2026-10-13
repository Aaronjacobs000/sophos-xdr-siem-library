"""Unit tests for n_sight_collector.py against a local mock server.

The mock serves the N-sight RMM Data Extraction API service list_failing_checks in the XML
shape N-able's developer documentation gives (result > items > client > site > workstations
and servers > failed_checks > check, with the API key in the query string), plus a Sophos
NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s collectors/n-able-n-sight-failing-checks -p 'test_*.py' -v
"""
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import n_sight_collector as c  # noqa: E402

API_KEY = "0123456789abcdeftestnsightkeynotreal"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def xml_for(clients, status="OK"):
    """clients: {clientid: (name, {siteid: (name, [(kind, devid, devname, [(checkid, desc, output)])])})}"""
    parts = [f'<?xml version="1.0" ?><result created="2026-10-12T22:40:11+11:00" host="SERVER" status="{status}"><items>']
    for cid, (cname, sites) in clients.items():
        parts.append(f"<client><clientid>{cid}</clientid><name>{escape(cname)}</name>")
        for sid, (sname, devices) in sites.items():
            parts.append(f"<site><siteid>{sid}</siteid><name>{escape(sname)}</name><workstations>")
            for kind in ("workstation", "server"):
                if kind == "server":
                    parts.append("</workstations><servers>")
                for dkind, did, dname, checks in devices:
                    if dkind != kind:
                        continue
                    parts.append(f"<{kind}><id>{did}</id><name>{escape(dname)}</name><failed_checks>")
                    for chk, desc, out in checks:
                        parts.append(f"<check><checkid>{chk}</checkid><check_type>1012</check_type><dsc_247>1</dsc_247>"
                                     f"<description>{escape(desc)}</description><date>2026-10-12</date><time>22:40:11</time>"
                                     f"<formatted_output>{escape(out)}</formatted_output><checkstatus>testerror</checkstatus></check>")
                    parts.append(f"</failed_checks></{kind}>")
            parts.append("</servers></site>")
        parts.append("</client>")
    parts.append("</items></result>")
    return "".join(parts).encode()


class Mock:
    def __init__(self):
        self.clients = {}
        self.status = "OK"
        self.codes = []
        self.ingest_codes = []
        self.ingested = []
        self.requests = []


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        m = self.mock
        m.requests.append(("GET", self.path, dict(self.headers)))
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path != "/api/" or q.get("service") != ["list_failing_checks"]:
            return self._send(404, b"", "text/plain")
        if q.get("apikey") != [API_KEY]:
            return self._send(200, b'<?xml version="1.0" ?><result status="FAIL"><error>Invalid API key</error></result>', "application/xml")
        if m.codes:
            return self._send(m.codes.pop(0), b"", "text/plain")
        clients = m.clients
        if "clientid" in q:
            clients = {k: v for k, v in clients.items() if str(k) == q["clientid"][0]}
        self._send(200, xml_for(clients, m.status), "application/xml")

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.requests.append(("POST", self.path, dict(self.headers)))
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._send(401, b"{}", "application/json")
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._send(code, b"{}", "application/json")
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        m.ingested.append({"headers": dict(self.headers), "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
        self._send(200, b"{}", "application/json")


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


class CollectorTest(unittest.TestCase):
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
             "NSIGHT_API_URL": self.base, "NSIGHT_API_KEY": API_KEY, "COLLECTOR_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def base_clients(self):
        return {1234: ("Acme Dental", {123: ("Head office", [
            ("workstation", 12, "ACME-WS-014", [(23, "Windows Service Check - WinDefend", "Status: STOPPED")]),
            ("server", 14, "ACME-SRV-02", [(31, "Event Log Check - Security", "4 events matched"), (32, "Backup Check", "Backup failed")]),
        ])})}

    def test_first_poll_sends_current_failures_flattened(self):
        self.mock.clients = self.base_clients()
        c.run_once(self.cfg())
        sent = self.sent()
        self.assertEqual([(r["State"], r["DeviceName"], r["CheckId"]) for r in sent],
                         [("failing", "ACME-WS-014", "23"), ("failing", "ACME-SRV-02", "31"), ("failing", "ACME-SRV-02", "32")])
        r = sent[0]
        self.assertEqual(list(r)[:2], ["State", "ObservedAt"])
        self.assertEqual((r["Source"], r["ClientName"], r["SiteName"], r["DeviceType"], r["Description"], r["FormattedOutput"]),
                         ("N-sight RMM", "Acme Dental", "Head office", "workstation", "Windows Service Check - WinDefend", "Status: STOPPED"))

    def test_changes_between_polls(self):
        self.mock.clients = self.base_clients()
        cfg = self.cfg()
        c.run_once(cfg)
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])
        self.mock.clients[1234][1][123][1][1][3].pop()          # check 32 clears
        self.mock.clients[1234][1][123][1][0][3].append((24, "Disk Space Check - C:", "5% free"))
        c.run_once(cfg)
        self.assertEqual(sorted((r["State"], r["CheckId"]) for r in self.sent()), [("cleared", "32"), ("failing", "24")])

    def test_send_existing_off_starts_quietly(self):
        self.mock.clients = self.base_clients()
        cfg = self.cfg(NSIGHT_SEND_EXISTING="0")
        c.run_once(cfg)
        self.assertEqual(self.sent(), [])
        self.mock.clients[1234][1][123][1][0][3].append((24, "Disk Space Check - C:", "5% free"))
        c.run_once(cfg)
        self.assertEqual([r["CheckId"] for r in self.sent()], ["24"])

    def test_client_ids_are_queried_one_by_one(self):
        self.mock.clients = {**self.base_clients(), 5678: ("Contoso Legal", {200: ("Main", [("workstation", 40, "CTS-WS-01", [(50, "AV Check", "Out of date")])])})}
        c.run_once(self.cfg(NSIGHT_CLIENT_IDS="5678"))
        self.assertEqual([r["ClientName"] for r in self.sent()], ["Contoso Legal"])

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.clients = self.base_clients()
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        self.assertEqual(len(out.getvalue().splitlines()), 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_bad_key_stops(self):
        self.mock.clients = self.base_clients()
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(NSIGHT_API_KEY="0000000000wrongkey"))
        self.assertFalse(os.path.exists(self.state))

    def test_server_errors_are_retried(self):
        self.mock.clients = self.base_clients()
        self.mock.codes = [503, 429]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_ingest_failure_keeps_the_state(self):
        self.mock.clients = self.base_clients()
        with self.assertRaises(c.CollectorError):
            c.run_once(self.cfg(NGSIEM_INGEST_KEY="wrong-key-000000000"))
        self.assertFalse(os.path.exists(self.state))

    def test_secrets_never_logged(self):
        self.mock.clients = self.base_clients()
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        logged = self.logbuf.getvalue()
        self.assertIn("failing checks", logged)
        for secret in (API_KEY, INGEST_KEY, "00000000-example-integration"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_plain_http_and_bad_values(self):
        with self.assertRaises(c.CollectorError):
            c.load_config({"NSIGHT_API_URL": "http://www.example.com", "NSIGHT_API_KEY": API_KEY})
        with self.assertRaises(c.CollectorError):
            c.load_config({"NSIGHT_API_URL": "https://www.example.com", "NSIGHT_API_KEY": API_KEY, "NSIGHT_CHECK_TYPE": "all"})
        with self.assertRaises(c.CollectorError):
            c.load_config({"NSIGHT_API_URL": "https://www.example.com", "NSIGHT_API_KEY": API_KEY, "NSIGHT_CLIENT_IDS": "abc"})

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.clients = self.base_clients()
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "N-sight API": self.cfg(NSIGHT_API_URL=r.base)}
            for code in (301, 302, 303, 307, 308):
                r.code = code
                for name, cfg in cases.items():
                    with self.subTest(code=code, url=name):
                        r.redirected.clear()
                        r.followed.clear()
                        if os.path.exists(self.state):
                            os.remove(self.state)
                        with self.assertRaises(c.CollectorError):
                            c.run_once(cfg)
                        self.assertEqual(len(r.redirected), 1)
                        self.assertEqual(r.followed, [])
                        self.assertFalse(os.path.exists(self.state))
        finally:
            r.close()


if __name__ == "__main__":
    unittest.main()
