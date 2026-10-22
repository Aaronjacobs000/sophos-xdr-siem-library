"""Unit tests for rapid7_insightvm_bridge.py against a local mock server.

The mock serves the shapes in Rapid7's InsightVM Cloud Integrations API reference (v4): POST
/vm/v4/integration/assets with size, cursor, currentTime, comparisonTime, includeSame and
includeUniqueIdentifiers in the query and {"asset": "<criteria>"} in the body, answering
{"data": [assets], "metadata": {"number", "size", "totalResources", "totalPages", "cursor"}, "links"},
where each asset carries its "new", "remediated" and (with includeSame) "same" findings, worked out
from each finding's found and remediated times against comparisonTime and currentTime; POST
/vm/v4/integration/vulnerabilities with {"vulnerability": "id IN [...]"}, answering the
definitions; errors as {"status", "message", "localized_message"}; and a Sophos NG-SIEM HTTP Ingest
endpoint. No real service is called.

  python3 -m unittest discover -s bridges/rapid7-insightvm-findings -p 'test_*.py' -v
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
import rapid7_insightvm_bridge as c  # noqa: E402

API_KEY = "test-rapid7-api-key-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
BASE = {"RAPID7_REGION": "au", "RAPID7_API_KEY": API_KEY}
ASSETS = "/vm/v4/integration/assets"
VULNS = "/vm/v4/integration/vulnerabilities"


def when(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _t(value):
    """A time the mock reads: the bridge's whole seconds, or the mock's own milliseconds."""
    return datetime.strptime(value.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z" if "." in value else "%Y-%m-%dT%H:%M:%S%z")


def finding(vuln, found, remediated=None, port=443, **extra):
    """A finding the mock tracks, with when it was found and, if it was, remediated."""
    f = {"vulnerability_id": vuln, "found": found, "remediated": remediated, "port": port}
    f.update(extra)
    return f


def asset(n, assessed, *findings, **extra):
    a = {"id": f"452534235-25a7-40a3-9321-28ce0b5cc90e-default-asset-{n}", "ip": f"192.0.2.{n}",
         "host_name": f"srv{n}.example.com", "os_family": "Linux", "os_name": "Linux", "os_system_name": "Ubuntu Linux",
         "last_assessed_for_vulnerabilities": assessed, "last_scan_end": assessed, "risk_score": 1250.5,
         "tags": [{"name": "Production", "type": "SITE"}], "findings": list(findings)}
    a.update(extra)
    return a


def definition(vid, title, severity="severe", score=7.5):
    return {"id": vid, "title": title, "severity": severity, "severity_score": 7, "risk_score": 612.4,
            "cvss_v2_score": 6.8, "cvss_v2_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P", "cvss_v3_score": score,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cves": "CVE-2026-1234",
            "categories": "Web,Remote Execution", "published": "2026-09-01T00:00:00Z", "modified": "2026-09-15T00:00:00Z",
            "added": "2026-09-02T00:00:00Z", "denial_of_service": False, "exploits": [], "malware_kits": [],
            "description": "A long description the bridge leaves out.", "links": [{"href": "https://example.com/a", "rel": "advisory"}],
            "references": "cve:CVE-2026-1234", "pci_status": "fail"}


class Mock:
    def __init__(self):
        self.assets = []
        self.defs = {}
        self.codes = []
        self.vuln_codes = []
        self.ingest_codes = []
        self.ingested = []
        self.queries = []
        self.vuln_queries = []
        self.keys = []
        self.answer = None
        self.refuse_cursor = False


def present(f, at):
    found = _t(f["found"])
    gone = _t(f["remediated"]) if f["remediated"] else None
    return found <= at and (gone is None or gone > at)


def out_finding(f, state):
    out = {"vulnerability_id": f["vulnerability_id"], "check_id": None, "first_found": f["found"], "last_found": f["found"],
           "key": "", "nic": "eth0", "port": f["port"], "protocol": "TCP", "proof": f"<p>Proof for {f['vulnerability_id']}</p>",
           "reintroduced": None, "solution_fix": "Upgrade to the latest version.", "solution_id": f"upgrade-{f['vulnerability_id']}",
           "solution_summary": "Upgrade", "solution_type": "PATCH", "status": "VULNERABLE_VERS"}
    if state == "remediated":
        out["remediation_date"] = f["remediated"]
    out.update({k: v for k, v in f.items() if k not in ("vulnerability_id", "found", "remediated", "port")})
    return out


def run_assets(mock, q, body):
    current = _t(q["currentTime"])
    comparison = _t(q["comparisonTime"]) if "comparisonTime" in q else current
    same = q.get("includeSame") == "true"
    rows = []
    crit = body.get("asset")
    since = None
    if crit is not None:
        m = re.fullmatch(r"last_assessed_for_vulnerabilities > (\S+)", crit)
        assert m, crit
        since = _t(m.group(1))
    for a in sorted(mock.assets, key=lambda x: x["id"]):
        if since is not None and _t(a["last_assessed_for_vulnerabilities"]) <= since:
            continue
        out = {k: v for k, v in a.items() if k != "findings"}
        out["new"] = [out_finding(f, "new") for f in a["findings"] if present(f, current) and not present(f, comparison)]
        out["remediated"] = [out_finding(f, "remediated") for f in a["findings"] if present(f, comparison) and not present(f, current)]
        if same:
            out["same"] = [out_finding(f, "same") for f in a["findings"] if present(f, current) and present(f, comparison)]
        rows.append(out)
    size = int(q.get("size", "10"))
    start = int(base64.b64decode(q["cursor"]).decode().split(":")[1]) if q.get("cursor") else 0
    page = rows[start:start + size]
    meta = {"number": start // size, "size": size, "totalResources": len(rows), "totalPages": -(-len(rows) // size)}
    if start + size < len(rows):
        meta["cursor"] = base64.b64encode(f"offset:{start + size}".encode()).decode()
    return {"data": page, "metadata": meta, "links": [{"href": "https://au.api.insight.rapid7.com/vm/v4/integration/assets", "rel": "self"}]}


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

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        parts = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.path in (ASSETS, VULNS):
            m.keys.append(self.headers.get("X-Api-Key"))
            if self.headers.get("X-Api-Key") != API_KEY:
                return self._send(401, {"message": "Unauthorized"})
            queue = m.codes if parts.path == ASSETS else m.vuln_codes
            if queue:
                code = queue.pop(0)
                if isinstance(code, tuple):
                    return self._send(*code)
                return self._send(code, {"status": code, "message": "Service unavailable.",
                                         "localized_message": "The service is not currently available. Please try again."})
            req = json.loads(body)
            if parts.path == ASSETS:
                m.queries.append({"query": q, "body": req})
                if m.refuse_cursor and q.get("cursor"):
                    m.refuse_cursor = False
                    return self._send(400, {"status": 400, "message": "Invalid cursor. Use the value returned in metadata.cursor from a previous response.", "links": []})
                if m.answer is not None:
                    return self._send(200, m.answer)
                return self._send(200, run_assets(m, q, req))
            m.vuln_queries.append({"query": q, "body": req})
            ids = re.fullmatch(r"id IN \[(.*)\]", req["vulnerability"]).group(1)
            ids = [x.strip().strip("'") for x in ids.split(",")]
            rows = [m.defs[i] for i in ids if i in m.defs]
            size = int(q.get("size", "10"))
            start = int(base64.b64decode(q["cursor"]).decode().split(":")[1]) if q.get("cursor") else 0
            meta = {"number": 0, "size": size, "totalResources": len(rows)}
            if start + size < len(rows):
                meta["cursor"] = base64.b64encode(f"offset:{start + size}".encode()).decode()
            return self._send(200, {"data": rows[start:start + size], "metadata": meta, "links": []})
        if not parts.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
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
    ("RAPID7_PAGE_SIZE", "page_size", 50, 200, int, 500),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 8760),
    ("BRIDGE_DELAY_SECONDS", "delay_seconds", 900, 60, int, 86400),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 120.0, 30.5, float, 10 ** 9),
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
        self._time = c.time.time
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.clock = self.now.timestamp()
        c.time.time = lambda: self.clock
        self.mock.defs = {"apache-httpd-cve-2026-1234": definition("apache-httpd-cve-2026-1234", "Apache HTTPD: CVE-2026-1234: Request smuggling"),
                          "openssl-cve-2026-2001": definition("openssl-cve-2026-2001", "OpenSSL: CVE-2026-2001: Denial of service", "moderate", 5.9)}

    def tearDown(self):
        c.time.sleep = self._sleep
        c.time.time = self._time
        c.LOG.removeHandler(self.handler)
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()
        gc.collect()
        self._warnings.__exit__(None, None, None)
        self.assertEqual(self.leaks, [], "a socket or file was left open")

    def cfg(self, **extra):
        e = {"NGSIEM_INGEST_URL": f"{self.base}/http-endpoint/v1/00000000-example-integration", "NGSIEM_INGEST_KEY": INGEST_KEY,
             "RAPID7_REGION": "au", "RAPID7_API_URL": self.base, "RAPID7_API_KEY": API_KEY, "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        return c.load_config(e)

    def ago(self, hours):
        return when(self.now - timedelta(hours=hours))

    def later(self, hours):
        self.clock = self.now.timestamp() + hours * 3600

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def key(self):
        return f"au@127.0.0.1:{self.server.server_address[1]}"

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("RAPID7_API_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_the_first_run_sends_every_current_finding_of_the_assets_assessed_in_the_lookback(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)),
                                  finding("openssl-cve-2026-2001", self.ago(6), port=None),
                                  finding("old-cve-2020-0001", self.ago(400), self.ago(300))),
                            asset(11, self.ago(30), finding("apache-httpd-cve-2026-1234", self.ago(40)))]
        self.assertEqual(c.run_once(self.cfg()), 2)
        raw = self.mock.ingested[0]["raw"]
        self.assertTrue(raw.startswith('{"rapid7_record":"finding","rapid7_region":"au","rapid7_state":"same","asset":{"id":"'), raw[:120])
        sent = self.sent()
        self.assertEqual([(r["rapid7_state"], r["finding"]["vulnerability_id"]) for r in sent],
                         [("same", "apache-httpd-cve-2026-1234"), ("same", "openssl-cve-2026-2001")])
        self.assertNotIn("same", sent[0]["asset"])
        self.assertNotIn("findings", sent[0]["asset"])
        self.assertEqual(sent[0]["asset"]["host_name"], "srv10.example.com")
        self.assertEqual(sent[0]["vulnerability"]["title"], "Apache HTTPD: CVE-2026-1234: Request smuggling")
        self.assertEqual(set(sent[0]["vulnerability"]), set(c.VULN_FIELDS))
        q = self.mock.queries[0]
        self.assertEqual({k: q["query"][k] for k in ("size", "includeSame", "includeUniqueIdentifiers")},
                         {"size": "50", "includeSame": "true", "includeUniqueIdentifiers": "true"})
        self.assertNotIn("comparisonTime", q["query"])
        self.assertEqual(q["body"], {"asset": f"last_assessed_for_vulnerabilities > {c._when(int(self.clock) - 24 * 3600)}"})
        self.assertEqual(q["query"]["currentTime"], c._when(int(self.clock) - 900))
        self.assertEqual(self.saved()[self.key()]["current"], q["query"]["currentTime"])
        self.assertEqual(set(self.mock.keys), {API_KEY})

    def test_later_runs_send_the_new_and_remediated_findings_since_the_last_run(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)),
                                  finding("openssl-cve-2026-2001", self.ago(6)))]
        cfg = self.cfg()
        c.run_once(cfg)
        first = self.mock.queries[0]["query"]["currentTime"]
        self.mock.ingested.clear()
        # An hour later: the scan found a new vulnerability, and the OpenSSL one is gone.
        a = self.mock.assets[0]
        a["last_assessed_for_vulnerabilities"] = when(self.now + timedelta(minutes=10))
        a["findings"][1]["remediated"] = when(self.now + timedelta(minutes=10))
        a["findings"].append(finding("nginx-cve-2026-3003", when(self.now + timedelta(minutes=10)), port=80))
        self.later(1)
        c.run_once(cfg)
        q = self.mock.queries[1]
        self.assertEqual(q["query"]["comparisonTime"], first)
        self.assertEqual(q["query"]["includeSame"], "false")
        self.assertEqual(q["body"], {"asset": f"last_assessed_for_vulnerabilities > {first}"})
        sent = self.sent()
        self.assertEqual([(r["rapid7_state"], r["finding"]["vulnerability_id"]) for r in sent],
                         [("new", "nginx-cve-2026-3003"), ("remediated", "openssl-cve-2026-2001")])
        self.assertEqual(sent[1]["finding"]["remediation_date"], when(self.now + timedelta(minutes=10)))
        self.assertNotIn("vulnerability", sent[0])
        # The next window starts where this one ended, and an unchanged asset sends nothing.
        self.mock.ingested.clear()
        self.later(2)
        c.run_once(cfg)
        self.assertEqual(self.mock.queries[2]["query"]["comparisonTime"], q["query"]["currentTime"])
        self.assertEqual(self.sent(), [])

    def test_include_same_sends_every_current_finding_on_each_run(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        cfg = self.cfg(RAPID7_INCLUDE_SAME="1")
        c.run_once(cfg)
        self.mock.ingested.clear()
        self.mock.assets[0]["last_assessed_for_vulnerabilities"] = when(self.now + timedelta(minutes=10))
        self.later(1)
        c.run_once(cfg)
        self.assertEqual(self.mock.queries[1]["query"]["includeSame"], "true")
        self.assertEqual([r["rapid7_state"] for r in self.sent()], ["same"])

    def test_no_new_window_until_the_delay_has_passed(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        cfg = self.cfg()
        c.run_once(cfg)
        self.assertEqual(c.run_once(cfg), 0)
        self.assertEqual(len(self.mock.queries), 1)
        self.assertIn("no new window yet", self.logbuf.getvalue())

    def test_pages_follow_the_cursor_and_a_stopped_window_goes_on_from_its_next_page(self):
        self.mock.assets = [asset(10 + i, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48))) for i in range(5)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(RAPID7_PAGE_SIZE="2"))
        state = self.saved()[self.key()]
        self.assertEqual(base64.b64decode(state["pending"]["cursor"]).decode(), "offset:2")
        self.assertNotIn("current", state)
        first = self.mock.queries[0]["query"]
        self.mock_first_body = self.mock.queries[0]["body"]
        self.assertEqual(state["pending"]["since"], c._when(int(self.clock) - 24 * 3600))
        self.assertEqual(self.mock.queries[1]["query"]["cursor"], state["pending"]["cursor"])
        self.mock.ingested.clear()
        self.mock.queries.clear()
        self.later(1)
        c.run_once(self.cfg(RAPID7_PAGE_SIZE="2"))
        # The same window, from the third asset: the same times and asset filter, an hour later.
        self.assertEqual([q["query"]["currentTime"] for q in self.mock.queries], [first["currentTime"]] * 2)
        self.assertEqual([q["body"] for q in self.mock.queries], [self.mock_first_body] * 2)
        self.assertEqual([base64.b64decode(q["query"]["cursor"]).decode() for q in self.mock.queries], ["offset:2", "offset:4"])
        self.assertEqual([r["asset"]["ip"] for r in self.sent()], ["192.0.2.12", "192.0.2.13", "192.0.2.14"])
        state = self.saved()[self.key()]
        self.assertNotIn("pending", state)
        self.assertEqual(state["current"], first["currentTime"])

    def test_a_refused_saved_cursor_reads_the_window_again_from_its_first_page(self):
        self.mock.assets = [asset(10 + i, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48))) for i in range(3)]
        with open(self.state, "w") as fh:
            json.dump({self.key(): {"pending": {"comparison": None, "current": c._when(int(self.clock) - 900),
                                                "cursor": "c3RhbGUtY3Vyc29y"}}}, fh)
        self.mock.refuse_cursor = True
        c.run_once(self.cfg(RAPID7_PAGE_SIZE="2"))
        self.assertEqual(len(self.sent()), 3)
        self.assertIn("refused the saved cursor", self.logbuf.getvalue())
        self.assertNotIn("cursor", self.mock.queries[1]["query"])

    def test_a_cursor_that_doesnt_move_on_stops_the_run(self):
        cursor = base64.b64encode(b"offset:0").decode()
        self.mock.answer = {"data": [asset(10, self.ago(5))], "metadata": {"cursor": cursor}}
        with open(self.state, "w") as fh:
            json.dump({self.key(): {"pending": {"comparison": None, "current": c._when(int(self.clock) - 900), "cursor": cursor}}}, fh)
        with self.assertRaisesRegex(c.BridgeError, "next cursor is the one it was sent"):
            c.run_once(self.cfg())

    def test_definitions_are_read_once_in_batches_with_safe_ids(self):
        ids = [f"example-cve-2026-{i:04d}" for i in range(250)]
        self.mock.defs.update({i: definition(i, f"Example {i}") for i in ids})
        self.mock.assets = [asset(10, self.ago(5), *[finding(i, self.ago(48)) for i in ids],
                                  finding("bad id' || 1", self.ago(48))),
                            asset(11, self.ago(5), *[finding(i, self.ago(48)) for i in ids[:10]])]
        client = c.Rapid7(self.cfg())
        c.run_once(self.cfg(), client=client)
        self.assertEqual([len(q["body"]["vulnerability"].split(",")) for q in self.mock.vuln_queries], [100, 100, 50])
        self.assertTrue(all(q["query"]["size"] == "500" for q in self.mock.vuln_queries))
        sent = self.sent()
        self.assertEqual(len(sent), 261)
        # An ID the bridge won't put in a filter, and one Rapid7 doesn't know, get no definition.
        self.assertNotIn("vulnerability", [r for r in sent if r["finding"]["vulnerability_id"] == "bad id' || 1"][0])
        self.assertNotIn("bad id", json.dumps([q["body"] for q in self.mock.vuln_queries]))
        self.assertEqual(sum("vulnerability" in r for r in sent), 260)

    def test_definitions_off_sends_no_vulnerabilities_request(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        c.run_once(self.cfg(RAPID7_DEFINITIONS="0"))
        self.assertEqual(self.mock.vuln_queries, [])
        self.assertNotIn("vulnerability", self.sent()[0])

    def test_a_refused_key_or_request_stops_with_rapid7s_message(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(RAPID7_API_KEY="another-wrong-key-000"))
        self.assertIn("Rapid7 refused the API key (HTTP 401): Unauthorized; check RAPID7_API_KEY", str(cm.exception))
        self.mock.codes = [(400, {"status": 400, "localized_message": None, "message": "Your query string format is not valid."})]
        with self.assertRaisesRegex(c.BridgeError, r"refused the assets request \(HTTP 400\): Your query string format is not valid\.$") as cm:
            c.run_once(self.cfg())
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.mock.codes = [(403, {"status": 403, "message": "Access to this resource is not allowed"})]
        with self.assertRaisesRegex(c.BridgeError, r"HTTP 403\): Access to this resource is not allowed"):
            c.run_once(self.cfg())
        self.assertFalse(os.path.exists(self.state))

    def test_an_answer_with_no_data_list_stops_the_run(self):
        for answer in ({"metadata": {}}, {"data": "x"}, [1, 2]):
            with self.subTest(answer=answer):
                self.mock.answer = answer
                with self.assertRaisesRegex(c.BridgeError, "returned JSON with no data list"):
                    c.run_once(self.cfg())
        self.mock.answer = b"<html>maintenance</html>"
        with self.assertRaisesRegex(c.BridgeError, "not JSON"):
            c.run_once(self.cfg())

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)),
                                  finding("openssl-cve-2026-2001", self.ago(30)))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["rapid7_record"] for x in lines], ["finding"] * 2)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        self.mock.codes = [(429, {"status": 429, "message": "Too many requests"}, {"Retry-After": "1"}), 503]
        self.mock.vuln_codes = [500]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.slept[0], 1.0)

    def test_gzip_batches_and_headers(self):
        self.mock.assets = [asset(10 + i, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48))) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(RAPID7_API_KEY="another-wrong-key-000", BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "other.json")))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("assets request", logged)
        for secret in (API_KEY, INGEST_KEY, "00000000-example-integration", "another-wrong-key-000"):
            self.assertNotIn(secret, logged)

    def test_state_is_kept_per_region_and_api(self):
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        c.run_once(self.cfg())
        self.mock.ingested.clear()
        c.run_once(self.cfg(RAPID7_REGION="us2"))
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.sent()[0]["rapid7_region"], "us2")
        self.assertEqual(set(self.saved()), {self.key(), self.key().replace("au@", "us2@")})

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "RAPID7_REGION": ""}, {**BASE, "RAPID7_REGION": "au.evil.example"}, {**BASE, "RAPID7_REGION": "a"},
                    {**BASE, "RAPID7_API_KEY": ""}, {**BASE, "RAPID7_API_URL": "http://au.api.insight.rapid7.com"},
                    {**BASE, "RAPID7_API_URL": "https://au.api.insight.rapid7.com/vm"},
                    {**BASE, "NGSIEM_INGEST_URL": "http://ingest.example/http-endpoint/v1/x"},
                    {**BASE, "RAPID7_PAGE_SIZE": "0"}, {**BASE, "RAPID7_PAGE_SIZE": "501"}, {**BASE, "BRIDGE_LOOKBACK_HOURS": "8761"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "RAPID7_API_KEY"}), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["api_url"], cfg["region"]), ("https://au.api.insight.rapid7.com", "au"))
        self.assertEqual((cfg["page_size"], cfg["delay_seconds"], cfg["lookback_hours"], cfg["include_same"], cfg["definitions"]),
                         (50, 900, 24.0, False, True))
        for region in ("us", "us2", "us3", "eu", "ca", "au", "ap", "aps2", "me1", "AU"):
            with self.subTest(region=region):
                self.assertEqual(c.load_config({**BASE, "RAPID7_REGION": region})["api_url"],
                                 f"https://{region.lower()}.api.insight.rapid7.com")

    def test_times_read_to_the_second_in_utc(self):
        want = int(datetime(2026, 10, 14, 3, 12, 45, tzinfo=timezone.utc).timestamp())
        self.assertEqual(c._seconds("2026-10-14T03:12:45Z"), want)
        for bad in ("2026-10-14", "2026-10-14T03:12:45", "2026-13-14T03:12:45Z", "", None, "yesterday"):
            with self.subTest(bad=bad):
                self.assertIsNone(c._seconds(bad))
        self.assertEqual(c._when(want), "2026-10-14T03:12:45Z")

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.assets = [asset(10, self.ago(5), finding("apache-httpd-cve-2026-1234", self.ago(48)))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": lambda: self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Rapid7 API": lambda: self.cfg(RAPID7_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and any(v.get("current") for v in self.saved().values()))
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
        for value in ("-1", "0", "501"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^RAPID7_PAGE_SIZE must be between 1 and 500$"):
                self.load(RAPID7_PAGE_SIZE=value)
        self.assertEqual(self.load(RAPID7_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(RAPID7_PAGE_SIZE="500")["page_size"], 500)

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

    def test_one_client_keeps_its_definitions_across_runs(self):
        self.run_once_raises(c.NetworkError("assets request to au.api.insight.rapid7.com failed: URLError"))
        self.assertEqual(c.main(["--interval", "5"]), 130)
        clients = [k["client"] for k in self.calls]
        self.assertEqual(len(clients), 2)
        self.assertIs(clients[0], clients[1])

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
        error = c.HostNotFound("assets request to au.api.insight.rapid7.com failed: the host name wasn't found; check the URL setting")
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
