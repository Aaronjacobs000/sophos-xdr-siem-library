"""Unit tests for qualys_vmdr_bridge.py against a local mock server.

The mock serves the shapes in Qualys's VM API documentation and output DTDs: POST
/api/6.0/fo/asset/host/vm/detection/ (a form body with action=list, detection_updated_since,
detection_updated_before, status, truncation_limit, id_min and the show_ options; answering
HOST_LIST_VM_DETECTION_OUTPUT XML with a DOCTYPE, CDATA values, a keep-alive comment, one HOST per
host in host ID order with its DETECTION_LIST, and a WARNING with code 1980 and the next page's URL
when the page is full), POST /api/4.0/fo/knowledge_base/vuln/ (action=list, details=All and ids,
answering KNOWLEDGE_BASE_VULN_LIST_OUTPUT XML), errors as SIMPLE_RETURN XML with a CODE and TEXT
(401 code 2000, 409 code 1965 with X-RateLimit-ToWait-Sec, and the others in Qualys's error code
appendix), and a Sophos NG-SIEM HTTP Ingest endpoint. Both of the detection request's time bounds
count, so the tests show a detection at a window's end is sent once. No real service is called.

  python3 -m unittest discover -s bridges/qualys-vmdr-detections -p 'test_*.py' -v
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
import unittest
import urllib.parse
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qualys_vmdr_bridge as c  # noqa: E402

USER = "acme_ab12"
PASSWORD = "test-qualys-password-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
BASE = {"QUALYS_API_URL": "https://qualysapi.qg1.apps.qualys.com.au", "QUALYS_USERNAME": USER,
        "QUALYS_PASSWORD": PASSWORD}
DETECTIONS = "/api/6.0/fo/asset/host/vm/detection/"
KB = "/api/4.0/fo/knowledge_base/vuln/"


def when(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detection(uvid, qid, updated, status="New", severity="4", **extra):
    d = {"UNIQUE_VULN_ID": str(uvid), "QID": str(qid), "TYPE": "Confirmed", "SEVERITY": severity, "PORT": "443",
         "PROTOCOL": "tcp", "SSL": "1", "RESULTS": f"Result for {uvid}", "STATUS": status,
         "FIRST_FOUND_DATETIME": updated, "LAST_FOUND_DATETIME": updated, "QDS": ("72", "HIGH"),
         "TIMES_FOUND": "1", "LAST_TEST_DATETIME": updated, "LAST_UPDATE_DATETIME": updated, "IS_IGNORED": "0",
         "IS_DISABLED": "0", "LAST_PROCESSED_DATETIME": updated}
    d.update(extra)
    return d


def host(hid, *dets, **extra):
    h = {"ID": str(hid), "ASSET_ID": str(9000000 + hid), "IP": f"192.0.2.{hid % 250}", "TRACKING_METHOD": "AGENT",
         "OS": "Windows Server 2022", "DNS": f"srv{hid}.example.com",
         "DNS_DATA": {"HOSTNAME": f"srv{hid}", "DOMAIN": "example.com", "FQDN": f"srv{hid}.example.com"},
         "NETBIOS": f"SRV{hid}", "LAST_SCAN_DATETIME": "2026-10-13T22:00:00Z", "detections": list(dets)}
    h.update(extra)
    return h


def _xml(name, value):
    if isinstance(value, tuple):
        return f'<{name} severity="{value[1]}">{escape(value[0])}</{name}>'
    if isinstance(value, dict):
        return f"<{name}>" + "".join(_xml(k, v) for k, v in value.items()) + f"</{name}>"
    return f"<{name}><![CDATA[{value}]]></{name}>"


def detection_xml(hosts, warning=None, keep_alive=True):
    out = ['<?xml version="1.0" encoding="UTF-8" ?>',
           '<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/6.0/fo/asset/host/vm/detection/dtd/output.dtd">',
           "<HOST_LIST_VM_DETECTION_OUTPUT>", "<RESPONSE>", "<DATETIME>2026-10-14T00:00:00Z</DATETIME>"]
    if keep_alive:
        out.append("<!-- keep-alive -->")
    if hosts:
        out.append("<HOST_LIST>")
        for h in hosts:
            out.append("<HOST>")
            for k, v in h.items():
                if k == "detections":
                    continue
                if k == "TAGS":
                    out.append("<TAGS>" + "".join(f"<TAG><TAG_ID>{t[0]}</TAG_ID><NAME><![CDATA[{t[1]}]]></NAME></TAG>" for t in v) + "</TAGS>")
                elif k == "ASSET_GROUP_LIST":
                    out.append("<ASSET_GROUP_LIST />")
                else:
                    out.append(_xml(k, v))
            out.append("<DETECTION_LIST>")
            for d in h["detections"]:
                out.append("<DETECTION>")
                for k, v in d.items():
                    if k == "QDS_FACTORS":
                        out.append("<QDS_FACTORS>" + "".join(f'<QDS_FACTOR name="{n}"><![CDATA[{x}]]></QDS_FACTOR>' for n, x in v.items()) + "</QDS_FACTORS>")
                    else:
                        out.append(_xml(k, v))
                out.append("</DETECTION>")
            out.append("</DETECTION_LIST></HOST>")
        out.append("</HOST_LIST>")
    if warning:
        out.append(f"<WARNING><CODE>{warning[0]}</CODE><TEXT>record limit exceeded. Use URL to get next batch of results.</TEXT>"
                   f"<URL><![CDATA[{warning[1]}]]></URL></WARNING>")
    out += ["</RESPONSE>", "</HOST_LIST_VM_DETECTION_OUTPUT>"]
    return "\n".join(out).encode()


def kb_vuln(qid, title, cves=("CVE-2026-1234",), cvss3="9.8"):
    cve = "".join(f"<CVE><ID><![CDATA[{x}]]></ID><URL><![CDATA[https://www.cve.org/CVERecord?id={x}]]></URL></CVE>" for x in cves)
    return (f"<VULN><QID>{qid}</QID><VULN_TYPE>Vulnerability</VULN_TYPE><SEVERITY_LEVEL>4</SEVERITY_LEVEL>"
            f"<TITLE><![CDATA[{title}]]></TITLE><CATEGORY>Windows</CATEGORY>"
            "<LAST_SERVICE_MODIFICATION_DATETIME>2026-09-02T02:43:07Z</LAST_SERVICE_MODIFICATION_DATETIME>"
            "<PUBLISHED_DATETIME>2026-08-26T14:08:11Z</PUBLISHED_DATETIME><PATCHABLE>1</PATCHABLE>"
            + (f"<CVE_LIST>{cve}</CVE_LIST>" if cves else "") +
            "<DIAGNOSIS><![CDATA[The vendor released an update.]]></DIAGNOSIS>"
            "<CVSS><BASE source=\"service\">7.5</BASE><TEMPORAL>6.5</TEMPORAL></CVSS>"
            f"<CVSS_V3><BASE>{cvss3}</BASE><TEMPORAL>8.5</TEMPORAL><VECTOR_STRING>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</VECTOR_STRING>"
            "<CVSS3_VERSION>3.1</CVSS3_VERSION></CVSS_V3>"
            "<THREAT_INTELLIGENCE><THREAT_INTEL id=\"2\"><![CDATA[Exploit_Public]]></THREAT_INTEL>"
            "<THREAT_INTEL id=\"5\"><![CDATA[Easy_Exploit]]></THREAT_INTEL></THREAT_INTELLIGENCE></VULN>")


def simple_return(code, text="Error text"):
    return (f'<?xml version="1.0" encoding="UTF-8" ?><!DOCTYPE SIMPLE_RETURN SYSTEM "https://qualysapi.qualys.com/api/2.0/simple_return.dtd">'
            f"<SIMPLE_RETURN><RESPONSE><DATETIME>2026-10-14T00:00:00Z</DATETIME><CODE>{code}</CODE>"
            f"<TEXT>{text}</TEXT></RESPONSE></SIMPLE_RETURN>").encode()


class Mock:
    def __init__(self):
        self.hosts = []
        self.kb = {}
        self.codes = []
        self.kb_codes = []
        self.ingest_codes = []
        self.ingested = []
        self.forms = []
        self.kb_forms = []
        self.paths = []
        self.headers = []
        self.answer = None
        self.kb_answer = None


def run_detections(mock, form):
    """The Host List Detection API on the mock's hosts: the status, severity and update-time
    filters (both bounds count), host ID order, truncation_limit and id_min."""
    since, before = c._seconds(form["detection_updated_since"]), c._seconds(form["detection_updated_before"])
    statuses = set(form.get("status", "New,Active,Re-Opened").split(","))
    sev = None
    if form.get("severities"):
        sev = set()
        for part in form["severities"].split(","):
            lo, _, hi = part.partition("-")
            sev |= {str(x) for x in range(int(lo), int(hi or lo) + 1)}
    id_min = int(form.get("id_min") or 0)
    limit = int(form.get("truncation_limit", "1000"))
    out = []
    for h in sorted(mock.hosts, key=lambda x: int(x["ID"])):
        if int(h["ID"]) < id_min:
            continue
        dets = [d for d in h["detections"] if since <= c._seconds(d["LAST_UPDATE_DATETIME"]) <= before
                and d["STATUS"] in statuses and (sev is None or d["SEVERITY"] in sev)]
        if form.get("show_results") == "0":
            dets = [{k: v for k, v in d.items() if k != "RESULTS"} for d in dets]
        if form.get("show_qds") == "0":
            dets = [{k: v for k, v in d.items() if k not in ("QDS", "QDS_FACTORS")} for d in dets]
        if dets:
            out.append({**h, "detections": dets})
    if limit and len(out) > limit:
        nxt = out[limit]["ID"]
        url = (f"https://qualysapi.qualys.com/api/6.0/fo/asset/host/vm/detection/?action=list&truncation_limit={limit}"
               f"&id_min={nxt}")
        return detection_xml(out[:limit], ("1980", url))
    return detection_xml(out)


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None, ctype="application/xml"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        want = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        return self.headers.get("Authorization") == want and self.headers.get("X-Requested-With")

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        m.paths.append(self.path)
        if self.path in (DETECTIONS, KB):
            m.headers.append(dict(self.headers))
            if not self._authorized():
                return self._send(401, simple_return("2000", "Bad Login/Password"))
            form = dict(urllib.parse.parse_qsl(body.decode()))
            queue = m.codes if self.path == DETECTIONS else m.kb_codes
            if queue:
                code = queue.pop(0)
                if isinstance(code, tuple):
                    return self._send(code[0], code[1], code[2] if len(code) > 2 else None)
                return self._send(code, simple_return("999", "Internal Error"))
            if self.path == DETECTIONS:
                m.forms.append(form)
                if m.answer is not None:
                    return self._send(200, m.answer)
                return self._send(200, run_detections(m, form))
            m.kb_forms.append(form)
            if m.kb_answer is not None:
                return self._send(200, m.kb_answer)
            vulns = "".join(m.kb[q] for q in form["ids"].split(",") if q in m.kb)
            return self._send(200, ('<?xml version="1.0" encoding="UTF-8" ?><KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE>'
                                    f"<DATETIME>2026-10-14T00:00:00Z</DATETIME><VULN_LIST>{vulns}</VULN_LIST>"
                                    "</RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>").encode())
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._send(401, b"{}", ctype="application/json")
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._send(code, b"{}", ctype="application/json")
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        m.ingested.append({"headers": dict(self.headers), "raw": body.decode(),
                           "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
        self._send(200, b"{}", ctype="application/json")


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
    ("QUALYS_PAGE_HOSTS", "page_hosts", 100, 500, int, 10000),
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
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.mock.kb = {"91500": kb_vuln("91500", "Microsoft Windows Security Update for October 2026"),
                        "38173": kb_vuln("38173", "SSL Certificate - Signature Verification Failed Vulnerability", cves=(),
                                         cvss3="5.3")}

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
             "QUALYS_API_URL": self.base, "QUALYS_USERNAME": USER, "QUALYS_PASSWORD": PASSWORD,
             "BRIDGE_STATE_FILE": self.state}
        e.update(extra)
        cfg = c.load_config(e)
        # The mock runs on 127.0.0.1, so name the platform as a real API server would.
        cfg["platform"] = "qualysapi.qg1.apps.qualys.com.au"
        return cfg

    def ago(self, minutes):
        return when(self.now - timedelta(minutes=minutes))

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def key(self):
        return f"{USER}@qualysapi.qg1.apps.qualys.com.au"

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("QUALYS_API_URL", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com/v1", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_each_detection_is_one_tagged_record_with_its_host_and_knowledgebase_entry(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)), detection(5002, 38173, self.ago(50), severity="2"),
                                TAGS=[("7001", "Production"), ("7002", "Web")], ASSET_GROUP_LIST=None),
                           host(102, detection(5003, 91500, self.ago(40), status="Fixed",
                                               LAST_FIXED_DATETIME=self.ago(40),
                                               QDS_FACTORS={"RTI": "[Exploit_Public]", "CVSS": "9.8", "epss": "0.94"}))]
        self.assertEqual(c.run_once(self.cfg()), 3)
        raw = self.mock.ingested[0]["raw"]
        self.assertTrue(raw.startswith('{"qualys_record":"detection","qualys_platform":"qualysapi.qg1.apps.qualys.com.au","HOST":{"ID":"101"'), raw[:200])
        sent = self.sent()
        self.assertEqual([r["DETECTION"]["UNIQUE_VULN_ID"] for r in sent], ["5001", "5002", "5003"])
        first = sent[0]
        self.assertNotIn("DETECTION_LIST", first["HOST"])
        self.assertEqual(first["HOST"]["DNS_DATA"], {"HOSTNAME": "srv101", "DOMAIN": "example.com", "FQDN": "srv101.example.com"})
        self.assertEqual(first["HOST"]["TAGS"], [{"TAG_ID": "7001", "NAME": "Production"}, {"TAG_ID": "7002", "NAME": "Web"}])
        self.assertEqual(first["HOST"]["ASSET_GROUP_LIST"], [])
        self.assertEqual(first["DETECTION"]["QDS"], {"value": "72", "severity": "HIGH"})
        self.assertEqual(first["DETECTION"]["RESULTS"], "Result for 5001")
        self.assertEqual(sent[2]["DETECTION"]["QDS_FACTORS"], {"RTI": "[Exploit_Public]", "CVSS": "9.8", "epss": "0.94"})
        self.assertEqual(sent[2]["DETECTION"]["STATUS"], "Fixed")
        self.assertEqual(first["KB"], {"TITLE": "Microsoft Windows Security Update for October 2026", "VULN_TYPE": "Vulnerability",
                                       "SEVERITY_LEVEL": "4", "CATEGORY": "Windows", "PUBLISHED_DATETIME": "2026-08-26T14:08:11Z",
                                       "PATCHABLE": "1", "CVE_LIST": ["CVE-2026-1234"], "CVSS": {"BASE": "7.5", "TEMPORAL": "6.5"},
                                       "CVSS_V3": {"BASE": "9.8", "TEMPORAL": "8.5",
                                                   "VECTOR_STRING": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                                       "THREAT_INTELLIGENCE": ["Exploit_Public", "Easy_Exploit"]})
        self.assertNotIn("CVE_LIST", sent[1]["KB"])
        # One KnowledgeBase request for the two QIDs, in QID order.
        self.assertEqual([f["ids"] for f in self.mock.kb_forms], ["38173,91500"])
        self.assertEqual(self.mock.kb_forms[0]["details"], "All")

    def test_the_detection_request_asks_for_every_status_in_a_form_body(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        c.run_once(self.cfg(QUALYS_SEVERITIES="3-5"))
        form = self.mock.forms[0]
        self.assertEqual({k: form[k] for k in ("action", "output_format", "status", "truncation_limit", "show_asset_id",
                                               "show_qds", "show_results", "show_igs", "severities")},
                         {"action": "list", "output_format": "XML", "status": "New,Active,Re-Opened,Fixed",
                          "truncation_limit": "100", "show_asset_id": "1", "show_qds": "1", "show_results": "1",
                          "show_igs": "0", "severities": "3-5"})
        self.assertNotIn("id_min", form)
        # The parameters and credentials never go in the URL.
        self.assertEqual(set(self.mock.paths) - {p for p in self.mock.paths if p.startswith("/http-endpoint/")}, {DETECTIONS, KB})
        self.assertTrue(all(h.get("X-Requested-With") == c.USER_AGENT for h in self.mock.headers))
        self.assertTrue(all(h.get("Content-Type") == "application/x-www-form-urlencoded" for h in self.mock.headers))

    def test_the_show_settings_change_the_request(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        c.run_once(self.cfg(QUALYS_SHOW_RESULTS="0", QUALYS_SHOW_QDS="0", QUALYS_SHOW_IGS="1", QUALYS_PAGE_HOSTS="7"))
        form = self.mock.forms[0]
        self.assertEqual((form["show_results"], form["show_qds"], form["show_igs"], form["truncation_limit"]), ("0", "0", "1", "7"))
        self.assertNotIn("severities", form)
        det = self.sent()[0]["DETECTION"]
        self.assertNotIn("RESULTS", det)
        self.assertNotIn("QDS", det)

    def test_the_window_ends_the_delay_before_now_and_the_first_run_starts_the_lookback_before_now(self):
        self.mock.hosts = [host(101, detection(5001, 91500, when(self.now - timedelta(hours=30))),
                                detection(5002, 91500, self.ago(60)), detection(5003, 91500, self.ago(5)))]
        c.run_once(self.cfg())
        self.assertEqual([r["DETECTION"]["UNIQUE_VULN_ID"] for r in self.sent()], ["5002"])
        form = self.mock.forms[0]
        since, before = c._seconds(form["detection_updated_since"]), c._seconds(form["detection_updated_before"])
        self.assertLess(abs(before - (self.now.timestamp() - 900)), 5)
        self.assertLess(abs(since - (self.now.timestamp() - 24 * 3600)), 5)
        self.assertEqual(self.saved()[self.key()]["cursor"], form["detection_updated_before"])
        self.mock.ingested.clear()
        c.run_once(self.cfg(BRIDGE_DELAY_SECONDS="0"))
        self.assertEqual([r["DETECTION"]["UNIQUE_VULN_ID"] for r in self.sent()], ["5003"])
        self.assertEqual(self.mock.forms[1]["detection_updated_since"], form["detection_updated_before"])

    def test_a_detection_at_the_windows_end_is_sent_once(self):
        # The mock counts both bounds, so the detection updated at the first window's end comes back
        # in the second window. The bridge kept its key and skips it there.
        end = self.now - timedelta(seconds=900)
        self.mock.hosts = [host(101, detection(5001, 91500, when(end)))]
        cfg = self.cfg()
        saved, c.time.time = c.time.time, lambda: self.now.timestamp()
        try:
            c.run_once(cfg)
            self.assertEqual(len(self.sent()), 1)
            self.assertEqual(self.saved()[self.key()]["boundary"], [f"101|5001|91500|{when(end)}"])
            # The status changes later: that is a new key, so it is sent.
            self.mock.hosts[0]["detections"].append(detection(5001, 91500, when(self.now - timedelta(seconds=600)), status="Active"))
            c.time.time = lambda: self.now.timestamp() + 600
            c.run_once(cfg)
        finally:
            c.time.time = saved
        self.assertEqual([(r["DETECTION"]["UNIQUE_VULN_ID"], r["DETECTION"]["STATUS"]) for r in self.sent()],
                         [("5001", "New"), ("5001", "Active")])
        self.assertEqual(len(self.mock.forms), 2)

    def test_pages_follow_id_min_and_a_stopped_window_goes_on_from_its_next_page(self):
        self.mock.hosts = [host(100 + i, detection(5000 + i, 91500, self.ago(60 - i))) for i in range(5)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(QUALYS_PAGE_HOSTS="2"))
        state = self.saved()[self.key()]
        self.assertEqual(state["pending"]["id_min"], "102")
        self.assertNotIn("cursor", state)
        first = self.mock.forms[0]
        self.assertEqual(self.mock.forms[1]["id_min"], "102")
        self.assertEqual([r["DETECTION"]["UNIQUE_VULN_ID"] for r in self.sent()], ["5000", "5001"])
        self.mock.ingested.clear()
        self.mock.forms.clear()
        c.time.time, saved = (lambda: self.now.timestamp() + 3600), c.time.time
        try:
            c.run_once(self.cfg(QUALYS_PAGE_HOSTS="2"))
        finally:
            c.time.time = saved
        # The same window, from host 102: the same since and end, an hour later.
        self.assertEqual([(f["detection_updated_since"], f["detection_updated_before"]) for f in self.mock.forms],
                         [(first["detection_updated_since"], first["detection_updated_before"])] * 2)
        self.assertEqual([f.get("id_min") for f in self.mock.forms], ["102", "104"])
        self.assertEqual([r["DETECTION"]["UNIQUE_VULN_ID"] for r in self.sent()], ["5002", "5003", "5004"])
        state = self.saved()[self.key()]
        self.assertNotIn("pending", state)
        self.assertEqual(state["cursor"], first["detection_updated_before"])

    def test_the_next_page_url_is_read_for_id_min_only(self):
        # The bridge never calls the URL in the warning, so the credentials go only to QUALYS_API_URL.
        self.mock.answer = detection_xml([host(101, detection(5001, 91500, self.ago(60)))],
                                         ("1980", "https://elsewhere.example.com/steal?action=list&id_min=250"))
        self.mock.hosts = []
        with self.assertRaises(c.BridgeError):
            # The mock answers the same page again, so the second request stops the run.
            c.run_once(self.cfg())
        self.assertEqual(self.mock.forms[1]["id_min"], "250")
        self.assertEqual({p for p in self.mock.paths if not p.startswith("/http-endpoint/")}, {DETECTIONS, KB})

    def test_a_warning_the_bridge_cant_page_with_stops_the_run(self):
        for warning in (("1980", "https://qualysapi.qualys.com/api/6.0/fo/asset/host/vm/detection/?action=list"),
                        ("1999", "https://qualysapi.qualys.com/api/6.0/fo/asset/host/vm/detection/?action=list&id_min=5")):
            with self.subTest(warning=warning):
                self.mock.answer = detection_xml([host(101, detection(5001, 91500, self.ago(60)))], warning)
                with self.assertRaisesRegex(c.BridgeError, "returned a warning the bridge can't page with"):
                    c.run_once(self.cfg())
                self.assertFalse(os.path.exists(self.state) and self.saved().get(self.key(), {}).get("cursor"))

    def test_a_next_page_that_doesnt_move_on_stops_the_run(self):
        self.mock.answer = detection_xml([host(101, detection(5001, 91500, self.ago(60)))],
                                         ("1980", "https://qualysapi.qualys.com/api/6.0/fo/asset/host/vm/detection/?action=list&id_min=101"))
        with self.assertRaisesRegex(c.BridgeError, "next page starts where the last one did"):
            c.run_once(self.cfg())

    def test_knowledgebase_entries_are_read_once(self):
        self.mock.hosts = [host(100 + i, detection(5000 + i, 91500, self.ago(60 - i)), detection(6000 + i, 12345, self.ago(60 - i)))
                           for i in range(4)]
        client = c.Qualys(self.cfg(QUALYS_PAGE_HOSTS="2"))
        c.run_once(self.cfg(QUALYS_PAGE_HOSTS="2"), client=client)
        self.assertEqual([f["ids"] for f in self.mock.kb_forms], ["12345,91500"])
        sent = self.sent()
        self.assertEqual(len(sent), 8)
        # QID 12345 isn't in the KnowledgeBase, so its records have no KB, and it isn't asked for again.
        self.assertEqual([("KB" in r) for r in sent if r["DETECTION"]["QID"] == "12345"], [False] * 4)
        self.assertEqual(client.kb_cache["12345"], None)

    def test_knowledgebase_requests_hold_at_most_500_qids(self):
        self.mock.hosts = [host(101, *[detection(5000 + i, 100000 + i, self.ago(60)) for i in range(1201)])]
        c.run_once(self.cfg())
        self.assertEqual([len(f["ids"].split(",")) for f in self.mock.kb_forms], [500, 500, 201])

    def test_qualys_kb_off_sends_no_knowledgebase_request(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        c.run_once(self.cfg(QUALYS_KB="0"))
        self.assertEqual(self.mock.kb_forms, [])
        self.assertNotIn("KB", self.sent()[0])

    def test_a_refused_knowledgebase_download_says_how_to_turn_it_off(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        self.mock.kb_codes = [(403, simple_return("2012", "User license is not authorized to run this API."))]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403, code 2012: User license is not authorized to run this API.", str(cm.exception))
        self.assertIn("QUALYS_KB=0", str(cm.exception))
        self.assertEqual(self.sent(), [])
        self.assertFalse(os.path.exists(self.state))

    def test_api_limits_are_retried_after_the_wait_qualys_gives(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        self.mock.codes = [(409, simple_return("1965", "Too many requests"), {"X-RateLimit-ToWait-Sec": "17"}),
                           (409, simple_return("1960", "Concurrency limit"), {"X-RateLimit-ToWait-Sec": "4"}),
                           (400, simple_return("1965", "Too many requests"), {"X-RateLimit-ToWait-Sec": "3"})]
        self.mock.kb_codes = [(409, simple_return("1920", "Blocked"), {"Retry-After": "2"})]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.slept[:4], [17.0, 4.0, 3.0, 2.0])
        self.assertIn("returned 409 (Qualys API limit); retrying in 17.0s", self.logbuf.getvalue())

    def test_api_limits_past_the_retries_are_a_network_error(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        self.mock.codes = [(409, simple_return("1965"), {"X-RateLimit-ToWait-Sec": "99999"})] * c.MAX_ATTEMPTS
        with self.assertRaises(c.NetworkError) as cm:
            c.run_once(self.cfg())
        self.assertIn("failed with HTTP 409", str(cm.exception))
        self.assertEqual(self.slept, [300.0] * (c.MAX_ATTEMPTS - 1))
        self.assertFalse(os.path.exists(self.state))

    def test_other_qualys_errors_stop_at_once_with_the_code_and_text(self):
        cases = [((401, simple_return("2000", "Bad Login/Password")), "refused the user name or password (HTTP 401, code 2000: Bad Login/Password); check QUALYS_USERNAME"),
                 ((403, simple_return("2002", "User account is inactive.")), "(HTTP 403, code 2002: User account is inactive.); the user needs API access"),
                 ((409, simple_return("2003", "Registration must be completed")), "refused the detection request (HTTP 409, code 2003: Registration must be completed)"),
                 ((400, simple_return("1905", "parameter severities has invalid value")), "(HTTP 400, code 1905: parameter severities has invalid value)")]
        for answer, message in cases:
            with self.subTest(code=answer[0]):
                self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
                self.mock.codes = [answer]
                del self.slept[:]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertNotIsInstance(cm.exception, c.NetworkError)
                self.assertIn(message, str(cm.exception))
                self.assertEqual(self.slept, [])
        self.assertFalse(os.path.exists(self.state))

    def test_an_msp_users_error_with_http_200_is_read_from_the_body(self):
        self.mock.answer = simple_return("1905", "parameter id_min has invalid value")
        with self.assertRaisesRegex(c.BridgeError, r"refused the detection request \(code 1905: parameter id_min has invalid value\)$") as cm:
            c.run_once(self.cfg())
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.mock.answer = simple_return("1965", "Too many requests")
        with self.assertRaisesRegex(c.NetworkError, r"API limits held the detection request \(code 1965\)"):
            c.run_once(self.cfg())

    def test_xml_that_declares_entities_or_isnt_xml_is_refused(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT [<!ENTITY a "aaaaaaaaaa">'
                b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>'
                b"<DATETIME>&b;</DATETIME></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>")
        for answer, message in ((bomb, "declares entities"), (b"<html>maintenance", "not XML"), (b'{"json": true}', "not XML"),
                                (b"<OTHER_OUTPUT><RESPONSE/></OTHER_OUTPUT>", "not a host detection list")):
            with self.subTest(message=message):
                self.mock.answer = answer
                with self.assertRaisesRegex(c.BridgeError, message):
                    c.run_once(self.cfg())

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)), detection(5002, 91500, self.ago(50)))]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["qualys_record"] for x in lines], ["detection"] * 2)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limits_and_server_errors_are_retried(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        self.mock.codes = [(429, b"", {"Retry-After": "1"}), 503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.slept[0], 1.0)

    def test_gzip_batches_and_headers(self):
        self.mock.hosts = [host(100 + i, detection(5000 + i, 91500, self.ago(60 - i))) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        self.mock.codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(QUALYS_PASSWORD="another-wrong-password-000",
                                BRIDGE_STATE_FILE=os.path.join(self.tmp.name, "other.json")))
        basic = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("detection request", logged)
        for secret in (PASSWORD, basic, INGEST_KEY, "00000000-example-integration", "another-wrong-password-000"):
            self.assertNotIn(secret, logged)

    def test_state_is_kept_per_user_and_platform(self):
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        cfg = self.cfg()
        c.run_once(cfg)
        cfg["platform"] = "qualysapi.qualys.eu"
        self.mock.ingested.clear()
        c.run_once(cfg)
        self.assertEqual(len(self.sent()), 1)
        self.assertEqual(self.sent()[0]["qualys_platform"], "qualysapi.qualys.eu")
        self.assertEqual(set(self.saved()), {self.key(), f"{USER}@qualysapi.qualys.eu"})

    def test_config_rejects_bad_values(self):
        for bad in ({**BASE, "QUALYS_API_URL": "http://qualysapi.qualys.com"},
                    {**BASE, "QUALYS_API_URL": "https://qualysapi.qualys.com/api/6.0"},
                    {**BASE, "QUALYS_API_URL": "https://qualysapi.qualys.com?x=1"},
                    {**BASE, "QUALYS_API_URL": ""}, {**BASE, "QUALYS_USERNAME": ""}, {**BASE, "QUALYS_PASSWORD": ""},
                    {**BASE, "QUALYS_USERNAME": "acme:ab12"},
                    {**BASE, "QUALYS_SEVERITIES": "6"}, {**BASE, "QUALYS_SEVERITIES": "3-"}, {**BASE, "QUALYS_SEVERITIES": "high"},
                    {**BASE, "NGSIEM_INGEST_URL": "http://ingest.example/http-endpoint/v1/x"},
                    {**BASE, "QUALYS_PAGE_HOSTS": "0"}, {**BASE, "BRIDGE_LOOKBACK_HOURS": "8761"}):
            with self.subTest(bad={k: v for k, v in bad.items() if k != "QUALYS_PASSWORD"}), self.assertRaises(c.BridgeError):
                c.load_config(bad)
        cfg = c.load_config(BASE)
        self.assertEqual((cfg["api_url"], cfg["platform"]), ("https://qualysapi.qg1.apps.qualys.com.au", "qualysapi.qg1.apps.qualys.com.au"))
        self.assertEqual((cfg["page_hosts"], cfg["delay_seconds"], cfg["lookback_hours"], cfg["kb"], cfg["show_results"],
                          cfg["show_qds"], cfg["show_igs"], cfg["severities"]), (100, 900, 24.0, True, True, True, False, None))
        self.assertEqual(c.load_config({**BASE, "QUALYS_API_URL": "https://qualysapi.qualys.com/"})["api_url"], "https://qualysapi.qualys.com")
        self.assertEqual(c.load_config({**BASE, "QUALYS_SEVERITIES": "1, 3-5"})["severities"], "1,3-5")

    def test_times_read_to_the_second_in_utc(self):
        want = int(datetime(2026, 10, 14, 3, 12, 45, tzinfo=timezone.utc).timestamp())
        self.assertEqual(c._seconds("2026-10-14T03:12:45Z"), want)
        self.assertEqual(c._seconds(" 2026-10-14T03:12:45Z\n"), want)
        for bad in ("2026-10-14", "2026-10-14T03:12:45", "2026-13-14T03:12:45Z", "", None, "yesterday"):
            with self.subTest(bad=bad):
                self.assertIsNone(c._seconds(bad))
        self.assertEqual(c._when(want), "2026-10-14T03:12:45Z")

    def test_xml_becomes_json_by_the_documented_rules(self):
        el = c.ET.fromstring(b'<DETECTION><QID>91500</QID><QDS severity="CRITICAL">95</QDS><QDS_FACTORS>'
                             b'<QDS_FACTOR name="RTI"><![CDATA[[Easy_Exploit]]]></QDS_FACTOR></QDS_FACTORS>'
                             b"<CVE_LIST/><X><Y>1</Y><Y>2</Y></X><EMPTY/></DETECTION>")
        self.assertEqual(c.to_json(el), {"QID": "91500", "QDS": {"value": "95", "severity": "CRITICAL"},
                                         "QDS_FACTORS": {"RTI": "[Easy_Exploit]"}, "CVE_LIST": [], "X": {"Y": ["1", "2"]},
                                         "EMPTY": ""})

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.hosts = [host(101, detection(5001, 91500, self.ago(60)))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": lambda: self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Qualys API": lambda: self.cfg(QUALYS_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and self.saved().get(self.key(), {}).get("cursor"))
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
        for value in ("-1", "0", "10001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^QUALYS_PAGE_HOSTS must be between 1 and 10,000$"):
                self.load(QUALYS_PAGE_HOSTS=value)
        self.assertEqual(self.load(QUALYS_PAGE_HOSTS="1")["page_hosts"], 1)
        self.assertEqual(self.load(QUALYS_PAGE_HOSTS="10000")["page_hosts"], 10000)

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

    def test_one_client_keeps_its_knowledgebase_cache_across_runs(self):
        self.run_once_raises(c.NetworkError("detection request to qualysapi.qualys.com failed: URLError"))
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

    def test_an_api_limit_keeps_polling_too(self):
        self.run_once_raises(c.NetworkError("Qualys's API limits held the detection request (code 1965); the next run tries again"))
        self.assertEqual(c.main(["--interval", "3600"]), 130)
        self.assertEqual(len(self.calls), 2)

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
        for code, body in ((429, b"{}"), (503, b"{}"), (409, simple_return("1965"))):
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
        for code in (302, 400, 401, 403, 404, 409):
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
        error = c.HostNotFound("detection request to qualysapi.qualys.com failed: the host name wasn't found; check the URL setting")
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
