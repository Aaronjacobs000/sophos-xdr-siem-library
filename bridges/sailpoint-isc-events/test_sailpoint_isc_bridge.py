"""Unit tests for sailpoint_isc_bridge.py against a local mock server.

The mock serves the shapes in SailPoint's API reference: POST /oauth/token (client credentials in
the form body: grant_type, client_id, client_secret; answering {"access_token", "token_type",
"expires_in", "scope"} or {"error", "error_description"}), and POST /v3/search?limit=N with a
Search body (indices ["events"], queryType DSL, a bool query with a range on created and
optional matches on type, sort ["id"], searchAfter [id]), answering a JSON list of
EventDocuments, or {"detailCode", "trackingId", "messages": [{"text"}]} on errors. Plus a Sophos
NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/sailpoint-isc-events -p 'test_*.py' -v
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
import sailpoint_isc_bridge as c  # noqa: E402

CLIENT_ID = "test-sailpoint-client-id-not-real"
SECRET = "test-sailpoint-client-secret-not-real"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def event(i, when, type_="AUTH", action="AUTHENTICATION-103", status="PASSED"):
    return {"org": "acme", "pod": "prd04-apse2", "created": iso(when), "id": f"{i:032x}", "action": action, "type": type_,
            "actor": {"name": f"user{i}"}, "target": {"name": f"user{i}"}, "stack": "oathkeeper",
            "trackingNumber": f"{i + 1000:032x}", "ipAddress": "203.0.113.24", "attributes": {"sourceName": "SailPoint"},
            "objects": ["AUTHENTICATION"], "operation": "REQUEST", "status": status,
            "technicalName": f"AUTHENTICATION_REQUEST_{status}", "name": f"Request Authentication {status.title()}",
            "synced": iso(when + timedelta(seconds=1)), "_type": "event", "_version": "v7"}


def error_body(code, text):
    return {"detailCode": f"{code} error", "trackingId": "0123456789abcdef0123456789abcdef",
            "messages": [{"locale": "en-US", "localeOrigin": "DEFAULT", "text": text}], "causes": []}


class Mock:
    def __init__(self):
        self.events = []
        self.access_tokens = []
        self.expired = set()
        self.token_requests = []
        self.searches = []
        self.search_codes = []
        self.token_codes = []
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
        if url.path == "/oauth/token":
            form = urllib.parse.parse_qs(body.decode())
            m.token_requests.append({"headers": dict(self.headers), "form": form, "query": url.query})
            if m.token_codes:
                code = m.token_codes.pop(0)
                return self._send(code, {"error": "server_error", "error_description": "try later"})
            if form.get("grant_type") != ["client_credentials"] or form.get("client_id") != [CLIENT_ID] \
                    or form.get("client_secret") != [SECRET]:
                return self._send(401, {"error": "invalid_client", "error_description": "Bad client credentials"})
            token = f"access-token-{len(m.access_tokens) + 1}"
            m.access_tokens.append(token)
            return self._send(200, {"access_token": token, "token_type": "bearer", "expires_in": 749,
                                    "scope": "sp:search:read", "tenant_id": "00000000-0000-0000-0000-000000000000"})
        if url.path == "/v3/search":
            query = urllib.parse.parse_qs(url.query)
            auth = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            req = json.loads(body)
            m.searches.append({"query": query, "body": req, "auth": auth, "headers": dict(self.headers)})
            if auth not in m.access_tokens or auth in m.expired:
                return self._send(401, error_body(401, "The request could not be authorized."))
            if m.search_codes:
                code = m.search_codes.pop(0)
                return self._send(code, error_body(code, "The server understood the request but refuses to authorize it."
                                                   if code == 403 else "slow down"))
            if req.get("indices") != ["events"] or req.get("queryType") != "DSL" or req.get("sort") != ["id"]:
                return self._send(400, error_body(400, "unexpected search body"))
            must = req["queryDsl"]["bool"]["must"]
            rng = must[0]["range"]["created"]
            lo, hi = c._parse_time(rng["gte"]), c._parse_time(rng["lte"])
            types = [s["match"]["type"] for x in must[1:] for s in x["bool"]["should"]]
            rows = [e for e in m.events if lo <= c._parse_time(e["created"]) <= hi and (not types or e["type"] in types)]
            # Events with no id sort last, as Elasticsearch puts a missing value.
            rows.sort(key=lambda e: (e.get("id") is None, e.get("id") or ""))
            if "searchAfter" in req:
                after = req["searchAfter"][0]
                rows = [e for e in rows if e.get("id") is not None and e["id"] > after]
            limit = int(query.get("limit", ["250"])[0])
            return self._send(200, rows[:limit])
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
    ("SAILPOINT_PAGE_SIZE", "page_size", 1000, 500, int, 10000),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 3600, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"SAILPOINT_TENANT": "acme", "SAILPOINT_CLIENT_ID": CLIENT_ID, "SAILPOINT_CLIENT_SECRET": SECRET}
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
        c.time.sleep = lambda s: None
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
                     SAILPOINT_API_URL=self.base, BRIDGE_STATE_FILE=self.state)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def test_pages_are_read_tagged_and_sent_oldest_first(self):
        self.mock.events = [event(i, self.ago(50 - i)) for i in range(5)]
        self.assertEqual(c.run_once(self.cfg(SAILPOINT_PAGE_SIZE="2")), 5)
        rows = self.sent()
        self.assertTrue(self.mock.ingested[0]["raw"].startswith('{"sailpoint_record":"event","org":"acme"'))
        self.assertEqual({k: v for k, v in rows[0].items() if k != "sailpoint_record"}, self.mock.events[0])
        self.assertEqual(sorted(r["id"] for r in rows), [e["id"] for e in self.mock.events])
        # Pages of two, two and one, one window, paged with searchAfter on the last id.
        bodies = [s["body"] for s in self.mock.searches]
        self.assertEqual([b.get("searchAfter") for b in bodies], [None, [f"{1:032x}"], [f"{3:032x}"]])
        self.assertEqual(len({json.dumps(b["queryDsl"]) for b in bodies}), 1)
        self.assertEqual(self.mock.searches[0]["query"], {"limit": ["2"]})
        self.assertEqual(bodies[0]["indices"], ["events"])
        self.assertEqual(bodies[0]["sort"], ["id"])
        rng = bodies[0]["queryDsl"]["bool"]["must"][0]["range"]["created"]
        self.assertLessEqual(c._parse_time(rng["lte"]), datetime.now(timezone.utc).timestamp() - 59)
        self.assertAlmostEqual(c._parse_time(rng["lte"]) - c._parse_time(rng["gte"]), 86400 - 60, delta=10)
        # Within a page, events go oldest first.
        first_page = [r["created"] for r in self.mock.ingested[0]["lines"]]
        self.assertEqual(first_page, sorted(first_page))

    def test_token_request_carries_the_credentials_in_the_form_body(self):
        self.mock.events = [event(0, self.ago(5))]
        c.run_once(self.cfg())
        req = self.mock.token_requests[0]
        self.assertEqual(req["form"], {"grant_type": ["client_credentials"], "client_id": [CLIENT_ID], "client_secret": [SECRET]})
        self.assertEqual(req["query"], "")
        self.assertEqual(req["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(self.mock.searches[0]["headers"]["Authorization"], "Bearer access-token-1")
        self.assertEqual(self.mock.searches[0]["headers"]["Content-Type"], "application/json")
        self.assertEqual(len(self.mock.token_requests), 1)

    def test_tenant_name_makes_the_api_url(self):
        cfg = c.load_config(base_env(SAILPOINT_TENANT="Acme-Sandbox"))
        self.assertEqual(cfg["api_url"], "https://acme-sandbox.api.identitynow.com")
        cfg = c.load_config(base_env(SAILPOINT_API_URL="https://acme.api.example-sailpoint-gov.example/"))
        self.assertEqual(cfg["api_url"], "https://acme.api.example-sailpoint-gov.example")

    def test_an_expired_access_token_is_renewed_once(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        cfg = self.cfg()
        client = c.SailPoint(cfg)
        client.token()
        self.mock.expired.add("access-token-1")
        state, sink = {}, c.Sink(cfg, False)
        c.collect(cfg, state, sink, lambda: None, client, datetime.now(timezone.utc).timestamp())
        self.assertEqual(len(self.sent()), 3)
        self.assertEqual(len(self.mock.token_requests), 2)
        self.assertEqual(self.mock.searches[-1]["auth"], "access-token-2")

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1800")
        c.run_once(cfg)
        first_end = c._parse_time(self.mock.searches[0]["body"]["queryDsl"]["bool"]["must"][0]["range"]["created"]["lte"])
        self.assertAlmostEqual(self.saved()["events"]["until"], first_end, delta=0.01)
        self.mock.ingested.clear()
        self.mock.searches.clear()
        # A late event inside the overlap, and a new one.
        self.mock.events += [event(7, self.ago(20)), event(8, self.ago(2))]
        c.run_once(cfg)
        self.assertEqual(sorted(r["id"] for r in self.sent()), [f"{7:032x}", f"{8:032x}"])
        start = c._parse_time(self.mock.searches[0]["body"]["queryDsl"]["bool"]["must"][0]["range"]["created"]["gte"])
        self.assertAlmostEqual(start, first_end - 1800, delta=0.01)
        # The ids kept for the next run are only those inside its overlap.
        self.assertTrue(all(t >= start - 60 for t in self.saved()["events"]["seen"].values()))

    def test_lookback_sets_the_first_window_within_retention(self):
        self.mock.events = [event(0, self.now - timedelta(days=3)), event(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["id"] for r in self.sent()], [f"{1:032x}"])
        self.mock.searches.clear()
        os.remove(self.state)
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="100000"))
        rng = self.mock.searches[0]["body"]["queryDsl"]["bool"]["must"][0]["range"]["created"]
        self.assertLess(c._parse_time(rng["lte"]) - c._parse_time(rng["gte"]), 365 * 86400)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(4)]
        self.mock.ingest_codes = [200, 400]
        with self.assertRaises(c.BridgeError):
            c.run_once(self.cfg(SAILPOINT_PAGE_SIZE="2"))
        saved = self.saved()["events"]
        self.assertNotIn("until", saved)
        self.assertEqual(len(saved["seen"]), 2)
        self.mock.ingest_codes = []
        self.mock.ingested.clear()
        c.run_once(self.cfg(SAILPOINT_PAGE_SIZE="2"))
        self.assertEqual(sorted(r["id"] for r in self.sent()), [f"{2:032x}", f"{3:032x}"])
        self.assertIn("until", self.saved()["events"])

    def test_event_dated_in_the_future_leaves_the_window_end_at_now(self):
        # A wrong clock can date an event ahead. The window still ends at the run's time.
        self.mock.events = [event(0, self.ago(5)), event(1, self.ago(-600))]
        c.run_once(self.cfg())
        self.assertLessEqual(self.saved()["events"]["until"], datetime.now(timezone.utc).timestamp())
        self.mock.events.append(event(2, self.ago(1)))
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual([r["id"] for r in self.sent()], [f"{2:032x}"])

    def test_event_types_filter_matches_each_type(self):
        self.mock.events = [event(0, self.ago(5)), event(1, self.ago(4), "PROVISIONING", "DisableAccount"),
                            event(2, self.ago(3), "SSO", "APP_LAUNCH_SAML")]
        c.run_once(self.cfg(SAILPOINT_EVENT_TYPES="auth, sso"))
        self.assertEqual(sorted(r["type"] for r in self.sent()), ["AUTH", "SSO"])
        must = self.mock.searches[0]["body"]["queryDsl"]["bool"]["must"]
        self.assertEqual(must[1], {"bool": {"should": [{"match": {"type": "AUTH"}}, {"match": {"type": "SSO"}}], "minimum_should_match": 1}})

    def test_events_without_an_id_are_sent_once(self):
        nameless = {k: v for k, v in event(5, self.ago(4)).items() if k != "id"}
        self.mock.events = [event(0, self.ago(5)), nameless]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 2)
        self.mock.ingested.clear()
        c.run_once(self.cfg())
        self.assertEqual(self.sent(), [])

    def test_a_full_page_ending_without_an_id_stops_the_window_there(self):
        nameless = {k: v for k, v in event(5, self.ago(4)).items() if k != "id"}
        self.mock.events = [event(0, self.ago(5)), nameless]
        c.run_once(self.cfg(SAILPOINT_PAGE_SIZE="2"))
        self.assertEqual(len(self.sent()), 2)
        self.assertIn("no id to page after", self.logbuf.getvalue())
        self.assertNotIn("until", self.saved()["events"])

    def test_refused_credentials_and_scope_stop_with_clear_errors(self):
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(SAILPOINT_CLIENT_SECRET="wrong-secret-0000000000"))
        self.assertIn("HTTP 401", str(cm.exception))
        self.assertIn("Bad client credentials", str(cm.exception))
        self.assertEqual(self.mock.searches, [])
        self.mock.search_codes = [403]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("HTTP 403", str(cm.exception))
        self.assertIn("sp:search:read", str(cm.exception))
        self.assertIn("refuses to authorize", str(cm.exception))
        self.assertFalse(os.path.exists(self.state))

    def test_dry_run_prints_and_changes_nothing(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["sailpoint_record"] for x in lines], ["event"] * 3)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.events = [event(i, self.ago(10 - i)) for i in range(3)]
        self.mock.search_codes = [429, 503]
        self.mock.token_codes = [503]
        self.mock.ingest_codes = [429]
        c.run_once(self.cfg())
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.events = [event(i, self.ago(30 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="1500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.events = [event(0, self.ago(5))]
        self.mock.search_codes = [503]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(SAILPOINT_CLIENT_SECRET="another-wrong-secret-000000"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("search request", logged)
        for secret in (CLIENT_ID, SECRET, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-000000", "access-token-1"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            {"SAILPOINT_CLIENT_ID": CLIENT_ID, "SAILPOINT_CLIENT_SECRET": SECRET},
            base_env(SAILPOINT_TENANT="acme.example.com"),
            base_env(SAILPOINT_TENANT="-acme"),
            base_env(SAILPOINT_API_URL="http://acme.api.example.com"),
            base_env(SAILPOINT_CLIENT_SECRET=""),
            {"SAILPOINT_TENANT": "acme", "SAILPOINT_CLIENT_SECRET": SECRET},
            base_env(SAILPOINT_PAGE_SIZE="0"),
            base_env(SAILPOINT_PAGE_SIZE="10001"),
            base_env(SAILPOINT_EVENT_TYPES="AUTH,type:sso"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env())
        self.assertEqual(cfg["api_url"], "https://acme.api.identitynow.com")
        self.assertEqual(cfg["page_size"], 1000)
        self.assertEqual(cfg["event_types"], [])

    def test_times_with_and_without_fractions_and_offsets(self):
        want = datetime(2026, 10, 14, 2, 10, 5, tzinfo=timezone.utc).timestamp()
        for text, expected in [("2026-10-14T02:10:05Z", want), ("2026-10-14T02:10:05.412Z", want + 0.412),
                               ("2026-10-14T02:10:05.4Z", want + 0.4), ("2026-10-14T13:10:05.412+11:00", want + 0.412),
                               ("2026-10-14T02:10:05.123456789Z", want + 0.123456)]:
            with self.subTest(text=text):
                self.assertAlmostEqual(c._parse_time(text), expected, places=5)
        self.assertIsNone(c._parse_time("yesterday"))
        self.assertIsNone(c._parse_time(None))

    def test_redirects_are_not_followed(self):
        # Following a redirect would send the key or token to another URL, so the run fails instead,
        # and nothing reaches the redirect's target.
        self.mock.events = [event(0, self.ago(5))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "SailPoint API": self.cfg(SAILPOINT_API_URL=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved()["events"])
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
                    self.assertAlmostEqual(c._parse_time(text), expected.timestamp(), places=5)


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

    def test_page_size_out_of_range_gives_its_range(self):
        for value in ("-1", "0", "10001"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^SAILPOINT_PAGE_SIZE must be between 1 and 10,000$"):
                self.load(SAILPOINT_PAGE_SIZE=value)
        self.assertEqual(self.load(SAILPOINT_PAGE_SIZE="1")["page_size"], 1)
        self.assertEqual(self.load(SAILPOINT_PAGE_SIZE="10000")["page_size"], 10000)


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
