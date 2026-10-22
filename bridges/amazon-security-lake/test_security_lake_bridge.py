"""Unit tests for security_lake_bridge.py against a local mock server.

The mock serves the shapes in the Amazon Athena API reference and the S3 API reference: POST / with
X-Amz-Target AmazonAthena.StartQueryExecution ({"QueryString", "ClientRequestToken", "WorkGroup",
"QueryExecutionContext", "ResultConfiguration"} answering {"QueryExecutionId"}), GetQueryExecution
(answering {"QueryExecution": {"Status": {"State", "StateChangeReason", "AthenaError"}, "Statistics":
{"DataManifestLocation"}, ...}}) and StopQueryExecution, with errors as {"__type", "Message"} (HTTP 400
TooManyRequestsException when throttled); and GET /<bucket>/<key> with Range, answering 206 and
Content-Range, 416 for a range past the end, and <Error><Code>...</Code><Message>...</Message></Error>
on errors. An UNLOAD query writes the matching rows of its table as gzip JSON Lines files under its TO
location, which must be empty, and a data manifest listing them, as the Athena UNLOAD docs describe.
Plus a Sophos NG-SIEM HTTP Ingest endpoint. No real service is called.

  python3 -m unittest discover -s bridges/amazon-security-lake -p 'test_*.py' -v
"""
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
import security_lake_bridge as c  # noqa: E402

KEY_ID = "AKIDEXAMPLETESTKEYID"
SECRET = "test-aws-secret-access-key-not-real-0000"
TOKEN = "test-aws-session-token-not-real-0000000000"
INGEST_KEY = "test-ngsiem-ingest-key-not-real"
REGION = "ap-southeast-2"
DB = "amazon_security_lake_glue_db_ap_southeast_2"
CT = "amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0"
R53 = "amazon_security_lake_table_ap_southeast_2_route53_2_0"
FLOW = "amazon_security_lake_table_ap_southeast_2_vpc_flow_2_0"
SH = "amazon_security_lake_table_ap_southeast_2_sh_findings_2_0"
UNLOAD_BUCKET = "example-security-lake-export"
RESULTS = "s3://example-athena-results/results/"
SQL = re.compile(r"""^UNLOAD \(SELECT (?P<cols>.+?) FROM "(?P<db>[^"]+)"\."(?P<table>[^"]+)" WHERE (?P<where>.+?)\) """
                 r"""TO 's3://(?P<bucket>[^/']+)/(?P<prefix>[^']*)' WITH \(format = 'JSON'\)$""")
WINDOW_DT = re.compile(r"^time_dt >= TIMESTAMP '(?P<lo>[^']+)' AND time_dt < TIMESTAMP '(?P<hi>[^']+)'$")
WINDOW_MS = re.compile(r"""^(?:eventday >= '(?P<d0>\d{8})' AND eventday <= '(?P<d1>\d{8})' AND )?"time" >= (?P<lo>\d+) AND "time" < (?P<hi>\d+)$""")
COLUMNS_SQL = re.compile(r"^SELECT column_name, data_type FROM information_schema\.columns WHERE table_schema = '(?P<db>[^']+)' "
                         r"AND table_name = '(?P<table>[^']+)' ORDER BY ordinal_position$")
# The columns of a source version 2 table, in the types Athena gives them (in part: the tables have more).
V2_COLUMNS = [("metadata", "row(product row(version varchar, name varchar, vendor_name varchar, feature row(name varchar)), "
               "uid varchar, profiles array(varchar), version varchar, processed_time_dt timestamp(3) with time zone)"),
              ("time", "bigint"), ("time_dt", "timestamp(3) with time zone"), ("cloud", "row(region varchar, provider varchar)"),
              ("api", "row(operation varchar, service row(name varchar), request row(uid varchar))"),
              ("actor", "row(\"user\" row(type varchar, name varchar, uid varchar, account row(uid varchar)), "
               "session row(created_time_dt timestamp(3) with time zone, is_mfa boolean))"),
              ("src_endpoint", "row(ip varchar)"), ("class_name", "varchar"), ("class_uid", "integer"), ("category_uid", "integer"),
              ("severity_id", "integer"), ("activity_id", "integer"), ("type_uid", "bigint"), ("status_id", "integer"),
              ("status", "varchar"), ("evidences", "array(row(data varchar, first_seen_time_dt timestamp(3) with time zone))"),
              ("unmapped", "map(varchar, varchar)"), ("accountid", "varchar"), ("region", "varchar"), ("asl_version", "varchar")]
# A source version 1 table: no time_dt, and partitioned by eventday.
V1_COLUMNS = [("metadata", "row(product row(name varchar), version varchar)"), ("time", "bigint"), ("class_uid", "integer"),
              ("unmapped", "map(varchar, varchar)"), ("region", "varchar"), ("accountid", "varchar"), ("eventday", "varchar")]


def ms(dt):
    return int(dt.timestamp() * 1000)


def dt_text(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def api_activity(i, when, operation="DescribeInstances"):
    """An OCSF API Activity record in the shape of Security Lake's CloudTrail records."""
    return {"metadata": {"product": {"version": "1.11", "name": "CloudTrail", "vendor_name": "AWS", "feature": {"name": "Management"}},
                         "uid": f"0f1e2d3c-4b5a-4987-a6b5-c4d3e2f1{i:04d}", "profiles": ["cloud", "datetime"], "version": "1.1.0"},
            "time": ms(when), "time_dt": dt_text(when), "cloud": {"region": REGION, "provider": "AWS"},
            "api": {"operation": operation, "service": {"name": "ec2.amazonaws.com"}, "request": {"uid": f"req-{i}"}},
            "actor": {"user": {"type": "AssumedRole", "name": "ops", "uid": "AROAEXAMPLEROLEID:ops", "account": {"uid": "111122223333"}}},
            "src_endpoint": {"ip": "192.0.2.10"}, "class_name": "API Activity", "class_uid": 6003, "category_uid": 6,
            "severity_id": 1, "activity_id": 2, "type_uid": 600302, "status_id": 1, "status": "Success",
            "accountid": "111122223333", "region": REGION, "asl_version": "2.0"}


class Mock:
    def __init__(self):
        self.rows = {}           # table -> rows
        self.columns = {}        # table -> [(name, type)]; V2_COLUMNS when not set
        self.objects = {}        # (bucket, key) -> bytes
        self.executions = {}     # query ID -> execution
        self.tokens = {}         # ClientRequestToken -> query ID
        self.states = ["QUEUED", "RUNNING"]
        self.finish = ("SUCCEEDED", None, None)
        self.rows_per_file = 1000
        self.members = 1
        self.no_manifest = False
        self.outside = False
        self.athena_answers = []  # (status, type, message) to send instead, in order
        self.s3_answers = []      # (status, code, message)
        self.athena_requests = []
        self.s3_requests = []
        self.stopped = []
        self.ingest_codes = []
        self.ingested = []
        self.range_ok = True


def pack(lines, members):
    """Gzip JSON Lines, in the given number of gzip members one after another."""
    if not lines:
        return b""
    step = max(1, -(-len(lines) // members))
    return b"".join(gzip.compress(("".join(x + "\n" for x in lines[i:i + step])).encode())
                    for i in range(0, len(lines), step))


class Handler(BaseHTTPRequestHandler):
    mock: Mock = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/x-amz-json-1.1", headers=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code == 429:
            self.send_header("Retry-After", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _xml(self, code, kind, message):
        body = (f'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>{kind}</Code><Message>{message}</Message>'
                f"<RequestId>4442587FB7D0A2F9</RequestId></Error>").encode()
        self._send(code, body, "application/xml")

    def _signed_for(self, service, body=b""):
        """Checks the signature: the signed headers, signed again with the test keys at the request's
        own X-Amz-Date, give the same Authorization header. The algorithm itself is checked against
        AWS's worked example in test_the_signature_matches_aws_s_worked_example."""
        auth = self.headers.get("Authorization") or ""
        m = re.match(r"^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), "
                     r"Signature=[0-9a-f]{64}$", auth)
        if not (m and m.group(1) == KEY_ID and m.group(3) == REGION and m.group(4) == service):
            return False
        names = m.group(5).split(";")
        if "host" not in names or "x-amz-date" not in names:
            return False
        token = self.headers.get("X-Amz-Security-Token")
        skip = {"host", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"}
        headers = {n: self.headers.get(n) for n in names if n not in skip}
        when = datetime.strptime(self.headers.get("X-Amz-Date"), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
        again = c.sigv4(self.command, f"http://{self.headers.get('Host')}{self.path}", headers, body, REGION, service,
                        KEY_ID, SECRET, token, now=when)
        return again["Authorization"] == auth

    def do_POST(self):
        m = self.mock
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/":
            return self._athena(json.loads(body), body)
        if not self.path.startswith("/http-endpoint/v1/") or self.headers.get("Authorization") != f"Bearer {INGEST_KEY}":
            return self._send(401, {}, "application/json")
        if m.ingest_codes:
            code = m.ingest_codes.pop(0)
            if code != 200:
                return self._send(code, {}, "application/json")
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        m.ingested.append({"headers": dict(self.headers), "raw": body.decode(),
                           "lines": [json.loads(x) for x in body.decode().splitlines() if x.strip()]})
        self._send(200, {}, "application/json")

    def _athena(self, req, raw):
        m = self.mock
        target = self.headers.get("X-Amz-Target") or ""
        m.athena_requests.append({"target": target, "body": req, "headers": dict(self.headers)})
        if not self._signed_for("athena", raw) or self.headers.get("X-Amz-Security-Token", TOKEN) != TOKEN:
            # AWS quotes the signed request in this message, the session token included.
            return self._send(400, {"__type": "InvalidSignatureException", "message": "The request signature we calculated "
                                    f"does not match. The canonical string was x-amz-security-token:{TOKEN}"})
        if self.headers.get("Content-Type") != "application/x-amz-json-1.1":
            return self._send(400, {"__type": "SerializationException"})
        if m.athena_answers:
            code, kind, message = m.athena_answers.pop(0)
            return self._send(code, {"__type": kind, "Message": message})
        if target == "AmazonAthena.StartQueryExecution":
            token = req.get("ClientRequestToken") or ""
            if not 32 <= len(token) <= 128:
                return self._send(400, {"__type": "InvalidRequestException", "Message": "Idempotent parameters must be provided"})
            if token in m.tokens:
                return self._send(200, {"QueryExecutionId": m.tokens[token]})
            sql = SQL.match(req["QueryString"])
            cols = COLUMNS_SQL.match(req["QueryString"])
            if not sql and not cols:
                return self._send(400, {"__type": "InvalidRequestException", "Message": "line 1:1: mismatched input"})
            qid = f"a1b2c3d4-0000-4000-8000-{len(m.executions):012d}"
            m.tokens[token] = qid
            m.executions[qid] = {"req": req, "sql": sql.groupdict() if sql else None, "columns": cols.groupdict() if cols else None,
                                 "states": list(m.states) if sql else [], "files": []}
            return self._send(200, {"QueryExecutionId": qid})
        if target == "AmazonAthena.GetQueryExecution":
            ex = m.executions.get(req.get("QueryExecutionId"))
            if not ex:
                return self._send(400, {"__type": "InvalidRequestException", "Message": "QueryExecution was not found"})
            status = {"SubmissionDateTime": 1791844811.0}
            if ex["states"]:
                status["State"] = ex["states"].pop(0)
            else:
                state, reason, retryable = ex.get("finish") or m.finish
                if ex["columns"]:
                    state, reason, retryable = "SUCCEEDED", None, None
                elif state == "SUCCEEDED" and "written" not in ex:
                    problem = self._unload(req["QueryExecutionId"], ex)
                    if problem:
                        ex["finish"] = state, reason, retryable = ("FAILED", problem, False)
                status["State"] = state
                if reason:
                    status["StateChangeReason"] = reason
                    status["AthenaError"] = {"ErrorCategory": 2, "ErrorType": 1001, "Retryable": retryable, "ErrorMessage": reason}
            stats = {"DataScannedInBytes": 1024}
            if status["State"] == "SUCCEEDED" and ex["sql"] and not m.no_manifest:
                stats["DataManifestLocation"] = f"{RESULTS}{req['QueryExecutionId']}-manifest.csv"
            return self._send(200, {"QueryExecution": {"QueryExecutionId": req["QueryExecutionId"], "Query": ex["req"]["QueryString"],
                                                       "StatementType": "DML", "Status": status, "Statistics": stats,
                                                       "WorkGroup": ex["req"].get("WorkGroup")}})
        if target == "AmazonAthena.GetQueryResults":
            ex = m.executions.get(req.get("QueryExecutionId"))
            if not ex or not ex["columns"]:
                return self._send(400, {"__type": "InvalidRequestException", "Message": "Query has not yet finished"})
            table = ex["columns"]["table"]
            cols = m.columns.get(table, V2_COLUMNS) if ex["columns"]["db"] == DB.lower() else []
            rows = [["column_name", "data_type"]] + [list(c) for c in cols]
            # Three rows a page, so the bridge has to follow NextToken.
            first = int(req.get("NextToken") or 0)
            page = rows[first:first + 3]
            out = {"ResultSet": {"Rows": [{"Data": [{"VarCharValue": v} for v in r]} for r in page],
                                 "ResultSetMetadata": {"ColumnInfo": [{"Name": "column_name", "Type": "varchar"},
                                                                      {"Name": "data_type", "Type": "varchar"}]}}}
            if first + 3 < len(rows):
                out["NextToken"] = str(first + 3)
            return self._send(200, out)
        if target == "AmazonAthena.StopQueryExecution":
            m.stopped.append(req.get("QueryExecutionId"))
            return self._send(200, {})
        return self._send(400, {"__type": "UnknownOperationException"})

    def _unload(self, qid, ex):
        """What Athena's UNLOAD does: refuse a TO location that holds data, then write the rows of
        the window as gzip JSON Lines files there, and a manifest in the query result location."""
        m, sql = self.mock, ex["sql"]
        ex["written"] = True
        if any(b == sql["bucket"] and k.startswith(sql["prefix"]) for b, k in m.objects):
            return "HIVE_PATH_ALREADY_EXISTS: Target directory for UNLOAD already exists"
        # Athena's JSON writer can't write a timestamp with a time zone.
        for name, dtype in m.columns.get(sql["table"], V2_COLUMNS):
            if "with time zone" in dtype and f'CAST("{name}" AS ' not in sql["cols"]:
                return "NOT_SUPPORTED: Unsupported Hive type: timestamp(3) with time zone"
        dt, ms_ = WINDOW_DT.match(sql["where"]), WINDOW_MS.match(sql["where"])
        if dt:
            lo = datetime.strptime(dt.group("lo"), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp() * 1000
            hi = datetime.strptime(dt.group("hi"), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp() * 1000
        elif ms_:
            lo, hi = int(ms_.group("lo")), int(ms_.group("hi"))
        else:
            return "SYNTAX_ERROR: line 1:1: the test mock doesn't know this WHERE clause"
        rows = [r for r in m.rows.get(sql["table"], []) if lo <= r["time"] < hi]
        uris = []
        for n in range(0, len(rows), m.rows_per_file):
            key = f"{sql['prefix']}20261021_000000_{n:05d}_{qid}.gz"
            m.objects[(sql["bucket"], key)] = pack([json.dumps(r) for r in rows[n:n + m.rows_per_file]], m.members)
            uris.append(f"s3://{sql['bucket']}/{key}")
        if m.outside:
            m.objects[(sql["bucket"], "elsewhere/other.gz")] = pack(['{"x": 1}'], 1)
            uris.append(f"s3://{sql['bucket']}/elsewhere/other.gz")
        bucket, _, key = f"{RESULTS}{qid}-manifest.csv"[len("s3://"):].partition("/")
        m.objects[(bucket, key)] = "".join(u + "\n" for u in uris).encode()
        ex["files"] = uris
        return None

    def do_GET(self):
        m = self.mock
        bucket, _, key = urllib.parse.unquote(self.path.lstrip("/")).partition("/")
        m.s3_requests.append({"bucket": bucket, "key": key, "headers": dict(self.headers)})
        if not self._signed_for("s3") or not self.headers.get("X-Amz-Content-Sha256"):
            return self._xml(403, "SignatureDoesNotMatch", f"The request signature does not match; token {TOKEN}")
        if m.s3_answers:
            code, kind, message = m.s3_answers.pop(0)
            return self._xml(code, kind, message)
        data = m.objects.get((bucket, key))
        if data is None:
            return self._xml(404, "NoSuchKey", "The specified key does not exist.")
        rng = self.headers.get("Range")
        if not rng or not m.range_ok:
            return self._send(200, data, "application/octet-stream")
        lo, hi = (int(x) for x in re.match(r"bytes=(\d+)-(\d+)$", rng).groups())
        if lo >= len(data):
            return self._xml(416, "InvalidRange", "The requested range is not satisfiable")
        part = data[lo:hi + 1]
        self._send(206, part, "application/octet-stream",
                   {"Content-Range": f"bytes {lo}-{lo + len(part) - 1}/{len(data)}"})


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
    ("ATHENA_QUERY_TIMEOUT", "query_timeout", 900, 600, int, 86400),
    ("BRIDGE_BATCH_BYTES", "batch_bytes", 100000, 50000, int, 10 ** 9),
    ("BRIDGE_LOOKBACK_HOURS", "lookback_hours", 24.0, 12.5, float, 10 ** 6),
    ("BRIDGE_DELAY_SECONDS", "delay_seconds", 900, 600, int, 86400),
    ("BRIDGE_OVERLAP_SECONDS", "overlap_seconds", 2700, 600, int, 10 ** 9),
    ("BRIDGE_HTTP_TIMEOUT", "timeout", 60.0, 30.5, float, 10 ** 9),
]


def base_env(**extra):
    e = {"AWS_REGION": REGION, "AWS_ACCESS_KEY_ID": KEY_ID, "AWS_SECRET_ACCESS_KEY": SECRET, "AWS_SESSION_TOKEN": TOKEN,
         "ATHENA_UNLOAD_LOCATION": f"s3://{UNLOAD_BUCKET}/security-lake-bridge/"}
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
        self._sleep, self._clock = c.time.sleep, c._clock
        self.slept = []
        self.clock = [1000.0]

        def sleep(seconds):
            self.slept.append(seconds)
            self.clock[0] += seconds

        c.time.sleep = sleep
        c._clock = lambda: self.clock[0]
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        c.time.sleep, c._clock = self._sleep, self._clock
        c.LOG.removeHandler(self.handler)
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()
        gc.collect()
        self._warnings.__exit__(None, None, None)
        self.assertEqual(self.leaks, [], "a socket or file was left open")

    def cfg(self, **extra):
        e = base_env(NGSIEM_INGEST_URL=f"{self.base}/http-endpoint/v1/00000000-example-integration", NGSIEM_INGEST_KEY=INGEST_KEY,
                     AWS_ENDPOINT_URL_ATHENA=self.base, AWS_ENDPOINT_URL_S3=self.base, BRIDGE_STATE_FILE=self.state,
                     SECURITY_LAKE_SOURCES="cloud_trail_mgmt", ATHENA_OUTPUT_LOCATION=RESULTS)
        e.update(extra)
        return c.load_config({k: v for k, v in e.items() if v is not None})

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    def sent(self):
        return [line for post in self.mock.ingested for line in post["lines"]]

    def saved(self):
        with open(self.state) as fh:
            return json.load(fh)

    def starts(self):
        """The UNLOAD queries started, oldest first."""
        return [r for r in self.mock.athena_requests if r["target"] == "AmazonAthena.StartQueryExecution"
                and SQL.match(r["body"]["QueryString"])]

    def unload_ids(self):
        return [q for q, ex in self.mock.executions.items() if ex["sql"]]

    def windows(self):
        """The [start, end) of each UNLOAD query, as epoch seconds."""
        out = []
        for r in self.starts():
            where = WINDOW_DT.match(SQL.match(r["body"]["QueryString"]).group("where"))
            out.append(tuple(datetime.strptime(where.group(g), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
                             for g in ("lo", "hi")))
        return out

    def test_a_url_setting_with_user_info_is_refused_at_startup(self):
        # urllib sends no user name or password from a URL, and the host isn't found with them in it,
        # so such a setting can never work. The bridge stops at startup and doesn't show them.
        for name in ("AWS_ENDPOINT_URL_ATHENA", "AWS_ENDPOINT_URL_S3", "NGSIEM_INGEST_URL"):
            for url in ("https://user:secret@api.example.com", "https://secret@api.example.com"):
                with self.subTest(name=name, url=url):
                    with self.assertRaises(c.BridgeError) as caught:
                        self.cfg(**{name: url})
                    self.assertEqual(str(caught.exception), f"{name} has a user name or password before the host "
                                     "(user:pass@), which the bridge can't use; remove it")

    def test_records_are_unloaded_tagged_and_sent(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(60 - i)) for i in range(3)]
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual([r["api"]["request"]["uid"] for r in self.sent()], ["req-0", "req-1", "req-2"])
        self.assertTrue(self.mock.ingested[0]["raw"].startswith(
            f'{{"security_lake_record":"ocsf","security_lake_table":"{CT}","metadata":{{'))
        first = {k: v for k, v in self.sent()[0].items() if k not in ("security_lake_record", "security_lake_table")}
        self.assertEqual(first, self.mock.rows[CT][0])
        # One UNLOAD of the table, into a location of its own under ATHENA_UNLOAD_LOCATION.
        (start,) = self.starts()
        sql = SQL.match(start["body"]["QueryString"]).groupdict()
        self.assertEqual((sql["db"], sql["table"], sql["bucket"]), (DB, CT, UNLOAD_BUCKET))
        self.assertRegex(sql["prefix"], r"^security-lake-bridge/\d{8}/[0-9a-f]{16}/$")
        self.assertEqual(self.mock.s3_requests[0]["key"], f"results/{self.unload_ids()[0]}-manifest.csv")
        # The column list came first, from information_schema, over two pages of results.
        listed = [r for r in self.mock.athena_requests if r["target"] == "AmazonAthena.StartQueryExecution"
                  and COLUMNS_SQL.match(r["body"]["QueryString"])]
        self.assertEqual(COLUMNS_SQL.match(listed[0]["body"]["QueryString"]).groupdict(), {"db": DB, "table": CT})
        self.assertGreater(len([r for r in self.mock.athena_requests if r["target"] == "AmazonAthena.GetQueryResults"]), 2)

    def test_the_query_names_its_workgroup_database_token_and_result_location(self):
        c.run_once(self.cfg(ATHENA_WORKGROUP="security-lake"))
        body = self.starts()[0]["body"]
        self.assertEqual(body["WorkGroup"], "security-lake")
        self.assertEqual(body["QueryExecutionContext"], {"Catalog": "AwsDataCatalog", "Database": DB})
        self.assertEqual(body["ResultConfiguration"], {"OutputLocation": RESULTS})
        self.assertRegex(body["ClientRequestToken"], r"^[0-9a-f]{32}$")
        headers = {k.lower(): v for k, v in self.starts()[0]["headers"].items()}
        self.assertEqual(headers["content-type"], "application/x-amz-json-1.1")
        self.assertEqual(headers["x-amz-security-token"], TOKEN)
        self.assertRegex(headers["x-amz-date"], r"^\d{8}T\d{6}Z$")
        # Without ATHENA_OUTPUT_LOCATION the workgroup's own result location is used.
        self.mock.athena_requests.clear()
        os.remove(self.state)
        c.run_once(self.cfg(ATHENA_OUTPUT_LOCATION=None))
        self.assertNotIn("ResultConfiguration", self.starts()[0]["body"])

    def test_the_default_tables_follow_the_region_and_sources(self):
        cfg = c.load_config(base_env())
        self.assertEqual(cfg["tables"], [CT, R53, FLOW, SH])
        self.assertEqual(cfg["database"], DB)
        cfg = c.load_config(base_env(AWS_REGION="us-east-1", SECURITY_LAKE_SOURCES="EKS_AUDIT, waf"))
        self.assertEqual(cfg["tables"], ["amazon_security_lake_table_us_east_1_eks_audit_2_0", "amazon_security_lake_table_us_east_1_waf_2_0"])
        self.assertEqual(cfg["database"], "amazon_security_lake_glue_db_us_east_1")
        # A query subscriber's resource links can have other names.
        cfg = c.load_config(base_env(SECURITY_LAKE_DATABASE="sl_link", SECURITY_LAKE_TABLES="ct_link,dns_link"))
        self.assertEqual((cfg["database"], cfg["tables"]), ("sl_link", ["ct_link", "dns_link"]))

    def test_each_table_is_read_and_kept_apart(self):
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        self.mock.rows[R53] = [{**api_activity(1, self.ago(29)), "class_uid": 4003}]
        self.assertEqual(c.run_once(self.cfg(SECURITY_LAKE_SOURCES="cloud_trail_mgmt,route53,vpc_flow")), 2)
        self.assertEqual([SQL.match(r["body"]["QueryString"]).group("table") for r in self.starts()], [CT, R53, FLOW])
        self.assertEqual([(r["security_lake_table"], r["class_uid"]) for r in self.sent()], [(CT, 6003), (R53, 4003)])
        self.assertEqual(sorted(self.saved()["tables"]), sorted([CT, R53, FLOW]))
        # Each query wrote to a location of its own: UNLOAD writes only to an empty one.
        self.assertEqual(len({SQL.match(r["body"]["QueryString"]).group("prefix") for r in self.starts()}), 3)

    def test_the_query_is_checked_until_it_ends(self):
        self.mock.states = ["QUEUED", "QUEUED", "RUNNING", "RUNNING", "RUNNING"]
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        self.assertEqual(c.run_once(self.cfg()), 1)
        checks = [r for r in self.mock.athena_requests if r["target"] == "AmazonAthena.GetQueryExecution"
                  and r["body"]["QueryExecutionId"] == self.unload_ids()[0]]
        self.assertEqual(len(checks), 6)
        self.assertEqual(self.slept, [1.0, 2.0, 4.0, 8.0, 10.0])

    def test_a_failed_query_stops_with_athena_s_reason(self):
        self.mock.finish = ("FAILED", "TABLE_NOT_FOUND: line 1:15: Table 'awsdatacatalog.x.y' does not exist", False)
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertNotIsInstance(cm.exception, c.NetworkError)
        self.assertIn("query FAILED: TABLE_NOT_FOUND", str(cm.exception))
        self.assertNotIn("until", self.saved().get("tables", {}).get(CT, {}) if os.path.exists(self.state) else {})
        # A failure Athena marks retryable is a network error, so --interval tries again.
        self.mock.finish = ("FAILED", "Query exhausted resources at this scale factor", True)
        with self.assertRaises(c.NetworkError):
            c.run_once(self.cfg())
        self.mock.finish = ("CANCELLED", "Query cancelled by user", False)
        with self.assertRaisesRegex(c.BridgeError, "query CANCELLED"):
            c.run_once(self.cfg())

    def test_a_query_past_its_time_limit_is_stopped_and_the_window_kept(self):
        self.mock.states = ["RUNNING"] * 100
        with self.assertRaisesRegex(c.NetworkError, "ran past ATHENA_QUERY_TIMEOUT and was stopped"):
            c.run_once(self.cfg(ATHENA_QUERY_TIMEOUT="60"))
        self.assertEqual(self.mock.stopped, self.unload_ids())
        self.assertLessEqual(sum(self.slept), 70)
        self.assertNotIn("until", self.saved().get("tables", {}).get(CT, {}) if os.path.exists(self.state) else {})

    def test_throttled_calls_are_retried_like_a_429(self):
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        self.mock.athena_answers = [(400, "TooManyRequestsException", "Rate exceeded"),
                                    (400, "com.amazonaws.athena#ThrottlingException", "Rate exceeded")]
        self.assertEqual(c.run_once(self.cfg()), 1)
        self.assertEqual(self.logbuf.getvalue().count("was throttled; retrying"), 2)
        self.mock.athena_answers = [(400, "TooManyRequestsException", "Rate exceeded")] * c.MAX_ATTEMPTS
        with self.assertRaisesRegex(c.NetworkError, "still throttled"):
            c.run_once(self.cfg())

    def test_refused_credentials_stop_without_any_of_aws_s_message(self):
        # AWS's message for a bad signature quotes the signed request, session token included.
        for kind in ("UnrecognizedClientException", "InvalidSignatureException", "ExpiredTokenException"):
            with self.subTest(kind=kind):
                self.mock.athena_answers = [(400 if kind != "ExpiredTokenException" else 403, kind, f"token {TOKEN} was refused")]
                with self.assertRaises(c.BridgeError) as cm:
                    c.run_once(self.cfg())
                self.assertIn(f"AWS refused the credentials for the {CT} column list query start", str(cm.exception))
                self.assertIn(kind, str(cm.exception))
                self.assertNotIn(TOKEN, str(cm.exception))
        self.mock.athena_answers = []
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(AWS_SESSION_TOKEN="another-session-token-not-real"))
        self.assertIn("InvalidSignatureException", str(cm.exception))
        self.assertNotIn(TOKEN, self.logbuf.getvalue() + str(cm.exception))

    def test_access_denied_names_the_permissions(self):
        self.mock.athena_answers = [(400, "AccessDeniedException", "User: arn:aws:iam::111122223333:user/bridge is not "
                                     "authorized to perform: athena:StartQueryExecution")]
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg())
        self.assertIn("is not authorized to perform: athena:StartQueryExecution", str(cm.exception))
        self.assertIn("IAM policy needs the Athena, Glue, Lake Formation and S3 permissions", str(cm.exception))

    def test_an_invalid_request_shows_athena_s_message(self):
        self.mock.athena_answers = [(400, "InvalidRequestException", "WorkGroup security-lake is not found.")]
        with self.assertRaisesRegex(c.BridgeError, r"Athena rejected the .+ \(HTTP 400, InvalidRequestException: WorkGroup security-lake is not found\.\)"):
            c.run_once(self.cfg())

    def test_no_data_manifest_stops_with_advice(self):
        self.mock.no_manifest = True
        with self.assertRaisesRegex(c.BridgeError, "no data manifest .+ not managed query results"):
            c.run_once(self.cfg())

    def test_a_file_outside_the_unload_location_is_refused(self):
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        self.mock.outside = True
        with self.assertRaisesRegex(c.BridgeError, "manifest lists a file outside its UNLOAD location"):
            c.run_once(self.cfg())
        self.assertEqual(self.sent(), [])

    def test_files_are_read_in_parts_and_their_gzip_members_joined(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(200 - i)) for i in range(40)]
        self.mock.rows_per_file = 15
        self.mock.members = 4
        saved = c.PART_BYTES, c.UNPACK_STEP
        c.PART_BYTES, c.UNPACK_STEP = 97, 64
        try:
            self.assertEqual(c.run_once(self.cfg()), 40)
        finally:
            c.PART_BYTES, c.UNPACK_STEP = saved
        self.assertEqual([r["api"]["request"]["uid"] for r in self.sent()], [f"req-{i}" for i in range(40)])
        ranges = [r["headers"].get("Range") for r in self.mock.s3_requests if r["key"].endswith(".gz")]
        self.assertTrue(all(re.match(r"^bytes=\d+-\d+$", x) for x in ranges), ranges)
        self.assertGreater(len(ranges), 3 * 5)

    def test_a_server_that_ignores_the_range_is_read_whole(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(30 - i)) for i in range(3)]
        self.mock.range_ok = False
        self.assertEqual(c.run_once(self.cfg()), 3)

    def test_an_empty_file_sends_nothing(self):
        c.run_once(self.cfg())
        self.mock.rows[CT] = []
        execution = self.mock.executions[self.unload_ids()[0]]
        self.assertEqual(execution["files"], [])
        # Athena can still list a file with nothing in it; S3 answers its first range with 416.
        self.mock.objects[(UNLOAD_BUCKET, "security-lake-bridge/empty.gz")] = b""
        aws = c.Aws(self.cfg())
        self.assertEqual(list(aws.records(UNLOAD_BUCKET, "security-lake-bridge/empty.gz", "test")), [])

    def test_damaged_files_stop_the_run(self):
        aws = c.Aws(self.cfg())
        good = pack([json.dumps(api_activity(0, self.now))], 1)
        cases = {"isn't gzip, or is damaged": b"not gzip at all",
                 "ended partway through its gzip data": good[:-12],
                 "found a line that is not JSON": pack(["{not json"], 1),
                 "found a line that is not a JSON object": pack(["[1, 2]"], 1)}
        for message, data in cases.items():
            with self.subTest(message=message):
                self.mock.objects[(UNLOAD_BUCKET, "x/file.gz")] = data
                with self.assertRaisesRegex(c.BridgeError, re.escape(message)):
                    list(aws.records(UNLOAD_BUCKET, "x/file.gz", "test"))
        saved = c.MAX_LINE_BYTES
        c.MAX_LINE_BYTES = 1024
        try:
            self.mock.objects[(UNLOAD_BUCKET, "x/file.gz")] = gzip.compress(b"{" + b" " * 5000)
            with self.assertRaisesRegex(c.BridgeError, "has a record over 0 MB, which the bridge refuses"):
                list(aws.records(UNLOAD_BUCKET, "x/file.gz", "test"))
        finally:
            c.MAX_LINE_BYTES = saved

    def test_next_run_reads_from_the_last_window_less_the_overlap_and_drops_repeats(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(36 - i)) for i in range(3)]
        cfg = self.cfg(BRIDGE_OVERLAP_SECONDS="1800", BRIDGE_DELAY_SECONDS="600")
        c.run_once(cfg)
        (first,) = self.windows()
        self.assertAlmostEqual(self.saved()["tables"][CT]["until"], first[1], delta=0.01)
        self.mock.ingested.clear()
        # A record that reached Security Lake late, inside the overlap; a finding that changed but
        # kept its uid; and a new one.
        late = api_activity(7, self.ago(20))
        changed = {**self.mock.rows[CT][2], "status": "Failure", "status_id": 2}
        new = api_activity(8, self.ago(11))
        self.mock.rows[CT] += [late, changed, new]
        c.run_once(cfg)
        self.assertEqual([r["metadata"]["uid"] for r in self.sent()], [late["metadata"]["uid"], changed["metadata"]["uid"], new["metadata"]["uid"]])
        second = self.windows()[1]
        self.assertAlmostEqual(second[0], first[1] - 1800, delta=0.01)

    def test_the_window_ends_the_delay_before_now(self):
        self.mock.rows[CT] = [api_activity(0, self.ago(20)), api_activity(1, self.ago(5))]
        c.run_once(self.cfg(BRIDGE_DELAY_SECONDS="600"))
        self.assertEqual([r["api"]["request"]["uid"] for r in self.sent()], ["req-0"])
        (window,) = self.windows()
        self.assertAlmostEqual(window[1], datetime.now(timezone.utc).timestamp() - 600, delta=5)

    def test_lookback_sets_the_first_window(self):
        self.mock.rows[CT] = [api_activity(0, self.now - timedelta(days=3)), api_activity(1, self.ago(60))]
        c.run_once(self.cfg(BRIDGE_LOOKBACK_HOURS="24"))
        self.assertEqual([r["api"]["request"]["uid"] for r in self.sent()], ["req-1"])
        (window,) = self.windows()
        self.assertAlmostEqual(window[0], self.now.timestamp() - 86400, delta=5)

    def test_window_moves_only_after_ingest_accepts(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(60 - i)) for i in range(4)]
        saved = c.SEND_RECORDS
        c.SEND_RECORDS = 2
        try:
            self.mock.ingest_codes = [200, 400]
            with self.assertRaises(c.BridgeError):
                c.run_once(self.cfg())
            state = self.saved()["tables"][CT]
            self.assertNotIn("until", state)
            self.assertEqual(len(state["seen"]), 2)
            self.mock.ingest_codes = []
            self.mock.ingested.clear()
            c.run_once(self.cfg())
        finally:
            c.SEND_RECORDS = saved
        self.assertEqual([r["api"]["request"]["uid"] for r in self.sent()], ["req-2", "req-3"])
        self.assertIn("until", self.saved()["tables"][CT])

    def test_a_saved_end_past_now_counts_as_the_window_end(self):
        with open(self.state, "w") as fh:
            json.dump({"tables": {CT: {"until": self.now.timestamp() + 7200}}}, fh)
        c.run_once(self.cfg(BRIDGE_DELAY_SECONDS="600", BRIDGE_OVERLAP_SECONDS="1800"))
        (window,) = self.windows()
        self.assertAlmostEqual(window[1] - window[0], 1800, delta=1)
        self.assertLessEqual(self.saved()["tables"][CT]["until"], datetime.now(timezone.utc).timestamp() - 599)

    def test_dry_run_prints_and_saves_nothing(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(30 - i)) for i in range(2)]
        out = io.StringIO()
        c.run_once(self.cfg(NGSIEM_INGEST_URL="", NGSIEM_INGEST_KEY=""), dry_run=True, out=out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([x["security_lake_record"] for x in lines], ["ocsf"] * 2)
        self.assertEqual(self.mock.ingested, [])
        self.assertFalse(os.path.exists(self.state))

    def test_rate_limit_and_server_errors_are_retried(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(30 - i)) for i in range(3)]
        self.mock.athena_answers = [(503, "ServiceUnavailable", ""), (500, "InternalServerException", "")]
        self.mock.s3_answers = [(503, "SlowDown", "Please reduce your request rate.")]
        self.mock.ingest_codes = [429]
        self.assertEqual(c.run_once(self.cfg()), 3)
        self.assertEqual(len(self.sent()), 3)

    def test_gzip_batches_and_headers(self):
        self.mock.rows[CT] = [api_activity(i, self.ago(60 - i)) for i in range(12)]
        c.run_once(self.cfg(BRIDGE_BATCH_BYTES="2500"))
        self.assertGreater(len(self.mock.ingested), 1)
        self.assertEqual(len(self.sent()), 12)
        for post in self.mock.ingested:
            self.assertEqual(post["headers"]["Content-Encoding"], "gzip")
            self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_secrets_never_logged(self):
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        self.mock.athena_answers = [(503, "ServiceUnavailable", "")]
        self.mock.ingest_codes = [503]
        c.run_once(self.cfg())
        with self.assertRaises(c.BridgeError) as cm:
            c.run_once(self.cfg(AWS_SECRET_ACCESS_KEY="another-wrong-secret-not-real"))
        logged = self.logbuf.getvalue() + str(cm.exception)
        self.assertIn("query start", logged)
        for secret in (SECRET, TOKEN, INGEST_KEY, "00000000-example-integration", "another-wrong-secret-not-real"):
            self.assertNotIn(secret, logged)

    def test_config_rejects_bad_values(self):
        cases = [
            base_env(AWS_REGION=None),
            base_env(AWS_REGION="Sydney"),
            base_env(AWS_ACCESS_KEY_ID=None),
            base_env(AWS_SECRET_ACCESS_KEY=None),
            base_env(ATHENA_UNLOAD_LOCATION=None),
            base_env(ATHENA_UNLOAD_LOCATION="https://example-bucket.s3.amazonaws.com/x/"),
            base_env(ATHENA_UNLOAD_LOCATION="s3://Bad_Bucket/x/"),
            base_env(ATHENA_UNLOAD_LOCATION="s3://example-bucket/x') TO 's3://other/"),
            base_env(ATHENA_UNLOAD_LOCATION="s3://example-bucket/a//b/"),
            base_env(ATHENA_OUTPUT_LOCATION="s3://example-bucket/x y/"),
            base_env(ATHENA_WORKGROUP="primary; DROP"),
            base_env(ATHENA_QUERY_TIMEOUT="10"),
            base_env(SECURITY_LAKE_DATABASE='db"."other'),
            base_env(SECURITY_LAKE_TABLES='ct" WHERE 1=1 --'),
            base_env(SECURITY_LAKE_SOURCES="cloud_trail_mgmt,okta"),
            base_env(SECURITY_LAKE_SOURCES=","),
            base_env(AWS_ENDPOINT_URL_ATHENA="http://athena.example.com"),
            base_env(AWS_ENDPOINT_URL_S3="https://s3.example.com/bucket"),
            base_env(BRIDGE_LOOKBACK_HOURS="0"),
            base_env(BRIDGE_DELAY_SECONDS="86401"),
            base_env(NGSIEM_INGEST_URL="http://ingest.example.com/http-endpoint/v1/x"),
        ]
        for env in cases:
            env = {k: v for k, v in env.items() if v is not None}
            with self.subTest(env=env), self.assertRaises(c.BridgeError):
                c.load_config(env)
        cfg = c.load_config(base_env(AWS_SESSION_TOKEN=None))
        self.assertEqual((cfg["athena_url"], cfg["s3_url"], cfg["workgroup"], cfg["output"], cfg["token"]),
                         (f"https://athena.{REGION}.amazonaws.com", None, "primary", None, None))
        self.assertEqual((cfg["unload_bucket"], cfg["unload_prefix"]), (UNLOAD_BUCKET, "security-lake-bridge/"))
        self.assertEqual(c.load_config(base_env(ATHENA_UNLOAD_LOCATION=f"s3://{UNLOAD_BUCKET}"))["unload_prefix"], "")
        self.assertEqual(c.load_config(base_env(AWS_REGION=None, AWS_DEFAULT_REGION="eu-west-2"))["region"], "eu-west-2")

    def test_the_signature_matches_aws_s_worked_example(self):
        # The GET request in AWS's guide to signing API requests (IAM ListUsers on 2015-08-30).
        headers = c.sigv4("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
                          {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, b"", "us-east-1", "iam",
                          "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None,
                          now=datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc).timestamp())
        self.assertEqual(headers["Authorization"], "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
                         "SignedHeaders=content-type;host;x-amz-date, "
                         "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
        self.assertEqual(headers["X-Amz-Date"], "20150830T123600Z")
        # S3 also signs the payload hash, and a session token is signed when there is one.
        s3 = c.sigv4("GET", "https://example-bucket.s3.ap-southeast-2.amazonaws.com/a%20b.gz", {}, None, REGION, "s3",
                     KEY_ID, SECRET, TOKEN)
        self.assertEqual(s3["X-Amz-Content-Sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,", s3["Authorization"])

    def test_s3_urls(self):
        aws = c.Aws(c.load_config(base_env()))
        self.assertEqual(aws.s3_url("example-bucket", "a b/c+d.gz"), f"https://example-bucket.s3.{REGION}.amazonaws.com/a%20b/c%2Bd.gz")
        self.assertEqual(aws.s3_url("example.bucket", "x.gz"), f"https://s3.{REGION}.amazonaws.com/example.bucket/x.gz")
        aws = c.Aws(c.load_config(base_env(AWS_ENDPOINT_URL_S3="https://bucket.vpce-0a1b2c3d.s3.ap-southeast-2.vpce.amazonaws.com")))
        self.assertEqual(aws.s3_url("example-bucket", "x.gz"),
                         "https://bucket.vpce-0a1b2c3d.s3.ap-southeast-2.vpce.amazonaws.com/example-bucket/x.gz")

    def test_s3_errors_stop_with_clear_errors(self):
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        cases = [((403, "AccessDenied", "Access Denied"), r"AWS refused the .+ manifest read \(HTTP 403, AccessDenied: Access Denied\); .+s3:GetObject"),
                 ((404, "NoSuchKey", "The specified key does not exist."), r"S3 has no object for the .+ manifest read \(HTTP 404, NoSuchKey\)"),
                 ((301, "PermanentRedirect", "The bucket you are attempting to access must be addressed using the specified endpoint."),
                  r"HTTP 301 \(PermanentRedirect\): the bucket isn't in ap-southeast-2"),
                 ((400, "ExpiredToken", f"The provided token has expired: {TOKEN}"), r"AWS refused the credentials .+ \(HTTP 400, ExpiredToken\)")]
        for answer, message in cases:
            with self.subTest(answer=answer):
                self.mock.s3_answers = [answer]
                with self.assertRaisesRegex(c.BridgeError, message) as cm:
                    c.run_once(self.cfg())
                self.assertNotIn(TOKEN, str(cm.exception))
        self.assertNotIn("until", self.saved().get("tables", {}).get(CT, {}) if os.path.exists(self.state) else {})

    def test_without_a_session_token_none_is_sent(self):
        c.run_once(self.cfg(AWS_SESSION_TOKEN=None))
        for r in self.mock.athena_requests + self.mock.s3_requests:
            self.assertNotIn("x-amz-security-token", {k.lower() for k in r["headers"]})

    def test_timestamp_literals_are_utc_to_the_millisecond(self):
        at = datetime(2026, 10, 21, 1, 2, 3, 456789, tzinfo=timezone.utc).timestamp()
        self.assertEqual(c._timestamp(at), "TIMESTAMP '2026-10-21 01:02:03.456'")
        cfg = c.load_config(base_env())
        self.assertEqual(c.unload_sql(cfg, CT, [("time", "bigint"), ("time_dt", "timestamp(3) with time zone")], at, at + 60,
                                      "security-lake-bridge/x/"),
                         f'UNLOAD (SELECT "time", CAST("time_dt" AS varchar) AS "time_dt" FROM "{DB}"."{CT}" WHERE time_dt >= '
                         f"TIMESTAMP '2026-10-21 01:02:03.456' AND time_dt < TIMESTAMP '2026-10-21 01:03:03.456') TO "
                         f"'s3://{UNLOAD_BUCKET}/security-lake-bridge/x/' WITH (format = 'JSON')")

    def test_every_timestamp_is_written_as_text_at_any_depth(self):
        # Athena's JSON writer can't write a timestamp with a time zone, which Security Lake's *_dt
        # columns hold, so each column with one is cast to its own type with the timestamps as varchar.
        cols = [("time", "bigint"), ("time_dt", "timestamp(3) with time zone"), ("start_time_dt", "timestamp(6)"),
                ("metadata", 'row(uid varchar, "desc" varchar, processed_time_dt timestamp(3) with time zone)'),
                ("evidences", "array(row(data varchar, first_seen_time_dt timestamp(3) with time zone))"),
                ("tags", "map(varchar, array(row(at timestamp(3), score decimal(10,2))))"),
                ("cloud", "row(region varchar, account row(uid varchar))"), ("unmapped", "map(varchar, varchar)")]
        self.assertEqual(c.select_list(cols), ", ".join([
            '"time"', 'CAST("time_dt" AS varchar) AS "time_dt"', 'CAST("start_time_dt" AS varchar) AS "start_time_dt"',
            'CAST("metadata" AS row("uid" varchar, "desc" varchar, "processed_time_dt" varchar)) AS "metadata"',
            'CAST("evidences" AS array(row("data" varchar, "first_seen_time_dt" varchar))) AS "evidences"',
            'CAST("tags" AS map(varchar, array(row("at" varchar, "score" decimal(10, 2))))) AS "tags"',
            '"cloud"', '"unmapped"']))
        self.assertEqual(c.parse_type('row("user" row(name varchar), "time" bigint)'),
                         ("row", [("user", ("row", [("name", ("type", "varchar"))])), ("time", ("type", "bigint"))]))
        for bad in ("row(", "array(varchar", "map(varchar)", "row(a varchar,)", "varchar)", "row(a varchar) x", "@"):
            with self.subTest(bad=bad), self.assertRaisesRegex(c.BridgeError, "column type the bridge can't read"):
                c.parse_type(bad)

    def test_a_table_without_time_dt_is_read_by_time_within_its_eventday_partitions(self):
        self.mock.columns[CT] = c_v1 = V1_COLUMNS
        self.mock.rows[CT] = [{"metadata": {"product": {"name": "CloudTrail"}, "version": "1.0.0-rc.2"}, "time": ms(self.ago(30)),
                               "class_uid": 3005, "unmapped": {}, "region": REGION, "accountid": "111122223333", "eventday": "20261021"}]
        self.assertEqual(c.run_once(self.cfg()), 1)
        where = SQL.match(self.starts()[0]["body"]["QueryString"]).group("where")
        m = WINDOW_MS.match(where)
        self.assertTrue(m and m.group("d0") and m.group("d1"), where)
        self.assertEqual(SQL.match(self.starts()[0]["body"]["QueryString"]).group("cols"), ", ".join(f'"{n}"' for n, _ in c_v1))

    def test_a_table_athena_lists_no_columns_for_stops_with_advice(self):
        with self.assertRaisesRegex(c.BridgeError, r"Athena lists no columns for sl_link\.x: check SECURITY_LAKE_DATABASE"):
            c.run_once(self.cfg(SECURITY_LAKE_DATABASE="sl_link", SECURITY_LAKE_TABLES="x"))
        self.mock.columns[CT] = [("metadata", "row(uid varchar)")]
        with self.assertRaisesRegex(c.BridgeError, "has neither a time_dt nor a time column"):
            c.run_once(self.cfg())
        self.assertEqual(self.starts(), [])

    def test_redirects_are_not_followed(self):
        # Following a redirect would send a signed request to another URL, so the run fails
        # instead, and nothing reaches the redirect's target.
        self.mock.rows[CT] = [api_activity(0, self.ago(30))]
        r = Redirects()
        try:
            cases = {"HTTP Ingest": self.cfg(NGSIEM_INGEST_URL=f"{r.base}/http-endpoint/v1/00000000-example-integration"),
                     "Athena": self.cfg(AWS_ENDPOINT_URL_ATHENA=r.base), "S3": self.cfg(AWS_ENDPOINT_URL_S3=r.base)}
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
                        self.assertFalse(os.path.exists(self.state) and "until" in self.saved().get("tables", {}).get(CT, {}))
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

    def test_query_timeout_out_of_range_gives_its_range(self):
        for value in ("-1", "29", "86401"):
            with self.subTest(value=value), self.assertRaisesRegex(c.BridgeError, r"^ATHENA_QUERY_TIMEOUT must be between 30 and 86,400$"):
                self.load(ATHENA_QUERY_TIMEOUT=value)
        self.assertEqual(self.load(ATHENA_QUERY_TIMEOUT="30")["query_timeout"], 30)

    def test_delay_is_at_most_a_day(self):
        with self.assertRaisesRegex(c.BridgeError, r"^BRIDGE_DELAY_SECONDS must be between 0 and 86,400$"):
            self.load(BRIDGE_DELAY_SECONDS="86401")
        self.assertEqual(self.load(BRIDGE_DELAY_SECONDS="0")["delay_seconds"], 0)


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
