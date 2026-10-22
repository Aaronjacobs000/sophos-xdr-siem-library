#!/usr/bin/env python3
"""Pull Qualys VMDR vulnerability detections with the Host List Detection API and send them to a
Sophos NG-SIEM HTTP Ingest integration, one JSON record per detection. Python 3 standard library only.

Qualys VMDR has no push for detections, so this script asks for the detections whose status changed
(New, Active, Re-Opened or Fixed) in each new window:

  POST https://{API server}/api/6.0/fo/asset/host/vm/detection/   action=list&detection_updated_since=...
  POST https://{API server}/api/4.0/fo/knowledge_base/vuln/       action=list&details=All&ids=...

with the user name and password of a Qualys user that can read the hosts (a Reader is enough). The
Host List Detection API answers in XML, one HOST element per host with its DETECTION_LIST. The bridge
turns each detection into one JSON record: the host's fields under "HOST", the detection's under
"DETECTION", and, unless QUALYS_KB=0, the QID's title, CVEs, CVSS scores and threat indicators from
the KnowledgeBase under "KB". "qualys_record" ("detection") and "qualys_platform" (the API server)
go first, so the library parser in parsers/qualys/qualys-vmdr can normalize it.

The request and response shapes follow Qualys's VM API documentation and the output DTDs.
Configuration comes from environment variables (see README.md). A window's end only moves after
HTTP Ingest accepted every record in it. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
import calendar
import gzip
import http.client
import json
import logging
import os
import random
import re
import socket
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("qualys_vmdr_bridge")
USER_AGENT = f"sophos-xdr-siem-library-qualys-vmdr-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 10000
RECORD_KEY = "qualys_record"
PLATFORM_KEY = "qualys_platform"
DETECTION_PATH = "/api/6.0/fo/asset/host/vm/detection/"
KB_PATH = "/api/4.0/fo/knowledge_base/vuln/"
# Every status, so a fixed detection is sent too. Without it, Qualys leaves out Fixed.
STATUSES = "New,Active,Re-Opened,Fixed"
# Qualys answers a call its API limits block with HTTP 409 (sometimes 400) and one of these codes:
# 1920 blocked by other calls, 1960 the concurrency limit, 1965 the rate limit. They are retried,
# waiting as long as X-RateLimit-ToWait-Sec says, for up to five minutes a time.
LIMIT_CODES = {"1920", "1960", "1965"}
# QIDs per KnowledgeBase request. Qualys says a list of 8,000 to 10,000 characters may get no answer.
KB_BATCH = 500
KB_CACHE_MAX = 200000
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Elements that hold a list of one kind of child, which become JSON arrays even with one child.
LIST_ELEMENTS = {"ASSET_GROUP_LIST", "TAGS", "CLOUD_PROVIDER_TAGS", "METADATA", "EC2", "GOOGLE", "AZURE",
                 "ALICLOUD", "OCI"}


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """Qualys or HTTP Ingest couldn't be reached, even after the retries, or Qualys's API limits
    held the call too long. With --interval the bridge logs it and tries again at the next interval."""


class HostNotFound(NetworkError):
    """A host name in a URL setting didn't resolve, even after the retries. Until a run has worked,
    it stops the bridge even with --interval, since it is most likely a mistyped URL."""


# ---------------------------------------------------------------- configuration

def _env(env: dict, name: str, default: str | None = None) -> str | None:
    value = env.get(name)
    if not (value and value.strip()) and name.startswith("BRIDGE_"):
        # Bridges were called collectors, so the old COLLECTOR_ names still work.
        value = env.get("COLLECTOR_" + name[len("BRIDGE_"):])
    return value.strip() if value and value.strip() else default


def _flag(env: dict, name: str, default: bool) -> bool:
    value = _env(env, name)
    if value is None:
        return default
    return value.lower() not in ("0", "false", "no", "off")


def _number(env: dict, name: str, default: str, cast=int, low: float = 0, high: int = 10 ** 9):
    """A numeric setting: a bad value stops the bridge with one plain error, not a traceback."""
    value = _env(env, name, default)
    try:
        number = cast(value)
    except ValueError:
        raise BridgeError(f"{name} must be a number") from None
    # NaN fails every comparison, so it lands here too.
    if not low <= number <= high:
        raise BridgeError(f"{name} must be between {low:,} and {high:,}")
    return number


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


def _refuse_user_info(url: str, what: str) -> None:
    """urllib sends no user name or password from a URL, and the host isn't found with them in
    it, so a URL setting that has them can never work."""
    if "@" in urllib.parse.urlsplit(url).netloc:
        raise BridgeError(f"{what} has a user name or password before the host (user:pass@), which the bridge "
                          "can't use; remove it")


_SEVERITIES = re.compile(r"[1-5](-[1-5])?(,[1-5](-[1-5])?)*")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "QUALYS_API_URL") or "").rstrip("/"),
        "username": _env(env, "QUALYS_USERNAME"),
        "password": _env(env, "QUALYS_PASSWORD"),
        "page_hosts": _number(env, "QUALYS_PAGE_HOSTS", "100", low=1, high=10000),
        "severities": _env(env, "QUALYS_SEVERITIES"),
        "show_results": _flag(env, "QUALYS_SHOW_RESULTS", True),
        "show_igs": _flag(env, "QUALYS_SHOW_IGS", False),
        "show_qds": _flag(env, "QUALYS_SHOW_QDS", True),
        "kb": _flag(env, "QUALYS_KB", True),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "qualys_vmdr_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=8760),
        "delay_seconds": _number(env, "BRIDGE_DELAY_SECONDS", "900", high=86400),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "120", float, low=0.001),
    }
    if not cfg["api_url"]:
        raise BridgeError("QUALYS_API_URL is required: your platform's API server, such as "
                          "https://qualysapi.qg1.apps.qualys.com.au")
    _refuse_user_info(cfg["api_url"], "QUALYS_API_URL")
    _require_https(cfg["api_url"], "QUALYS_API_URL")
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment or not parts.hostname:
        raise BridgeError("QUALYS_API_URL must be the API server's address with no path, such as "
                          "https://qualysapi.qg1.apps.qualys.com.au")
    cfg["platform"] = parts.hostname
    if not cfg["username"] or not cfg["password"]:
        raise BridgeError("QUALYS_USERNAME and QUALYS_PASSWORD are required")
    if ":" in cfg["username"]:
        raise BridgeError("QUALYS_USERNAME can't have a colon in it")
    if cfg["severities"] is not None:
        cfg["severities"] = cfg["severities"].replace(" ", "")
        if not _SEVERITIES.fullmatch(cfg["severities"]):
            raise BridgeError("QUALYS_SEVERITIES must be levels 1 to 5 and ranges, comma separated, such as 3-5 or 4,5")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    if cfg["ingest_url"]:
        _refuse_user_info(cfg["ingest_url"], "NGSIEM_INGEST_URL")
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    """The host and port, for log lines and errors. A user name or password in the URL is a
    credential, so it shows as [redacted]."""
    _, at, host = urllib.parse.urlsplit(url).netloc.rpartition("@")
    return f"[redacted]@{host}" if at else host


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            # Honor the server's wait for up to five minutes, so a bad value can't stall the bridge.
            return min(300.0, max(0.0, float(retry_after)))
        except ValueError:
            pass
    return min(60.0, 2 ** attempt) + random.uniform(0, 1)


class HttpStatus(BridgeError):
    def __init__(self, what: str, url: str, code: int, body: bytes = b""):
        if code in REDIRECT_STATUS:
            message = (f"{what} to {_host(url)} answered with a redirect (HTTP {code}), which the bridge refuses "
                       "so the key or token never goes to another URL; check the URL setting")
        elif code in UNSUPPORTED_STATUS:
            message = (f"{what} to {_host(url)} failed with HTTP {code}: {UNSUPPORTED_STATUS[code]}, and a retry "
                       "won't change that; check the URL setting")
        else:
            message = f"{what} to {_host(url)} failed with HTTP {code}"
        super().__init__(message)
        self.code = code
        self.body = body


class RetriedStatus(HttpStatus, NetworkError):
    """A 408, 429, 500, 502, 503 or 504, or a Qualys API limit, that outlasted the retries. It is a
    NetworkError too, so with --interval the bridge logs it and tries again at the next interval."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _read(resp, what: str, url: str, limit: int | None = None) -> bytes:
    """Reads a response body, but no more than the limit, so a broken or hostile endpoint can't
    use up memory. It reads 1 MB at a time: before Python 3.10, read(n) set aside all n bytes first.
    A body that ends short of its Content-Length raises IncompleteRead, like a cut-off chunked one."""
    limit = limit or MAX_RESPONSE_BYTES
    chunks, size = [], 0
    while True:
        chunk = resp.read(min(1048576, limit + 1 - size))
        if not chunk:
            # read(n) returns nothing, with no error, when the connection closes before the
            # Content-Length is reached. http.client still counts the bytes it was promised.
            owed = getattr(resp, "length", None)
            if owed:
                raise http.client.IncompleteRead(b"", owed)
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise BridgeError(f"{what} to {_host(url)} sent more than {limit // 1048576} MB, which the bridge "
                              "refuses so a bad response can't use up memory")


# Retried, then a NetworkError. On Python 3.9 a read timeout is socket.timeout, which isn't a
# TimeoutError yet, and IncompleteRead means the connection closed partway through an answer.
_NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError, http.client.IncompleteRead)


def _limited(code: int, body: bytes) -> bool:
    """True for an answer Qualys's API limits blocked: HTTP 409 or 400 with code 1920, 1960 or 1965."""
    return code in (400, 409) and _qualys_error(body)[0] in LIMIT_CODES


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504, and Qualys's API limits, with
    backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, _read(resp, what, url)
        except urllib.error.HTTPError as e:
            # Read the body, then close the error response so its socket is released now, not
            # when the error is garbage collected. A status that is retried is retried whatever
            # its body, so a body over the limit only stops the run for the other statuses.
            try:
                error_body = _read(e, what, url)
            except BridgeError:
                if e.code not in RETRY_STATUS:
                    raise
                error_body = b""
            except _NETWORK_ERRORS:
                # The body was cut short or timed out: the status still decides what happens.
                error_body = b""
            finally:
                e.close()
            limited = _limited(e.code, error_body)
            if (e.code in RETRY_STATUS or limited) and attempt < MAX_ATTEMPTS - 1:
                wait = None
                if e.headers:
                    wait = e.headers.get("X-RateLimit-ToWait-Sec") if limited else None
                    wait = wait or e.headers.get("Retry-After")
                delay = _retry_delay(attempt, wait)
                LOG.warning("%s to %s returned %s%s; retrying in %.1fs", what, _host(url), e.code,
                            " (Qualys API limit)" if limited else "", delay)
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS or limited:
                raise RetriedStatus(what, url, e.code, error_body) from None
            raise HttpStatus(what, url, e.code, error_body) from None
        except _NETWORK_ERRORS as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            if isinstance(e, urllib.error.URLError) and isinstance(e.reason, socket.gaierror):
                raise HostNotFound(f"{what} to {_host(url)} failed: the host name wasn't found; "
                                   "check the URL setting") from None
            raise NetworkError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
        except ValueError:
            # http.client puts a header value it refuses, such as a key with a line break in it,
            # in its error, so that error isn't passed on.
            raise BridgeError(f"{what} to {_host(url)} couldn't be sent: a key or token has a line break or "
                              "another character a request header can't carry") from None
        except http.client.HTTPException as e:
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise BridgeError(f"{what} to {_host(url)} failed")


# ---------------------------------------------------------------- XML

def _parse_xml(body: bytes, what: str) -> ET.Element:
    """Parses a Qualys XML answer. Qualys's answers declare no entities, so a document that does is
    refused before parsing: entity expansion is how an XML answer can use up memory. ElementTree
    never fetches the DTD a DOCTYPE names, and skips the keep-alive comments Qualys sends."""
    if b"<!ENTITY" in body:
        raise BridgeError(f"{what} returned XML that declares entities, which the bridge refuses")
    try:
        return ET.fromstring(body)
    except ET.ParseError:
        raise BridgeError(f"{what} returned a body that is not XML") from None


def _text(el: ET.Element | None) -> str | None:
    if el is None:
        return None
    return (el.text or "").strip()


def _qualys_error(body: bytes) -> tuple[str | None, str]:
    """Qualys answers an error with <SIMPLE_RETURN><RESPONSE><CODE> and <TEXT>. Returns (code, text),
    or (None, "") when the body is something else."""
    if not body or b"SIMPLE_RETURN" not in body or b"<!ENTITY" in body:
        return None, ""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None, ""
    if root.tag != "SIMPLE_RETURN":
        return None, ""
    return _text(root.find("RESPONSE/CODE")), (_text(root.find("RESPONSE/TEXT")) or "")[:200]


def to_json(el: ET.Element):
    """One XML element as JSON, by these rules: an element with only text is its text; an element
    with attributes is {"value": its text, and each attribute}; an element whose children all carry
    a name attribute and only text, such as QDS_FACTORS, is {name: text}; a *_LIST element and the
    other list elements are an array of their children; any other element is an object of its
    children, with a child that repeats as an array."""
    children = list(el)
    listed = el.tag.endswith("_LIST") or el.tag in LIST_ELEMENTS
    if not children and listed:
        return []
    if not children:
        text = (el.text or "").strip()
        if el.attrib:
            return {"value": text, **el.attrib}
        return text
    if all("name" in c.attrib and not list(c) for c in children):
        return {c.attrib["name"]: (c.text or "").strip() for c in children}
    if listed:
        return [to_json(c) for c in children]
    out: dict = {}
    repeated = set()
    for c in children:
        value = to_json(c)
        if c.tag not in out:
            out[c.tag] = value
            continue
        if c.tag not in repeated:
            out[c.tag] = [out[c.tag]]
            repeated.add(c.tag)
        out[c.tag].append(value)
    return out


def kb_entry(vuln: ET.Element) -> dict:
    """The KnowledgeBase fields the record carries for one QID, in Qualys's names."""
    out = {}
    for name in ("TITLE", "VULN_TYPE", "SEVERITY_LEVEL", "CATEGORY", "PUBLISHED_DATETIME", "PATCHABLE"):
        value = _text(vuln.find(name))
        if value:
            out[name] = value
    cves = [_text(c) for c in vuln.findall("CVE_LIST/CVE/ID")]
    if cves:
        out["CVE_LIST"] = [c for c in cves if c]
    for block in ("CVSS", "CVSS_V3"):
        scores = {k: _text(vuln.find(f"{block}/{k}")) for k in ("BASE", "TEMPORAL", "VECTOR_STRING")}
        scores = {k: v for k, v in scores.items() if v}
        if scores:
            out[block] = scores
    threats = [_text(t) for t in vuln.findall("THREAT_INTELLIGENCE/THREAT_INTEL")]
    if threats:
        out["THREAT_INTELLIGENCE"] = [t for t in threats if t]
    return out


# ---------------------------------------------------------------- Qualys

def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime(TIME_FORMAT)


class Qualys:
    """Calls the Host List Detection and KnowledgeBase APIs with basic authentication. Every
    request carries the X-Requested-With header Qualys requires, and the parameters go in a form
    body, so no proxy or server log keeps them."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        auth = base64.b64encode(f"{cfg['username']}:{cfg['password']}".encode("utf-8")).decode("ascii")
        self._headers = {"Authorization": f"Basic {auth}", "X-Requested-With": USER_AGENT,
                         "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/xml"}
        self.kb_cache: dict = {}

    def _call(self, path: str, params: dict, what: str) -> ET.Element:
        url = self.cfg["api_url"] + path
        body = urllib.parse.urlencode(params).encode("ascii")
        try:
            _, raw = _request("POST", url, self._headers, body, self.cfg["timeout"], what)
        except HttpStatus as e:
            code, text = _qualys_error(e.body)
            detail = f"HTTP {e.code}" + (f", code {code}: {text}" if code else "")
            if e.code == 401:
                raise BridgeError(f"Qualys refused the user name or password ({detail}); check QUALYS_USERNAME and "
                                  "QUALYS_PASSWORD, and that the user has API access") from None
            if e.code in (400, 403, 409) and not isinstance(e, RetriedStatus):
                hint = ""
                if e.code == 403:
                    hint = ("; the subscription may not allow KnowledgeBase downloads, so set QUALYS_KB=0"
                            if path == KB_PATH else "; the user needs API access and permission to read the hosts")
                raise BridgeError(f"Qualys refused the {what} ({detail}){hint}") from None
            raise
        root = _parse_xml(raw, what)
        if root.tag == "SIMPLE_RETURN":
            # An MSP user's errors come with HTTP 200, so the body says what happened.
            code, text = _qualys_error(raw)
            if code in LIMIT_CODES:
                raise NetworkError(f"Qualys's API limits held the {what} (code {code}); the next run tries again")
            raise BridgeError(f"Qualys refused the {what} (code {code or 'unknown'}: {text or 'no message'})")
        return root

    def detections(self, since: str, before: str, id_min: str | None) -> tuple[list[ET.Element], str | None]:
        """One page of hosts with the detections whose status changed from since to before, and the
        id_min of the next page, or None on the last one."""
        params = {"action": "list", "output_format": "XML", "status": STATUSES,
                  "detection_updated_since": since, "detection_updated_before": before,
                  "truncation_limit": str(self.cfg["page_hosts"]), "show_asset_id": "1",
                  "show_qds": "1" if self.cfg["show_qds"] else "0",
                  "show_results": "1" if self.cfg["show_results"] else "0",
                  "show_igs": "1" if self.cfg["show_igs"] else "0"}
        if self.cfg["severities"]:
            params["severities"] = self.cfg["severities"]
        if id_min:
            params["id_min"] = id_min
        root = self._call(DETECTION_PATH, params, "detection request")
        if root.tag != "HOST_LIST_VM_DETECTION_OUTPUT" or root.find("RESPONSE") is None:
            raise BridgeError(f"the detection request returned XML that is not a host detection list ({root.tag})")
        hosts = root.findall("RESPONSE/HOST_LIST/HOST")
        warning = root.find("RESPONSE/WARNING")
        if warning is None:
            return hosts, None
        url = _text(warning.find("URL")) or ""
        # The next page's URL names the same request with id_min. The bridge reads only id_min from
        # it and sends the next request itself, so the credentials go only to QUALYS_API_URL.
        m = re.search(r"[?&]id_min=(\d+)(?:&|$)", url)
        if _text(warning.find("CODE")) != "1980" or not m:
            raise BridgeError(f"the detection request returned a warning the bridge can't page with "
                              f"(code {_text(warning.find('CODE')) or 'none'})")
        if id_min and int(m.group(1)) <= int(id_min):
            raise BridgeError("the detection request's next page starts where the last one did, so the bridge stops")
        return hosts, m.group(1)

    def knowledge(self, qids: list[str]) -> dict:
        """The KnowledgeBase entry of each QID, read once and kept while the bridge runs."""
        wanted = sorted({q for q in qids if q and q not in self.kb_cache}, key=int)
        for i in range(0, len(wanted), KB_BATCH):
            chunk = wanted[i:i + KB_BATCH]
            root = self._call(KB_PATH, {"action": "list", "details": "All", "ids": ",".join(chunk)},
                              "KnowledgeBase request")
            if root.tag != "KNOWLEDGE_BASE_VULN_LIST_OUTPUT":
                raise BridgeError(f"the KnowledgeBase request returned XML that is not a vulnerability list ({root.tag})")
            if len(self.kb_cache) + len(chunk) > KB_CACHE_MAX:
                self.kb_cache.clear()
            found = {}
            for vuln in root.findall("RESPONSE/VULN_LIST/VULN"):
                qid = _text(vuln.find("QID"))
                if qid:
                    found[qid] = kb_entry(vuln)
            # A QID the KnowledgeBase doesn't return is remembered as missing, so it isn't asked for again.
            for qid in chunk:
                self.kb_cache[qid] = found.get(qid)
        return {q: self.kb_cache.get(q) for q in qids}


# ---------------------------------------------------------------- HTTP Ingest

class Sink:
    """Batches records as NDJSON and posts them to HTTP Ingest, or prints them in dry-run."""

    def __init__(self, cfg: dict, dry_run: bool, out=None):
        self.cfg, self.dry_run = cfg, dry_run
        self.out = out or sys.stdout
        self.sent = 0
        self.batches = 0
        if not dry_run and not (cfg["ingest_url"] and cfg["ingest_key"]):
            raise BridgeError("NGSIEM_INGEST_URL and NGSIEM_INGEST_KEY are required unless --dry-run is set")

    def send(self, records: list[dict]) -> None:
        batch, size = [], 0
        for rec in records:
            line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
            n = len(line.encode("utf-8")) + 1
            if batch and size + n > self.cfg["batch_bytes"]:
                self._post(batch)
                batch, size = [], 0
            batch.append(line)
            size += n
        if batch:
            self._post(batch)

    def _post(self, lines: list[str]) -> None:
        body = ("\n".join(lines) + "\n").encode("utf-8")
        if self.dry_run:
            self.out.write(body.decode("utf-8"))
            self.out.flush()
        else:
            headers = {"Authorization": f"Bearer {self.cfg['ingest_key']}", "Content-Type": "application/json"}
            if self.cfg["gzip"]:
                body = gzip.compress(body)
                headers["Content-Encoding"] = "gzip"
            _request("POST", self.cfg["ingest_url"], headers, body, self.cfg["timeout"], "HTTP Ingest POST")
        self.sent += len(lines)
        self.batches += 1


# ---------------------------------------------------------------- collection

_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")


def _seconds(value) -> int | None:
    """A Qualys time, such as 2026-10-14T03:12:45Z, in seconds since the epoch. Qualys gives UTC to
    the second. Parsed by hand, so it reads the same on Python 3.9 to 3.13."""
    m = _TIME.fullmatch(str(value or "").strip())
    if not m:
        return None
    try:
        moment = datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None
    return calendar.timegm(moment.utctimetuple())


def _key(host: dict, det: dict) -> str:
    """Names one status of one detection: the host, the detection (Qualys says the unique
    vulnerability ID and the QID together are unique) and when its status last changed."""
    return "|".join(str(x or "") for x in (host.get("ID"), det.get("UNIQUE_VULN_ID"), det.get("QID"),
                                            det.get("LAST_UPDATE_DATETIME")))


def records_of(hosts: list[ET.Element], cfg: dict) -> list[tuple[dict, dict]]:
    """Each detection of each host as (host, detection), in the order Qualys returned them."""
    out = []
    for host_el in hosts:
        dets = host_el.findall("DETECTION_LIST/DETECTION")
        host = {}
        for child in host_el:
            if child.tag != "DETECTION_LIST":
                host[child.tag] = to_json(child)
        for det_el in dets:
            out.append((host, to_json(det_el)))
    return out


def build(host: dict, det: dict, kb: dict | None, cfg: dict) -> dict:
    rec = {RECORD_KEY: "detection", PLATFORM_KEY: cfg["platform"], "HOST": host, "DETECTION": det}
    if kb:
        rec["KB"] = kb
    return rec


def collect(cfg: dict, state: dict, sink: Sink, save, client: Qualys, now: int) -> int:
    """Reads the detections whose status changed from where the last window ended to
    BRIDGE_DELAY_SECONDS before now, a page of hosts at a time. A window left partway (a run that
    stopped after some pages) goes on from the next page, with the same end. The saved position
    only moves after HTTP Ingest accepted a page."""
    key = f"{cfg['username']}@{cfg['platform']}"
    cur = state.setdefault(key, {})
    pending = cur.get("pending") if isinstance(cur.get("pending"), dict) else None
    cursor = _seconds(cur.get("cursor"))
    if pending and _seconds(pending.get("end")) is not None and _seconds(pending.get("since")) is not None:
        # The same window, from the next page: its since and end stay as they were.
        start, end = _seconds(pending["since"]), _seconds(pending["end"])
        id_min = str(pending.get("id_min") or "") or None
        edge = {x for x in (pending.get("edge") or []) if isinstance(x, str)}
    else:
        end = now - cfg["delay_seconds"]
        start = cursor if cursor is not None else now - int(cfg["lookback_hours"] * 3600)
        id_min, edge = None, set()
    # A saved position later than the window's end (the clock went back) counts as the end.
    start = min(start, end)
    boundary = {x for x in (cur.get("boundary") or []) if isinstance(x, str)}
    if start >= end:
        LOG.info("detections: no new window yet")
        return 0
    since, before = _when(start), _when(end)
    sent = 0
    for _ in range(MAX_PAGES):
        hosts, next_id = client.detections(since, before, id_min)
        pairs = [(h, d) for h, d in records_of(hosts, cfg) if _key(h, d) not in boundary]
        kb = client.knowledge([str(d.get("QID") or "") for _, d in pairs]) if cfg["kb"] and pairs else {}
        fresh = [build(h, d, kb.get(str(d.get("QID") or "")), cfg) for h, d in pairs]
        if fresh:
            sink.send(fresh)
            sent += len(fresh)
        # A detection whose status changed at the window's end may come back in the next window, if
        # Qualys counts both bounds in, so its key is kept to skip it there.
        edge |= {_key(h, d) for h, d in pairs if _seconds(d.get("LAST_UPDATE_DATETIME")) == end}
        if next_id:
            id_min = next_id
            cur["pending"] = {"since": since, "end": before, "id_min": id_min, "edge": sorted(edge)}
            save()
            continue
        cur.pop("pending", None)
        cur.update({"cursor": before, "boundary": sorted(edge)})
        save()
        break
    else:
        LOG.warning("detections: stopped after %d pages; the next run goes on from there", MAX_PAGES)
    LOG.info("detections: %d sent", sent)
    return sent


# ---------------------------------------------------------------- state and main

def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def save_state(path: str, state: dict) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=folder)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh, separators=(",", ":"))
    os.replace(tmp, path)


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Qualys | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or Qualys(cfg)
    count = collect(cfg, state, sink, save, client, int(time.time()))
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Qualys VMDR detections to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=_env(dict(os.environ), "BRIDGE_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    if args.interval < 0:
        ap.error("--interval must be 0 or more")
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "BRIDGE_DRY_RUN", False)
    try:
        cfg = load_config()
        # One client for the life of the bridge, so the KnowledgeBase entries it read stay cached.
        client = Qualys(cfg)
        worked = False
        while True:
            try:
                run_once(cfg, dry_run, client=client)
                worked = True
            except NetworkError as e:
                # A host name that doesn't resolve before any run has worked is most likely a
                # mistyped URL, so it stops the bridge.
                if not args.interval or (isinstance(e, HostNotFound) and not worked):
                    raise
                LOG.error("%s; trying again in %d seconds", e, args.interval)
            except BridgeError:
                raise
            except Exception as e:
                if not args.interval:
                    raise
                LOG.error("the run failed with an unexpected %s at %s; trying again in %d seconds",
                          type(e).__name__, _where(e), args.interval)
            if not args.interval:
                return 0
            time.sleep(args.interval)
    except BridgeError as e:
        LOG.error("%s", e)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
