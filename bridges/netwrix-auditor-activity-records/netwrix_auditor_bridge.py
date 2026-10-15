#!/usr/bin/env python3
"""Pull Netwrix Auditor activity records from the Netwrix Auditor Integration API and send them to
a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Netwrix Auditor keeps its audit trail (Active Directory, Microsoft Entra ID, Exchange, Microsoft
365, file servers, Windows Server, SQL Server, logons and the other data sources it monitors) in
its Audit Database on the customer's own network, and the Integration API on Netwrix Auditor
Server is pull only. This script runs inside that network, signs in with a Windows account that
can review the activity records, and searches them by time:

  POST https://<Netwrix Auditor Server>:9699/netwrix/api/v1/activity_records/search?format=json&count=<n>

Each record goes out with "netwrix_auditor_record": "activity_record" first, then the record as
Netwrix returns it, so the library parser in parsers/netwrix/netwrix-auditor can recognize and
normalize it.

Each run searches from the end of its last window, less an overlap, to now, by When (the time of
the change), following the ContinuationMark, and drops records it already sent by their RID. The
request and response shapes follow Netwrix's Integration API reference. Configuration comes from
environment variables (see README.md). A window's end only moves after HTTP Ingest accepted every
record in it. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.client
import json
import logging
import os
import random
import socket
import ssl
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("netwrix_auditor_bridge")
USER_AGENT = f"parser-studio-netwrix-auditor-bridge/{__version__}"
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
RECORD_KEY = "netwrix_auditor_record"
SEARCH_PATH = "/netwrix/api/v1/activity_records/search"
# A window ends this long before now, so a clock a little ahead of Netwrix Auditor Server's never
# asks for the future.
END_MARGIN_SECONDS = 60
SEEN_LIMIT = 200000


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """The API or HTTP Ingest couldn't be reached, even after the retries. With --interval the
    bridge logs it and tries again at the next interval."""


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


def _list(env: dict, name: str, default: str = "") -> list[str]:
    return list(dict.fromkeys(x.strip() for x in (_env(env, name, default) or "").split(",") if x.strip()))


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "NETWRIX_API_URL") or "").rstrip("/"),
        "username": _env(env, "NETWRIX_USERNAME"),
        "password": _env(env, "NETWRIX_PASSWORD"),
        "ca_file": _env(env, "NETWRIX_CA_FILE"),
        "data_sources": _list(env, "NETWRIX_DATA_SOURCES"),
        "page_size": _number(env, "NETWRIX_PAGE_SIZE", "1000", low=1, high=5000),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "netwrix_auditor_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "120", float, low=0.001),
    }
    if not cfg["api_url"]:
        raise BridgeError("NETWRIX_API_URL is required: https://<Netwrix Auditor Server name>:9699, "
                          "with the name the server's certificate gives")
    parts = urllib.parse.urlsplit(cfg["api_url"])
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise BridgeError("NETWRIX_API_URL takes the scheme, host and port only, such as "
                          "https://nwxserver.corp.example.com:9699")
    if not cfg["username"] or not cfg["password"]:
        raise BridgeError("NETWRIX_USERNAME (DOMAIN\\user) and NETWRIX_PASSWORD are required")
    if any(c in cfg["username"] for c in ":\r\n"):
        raise BridgeError("NETWRIX_USERNAME can't contain a colon or a line break")
    if cfg["ca_file"] and not os.path.isfile(cfg["ca_file"]):
        raise BridgeError("NETWRIX_CA_FILE must be the path of a PEM file that holds the certificate to trust")
    if cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_LOOKBACK_HOURS must be above 0")
    _require_https(cfg["api_url"], "NETWRIX_API_URL")
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
    """A 408, 429, 500, 502, 503 or 504 that outlasted the retries. It is a NetworkError too, so with --interval
    the bridge logs it and tries again at the next interval."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def tls_opener(ca_file: str | None):
    """The opener for Netwrix Auditor Server. Netwrix's Integration API uses a self-signed certificate
    it generates unless you assign another, so NETWRIX_CA_FILE can name the certificate (or the CA
    that issued it) to trust. Certificates are always checked, and so is the host name."""
    if not ca_file:
        return _OPENER
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError, ValueError):
        raise BridgeError("NETWRIX_CA_FILE couldn't be read as a PEM certificate") from None
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))


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


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str, opener=None):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body)."""
    opener = opener or _OPENER
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=timeout) as resp:
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
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None)
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS:
                raise RetriedStatus(what, url, e.code, error_body) from None
            raise HttpStatus(what, url, e.code, error_body) from None
        except _NETWORK_ERRORS as e:
            # A certificate that fails the check is refused at once: a retry gets the same certificate.
            reason = getattr(e, "reason", None)
            if isinstance(e, ssl.SSLCertVerificationError) or isinstance(reason, ssl.SSLCertVerificationError):
                raise BridgeError(f"{what} to {_host(url)} failed: the server's certificate isn't trusted or doesn't "
                                  "name this host; for Netwrix Auditor Server, set NETWRIX_CA_FILE to its certificate "
                                  "and use the host name it gives") from None
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


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise BridgeError(f"{what} returned a body that is not JSON") from None


def _error_message(body: bytes) -> str:
    """Netwrix answers most errors with {"ErrorList": [{"Category", "Description", "Location"}]}, and
    some with an empty body. Keep the message short."""
    try:
        data = json.loads(body)
    except ValueError:
        return "no message"
    errors = data.get("ErrorList") if isinstance(data, dict) else None
    first = errors[0] if isinstance(errors, list) and errors and isinstance(errors[0], dict) else {}
    category, description = first.get("Category"), first.get("Description")
    text = f"{category}: {description}" if category and description else str(description or category or "")
    return text[:200] or "no message"


# ---------------------------------------------------------------- Netwrix Auditor Integration API

class Netwrix:
    """Calls the Integration API with the account in 'Authorization: Basic', over HTTPS. Netwrix
    lists NTLM, Negotiate, Digest and Basic; Python's standard library speaks only Basic."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.opener = tls_opener(cfg["ca_file"])
        token = base64.b64encode(f"{cfg['username']}:{cfg['password']}".encode("utf-8")).decode()
        self._auth = f"Basic {token}"

    def search(self, flt: dict, mark: str | None) -> dict:
        query = urllib.parse.urlencode({"format": "json", "count": self.cfg["page_size"]})
        url = f"{self.cfg['api_url']}{SEARCH_PATH}?{query}"
        body = {"FilterList": flt}
        if mark:
            body = {"ContinuationMark": mark, **body}
        headers = {"Authorization": self._auth, "Accept": "application/json",
                   "Content-Type": "application/json; charset=utf-8"}
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        what = "activity records search"
        try:
            _, raw = _request("POST", url, headers, data, self.cfg["timeout"], what, self.opener)
        except RetriedStatus as e:
            if e.code == 500:
                raise NetworkError(f"Netwrix Auditor answered the {what} with HTTP 500: {_error_message(e.body)}; "
                                   "Netwrix says this comes from an expired license, an unreachable Archive Service "
                                   "or an internal error") from None
            raise
        except HttpStatus as e:
            if e.code == 401:
                raise BridgeError(f"Netwrix Auditor refused the {what} (HTTP 401); check NETWRIX_USERNAME (DOMAIN\\user) "
                                  "and NETWRIX_PASSWORD, and that the Integration API accepts Basic authentication") from None
            if e.code == 403:
                raise BridgeError(f"Netwrix Auditor refused the {what} (HTTP 403): {_error_message(e.body)}; the account "
                                  "needs the Global reviewer role, or the Reviewer role on the monitoring plans to read") from None
            if e.code in (404, 405):
                raise BridgeError(f"Netwrix Auditor answered the {what} with HTTP {e.code}; check NETWRIX_API_URL and "
                                  "that Leverage Integration API is on under Settings > Integrations") from None
            if e.code == 400:
                raise BridgeError(f"Netwrix Auditor rejected the {what} (HTTP 400): {_error_message(e.body)}") from None
            raise
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
        return data


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

def _fromisoformat(text: str) -> datetime:
    """datetime.fromisoformat, the same on Python 3.9 to 3.13. Before 3.11 it takes no Z, only 3 or 6
    fraction digits and only +HH:MM offsets (no version takes z), so the text is rewritten first."""
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, rest = text.split(".", 1)
        # The fraction is the digits right after the point. An offset after them keeps its place.
        tail = rest.lstrip("0123456789")
        text = head + "." + (rest[:len(rest) - len(tail)] + "000000")[:6] + tail
    if text[-5:-4] in ("+", "-") and text[-4:].isdigit():
        text = text[:-2] + ":" + text[-2:]  # +1000 becomes +10:00
    return datetime.fromisoformat(text)


def _parse_time(value) -> float | None:
    """When is ISO 8601 in UTC (2017-02-14T15:42:34Z) or with an offset (+HH:mm or -HH:mm). A time
    without either is read as UTC."""
    v = str(value or "").strip()
    try:
        dt = _fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _netwrix_time(epoch: float) -> str:
    """The When filter takes YYYY-MM-DDTHH:mm:ssZ, in whole seconds."""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key(record: dict) -> str:
    """RID is the record's unique key in the Audit Database. A record without one is known by the hash
    of the whole record."""
    rid = record.get("RID")
    if isinstance(rid, str) and rid:
        return "rid:" + rid
    return "sha:" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _records(data: dict) -> list:
    """The records come in ActivityRecordList. Netwrix's docs also name the array ActivityRecordSearch
    for the pages after the first, so that name is read too."""
    for name in ("ActivityRecordList", "ActivityRecordSearch"):
        if name in data:
            rows = data[name]
            if rows is None:
                return []
            if not isinstance(rows, list):
                raise BridgeError(f"activity records search returned {name} that is not a list")
            return rows
    return []


def collect(cfg: dict, state: dict, sink: Sink, save, client: Netwrix, now: float) -> int:
    """Searches from the end of the last window, less the overlap, to now, by When, following the
    ContinuationMark, and sends the records not sent before. The window's end is saved only after
    every page of it was sent."""
    since = state.get("until")
    # A saved end later than now (the clock went back) counts as now.
    start = (min(since, now - END_MARGIN_SECONDS) - cfg["overlap_seconds"]) if isinstance(since, (int, float)) \
        else (now - cfg["lookback_hours"] * 3600)
    end = now - END_MARGIN_SECONDS
    start = min(start, end - 1)
    seen = {k: t for k, t in (state.get("seen") or {}).items() if isinstance(t, (int, float)) and t >= start - 60}
    state["seen"] = seen
    flt = {"When": {"From": _netwrix_time(start), "To": _netwrix_time(end)}}
    if cfg["data_sources"]:
        flt["DataSource"] = list(cfg["data_sources"])
    sent, mark = 0, None
    for _ in range(MAX_PAGES):
        data = client.search(flt, mark)
        records = _records(data)
        fresh = {}
        for r in records:
            if not isinstance(r, dict):
                continue
            k = _key(r)
            if k not in seen and k not in fresh:
                t = _parse_time(r.get("When"))
                fresh[k] = (t if t is not None else now, r)
        if fresh:
            sink.send([{RECORD_KEY: "activity_record", **r} for _, r in fresh.values()])
            # Only now that HTTP Ingest took them do they count as sent.
            seen.update({k: t for k, (t, _) in fresh.items()})
            if len(seen) > SEEN_LIMIT:
                state["seen"] = seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
            sent += len(fresh)
            save()
        mark = data.get("ContinuationMark")
        # The last page is the one with no records.
        if not records or not mark or not isinstance(mark, str):
            break
    else:
        LOG.warning("stopped after %d pages; the next run reads the same window again", MAX_PAGES)
        return sent
    state["until"] = end
    save()
    LOG.info("activity records: %d sent", sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Netwrix | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = client or Netwrix(cfg)
    count = collect(cfg, state, sink, save, client, time.time())
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
    ap = argparse.ArgumentParser(description="Send Netwrix Auditor activity records to Sophos NG-SIEM HTTP Ingest.")
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
        # One client for every run, so the certificate is read once.
        client = Netwrix(cfg)
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
