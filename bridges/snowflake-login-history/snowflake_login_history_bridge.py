#!/usr/bin/env python3
"""Pull Snowflake login history with the Snowflake SQL API and send it to a Sophos NG-SIEM HTTP
Ingest integration, one JSON record per login attempt. Python 3 standard library only.

Snowflake records every login attempt, failed or successful, in the Account Usage view
SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY, kept for a year and filled with up to two hours of latency.
Snowflake has no push for it, so this script runs one query for each new window:

  POST https://{account}.snowflakecomputing.com/api/v2/statements
  GET  https://{account}.snowflakecomputing.com/api/v2/statements/{statementHandle}[?partition=N]

with a programmatic access token for a service user whose role reads only the security views (the
SNOWFLAKE.SECURITY_VIEWER database role) and uses one warehouse.

Each row goes on as an object keyed by column name, with "snowflake_record" first ("login_history")
and the account name, so the library parser in parsers/snowflake/login-history can normalize it.
Values stay the strings the SQL API returns, so IDs keep every digit; EVENT_TIMESTAMP becomes an
RFC 3339 time in UTC.

The request and response shapes follow Snowflake's SQL API reference. Configuration comes from
environment variables (see README.md). The saved position only moves after HTTP Ingest accepted
every record before it. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
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
import zlib
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("snowflake_login_history_bridge")
USER_AGENT = f"parser-studio-snowflake-login-history-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
# A result partition arrives gzip compressed, and the cap applies before and after it is unpacked.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 10000
MAX_PAGE_SIZE = 100000
RECORD_KEY = "snowflake_record"
ACCOUNT_KEY = "snowflake_account"
STATEMENTS_PATH = "/api/v2/statements"
# Snowflake keeps LOGIN_HISTORY for a year.
RETENTION_DAYS = 365
NS = 1_000_000_000
# How much longer than the statement's own timeout the bridge waits for it before cancelling it.
POLL_GRACE_SECONDS = 30
# The longest wait between two checks on a statement that is still running.
MAX_POLL_SECONDS = 5.0
# Snowflake's code for a statement that reached its timeout and was cancelled.
TIMEOUT_CODE = "000630"
# Snowflake's code for a result set too large to return whole.
TOO_LARGE_CODE = "391908"
# One page of login attempts after a position (time, then EVENT_ID), oldest first. The bounds are
# bind variables, so the statement never changes and nothing from a saved file reaches the SQL.
STATEMENT = ("SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
             "WHERE EVENT_TIMESTAMP < ? AND (EVENT_TIMESTAMP > ? OR (EVENT_TIMESTAMP = ? AND EVENT_ID > ?)) "
             "ORDER BY EVENT_TIMESTAMP, EVENT_ID LIMIT {limit}")


class BridgeError(Exception):
    """A failure that stops the run without moving a window past unsent data."""


class NetworkError(BridgeError):
    """Snowflake or HTTP Ingest couldn't be reached, even after the retries, or a query didn't
    finish in time. With --interval the bridge logs it and tries again at the next interval."""


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


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "account_url": (_env(env, "SNOWFLAKE_ACCOUNT_URL") or "").rstrip("/"),
        "token": _env(env, "SNOWFLAKE_TOKEN"),
        "warehouse": _env(env, "SNOWFLAKE_WAREHOUSE"),
        "role": _env(env, "SNOWFLAKE_ROLE"),
        "page_size": _number(env, "SNOWFLAKE_PAGE_SIZE", "10000", low=1, high=MAX_PAGE_SIZE),
        "query_timeout": _number(env, "SNOWFLAKE_QUERY_TIMEOUT", "300", low=1, high=3600),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "snowflake_login_history_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=RETENTION_DAYS * 24),
        "delay_seconds": _number(env, "BRIDGE_DELAY_SECONDS", "10800", high=86400),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
    }
    if not cfg["account_url"]:
        raise BridgeError("SNOWFLAKE_ACCOUNT_URL is required: the account URL, such as "
                          "https://myorg-myaccount.snowflakecomputing.com")
    _refuse_user_info(cfg["account_url"], "SNOWFLAKE_ACCOUNT_URL")
    _require_https(cfg["account_url"], "SNOWFLAKE_ACCOUNT_URL")
    parts = urllib.parse.urlsplit(cfg["account_url"])
    if parts.path or parts.query or parts.fragment or not parts.hostname:
        raise BridgeError("SNOWFLAKE_ACCOUNT_URL must be the account's address with no path, such as "
                          "https://myorg-myaccount.snowflakecomputing.com")
    # The account is the first label of the host name, as in myorg-myaccount.snowflakecomputing.com.
    cfg["account"] = parts.hostname.split(".")[0]
    if not cfg["token"]:
        raise BridgeError("SNOWFLAKE_TOKEN is required: a programmatic access token for the bridge's user")
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
    """A 408, 429, 500, 502, 503 or 504 that outlasted the retries. It is a NetworkError too, so with --interval
    the bridge logs it and tries again at the next interval."""


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


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, body)."""
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
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After") if e.headers else None)
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            if e.code in RETRY_STATUS:
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


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise BridgeError(f"{what} returned a body that is not JSON") from None


def _sf_error(body: bytes) -> tuple[str, str]:
    """Snowflake answers an error with {"code", "message", "sqlState", "statementHandle"}. Returns
    the code and a short message."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "", "no message"
    if not isinstance(data, dict):
        return "", "no message"
    code = data.get("code")
    code = str(code) if isinstance(code, (str, int)) and not isinstance(code, bool) else ""
    return code[:20], str(data.get("message") or "")[:300] or "no message"


# ---------------------------------------------------------------- Snowflake

_HANDLE = re.compile(r"[0-9A-Za-z-]{8,64}")


class Snowflake:
    """Runs statements with the SQL API. Every request carries the programmatic access token as
    'Authorization: Bearer'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _call(self, method: str, url: str, body: bytes | None, what: str) -> tuple[int, bytes]:
        headers = {"Authorization": f"Bearer {self.cfg['token']}",
                   "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
                   "Accept": "application/json", "Content-Type": "application/json"}
        try:
            return _request(method, url, headers, body, self.cfg["timeout"], what)
        except HttpStatus as e:
            code, message = _sf_error(e.body)
            if e.code == 401:
                # Snowflake's message for a refused token can show part of the token, so only its
                # code is given.
                raise BridgeError(f"Snowflake refused the token on the {what} (HTTP 401{', code ' + code if code else ''}); "
                                  "check SNOWFLAKE_TOKEN, that it hasn't expired, and that the bridge's user is under a "
                                  "network policy that allows this machine's address") from None
            if e.code == 422 and code == TIMEOUT_CODE:
                raise NetworkError(f"the query reached its timeout of {self.cfg['query_timeout']} seconds in Snowflake and "
                                   "was cancelled; the next run tries the same window again") from None
            if e.code in (400, 403, 404, 422):
                raise BridgeError(f"Snowflake refused the {what} (HTTP {e.code}{', code ' + code if code else ''}): "
                                  f"{message}") from None
            raise

    def _answer(self, raw: bytes, what: str) -> dict:
        data = _json(raw, what)
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
        return data

    def _url(self, handle, suffix: str = "") -> str:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BridgeError("Snowflake's answer has no statement handle the bridge can use")
        return f"{self.cfg['account_url']}{STATEMENTS_PATH}/{handle}{suffix}"

    def _cancel(self, handle: str) -> None:
        try:
            self._call("POST", self._url(handle, "/cancel"), b"", "statement cancel")
        except BridgeError as e:
            LOG.warning("couldn't cancel the statement: %s", e)

    def query(self, start_ns: int, start_id: str | None, end_ns: int, limit: int) -> list[tuple[dict, int, str]]:
        """Runs one page of the query and returns its rows, from every partition of the result, as
        (record, time in nanoseconds, EVENT_ID). A statement that is still running is checked
        until it finishes, for up to SNOWFLAKE_QUERY_TIMEOUT seconds and a little more; past that
        it is cancelled and the run ends with a NetworkError, so the window stays where it was."""
        body = {"statement": STATEMENT.format(limit=int(limit)), "timeout": int(self.cfg["query_timeout"]),
                "bindings": {"1": {"type": "TIMESTAMP_LTZ", "value": str(int(end_ns))},
                             "2": {"type": "TIMESTAMP_LTZ", "value": str(int(start_ns))},
                             "3": {"type": "TIMESTAMP_LTZ", "value": str(int(start_ns))},
                             # No EVENT_ID yet means every login at the start time: IDs are above -1.
                             "4": {"type": "FIXED", "value": start_id or "-1"}}}
        for key in ("warehouse", "role"):
            if self.cfg[key]:
                body[key] = self.cfg[key]
        deadline = time.monotonic() + self.cfg["query_timeout"] + POLL_GRACE_SECONDS
        status, raw = self._call("POST", f"{self.cfg['account_url']}{STATEMENTS_PATH}",
                                 json.dumps(body).encode("utf-8"), "query request")
        checks = 0
        while status == 202:
            # Still running: Snowflake answers with the statement's handle, to check on it.
            handle = self._answer(raw, "query status").get("statementHandle")
            url = self._url(handle)
            if time.monotonic() >= deadline:
                self._cancel(handle)
                raise NetworkError(f"the query didn't finish within {self.cfg['query_timeout'] + POLL_GRACE_SECONDS} "
                                   "seconds, so it was cancelled; the next run tries the same window again")
            time.sleep(min(MAX_POLL_SECONDS, 0.5 * 2 ** checks))
            checks += 1
            status, raw = self._call("GET", url, None, "query status")
        if status != 200:
            raise BridgeError(f"the query request answered HTTP {status}, which the bridge doesn't expect")
        return self._rows(self._answer(raw, "query result"))

    def _rows(self, result: dict) -> list[tuple[dict, int, str]]:
        if str(result.get("code") or "") == TOO_LARGE_CODE:
            raise BridgeError("Snowflake said the result was too large to return whole; lower SNOWFLAKE_PAGE_SIZE")
        meta = result.get("resultSetMetaData")
        columns = meta.get("rowType") if isinstance(meta, dict) else None
        if not isinstance(columns, list) or not all(isinstance(c, dict) and isinstance(c.get("name"), str) for c in columns):
            raise BridgeError("the query succeeded but its answer has no column list")
        names = [c["name"] for c in columns]
        kinds = [str(c.get("type") or "").lower() for c in columns]
        if "EVENT_TIMESTAMP" not in names or "EVENT_ID" not in names:
            raise BridgeError("the query's answer has no EVENT_TIMESTAMP or EVENT_ID column")
        at, ids = names.index("EVENT_TIMESTAMP"), names.index("EVENT_ID")
        partitions = meta.get("partitionInfo")
        if not isinstance(partitions, list) or not partitions:
            partitions = [{}]
        rows = []
        for index, info in enumerate(partitions):
            if index == 0:
                data = result.get("data")
            else:
                data = self._partition(self._call("GET", self._url(result.get("statementHandle"), f"?partition={index}"),
                                                  None, "result partition")[1])
            if not isinstance(data, list) or not all(isinstance(r, list) and len(r) == len(names) for r in data):
                raise BridgeError(f"partition {index} of the result isn't a list of rows with {len(names)} columns")
            expected = info.get("rowCount") if isinstance(info, dict) else None
            if isinstance(expected, int) and not isinstance(expected, bool) and expected != len(data):
                raise BridgeError(f"partition {index} of the result has {len(data)} rows, but Snowflake said {expected}")
            for row in data:
                ns, eid = _epoch_ns(row[at]), row[ids]
                if ns is None or not isinstance(eid, str) or not _DIGITS.fullmatch(eid):
                    raise BridgeError("a login record has no EVENT_TIMESTAMP or EVENT_ID the bridge can read, so the "
                                      "window can't move past it")
                rows.append(({name: _value(kind, value) for name, kind, value in zip(names, kinds, row)}, ns, eid))
        total = meta.get("numRows")
        if isinstance(total, int) and not isinstance(total, bool) and total != len(rows):
            raise BridgeError(f"the result has {len(rows)} rows, but Snowflake said {total}")
        return rows

    def _partition(self, raw: bytes):
        """A partition after the first arrives gzip compressed and holds only its rows, as
        {"data": [...]}. It is unpacked to no more than the response cap."""
        if raw[:2] == b"\x1f\x8b":
            unpack = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                out = unpack.decompress(raw, MAX_RESPONSE_BYTES + 1)
            except zlib.error:
                raise BridgeError("result partition sent gzip data the bridge couldn't unpack") from None
            if len(out) > MAX_RESPONSE_BYTES:
                raise BridgeError(f"result partition unpacks to more than {MAX_RESPONSE_BYTES // 1048576} MB, which the "
                                  "bridge refuses so a bad response can't use up memory")
            if not unpack.eof:
                raise BridgeError("result partition sent gzip data that ends partway")
            raw = out
        data = _json(raw, "result partition")
        return data.get("data") if isinstance(data, dict) else data


# ---------------------------------------------------------------- values and times

_EPOCH = re.compile(r"(-?\d{1,12})(?:\.(\d{1,9}))?")
_DIGITS = re.compile(r"\d{1,38}")


def _epoch_ns(text) -> int | None:
    """A TIMESTAMP_LTZ or TIMESTAMP_NTZ value as the SQL API returns it, seconds since the epoch with
    nine decimals ("1792040000.123000000"), in nanoseconds. Parsed by hand, so it keeps every digit."""
    if not isinstance(text, str):
        return None
    m = _EPOCH.fullmatch(text.strip())
    if not m:
        return None
    seconds, fraction = int(m.group(1)), int((m.group(2) or "").ljust(9, "0"))
    return seconds * NS + (-fraction if m.group(1).startswith("-") else fraction)


def _iso(ns: int) -> str:
    """RFC 3339 in UTC, to the millisecond or finer, such as 2026-10-14T16:12:44.123Z."""
    seconds, fraction = divmod(ns, NS)
    digits = f"{fraction:09d}".rstrip("0").ljust(3, "0")
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{digits}Z"


def _value(kind: str, value):
    """A column's value as the record carries it: TIMESTAMP_LTZ and TIMESTAMP_NTZ as RFC 3339 in UTC,
    everything else as the string (or null) the SQL API returned."""
    if isinstance(value, str) and kind in ("timestamp_ltz", "timestamp_ntz"):
        ns = _epoch_ns(value)
        return _iso(ns) if ns is not None else value
    return value


def tag(row: dict, cfg: dict) -> dict:
    out = {RECORD_KEY: "login_history", ACCOUNT_KEY: cfg["account"]}
    out.update({k: v for k, v in row.items() if k not in (RECORD_KEY, ACCOUNT_KEY)})
    return out


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

def collect(cfg: dict, state: dict, sink: Sink, save, client: Snowflake, now_ns: int) -> int:
    """Reads the login attempts from where the last run ended to BRIDGE_DELAY_SECONDS before now, a
    page at a time, oldest first. Each page starts after the last one's final row (its time, then
    its EVENT_ID), so no row is read twice. The saved position only moves after HTTP Ingest
    accepted a page."""
    cur = state.setdefault(cfg["account"], {})
    end = now_ns - cfg["delay_seconds"] * NS
    cursor = cur.get("cursor_ns")
    if isinstance(cursor, int) and not isinstance(cursor, bool):
        # A saved position later than the window's end (the clock went back) counts as the end.
        start = min(cursor, end)
        saved_id = cur.get("cursor_id")
        start_id = saved_id if start == cursor and isinstance(saved_id, str) and _DIGITS.fullmatch(saved_id) else None
    else:
        start = now_ns - int(cfg["lookback_hours"] * 3600) * NS
        start_id = None
    floor = now_ns - RETENTION_DAYS * 86400 * NS
    if start < floor:
        start, start_id = floor, None
    if start >= end:
        LOG.info("login history: no new window yet")
        return 0
    sent = 0
    limit = cfg["page_size"]
    for _ in range(MAX_PAGES):
        rows = client.query(start, start_id, end, limit)
        if rows:
            sink.send([tag(rec, cfg) for rec, _, _ in rows])
            sent += len(rows)
            _, start, start_id = rows[-1]
        if len(rows) < limit:
            cur.update({"cursor_ns": end, "cursor_id": None})
            save()
            break
        cur.update({"cursor_ns": start, "cursor_id": start_id})
        save()
    else:
        LOG.warning("login history: stopped after %d pages; the next run goes on from there", MAX_PAGES)
    LOG.info("login history: %d sent", sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    client = Snowflake(cfg)
    count = collect(cfg, state, sink, save, client, time.time_ns())
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
    ap = argparse.ArgumentParser(description="Send Snowflake login history to Sophos NG-SIEM HTTP Ingest.")
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
        worked = False
        while True:
            try:
                run_once(cfg, dry_run)
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
