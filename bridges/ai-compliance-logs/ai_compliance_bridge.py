#!/usr/bin/env python3
"""Pull OpenAI and Anthropic enterprise compliance logs and send them to a Sophos NG-SIEM
HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Sources:
  openai_clp     ChatGPT Enterprise Compliance Logs Platform (JSONL files, Admin API key)
  openai_audit   OpenAI API Platform audit logs (Admin API key)
  anthropic      Claude Compliance API Activity Feed (Compliance Access Key or Admin API key)

Configuration comes from environment variables (see README.md). Each source keeps a cursor in
the state file and only moves it after its records were accepted by HTTP Ingest. Content
redaction is on by default. --dry-run prints what would be sent and changes nothing.
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
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("ai_compliance_bridge")
USER_AGENT = f"parser-studio-ai-compliance-bridge/{__version__}"
REDACTED = "[redacted]"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# 501 and 505 say the server will never take the request as it is sent, so they aren't retried.
UNSUPPORTED_STATUS = {501: "the server doesn't support this request",
                      505: "the server doesn't support HTTP/1.1, the version the bridge uses"}
# _request refuses these unless told otherwise, so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
# A response body over this stops the run, so a broken or hostile endpoint can't use up memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# A signed log file download can be much larger than an API page, so it gets its own cap.
MAX_FILE_BYTES = 512 * 1024 * 1024
SEEN_LIMIT = 20000
RECORD_WARN_BYTES = 500_000


class BridgeError(Exception):
    """A failure that stops the run without moving any cursor past unsent data."""


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


def _csv(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "ai_compliance_state.json"),
        "redact": _flag(env, "BRIDGE_REDACT", True),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float, high=10 ** 6),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float, low=0.001),
        "openai_clp": {
            "key": _env(env, "OPENAI_COMPLIANCE_API_KEY"),
            "principal_id": _env(env, "OPENAI_CLP_PRINCIPAL_ID"),
            "event_types": _csv(_env(env, "OPENAI_CLP_EVENT_TYPES", "AUTH_LOG,AUDIT_LOG")),
            "base_url": _env(env, "OPENAI_CLP_BASE_URL", "https://api.chatgpt.com/v1").rstrip("/"),
        },
        "openai_audit": {
            "key": _env(env, "OPENAI_ADMIN_KEY"),
            "base_url": _env(env, "OPENAI_API_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        },
        "anthropic": {
            "key": _env(env, "ANTHROPIC_COMPLIANCE_KEY"),
            "base_url": _env(env, "ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/"),
            "version": _env(env, "ANTHROPIC_VERSION", "2023-06-01"),
            "activity_types": _csv(_env(env, "ANTHROPIC_ACTIVITY_TYPES")),
            "organization_ids": _csv(_env(env, "ANTHROPIC_ORGANIZATION_IDS")),
            "settle_seconds": _number(env, "ANTHROPIC_SETTLE_SECONDS", "60"),
        },
    }
    configured = [s for s in ("openai_clp", "openai_audit", "anthropic") if cfg[s]["key"]]
    cfg["sources"] = _csv(_env(env, "BRIDGE_SOURCES")) or configured
    for s in cfg["sources"]:
        if s not in ("openai_clp", "openai_audit", "anthropic"):
            raise BridgeError(f"unknown source in BRIDGE_SOURCES: {s}")
        if not cfg[s]["key"]:
            raise BridgeError(f"source {s} has no API key set")
    if "openai_clp" in cfg["sources"] and not cfg["openai_clp"]["principal_id"]:
        raise BridgeError("OPENAI_CLP_PRINCIPAL_ID (workspace ID, or org- ID) is required for openai_clp")
    for s in cfg["sources"]:
        _require_https(cfg[s]["base_url"], f"the {s} base URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


# ---------------------------------------------------------------- HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key to another URL, so it isn't followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_NO_REDIRECT = urllib.request.build_opener(_NoRedirect)


class _HttpsRedirect(urllib.request.HTTPRedirectHandler):
    """For the signed log file URL, which is a credential: follows a redirect only to https."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        try:
            _require_https(urllib.parse.urljoin(req.full_url, newurl), "a redirect from the signed file download")
        except BridgeError:
            fp.close()
            raise
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_HTTPS_REDIRECT = urllib.request.build_opener(_HttpsRedirect)


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


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float,
             redirects: str = "refuse", what: str = "request", limit: int | None = None):
    """Send a request, retrying 408, 429, 500, 502, 503 and 504 with backoff. Returns (status, headers, body).
    A redirect fails like any other status by default, so a key only goes to the configured host.
    redirects="return" hands a redirect to the caller instead, and "follow" follows one to https,
    for a request that carries no key: the signed file URL, which comes from the API, not a setting."""
    opener = _HTTPS_REDIRECT if redirects == "follow" else _NO_REDIRECT
    check = "" if redirects == "follow" else "; check the URL setting"
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers, _read(resp, what, url, limit)
        except urllib.error.HTTPError as e:
            redirect = e.code in (301, 302, 303, 307, 308) and redirects == "return"
            # Read what a redirect needs, then close the error response so its socket is released
            # now, not when the error is garbage collected. The code and headers stay readable.
            try:
                error_body = _read(e, what, url, limit) if redirect else b""
            except _NETWORK_ERRORS:
                # The body was cut short or timed out: the status still decides what happens.
                error_body = b""
            finally:
                e.close()
            if redirect:
                return e.code, e.headers, error_body
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers.get("Retry-After"))
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            if e.code in REDIRECT_STATUS and redirects == "refuse":
                raise BridgeError(f"{what} to {_host(url)} answered with a redirect (HTTP {e.code}), which the bridge "
                                     "refuses so the key never goes to another URL; check the URL setting") from None
            if e.code in RETRY_STATUS:
                # A NetworkError, so with --interval the bridge logs it and tries again at the next interval.
                raise NetworkError(f"{what} to {_host(url)} failed with HTTP {e.code}") from None
            if e.code in UNSUPPORTED_STATUS:
                raise BridgeError(f"{what} to {_host(url)} failed with HTTP {e.code}: {UNSUPPORTED_STATUS[e.code]}, "
                                  f"and a retry won't change that{check}") from None
            raise BridgeError(f"{what} to {_host(url)} failed with HTTP {e.code}") from None
        except _NETWORK_ERRORS as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            if isinstance(e, urllib.error.URLError) and isinstance(e.reason, socket.gaierror):
                if redirects == "follow":
                    raise HostNotFound(f"{what} to {_host(url)} failed: the host name in the signed URL the API "
                                       "redirected to wasn't found") from None
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


def _get_json(url: str, headers: dict, timeout: float, what: str):
    status, _, body = _request("GET", url, {**headers, "Accept": "application/json", "User-Agent": USER_AGENT},
                               None, timeout, what=what)
    try:
        return json.loads(body)
    except ValueError:
        raise BridgeError(f"{what} to {_host(url)} returned a body that is not JSON") from None


# ---------------------------------------------------------------- redaction

# Keys whose string values identify something rather than carry user content.
_KEEP_KEY = re.compile(r"(^|_)(id|ids|type|action|status|model|mode|result|privilege|provider|client_type|event_type)$|_at$|^timestamp$")


def _redact_tree(value, key: str | None = None):
    if isinstance(value, dict):
        return {k: _redact_tree(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_tree(v, key) for v in value]
    if isinstance(value, str) and value and not (key and _KEEP_KEY.search(key)):
        return REDACTED
    return value


_CLP_ENVELOPE = {"event_id", "type", "timestamp", "principal", "actor", "request_metadata"}
_CLP_AUDIT_TEXT = ("instructions", "system_instruction", "workspace_policy")


def redact_openai_clp(rec: dict) -> dict:
    """Remove prompt and response text from a Compliance Logs Platform record."""
    kind = rec.get("type")
    if kind == "AUTH_LOG":
        return rec
    if kind == "AUDIT_LOG":
        data = rec.get("action_data")
        if isinstance(data, dict):
            for k in _CLP_AUDIT_TEXT:
                if isinstance(data.get(k), str) and data[k]:
                    data[k] = REDACTED
        return rec
    if kind == "CONVERSATION_MESSAGE":
        msg = rec.get("message")
        if isinstance(msg, dict):
            if "content" in msg:
                msg["content"] = _redact_tree(msg["content"])
            if "files" in msg:
                msg["files"] = _redact_tree(msg["files"])
            author = msg.get("author")
            if isinstance(author, dict) and author.get("applied_custom_instructions"):
                author["applied_custom_instructions"] = REDACTED
        conv = rec.get("conversation")
        if isinstance(conv, dict) and conv.get("title"):
            conv["title"] = REDACTED
        return rec
    # Other log types (Codex, apps, plugins, agents) can carry prompts and output: keep the
    # envelope and IDs, redact every other string.
    return {k: (v if k in _CLP_ENVELOPE else _redact_tree(v, k)) for k, v in rec.items()}


def redact_anthropic(rec: dict) -> dict:
    """The Activity Feed carries no chat text; request_body and any title or name are cleared."""
    for k in ("request_body", "title", "description", "filename"):
        if isinstance(rec.get(k), str) and rec[k]:
            rec[k] = REDACTED
    return rec


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
        lines = []
        for rec in records:
            line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
            if len(line.encode("utf-8")) > RECORD_WARN_BYTES:
                LOG.warning("a record is over %d bytes; HTTP Ingest may split or truncate it", RECORD_WARN_BYTES)
            lines.append(line)
        batch, size = [], 0
        for line in lines:
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
            headers = {"Authorization": f"Bearer {self.cfg['ingest_key']}", "Content-Type": "application/json",
                       "User-Agent": USER_AGENT}
            if self.cfg["gzip"]:
                body = gzip.compress(body)
                headers["Content-Encoding"] = "gzip"
            _request("POST", self.cfg["ingest_url"], headers, body, self.cfg["timeout"], what="HTTP Ingest POST")
        self.sent += len(lines)
        self.batches += 1


# ---------------------------------------------------------------- helpers

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _parse_time(value: str) -> datetime:
    dt = _fromisoformat(value.strip())
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _remember(seen: list, ids: list) -> list:
    out = list(dict.fromkeys(list(seen) + list(ids)))
    return out[-SEEN_LIMIT:]


# ---------------------------------------------------------------- sources

def collect_openai_clp(cfg: dict, state: dict, sink: Sink, save) -> int:
    src = cfg["openai_clp"]
    pid = src["principal_id"]
    scope = "organizations" if pid.startswith("org-") else "workspaces"
    base = f"{src['base_url']}/compliance/{scope}/{urllib.parse.quote(pid, safe='')}/logs"
    auth = {"Authorization": f"Bearer {src['key']}"}
    st = state.setdefault("openai_clp", {})
    total = 0
    default_after = _iso(datetime.now(timezone.utc) - timedelta(hours=cfg["lookback_hours"]))
    for event_type in src["event_types"]:
        cur = st.setdefault(event_type, {"after": default_after, "seen": []})
        while True:
            q = urllib.parse.urlencode({"event_type": event_type, "after": cur["after"], "limit": 100})
            page = _get_json(f"{base}?{q}", auth, cfg["timeout"], f"list {event_type} files")
            for f in page.get("data") or []:
                records = _download_clp_file(f"{base}/{urllib.parse.quote(f['id'], safe='')}", auth, cfg["timeout"])
                seen = set(cur["seen"])
                fresh = [r for r in records if r.get("event_id") not in seen]
                if cfg["redact"]:
                    fresh = [redact_openai_clp(r) for r in fresh]
                if fresh:
                    sink.send(fresh)
                total += len(fresh)
                cur["seen"] = _remember(cur["seen"], [r.get("event_id") for r in records])
                cur["after"] = f["end_time"]
                save()
                LOG.info("openai_clp %s: file %s gave %d new records", event_type, f.get("file_name", "?"), len(fresh))
            if page.get("last_end_time"):
                cur["after"] = page["last_end_time"]
                save()
            if not page.get("has_more"):
                break
    return total


def _download_clp_file(url: str, auth: dict, timeout: float) -> list[dict]:
    status, headers, body = _request("GET", url, {**auth, "User-Agent": USER_AGENT}, None, timeout,
                                     redirects="return", what="download log file")
    if status in (301, 302, 303, 307, 308):
        location = headers.get("Location")
        if not location:
            raise BridgeError("log file download redirect has no Location")
        location = urllib.parse.urljoin(url, location)
        # The signed URL carries its own authorization: never send the API key to it, never log
        # it (its query string is a credential), and only fetch it over https.
        _require_https(location, "the log file's signed URL")
        _, _, body = _request("GET", location, {"User-Agent": USER_AGENT}, None, timeout, redirects="follow",
                              what="signed file download", limit=MAX_FILE_BYTES)
    out = []
    for line in body.decode("utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                raise BridgeError("a log file line is not JSON") from None
    return out


def collect_openai_audit(cfg: dict, state: dict, sink: Sink, save) -> int:
    src = cfg["openai_audit"]
    auth = {"Authorization": f"Bearer {src['key']}", "Content-Type": "application/json"}
    now = int(time.time())
    cur = state.setdefault("openai_audit", {"since": now - int(cfg["lookback_hours"] * 3600), "seen": []})
    gte = min(cur["since"], now) - cfg["overlap_seconds"]
    records, after = [], None
    while True:
        params = {"effective_at[gte]": gte, "limit": 100}
        if after:
            params["after"] = after
        page = _get_json(f"{src['base_url']}/organization/audit_logs?{urllib.parse.urlencode(params)}", auth,
                         cfg["timeout"], "list audit logs")
        records.extend(page.get("data") or [])
        after = page.get("last_id")
        if not page.get("has_more") or not after:
            break
    seen = set(cur["seen"])
    fresh = sorted((r for r in records if r.get("id") not in seen), key=lambda r: (r.get("effective_at", 0), r.get("id", "")))
    if fresh:
        sink.send(fresh)
    # A record dated in the future, from a wrong clock, mustn't move the cursor past now: the
    # next run would ask only for records after it.
    newest = min(max([r.get("effective_at", 0) for r in records] + [cur["since"]]), now)
    # The next run re-reads the overlap before `newest`; remember those ids to drop repeats.
    keep = [r["id"] for r in records if r.get("id") and r.get("effective_at", 0) >= newest - cfg["overlap_seconds"]]
    cur["seen"] = _remember([], keep)
    cur["since"] = newest
    save()
    LOG.info("openai_audit: %d new records", len(fresh))
    return len(fresh)


def collect_anthropic(cfg: dict, state: dict, sink: Sink, save) -> int:
    src = cfg["anthropic"]
    headers = {"x-api-key": src["key"], "anthropic-version": src["version"]}
    now = datetime.now(timezone.utc)
    cur = state.setdefault("anthropic", {"since": _iso(now - timedelta(hours=cfg["lookback_hours"])), "seen": []})
    # Window polling: stop short of the present so late-indexed activity is queryable, and
    # overlap the previous window; duplicates are dropped by activity id.
    lt = now - timedelta(seconds=src["settle_seconds"])
    gte = _parse_time(cur["since"]) - timedelta(seconds=cfg["overlap_seconds"])
    if lt <= gte:
        return 0
    seen = set(cur["seen"])
    window_ids, total, after = [], 0, None
    while True:
        params = [("created_at.gte", _iso(gte)), ("created_at.lt", _iso(lt)), ("order", "asc"), ("limit", "1000")]
        params += [("activity_types[]", t) for t in src["activity_types"]]
        params += [("organization_ids[]", o) for o in src["organization_ids"]]
        if after:
            params.append(("after_id", after))
        page = _get_json(f"{src['base_url']}/v1/compliance/activities?{urllib.parse.urlencode(params)}", headers,
                         cfg["timeout"], "list activities")
        data = page.get("data") or []
        window_ids.extend((r.get("id"), r.get("created_at")) for r in data)
        fresh = [r for r in data if r.get("id") not in seen]
        if cfg["redact"]:
            fresh = [redact_anthropic(r) for r in fresh]
        if fresh:
            sink.send(fresh)
        total += len(fresh)
        after = page.get("last_id")
        if not page.get("has_more") or not after:
            break
    cutoff = lt - timedelta(seconds=cfg["overlap_seconds"])
    keep = [i for i, ts in window_ids if i and ts and _parse_time(ts) >= cutoff]
    cur["seen"] = _remember([], keep)
    cur["since"] = _iso(lt)
    save()
    LOG.info("anthropic: %d new records", total)
    return total


SOURCES = {"openai_clp": collect_openai_clp, "openai_audit": collect_openai_audit, "anthropic": collect_anthropic}


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
        json.dump(state, fh, indent=1)
    os.replace(tmp, path)


def run_once(cfg: dict, dry_run: bool = False, out=None) -> dict:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    counts = {}
    for name in cfg["sources"]:
        counts[name] = SOURCES[name](cfg, state, sink, save)
    LOG.info("run finished: %s records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return counts


def _where(e: BaseException) -> str:
    """Where in this script an unexpected error came from: the line and function, never a value,
    so no key or record reaches the log."""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if os.path.basename(f.filename) == os.path.basename(__file__)]
    f = (mine or frames)[-1]
    return f"line {f.lineno} in {f.name}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send OpenAI and Anthropic compliance logs to Sophos NG-SIEM HTTP Ingest.")
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
        if not cfg["sources"]:
            raise BridgeError("no source configured: set OPENAI_COMPLIANCE_API_KEY, OPENAI_ADMIN_KEY or ANTHROPIC_COMPLIANCE_KEY")
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
