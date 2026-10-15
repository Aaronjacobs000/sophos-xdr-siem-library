#!/usr/bin/env python3
"""Pull Atlassian organization audit log events from the Atlassian Organizations REST API and send
them to a Sophos NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard
library only.

The organization audit log (Atlassian Guard, or a Cloud Enterprise plan) reaches other tools
through the Organizations REST API, which is pull only, so this script polls the events stream with
an organization admin API key and posts each event with "atlassian_record": "event" first, so the
library parsers in parsers/atlassian/atlassian-organization-audit-log can normalize it:

  GET https://api.atlassian.com/admin/v1/orgs/{orgId}/events-stream   (from, cursor, limit, sortOrder=asc)
  GET https://api.atlassian.com/admin/v1/orgs/{orgId}/event-actions   (the display name of each action)

The bridge also adds the organization ID, and the display name and group of the event's action
from the event actions list, since Atlassian doesn't publish its action keys.

The request and response shapes follow Atlassian's Organizations REST API reference and OpenAPI
document. Configuration comes from environment variables (see README.md). The cursor only moves
after HTTP Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
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
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("atlassian_org_audit_bridge")
USER_AGENT = f"parser-studio-atlassian-org-audit-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
MAX_PAGES = 10000
SEEN_LIMIT = 50000
RECORD_KEY = "atlassian_record"
ORG_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class BridgeError(Exception):
    """A failure that stops the run without moving the cursor past unsent data."""


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


def _number(env: dict, name: str, default: str, cast=int):
    value = _env(env, name, default)
    try:
        return cast(value)
    except ValueError:
        raise BridgeError(f"{name} must be a number") from None


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise BridgeError(f"{what} must be an https URL")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "ATLASSIAN_API_URL", "https://api.atlassian.com") or "").rstrip("/"),
        "api_key": _env(env, "ATLASSIAN_API_KEY"),
        "org_id": _env(env, "ATLASSIAN_ORG_ID"),
        "action_names": _flag(env, "ATLASSIAN_ACTION_NAMES", True),
        "page_limit": _number(env, "ATLASSIAN_PAGE_LIMIT", "500"),
        "state_file": _env(env, "BRIDGE_STATE_FILE", "atlassian_org_audit_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": _number(env, "BRIDGE_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "BRIDGE_LOOKBACK_HOURS", "24", float),
        "overlap_seconds": _number(env, "BRIDGE_OVERLAP_SECONDS", "300"),
        "timeout": _number(env, "BRIDGE_HTTP_TIMEOUT", "60", float),
    }
    if not cfg["api_key"]:
        raise BridgeError("ATLASSIAN_API_KEY is required")
    if not cfg["org_id"] or not ORG_ID.match(cfg["org_id"]):
        raise BridgeError("ATLASSIAN_ORG_ID is required: the organization ID from the Atlassian Administration URL")
    if not 1 <= cfg["page_limit"] <= 500:
        raise BridgeError("ATLASSIAN_PAGE_LIMIT must be from 1 to 500")
    if cfg["overlap_seconds"] < 0 or cfg["lookback_hours"] <= 0:
        raise BridgeError("BRIDGE_OVERLAP_SECONDS can't be negative and BRIDGE_LOOKBACK_HOURS must be above 0")
    _require_https(cfg["api_url"], "ATLASSIAN_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


def _retry_delay(attempt: int, headers) -> float:
    """Atlassian names the end of the rate limit period in X-RateLimit-Reset (ISO 8601, UTC).
    Retry-After is honored too, and anything else backs off."""
    reset = headers.get("X-RateLimit-Reset") if headers else None
    if reset:
        try:
            at = datetime.fromisoformat(reset.strip().replace("Z", "+00:00"))
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            return min(300.0, max(0.0, at.timestamp() - time.time()) + random.uniform(0, 1))
        except ValueError:
            pass
    retry_after = headers.get("Retry-After") if headers else None
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
        else:
            message = f"{what} to {_host(url)} failed with HTTP {code}"
        super().__init__(message)
        self.code = code
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Following a redirect would send the request's key or token to another URL, so it isn't
    followed: the redirect fails like any other status."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _request(method: str, url: str, headers: dict, body: bytes | None, timeout: float, what: str):
    """Send a request, retrying 408, 429 and 5xx with backoff. Returns (status, body)."""
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            # Read the body, then close the error response so its socket is released now, not
            # when the error is garbage collected.
            error_body = e.read()
            e.close()
            if e.code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, e.headers)
                LOG.warning("%s to %s returned %s; retrying in %.1fs", what, _host(url), e.code, delay)
                time.sleep(delay)
                continue
            raise HttpStatus(what, url, e.code, error_body) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, None)
                LOG.warning("%s to %s failed (%s); retrying in %.1fs", what, _host(url), type(e).__name__, delay)
                time.sleep(delay)
                continue
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
        except ValueError:
            # http.client puts a header value it refuses, such as a key with a line break in it,
            # in its error, so that error isn't passed on.
            raise BridgeError(f"{what} to {_host(url)} couldn't be sent: a key or token has a line break or "
                              "another character a request header can't carry") from None
        except http.client.HTTPException as e:
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise BridgeError(f"{what} to {_host(url)} failed")


def _errors(body: bytes) -> tuple[str, str]:
    """Atlassian answers {"errors": [{"code": "ADMIN-400-1", "title", "detail"}]} for 400, 404 and
    500, and {"code", "message"} for 401 and 429. Returns (code, short message)."""
    try:
        data = json.loads(body) or {}
    except ValueError:
        return "", "no message"
    if isinstance(data, dict) and isinstance(data.get("errors"), list) and data["errors"]:
        e = data["errors"][0] if isinstance(data["errors"][0], dict) else {}
        return str(e.get("code") or ""), str(e.get("detail") or e.get("title") or "")[:200] or "no message"
    if isinstance(data, dict):
        return str(data.get("code") or ""), str(data.get("message") or "")[:200] or "no message"
    return "", "no message"


class InvalidCursor(BridgeError):
    """Atlassian refused the saved cursor (ADMIN-400-1)."""


# ---------------------------------------------------------------- Atlassian Organizations REST API

class Atlassian:
    """Reads the Organizations REST API with 'Authorization: Bearer <API key>'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def get(self, path: str, params: dict, what: str) -> dict:
        query = urllib.parse.urlencode(params)
        url = f"{self.cfg['api_url']}/admin/v1/orgs/{urllib.parse.quote(self.cfg['org_id'], safe='')}{path}" + (f"?{query}" if query else "")
        headers = {"Authorization": f"Bearer {self.cfg['api_key']}", "Accept": "application/json"}
        try:
            _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
        except HttpStatus as e:
            code, message = _errors(e.body)
            if e.code == 400 and code == "ADMIN-400-1":
                raise InvalidCursor(f"Atlassian refused the saved cursor ({code})") from None
            if e.code == 400:
                raise BridgeError(f"Atlassian rejected {what} (HTTP 400 {code}): {message}") from None
            if e.code in (401, 403):
                raise BridgeError(f"Atlassian refused the API key for {what} (HTTP {e.code}); check ATLASSIAN_API_KEY, that it "
                                     "hasn't expired or been revoked, and that a key with scopes has read:events:admin") from None
            if e.code == 404:
                raise BridgeError(f"Atlassian answered {what} with HTTP 404 ({code or 'not found'}); check ATLASSIAN_ORG_ID") from None
            raise
        try:
            data = json.loads(raw)
        except ValueError:
            raise BridgeError(f"{what} returned a body that is not JSON") from None
        if not isinstance(data, dict):
            raise BridgeError(f"{what} returned JSON that is not an object")
        return data

    def action_names(self) -> dict:
        data = self.get("/event-actions", {}, "event actions request")
        names = {}
        for a in data.get("data") or []:
            if isinstance(a, dict) and a.get("id"):
                attrs = a.get("attributes") or {}
                names[str(a["id"])] = (attrs.get("displayName"), attrs.get("groupDisplayName"))
        return names


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

def _epoch(value) -> float | None:
    """time and processedAt are ISO 8601 in UTC with milliseconds, such as 2025-02-27T18:50:12.281Z."""
    try:
        return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def tag(event: dict, cfg: dict, names: dict) -> dict:
    rec = {RECORD_KEY: "event", "orgId": cfg["org_id"], **event}
    action = str(((event.get("attributes") or {}).get("action")) or "")
    name, group = names.get(action, (None, None))
    if name:
        rec["actionDisplayName"] = name
    if group:
        rec["actionGroup"] = group
    return rec


def collect_events(cfg: dict, state: dict, sink: Sink, save, client: Atlassian) -> int:
    """Poll the events stream: from the saved cursor, or from the lookback on the first run (or
    after Atlassian refuses the cursor, from the last event's time minus the overlap). Each page's
    new events are sent, then its cursor saved, until a page comes back empty or without a cursor."""
    cur = state.setdefault("events", {})
    seen = list(cur.get("seen") or [])
    seen_set = set(seen)
    names = None
    sent = 0

    def first_params() -> dict:
        since = cur.get("last_time")
        start = (since - cfg["overlap_seconds"]) if since else (time.time() - cfg["lookback_hours"] * 3600)
        return {"from": str(int(start * 1000)), "limit": cfg["page_limit"], "sortOrder": "asc"}

    params = {"cursor": cur["cursor"], "limit": cfg["page_limit"]} if cur.get("cursor") else first_params()
    restarted = False
    for _ in range(MAX_PAGES):
        try:
            data = client.get("/events-stream", params, "events stream request")
        except InvalidCursor:
            if restarted or "cursor" not in params:
                raise
            LOG.warning("Atlassian refused the saved cursor; reading again from the last event's time")
            restarted = True
            params = first_params()
            continue
        items = [e for e in data.get("data") or [] if isinstance(e, dict)]
        fresh = [e for e in items if str(e.get("id")) not in seen_set]
        if fresh:
            if names is None:
                names = client.action_names() if cfg["action_names"] else {}
            sink.send([tag(e, cfg, names) for e in fresh])
            for e in fresh:
                seen.append(str(e.get("id")))
                seen_set.add(str(e.get("id")))
            sent += len(fresh)
        times = [t for t in (_epoch((e.get("attributes") or {}).get("processedAt") or (e.get("attributes") or {}).get("time")) for e in items) if t]
        if times:
            cur["last_time"] = max([cur.get("last_time") or 0] + times)
        nxt = (data.get("meta") or {}).get("next")
        if nxt:
            cur["cursor"] = nxt
        cur["seen"] = seen[-SEEN_LIMIT:]
        save()
        if not items or not nxt:
            break
        params = {"cursor": nxt, "limit": cfg["page_limit"]}
    else:
        LOG.warning("stopped after %d pages; the next run continues from the saved cursor", MAX_PAGES)
    LOG.info("events: %d sent", sent)
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
        json.dump(state, fh, indent=1)
    os.replace(tmp, path)


def run_once(cfg: dict, dry_run: bool = False, out=None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    count = collect_events(cfg, state, sink, save, Atlassian(cfg))
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Atlassian organization audit log events to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=_env(dict(os.environ), "BRIDGE_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "BRIDGE_DRY_RUN", False)
    try:
        cfg = load_config()
        while True:
            run_once(cfg, dry_run)
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
