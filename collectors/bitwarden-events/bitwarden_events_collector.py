#!/usr/bin/env python3
"""Pull Bitwarden organization event logs from the Bitwarden Public API and send them to a Sophos
NG-SIEM HTTP Ingest integration, one JSON record per line. Python 3 standard library only.

Bitwarden offers its organization event logs to a SIEM only through the Public API, which is pull
only, so this script signs in with the organization's API key, reads the events by time window, and
posts each one with "bitwarden_record": "event" first, so the library parsers in
parsers/bitwarden/bitwarden-event-logs can normalize it:

  POST https://identity.bitwarden.com/connect/token   (client_credentials, scope api.organization)
  GET  https://api.bitwarden.com/public/events        (start, end, continuationToken)
  GET  https://api.bitwarden.com/public/members       (optional, for member emails and names)

An event names users and members only by ID, so the collector adds the organization ID from the
API key, and the email and name of the acting user and of the member from the member list.

The request and response shapes follow Bitwarden's Public API reference and OpenAPI document.
Configuration comes from environment variables (see README.md). The cursor only moves after HTTP
Ingest accepted the records. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
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
LOG = logging.getLogger("bitwarden_events_collector")
USER_AGENT = f"parser-studio-bitwarden-events-collector/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
MAX_PAGES = 20000
SEEN_LIMIT = 100000
RECORD_KEY = "bitwarden_record"
CLIENT_ID = re.compile(r"^organization\.([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")


class CollectorError(Exception):
    """A failure that stops the run without moving the cursor past unsent data."""


# ---------------------------------------------------------------- configuration

def _env(env: dict, name: str, default: str | None = None) -> str | None:
    value = env.get(name)
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
        raise CollectorError(f"{name} must be a number") from None


def _require_https(url: str, what: str) -> None:
    """Keys travel with every request, so only https is allowed (plain http to this machine is
    allowed for local testing)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise CollectorError(f"{what} must be an https URL")


def load_config(env: dict | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    cfg = {
        "ingest_url": _env(env, "NGSIEM_INGEST_URL"),
        "ingest_key": _env(env, "NGSIEM_INGEST_KEY"),
        "api_url": (_env(env, "BITWARDEN_API_URL", "https://api.bitwarden.com") or "").rstrip("/"),
        "identity_url": (_env(env, "BITWARDEN_IDENTITY_URL", "https://identity.bitwarden.com") or "").rstrip("/"),
        "client_id": _env(env, "BITWARDEN_CLIENT_ID"),
        "client_secret": _env(env, "BITWARDEN_CLIENT_SECRET"),
        "member_lookup": _flag(env, "BITWARDEN_MEMBER_LOOKUP", True),
        "state_file": _env(env, "COLLECTOR_STATE_FILE", "bitwarden_events_state.json"),
        "gzip": _flag(env, "COLLECTOR_GZIP", True),
        "batch_bytes": _number(env, "COLLECTOR_BATCH_BYTES", "100000"),
        "lookback_hours": _number(env, "COLLECTOR_LOOKBACK_HOURS", "24", float),
        "overlap_seconds": _number(env, "COLLECTOR_OVERLAP_SECONDS", "3600"),
        "timeout": _number(env, "COLLECTOR_HTTP_TIMEOUT", "60", float),
    }
    if not cfg["client_id"] or not cfg["client_secret"]:
        raise CollectorError("BITWARDEN_CLIENT_ID and BITWARDEN_CLIENT_SECRET are required")
    m = CLIENT_ID.match(cfg["client_id"])
    if not m:
        raise CollectorError("BITWARDEN_CLIENT_ID must be the organization API key's client_id, organization.<organization id>")
    cfg["organization_id"] = m.group(1).lower()
    if cfg["overlap_seconds"] < 0 or cfg["lookback_hours"] <= 0:
        raise CollectorError("COLLECTOR_OVERLAP_SECONDS can't be negative and COLLECTOR_LOOKBACK_HOURS must be above 0")
    if cfg["lookback_hours"] > 366 * 24:
        raise CollectorError("COLLECTOR_LOOKBACK_HOURS can be at most 8784 (366 days), the longest range the API accepts")
    _require_https(cfg["api_url"], "BITWARDEN_API_URL")
    _require_https(cfg["identity_url"], "BITWARDEN_IDENTITY_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
    return min(60.0, 2 ** attempt) + random.uniform(0, 1)


class HttpStatus(CollectorError):
    def __init__(self, what: str, url: str, code: int, body: bytes = b""):
        if code in REDIRECT_STATUS:
            message = (f"{what} to {_host(url)} answered with a redirect (HTTP {code}), which the collector refuses "
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
                delay = _retry_delay(attempt, e.headers.get("Retry-After"))
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
            raise CollectorError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
    raise CollectorError(f"{what} to {_host(url)} failed")


def _json(body: bytes, what: str):
    try:
        return json.loads(body)
    except ValueError:
        raise CollectorError(f"{what} returned a body that is not JSON") from None


def _error_message(body: bytes) -> str:
    """The Public API's ErrorResponseModel is {"object": "error", "message": ..., "errors": {...}}.
    Keep the message short."""
    try:
        data = json.loads(body) or {}
        message = data.get("message") or ""
    except (ValueError, AttributeError, TypeError):
        message = ""
    return str(message)[:200] or "no message"


# ---------------------------------------------------------------- Bitwarden Public API

class Bitwarden:
    """Gets an access token with the organization API key (OAuth 2.0 client credentials, scope
    api.organization), renews it before it expires or when the API answers 401, and reads the
    Public API with 'Authorization: Bearer'."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.access_token = None
        self.expires_at = 0.0

    def sign_in(self) -> None:
        url = f"{self.cfg['identity_url']}/connect/token"
        form = {"grant_type": "client_credentials", "scope": "api.organization",
                "client_id": self.cfg["client_id"], "client_secret": self.cfg["client_secret"]}
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        try:
            _, raw = _request("POST", url, headers, urllib.parse.urlencode(form).encode(), self.cfg["timeout"], "Bitwarden token request")
        except HttpStatus as e:
            if e.code in REDIRECT_STATUS:
                raise
            raise CollectorError(f"Bitwarden refused the API key (HTTP {e.code}); check BITWARDEN_CLIENT_ID and "
                                 "BITWARDEN_CLIENT_SECRET, and that BITWARDEN_IDENTITY_URL is for the organization's server") from None
        data = _json(raw, "Bitwarden token request") or {}
        if not isinstance(data, dict) or not data.get("access_token"):
            raise CollectorError("Bitwarden token request returned no access token")
        self.access_token = data["access_token"]
        try:
            lifetime = int(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            lifetime = 3600
        # Renew a minute early so a token never expires mid-request.
        self.expires_at = time.time() + max(60, lifetime - 60)

    def get(self, path: str, params: dict, what: str) -> dict:
        if not self.access_token or time.time() >= self.expires_at:
            self.sign_in()
        query = urllib.parse.urlencode(params)
        url = f"{self.cfg['api_url']}{path}" + (f"?{query}" if query else "")
        renewed = False
        while True:
            headers = {"Authorization": f"Bearer {self.access_token}", "Accept": "application/json"}
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], what)
            except HttpStatus as e:
                if e.code == 401 and not renewed:
                    LOG.info("Bitwarden rejected the access token; getting a new one")
                    self.sign_in()
                    renewed = True
                    continue
                if e.code == 400:
                    raise CollectorError(f"Bitwarden rejected {what} (HTTP 400): {_error_message(e.body)}") from None
                if e.code in (401, 403):
                    raise CollectorError(f"Bitwarden refused {what} (HTTP {e.code}); the organization needs a plan with "
                                         "API access (Teams or Enterprise) and an API key that is still current") from None
                raise
            data = _json(raw, what)
            if not isinstance(data, dict):
                raise CollectorError(f"{what} returned JSON that is not an object")
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
            raise CollectorError("NGSIEM_INGEST_URL and NGSIEM_INGEST_KEY are required unless --dry-run is set")

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

_RFC3339 = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?$", re.I)


def _epoch(value) -> float | None:
    """date is ISO 8601 in UTC with up to 7 fractional digits, such as 2020-11-04T15:01:21.698Z."""
    m = _RFC3339.match(str(value or "").strip())
    if not m:
        return None
    date, hm, sec, frac, zone = m.groups()
    zone = (zone or "Z").upper()
    zone = "+00:00" if zone == "Z" else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
    try:
        dt = datetime.fromisoformat(f"{date}T{hm}:{sec or '00'}{zone}")
    except ValueError:
        return None
    return dt.timestamp() + (float(f"0.{frac}") if frac else 0.0)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _key(event: dict) -> str:
    """Events carry no ID, so a repeat is found by the hash of the whole event."""
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def members(cfg: dict, client: Bitwarden) -> tuple[dict, dict]:
    """Two maps from GET /public/members: the organization member ID (memberId) and the Bitwarden
    user ID (actingUserId) to the member's email and name."""
    data = client.get("/public/members", {}, "members request")
    by_member, by_user = {}, {}
    for m in data.get("data") or []:
        if not isinstance(m, dict):
            continue
        who = {"email": m.get("email"), "name": m.get("name")}
        if m.get("id"):
            by_member[str(m["id"]).lower()] = who
        if m.get("userId"):
            by_user[str(m["userId"]).lower()] = who
    return by_member, by_user


def tag(event: dict, cfg: dict, by_member: dict, by_user: dict) -> dict:
    rec = {RECORD_KEY: "event", "organizationId": cfg["organization_id"], **event}
    actor = by_user.get(str(event.get("actingUserId") or "").lower())
    if actor:
        rec["actingUserEmail"], rec["actingUserName"] = actor["email"], actor["name"]
    member = by_member.get(str(event.get("memberId") or "").lower())
    if member:
        rec["memberEmail"], rec["memberName"] = member["email"], member["name"]
    return rec


def collect_events(cfg: dict, state: dict, sink: Sink, save, client: Bitwarden) -> int:
    """Read every page of [cursor minus the overlap, now], send the events not sent before, oldest
    first, then move the cursor to now."""
    now = time.time()
    cur = state.setdefault("events", {"since": now - cfg["lookback_hours"] * 3600, "seen": []})
    start = max(cur["since"] - cfg["overlap_seconds"], now - 366 * 86400)
    # One fixed window per run: each page request repeats the same start and end with the token.
    params = {"start": _iso(start), "end": _iso(now)}
    rows, token = [], None
    for _ in range(MAX_PAGES):
        data = client.get("/public/events", dict(params, continuationToken=token) if token else params, "events request")
        items = data.get("data") or []
        if not isinstance(items, list):
            raise CollectorError("events request returned data that is not a list")
        rows.extend(e for e in items if isinstance(e, dict))
        token = data.get("continuationToken")
        if not token:
            break
    else:
        raise CollectorError(f"stopped after {MAX_PAGES} pages; shorten COLLECTOR_LOOKBACK_HOURS")
    seen = set(cur["seen"])
    fresh, keys = [], set()
    for e in rows:
        k = _key(e)
        if k in seen or k in keys:
            continue
        keys.add(k)
        fresh.append(e)
    # The API returns the newest events first; send them oldest first.
    fresh.sort(key=lambda e: _epoch(e.get("date")) or 0.0)
    if fresh:
        by_member, by_user = members(cfg, client) if cfg["member_lookup"] else ({}, {})
        sink.send([tag(e, cfg, by_member, by_user) for e in fresh])
    # Keep the hashes of the events that the next run's overlap reads again, so they aren't sent twice.
    cutoff = now - cfg["overlap_seconds"]
    recent = [_key(e) for e in rows if (_epoch(e.get("date")) or now) >= cutoff]
    cur["seen"] = list(dict.fromkeys(recent))[-SEEN_LIMIT:]
    cur["since"] = now
    save()
    LOG.info("events: %d read, %d new", len(rows), len(fresh))
    return len(fresh)


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


def run_once(cfg: dict, dry_run: bool = False, out=None, client: Bitwarden | None = None) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    count = collect_events(cfg, state, sink, save, client or Bitwarden(cfg))
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Bitwarden organization event logs from the Public API to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=os.environ.get("COLLECTOR_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "COLLECTOR_DRY_RUN", False)
    try:
        cfg = load_config()
        client = Bitwarden(cfg)
        while True:
            run_once(cfg, dry_run, client=client)
            if not args.interval:
                return 0
            time.sleep(args.interval)
    except CollectorError as e:
        LOG.error("%s", e)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
