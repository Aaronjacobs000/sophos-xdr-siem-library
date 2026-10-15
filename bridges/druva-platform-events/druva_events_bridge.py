#!/usr/bin/env python3
"""Pull Druva Cloud Platform events (cybersecurity and administrator audit events) from the
Druva Cloud Platform Events API and send them to a Sophos NG-SIEM HTTP Ingest integration, one
JSON record per line. Python 3 standard library only.

Druva offers these events only through its pull API, so this script reads
GET /platform/eventmanagement/v3/events with the API's page token, which it saves between runs,
and posts each event with a "druva_record": "platform_event" key in front, so the library parsers
in parsers/druva/druva-cloud-platform-events can recognize and normalize it.

The request and response shapes follow Druva's API reference (List Events, Cybersecurity Events,
Druva Cloud Platform Events v3) and its OAuth 2.0 client credentials flow. Configuration comes
from environment variables (see README.md). The saved page token only moves after HTTP Ingest
accepted that page. --dry-run prints what would be sent and changes nothing.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import http.client
import json
import logging
import os
import random
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"
LOG = logging.getLogger("druva_events_bridge")
USER_AGENT = f"parser-studio-druva-events-bridge/{__version__}"
RETRY_STATUS = {408, 429, 500, 502, 503, 504}
# The opener doesn't follow these (see _NoRedirect), so the error names them as refused.
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_ATTEMPTS = 6
MAX_PAGES = 10000
TOKEN_PATH = "/token"
EVENTS_PATH = "/platform/eventmanagement/v3/events"
RECORD = "platform_event"


class BridgeError(Exception):
    """A failure that stops the run without moving the page token past unsent data."""


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
        "api_url": (_env(env, "DRUVA_API_URL", "https://apis.druva.com") or "").rstrip("/"),
        "client_id": _env(env, "DRUVA_CLIENT_ID"),
        "secret_key": _env(env, "DRUVA_SECRET_KEY"),
        "features": [x.strip().lower() for x in (_env(env, "DRUVA_FEATURES") or "").split(",") if x.strip()],
        "state_file": _env(env, "BRIDGE_STATE_FILE", "druva_events_state.json"),
        "gzip": _flag(env, "BRIDGE_GZIP", True),
        "batch_bytes": int(_env(env, "BRIDGE_BATCH_BYTES", "100000")),
        "page_size": int(_env(env, "BRIDGE_PAGE_SIZE", "500")),
        "lookback_hours": float(_env(env, "BRIDGE_LOOKBACK_HOURS", "24")),
        "timeout": float(_env(env, "BRIDGE_HTTP_TIMEOUT", "60")),
    }
    if not cfg["client_id"] or not cfg["secret_key"]:
        raise BridgeError("DRUVA_CLIENT_ID and DRUVA_SECRET_KEY are required")
    if not 1 <= cfg["page_size"] <= 500:
        raise BridgeError("BRIDGE_PAGE_SIZE must be from 1 to 500")
    _require_https(cfg["api_url"], "DRUVA_API_URL")
    if cfg["ingest_url"]:
        _require_https(cfg["ingest_url"], "NGSIEM_INGEST_URL")
    return cfg


# ---------------------------------------------------------------- HTTP

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


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
            raise BridgeError(f"{what} to {_host(url)} failed: {type(e).__name__}") from None
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
    """Druva's APIError is {"code", "message", "data", "retryable"}. Keep the message short."""
    try:
        data = json.loads(body) or {}
        message = data.get("message") or data.get("error_description") or data.get("error") or ""
    except (ValueError, AttributeError, TypeError):
        message = ""
    return str(message)[:200] or "no message"


# ---------------------------------------------------------------- Druva API

class DruvaClient:
    """Gets an access token with the client credentials grant and calls the Events API with
    'Authorization: Bearer <token>'. Druva's tokens last 30 minutes (15 on inSync GovCloud),
    so a token is renewed a minute before it expires, and once more if Druva refuses it."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._token = None
        self._expires = 0.0

    def _new_token(self) -> str:
        url = f"{self.cfg['api_url']}{TOKEN_PATH}"
        basic = base64.b64encode(f"{self.cfg['client_id']}:{self.cfg['secret_key']}".encode()).decode()
        headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "read"}).encode()
        try:
            _, raw = _request("POST", url, headers, body, self.cfg["timeout"], "token request")
        except HttpStatus as e:
            if e.code in (400, 401, 403):
                raise BridgeError(f"Druva refused the API credentials (HTTP {e.code}): {_error_message(e.body)}; "
                                     "check DRUVA_CLIENT_ID and DRUVA_SECRET_KEY, and that DRUVA_API_URL is the cloud "
                                     "the credentials were created in") from None
            raise
        data = _json(raw, "token request")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise BridgeError("token request returned no access_token")
        try:
            lifetime = float(data.get("expires_in") or 900)
        except (TypeError, ValueError):
            lifetime = 900.0
        self._token = token
        self._expires = time.monotonic() + max(60.0, lifetime - 60.0)
        return token

    def token(self, renew: bool = False) -> str:
        if renew or not self._token or time.monotonic() >= self._expires:
            return self._new_token()
        return self._token

    def events(self, page_token: str | None) -> dict:
        if page_token:
            # A request with pageToken can't carry filters or a page size.
            query = urllib.parse.urlencode({"pageToken": page_token})
        else:
            query = urllib.parse.urlencode({"pageSize": self.cfg["page_size"]})
        url = f"{self.cfg['api_url']}{EVENTS_PATH}?{query}"
        for renew in (False, True):
            headers = {"Authorization": f"Bearer {self.token(renew)}", "Accept": "application/json"}
            try:
                _, raw = _request("GET", url, headers, None, self.cfg["timeout"], "events request")
                break
            except HttpStatus as e:
                # Druva answers an expired access token with 403 (401 in some specs): renew once.
                if e.code in (401, 403) and not renew:
                    LOG.info("events request returned %s; renewing the access token", e.code)
                    continue
                if e.code in (400, 401, 403):
                    hint = (" A saved page token Druva no longer accepts needs a fresh start: run once with --reset."
                            if page_token else "")
                    raise BridgeError(f"Druva refused the events request (HTTP {e.code}): {_error_message(e.body)}."
                                         f"{hint} Check that the API credentials have a role that can read events.") from None
                raise
        data = _json(raw, "events request")
        if not isinstance(data, dict):
            raise BridgeError("events request returned JSON that is not an object")
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

def event_time(event: dict) -> datetime | None:
    """timeStamp is epoch seconds in the v3 reference; some Druva examples send RFC 3339 text."""
    value = event.get("timeStamp")
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(float(value), timezone.utc)
        if isinstance(value, str) and value.strip():
            text = value.strip()
            if text.isdigit():
                return datetime.fromtimestamp(float(text), timezone.utc)
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None
    return None


def collect(cfg: dict, state: dict, sink: Sink, save, client: DruvaClient, reset: bool = False) -> int:
    """Read pages from the saved page token, or from the start on the first run (sending only
    events inside the lookback), until a page brings no events. Each page is sent, then its
    next page token saved."""
    token = None if reset else state.get("page_token")
    first_run = not token
    since = datetime.now(timezone.utc) - timedelta(hours=cfg["lookback_hours"]) if first_run else None
    wanted = set(cfg["features"])
    sent = skipped_old = 0
    for _ in range(MAX_PAGES):
        data = client.events(token)
        events = data.get("events") or []
        if not isinstance(events, list):
            raise BridgeError("events request returned events that are not a list")
        rows = [e for e in events if isinstance(e, dict)]
        if since is not None:
            keep = [e for e in rows if (event_time(e) or since) >= since]
            skipped_old += len(rows) - len(keep)
            rows = keep
        if wanted:
            rows = [e for e in rows if str(e.get("feature") or "").lower() in wanted]
        if rows:
            sink.send([{"druva_record": RECORD, **e} for e in rows])
            sent += len(rows)
        next_token = data.get("nextPageToken")
        if next_token and isinstance(next_token, str):
            state["page_token"] = next_token
            save()
        # Caught up: an empty page, no next token, or the same token again (Druva keeps the token
        # when there is nothing new).
        if not events or not next_token or next_token == token:
            break
        token = next_token
    else:
        LOG.warning("stopped after %d pages; the next run continues from the saved page token", MAX_PAGES)
    if skipped_old:
        LOG.info("first run: %d events older than the %g-hour lookback were not sent", skipped_old, cfg["lookback_hours"])
    LOG.info("platform events: %d sent", sent)
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


def run_once(cfg: dict, dry_run: bool = False, out=None, reset: bool = False) -> int:
    state = load_state(cfg["state_file"])
    sink = Sink(cfg, dry_run, out)
    save = (lambda: None) if dry_run else (lambda: save_state(cfg["state_file"], state))
    sent = collect(cfg, state, sink, save, DruvaClient(cfg), reset)
    LOG.info("run finished: %d records sent in %d batches%s", sink.sent, sink.batches, " (dry run, nothing sent)" if dry_run else "")
    return sent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send Druva Cloud Platform events from the Events API to Sophos NG-SIEM HTTP Ingest.")
    ap.add_argument("--dry-run", action="store_true", help="print the NDJSON that would be sent; send and save nothing")
    ap.add_argument("--reset", action="store_true", help="ignore the saved page token and start again, sending only the lookback")
    ap.add_argument("--interval", type=int, default=0, help="poll every N seconds instead of running once")
    ap.add_argument("--log-level", default=_env(dict(os.environ), "BRIDGE_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    dry_run = args.dry_run or _flag(dict(os.environ), "BRIDGE_DRY_RUN", False)
    try:
        cfg = load_config()
        reset = args.reset
        while True:
            run_once(cfg, dry_run, reset=reset)
            reset = False
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
