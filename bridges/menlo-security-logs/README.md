# Menlo Security logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Menlo Security tenant or Sophos NG-SIEM HTTP Ingest integration. Menlo's Log API reference needs a Menlo sign-in, so its unit tests use a local mock built from Menlo's own Microsoft Sentinel connector and the Cortex XSOAR Menlo Security pack, both MIT licensed. Run it with `--dry-run` first and check what it would send.

Menlo Security offers the logs of its cloud proxy and isolation platform (web requests, downloads and proxy events, admin audit, email isolation, DLP and more) through its Log API, which is pull only. This script reads them and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"menlo_record": "<log type>"` in front of each event, and the library parsers in `parsers/menlo-security/menlo-security` normalize the web and audit logs. Sophos Fusion has no Menlo Security integration.

| Data | Endpoint | Auth |
| --- | --- | --- |
| Events of each log type in `MENLO_LOG_TYPES` | `POST /api/rep/v2/fetch/client_select?format=JSON&limit=&start=&end=` | The token in the JSON body, as the API takes it |

Python 3.9 or later, standard library only. One file: `menlo_logs_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/menlo-security/menlo-security` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own events before you turn them on.

**Menlo Security.** In the Menlo Admin Portal, create an API token with only the Log Export API permission, which reads logs and changes nothing; Google's and Logpresso's setup guides put it under Settings > Authentication > API Tokens. Copy the token when it is shown. The bridge uses the v2 endpoint, which takes the tokens the Admin Portal makes; a legacy token for the v1 endpoint won't work.

Menlo's own connector names an expired token as a cause of missing data, so note when yours expires and replace it before then.

## Configuration

Everything comes from environment variables. Keep the Menlo token and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `MENLO_TOKEN` | none | The API token with the Log Export API permission. |
| `MENLO_API_URL` | `https://logs.menlosecurity.com` | The Log API host. |
| `MENLO_LOG_TYPES` | `web,audit` | The log types to read, comma separated: `web`, `audit`, `email`, `smtp`, `attachment`, `dlp`, `bandwidth`, `heat`, `firewall`, `auth_flows` or `ms_client_logs`. The library parsers normalize `web` and `audit`; the parent takes the others as generic records. |
| `MENLO_PAGE_LIMIT` | `1000` | Events per request, 1 to 10000. A page of 10,000 web events can be about 17 MB. |
| `BRIDGE_STATE_FILE` | `menlo_logs_state.json` | Each log type's last window end and the events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 720. Menlo doesn't publish its retention, and other connectors refuse a start more than 30 days back. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How far before the last window's end each run reads again, for events Menlo lists late. Repeats are dropped. |
| `BRIDGE_WINDOW_MINUTES` | `5` | How long each request's window is, 1 to 1440. Menlo's advice, as the XSOAR pack quotes it, is windows of about 5 minutes for a busy tenant. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `120` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 menlo_logs_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 menlo_logs_bridge.py                   # one pass, for cron or a systemd timer
python3 menlo_logs_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every log type was read and sent. On an error the bridge logs it with the HTTP status and Menlo's reason, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or token error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/menlo-security-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Menlo Security logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/menlo-security-logs/menlo_logs_bridge.py --interval 300
EnvironmentFile=/etc/menlo-security-logs.env
DynamicUser=yes
StateDirectory=menlo-security-logs
WorkingDirectory=/var/lib/menlo-security-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads each log type from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to three minutes before now, as Menlo's own connector does, and never from more than 30 days back, in windows of `BRIDGE_WINDOW_MINUTES`, oldest first. `start` and `end` are Unix times in seconds. Menlo doesn't say whether it includes the ends, so each window starts a second before the last one ended, and the repeat is dropped.
- The body is `{"token": "<MENLO_TOKEN>", "log_type": "<type>"}`. Menlo answers a list of wrappers, each `{"result": {"events": [{"event": {...}}], "pagingIdentifiers": {...}}}`; the bridge reads the events of every wrapper. While there are more, it sends the same query again with `pagingIdentifiers` set to the ones it sent updated with the ones it got, as Menlo's connector does. A window ends at `last_iteration: true`, which Menlo's connector reads in `result` and other connectors in `pagingIdentifiers`, so either one counts, or at a page with no events, an answer with no `pagingIdentifiers`, or the empty answer Menlo gives when there is no data. The same `pagingIdentifiers` twice stops the run.
- Events have no ID, so the bridge drops repeats by a hash of the whole event. Each window's end is saved once every page of it was sent, and never past the time of the run.
- Event times have no zone, such as `2026-10-21T21:02:11.218000`, and are read as UTC, as Menlo's connector does.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. A 401 or 403 means the token was refused or can't read that log type, a 400 shows Menlo's reason, and a 404 or 405 means `MENLO_API_URL` is wrong. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Menlo or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the Menlo token, a request body, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/menlo-security-logs -p 'test_*.py' -v
```

The tests start a local mock of the Log API and HTTP Ingest, built from the shapes in Menlo's connector and the XSOAR pack, and check the query, body and headers, paging with `pagingIdentifiers` and each way Menlo marks the last page, answers of several wrappers, each log type on its own, windows, the second before each one, overlaps and repeats, the lookback and the 30-day limit, that a window ends only after HTTP Ingest accepted it and never past now, Menlo's errors, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, times on Python 3.9 to 3.13, and that no secret reaches the log.

## References

- Menlo Security's Microsoft Sentinel connector, written by Menlo (the v2 endpoint, request body, paging, its 3-minute lag and the web, audit and bandwidth fields): https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/MenloSecurity
- Cortex XSOAR Menlo Security pack (the log types, the list of wrappers, the empty answer for no data, sample responses): https://github.com/demisto/content/tree/master/Packs/MenloSecurity
- Google Security Operations Menlo Security parser docs (the API token and its Log Export API permission): https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/menlo-security
- Menlo Security docs, which need a sign-in: https://admin.menlosecurity.com/docs
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
