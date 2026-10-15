# Datto RMM Activity Log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Datto RMM account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the response shapes in Datto's API help page and public OpenAPI spec. Run it with `--dry-run` first and check what it would send.

Datto RMM pushes monitor alerts through Global Webhooks, but its Activity Log is only available from the API. That log is where an RMM intrusion shows up: logins, jobs and components run, remote takeover and Web Remote sessions, file transfers, and device and user changes. This script polls `GET /api/v2/activity-logs`, keeps a cursor, and sends each record unchanged as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser `DATTO_RMM_ACTIVITY_JSON_STANDALONE_CLOUDAUDIT` in `parsers/datto/datto-rmm` then normalizes it to CloudAudit.

Python 3.9 or later, standard library only. One file: `datto_rmm_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/datto/datto-rmm` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Datto RMM.** An administrator turns on Setup > Global Settings > Access Control > Enable API Access, then creates a user for the bridge and clicks Generate API Keys on it. Give it an API security level that can view the Activity Log (user activity needs the Administrator security level; device activity follows the Sites > Devices permission). Copy the API URL, API Key and API Secret Key. The secret is shown once.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `DATTO_RMM_API_URL` | none | The API URL shown on the user, for example `https://merlot-api.centrastage.net`. |
| `DATTO_RMM_API_KEY` | none | The user's API Key. |
| `DATTO_RMM_API_SECRET` | none | The user's API Secret Key. |
| `DATTO_RMM_ENTITIES` | `device,user` | Which activity to read: `device`, `user` or both. |
| `DATTO_RMM_PAGE_SIZE` | `250` | Records per page; Datto returns at most 250. |
| `BRIDGE_STATE_FILE` | `datto_rmm_state.json` | Cursor and recently seen IDs. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. Datto keeps the Activity Log for 180 days. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much of the previous window each run re-reads, to catch late records. Repeats are dropped by ID. |
| `BRIDGE_SETTLE_SECONDS` | `60` | Each window stops this far before now. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 datto_rmm_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 datto_rmm_bridge.py                  # one pass, for cron or a systemd timer
python3 datto_rmm_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means the window was read and sent. On an error the bridge logs the step and the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same window again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

As a systemd service that polls, with the variables in `/etc/datto-rmm-activity-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Datto RMM Activity Log bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/datto-rmm-activity-logs/datto_rmm_bridge.py --interval 300
EnvironmentFile=/etc/datto-rmm-activity-logs.env
DynamicUser=yes
StateDirectory=datto-rmm-activity-logs
WorkingDirectory=/var/lib/datto-rmm-activity-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- It requests an access token from `<API URL>/auth/oauth/token` with the password grant, the API key and secret as user name and password, and the OAuth client `public-client` / `public` that Datto documents. Tokens last 100 hours; on a 401 it asks for a new one once.
- It reads `from` (the cursor minus the overlap) to `until` (now minus the settle time) with `order=asc`, and follows `pageDetails.nextPageUrl` until it is empty. It only follows page links with the configured API URL's scheme and host, so the token never goes anywhere else or over plain http.
- It sends the new records oldest first, then saves the cursor and the IDs inside the overlap.

The API and HTTP Ingest both deliver at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

Rate limits: Datto allows 600 read requests a minute across the whole account, and blocks the address for a while after repeated requests past the limit. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times (honoring `Retry-After` up to 5 minutes), and stops on 403 so it doesn't make a block worse. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the Datto RMM API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

The bridge never logs the API key or secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/datto-rmm-activity-logs -p 'test_*.py' -v
```

The tests start a local mock of the Datto RMM token endpoint, the Activity Log endpoint and HTTP Ingest, built from the documented shapes, and check paging, the cursor and overlap, the settle window, dry-run, token renewal, retries, the 403 stop, the page-link host check, batching and gzip, and that no secret reaches the log.

## References

- Datto RMM API v2 help (enabling the API, OAuth, rate limits, pagination): https://rmm.datto.com/help/en/Content/2SETUP/APIv2.htm
- Datto RMM Activity Log: https://rmm.datto.com/help/en/Content/3NEWUI/Analytics/ActivityLog.htm
- Datto RMM OpenAPI spec (ActivityLog, ActivityLogsPage, PaginationData): https://merlot-api.centrastage.net/api/v3/api-docs
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract (URL, bearer header, NDJSON and gzip rules), in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
