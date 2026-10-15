# Kaseya VSA 10 audit log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real VSA 10 server, a Pulseway account or a Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the response shapes in the VSA 10 REST API documentation. Run it with `--dry-run` first and check what it would send.

VSA 10 pushes notifications through webhooks, but its audit log is only available from the API. That log records who ran which ad-hoc or automation script on which device, remote control sessions, file transfers, API token and account changes, with the source address of each request. This script polls `GET /api/v3/auditlogs`, keeps the last `AuditLogRecordId` as its cursor, and sends each record unchanged as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser `KASEYA_VSA10_AUDIT_JSON_STANDALONE_CLOUDAUDIT` in `parsers/kaseya/vsa-10` then normalizes it to CloudAudit.

Pulseway's API documentation describes the same audit log endpoint, records and authentication, so the script should read Pulseway with `VSA10_API_URL` set to its API base. That hasn't been tested. VSA 9.5 is a different product with a different API.

Python 3.9 or later, standard library only. One file: `kaseya_vsa10_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/kaseya/vsa-10` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn them on.

**VSA 10.** Under Configuration > API Access > Third-Party Tokens, create a token for the bridge with read access to the audit log only, and restrict it to the bridge's IP address. Copy the token ID and secret.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `VSA10_API_URL` | none | The API base, `https://<server_name>/api/v3` for VSA 10. |
| `VSA10_TOKEN_ID` | none | The third-party token ID. |
| `VSA10_TOKEN_SECRET` | none | The third-party token secret. |
| `VSA10_PAGE_SIZE` | `1000` | Records per request (`$top`), 1 to 5000. |
| `VSA10_START_ID` | none | On the first run, start after this `AuditLogRecordId` instead of using the lookback. |
| `BRIDGE_STATE_FILE` | `kaseya_vsa10_state.json` | The cursor. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 kaseya_vsa10_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 kaseya_vsa10_bridge.py                  # one pass, for cron or a systemd timer
python3 kaseya_vsa10_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs the step and the HTTP status, stops, and keeps the cursor at the last page HTTP Ingest accepted. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

As a systemd service that polls, with the variables in `/etc/kaseya-vsa10-audit-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Kaseya VSA 10 audit log bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/kaseya-vsa10-audit-logs/kaseya_vsa10_bridge.py --interval 300
EnvironmentFile=/etc/kaseya-vsa10-audit-logs.env
DynamicUser=yes
StateDirectory=kaseya-vsa10-audit-logs
WorkingDirectory=/var/lib/kaseya-vsa10-audit-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- It authenticates with HTTP Basic (token ID and secret), as the API documentation shows.
- The first run asks for `$filter=AuditLogRecordDateTime ge <now minus the lookback>` (a standard OData date filter; the documentation's own example filters with `year()`), unless `VSA10_START_ID` is set. Later runs ask for `$filter=AuditLogRecordId gt <cursor>`.
- Every request sorts by `AuditLogRecordId asc` and reads `$top` records. After each page HTTP Ingest accepts, the cursor moves to that page's last ID. It stops at a short page.

Rate limits: about 3600 requests an hour per token and endpoint, and at most 100 failed requests a minute (2000 an hour) per address. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes, and stops on 401 or 403. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the VSA 10 API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a page and saving the cursor can send that page again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the token ID or secret, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/kaseya-vsa10-audit-logs -p 'test_*.py' -v
```

The tests start a local mock of the audit log endpoint and HTTP Ingest, built from the documented shapes, and check the lookback and keyset paging, the start ID, the cursor after a failed batch, dry-run, retries, the stop on a bad token, batching and gzip, and that no secret reaches the log.

## References

- VSA 10 REST API (Audit Logs, Notification Webhooks, authentication, rate limits): https://api.vsax.net
- VSA 10 API access and third-party tokens: https://help.vsa10.kaseya.com/help/Content/2-Administration/configuration/api.htm
- VSA 10 audit log: https://help.vsa10.kaseya.com/help/Content/2-Administration/server-admin/audit-log.htm
- Pulseway REST API: https://api.pulseway.com/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
