# ESET Connect detections bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real ESET PROTECT account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from ESET's public ESET Connect API reference and OpenAPI specifications. Run it with `--dry-run` first and check what it would send.

ESET PROTECT (cloud) has no syslog export, so this script signs in to ESET Connect as an API user, lists detections by time window from the Incident Management API, and sends each detection as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"eset_connect_record": "detection"` to each record, and the library parsers in `parsers/eset/eset-protect-cloud` normalize them. For ESET PROTECT On-Prem, use its syslog export and `parsers/eset/eset-protect-on-prem` instead.

| Data | Endpoint | `eset_connect_record` |
| --- | --- | --- |
| Detections from ESET PROTECT: antivirus, firewall, network intrusion, HIPS, web access and the rest | `GET /v1/detections` on `https://<region>.incident-management.eset.systems` | `detection` |

ESET documents `/v2/detections` for ESET Cloud Office Security only, so the bridge reads `/v1/detections`. Incidents (`/v2/incidents`) aren't collected.

Python 3.9 or later, standard library only. One file: `eset_connect_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/eset/eset-protect-cloud` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**ESET.** Only a Root or Superuser administrator can create an API user. In ESET PROTECT Hub, go to Users, add a user for the bridge, and turn on **Integrations** under Permissions; in ESET Business Account or ESET MSP Administrator 2, turn on Integrations under the user's Access Rights. The new user has to sign in to ESET PROTECT Hub once before it can use the API. If you also run ESET Inspect and want ESET PROTECT detections only, give the user a custom permission set without ESET Inspect access, as ESET's Incident Management page describes. Note the region your account is in: `eu`, `de`, `us`, `ca` or `jpn`.

## Configuration

Everything comes from environment variables. Keep the password in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `ESET_CONNECT_REGION` | `eu` | Your ESET Connect region: `eu`, `de`, `us`, `ca` or `jpn`. |
| `ESET_CONNECT_USERNAME` | none | The API user's email address. |
| `ESET_CONNECT_PASSWORD` | none | The API user's password. |
| `ESET_CONNECT_DEVICE_UUID` | none | Only read detections from this device. Leave it unset for all devices. |
| `ESET_CONNECT_PAGE_SIZE` | `500` | Detections per page, 1 to 1000. |
| `ESET_CONNECT_TOKEN_URL` | from the region | Overrides `https://<region>.business-account.iam.eset.systems`. |
| `ESET_CONNECT_API_URL` | from the region | Overrides `https://<region>.incident-management.eset.systems`. |
| `BRIDGE_STATE_FILE` | `eset_connect_state.json` | The cursor and the IDs of recently sent detections. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How much before the cursor each run reads again, for detections that reach ESET Connect late. Repeats are dropped by detection `uuid`. |
| `BRIDGE_PENDING_WAIT_SECONDS` | `15` | How long to wait before asking again when ESET answers 202 (query still running). |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `150` | Seconds per request. ESET answers a slow query within 120 seconds. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 eset_connect_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 eset_connect_bridge.py                   # one pass, for cron or a systemd timer
python3 eset_connect_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same window again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log. A token refresh that fails in an outage stops the run, rather than signing in and going through the retries again.

As a systemd service that polls, with the variables in `/etc/eset-connect.env` (owned by root, mode 600):

```ini
[Unit]
Description=ESET Connect detections bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/eset-connect/eset_connect_bridge.py --interval 300
EnvironmentFile=/etc/eset-connect.env
DynamicUser=yes
StateDirectory=eset-connect
WorkingDirectory=/var/lib/eset-connect
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- It signs in with `POST /oauth/token` (form fields `grant_type=password`, `username`, `password`) and sends the access token as `Authorization: Bearer`. ESET's tokens last 60 minutes; the bridge renews the token with `grant_type=refresh_token` a minute before it expires, and once more if the API answers 401. If ESET refuses the refresh token, it signs in again.
- Each run asks for detections with `occurTime` from the cursor minus the overlap (`startTime`, inclusive) up to the start of the run (`endTime`, exclusive), and follows `nextPageToken` until a page comes back without one.
- When a query takes ESET more than 30 seconds, ESET answers `202 Accepted` with a `response-id` header and keeps the result for 10 minutes. The bridge asks again with the same query and that header until the result is ready.
- It sends the detections it hasn't sent, oldest first, then moves the cursor to the start of the run.
- ESET filters on when a detection happened, not when it reached ESET Connect, so a detection from a device that was offline for longer than the overlap is missed. Raise `BRIDGE_OVERLAP_SECONDS` if your devices report late.

ESET allows 10 calls a second per API user, account and address. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from ESET or HTTP Ingest is refused, not followed, so no password, token or key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the password, the access or refresh token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/eset-connect -p 'test_*.py' -v
```

The tests start a local mock of the ESET token and detections endpoints and HTTP Ingest, built from the documented shapes, and check paging, tagging, oldest-first order, the query window, the device filter, the lookback, a late detection inside the overlap, repeats, bad credentials, renewing a rejected or expiring token, a pending query (202 and `response-id`), dry-run, retries, batching and gzip, refused redirects, and that no secret reaches the log.

## References

- ESET Connect list detections (v1): https://help.eset.com/eset_connect/en-US/incident_management_v1_detections_get.html
- ESET Connect token: https://help.eset.com/eset_connect/en-US/authentication_oauth_token_post.html
- Create an API user: https://help.eset.com/eset_connect/en-US/create_api_user_account.html
- How the API works (202 and `response-id`): https://help.eset.com/eset_connect/en-US/how_api_works.html
- Pagination: https://help.eset.com/eset_connect/en-US/pagination.html
- Rate limits: https://help.eset.com/eset_connect/en-US/rate_limits.html
- Which products use v1 and v2: https://help.eset.com/eset_connect/en-US/incident_management.html
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
