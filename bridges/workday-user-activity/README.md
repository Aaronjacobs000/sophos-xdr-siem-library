# Workday user activity bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Workday tenant or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Workday's Privacy API reference. Run it with `--dry-run` first and check what it would send.

Workday's user activity log records who ran which task or report, and read, changed or downloaded which data, from which address and session, once User Activity Logging is turned on for the tenant. Workday offers it through the `activityLogging` resource of its REST API, which is pull only. This script reads it and sends each entry as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"workday_record": "user_activity"` and `"workday_tenant"` in front of each entry, and the library parser in `parsers/workday/workday-user-activity` normalizes them. Sophos Fusion has no Workday integration.

| Data | Endpoint | Auth |
| --- | --- | --- |
| Access token | `POST /ccx/oauth2/<tenant>/token` | `grant_type=refresh_token`, the API client's ID and secret in HTTP Basic |
| User activity entries | `GET /ccx/api/privacy/v1/<tenant>/activityLogging` | `Authorization: Bearer <access token>` |

Python 3.9 or later, standard library only. One file: `workday_activity_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/workday/workday-user-activity` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own entries before you turn it on.

**Workday.** The resource is secured by the System Auditing domain and needs the System scope. You can only read the entries the security profile of the user permits, so the bridge's user goes in an unconstrained group. As a security administrator:

1. In Edit Tenant Setup - System, turn on Enable User Activity Logging. In Edit Tenant Setup - Security, make sure OAuth 2.0 Clients Enabled is on.
2. Create Integration System User for the bridge, with Do Not Allow UI Sessions on.
3. Create Integration System Security Group (Unconstrained) and add the user to it.
4. View Domain for System Auditing, then Edit Security Policy Permissions: give the group Get under Integration Permissions and View under Report/Task Permissions. Then Activate Pending Security Policy Changes. That is all the bridge needs; it reads and changes nothing else.
5. Register API Client for Integrations, with Non-Expiring Refresh Tokens on and only System under Scope (Functional Areas). Copy the Client ID and Client Secret.
6. On the API client, choose Manage Refresh Tokens for Integrations, pick the integration system user, and Generate New Refresh Token. Generating another one later revokes this one.
7. View API Clients shows the Token Endpoint, `https://<host>/ccx/oauth2/<tenant>/token`. The host and tenant in it are `WORKDAY_HOST_URL` and `WORKDAY_TENANT`.

Workday keeps user activity for 30 days, and writes the log about every 2 minutes. The bridge's own reads show up in the log too, as `privacy/activityLogging/userActivity (GET)` by the integration system user.

## Configuration

Everything comes from environment variables. Keep the client secret, the refresh token and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `WORKDAY_HOST_URL` | none | The services host, scheme and host only, such as `https://wd2-impl-services1.workday.com`. |
| `WORKDAY_TENANT` | none | The tenant name, as in the token endpoint. |
| `WORKDAY_CLIENT_ID` | none | The API client's Client ID. |
| `WORKDAY_CLIENT_SECRET` | none | The API client's Client Secret. |
| `WORKDAY_REFRESH_TOKEN` | none | The integration system user's refresh token. |
| `WORKDAY_PAGE_LIMIT` | `1000` | Entries per request, 1 to 1000. Workday's reference gives 1000 as the most in one place and 100 in another; set 100 if Workday refuses 1000. |
| `WORKDAY_INSTANCES_RETURNED` | `1` | `instancesReturned`, 1 to 25: one query returns at most this many times 10,000 entries. Workday recommends 1 as the fastest. |
| `BRIDGE_STATE_FILE` | `workday_activity_state.json` | The last window end and the entries sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 720 (the 30 days Workday keeps). |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for entries Workday writes late. Repeats are dropped. |
| `BRIDGE_WINDOW_MINUTES` | `60` | How long each query's window is, 1 to 1440. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `180` | Seconds per request. Workday builds a cache on a query's first page, which can be slow. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 workday_activity_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 workday_activity_bridge.py                   # one pass, for cron or a systemd timer
python3 workday_activity_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every window was read and sent. On an error the bridge logs it with the HTTP status and Workday's message, stops, and leaves the window where it was, so the next run reads the same entries again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or credential error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/workday-user-activity.env` (owned by root, mode 600):

```ini
[Unit]
Description=Workday user activity bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/workday-user-activity/workday_activity_bridge.py --interval 300
EnvironmentFile=/etc/workday-user-activity.env
DynamicUser=yes
StateDirectory=workday-user-activity
WorkingDirectory=/var/lib/workday-user-activity
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- The bridge gets an access token with `grant_type=refresh_token` and the API client in HTTP Basic, and keeps using `WORKDAY_REFRESH_TOKEN`. It renews the access token a minute before `expires_in` runs out, after an hour when Workday sends no `expires_in` or -1, and once more when Workday refuses it.
- Each run reads from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to three minutes before now, and never from more than 30 days back, in windows of `BRIDGE_WINDOW_MINUTES`, oldest first: `GET activityLogging?from=<start>&to=<end>&limit=<WORKDAY_PAGE_LIMIT>&offset=<n>&instancesReturned=<WORKDAY_INSTANCES_RETURNED>`, with times in UTC as `2026-10-03T07:00:00Z`. Workday doesn't say whether it includes the ends, so each window starts a second before the last one ended, and the repeat is dropped.
- Workday answers `{"total": <entries matched>, "data": [...]}`. The bridge adds the entries it got to `offset` and asks again until `offset` reaches `total`, or a page is empty when there is no `total`. A page can hold fewer entries than the limit and still have more after it.
- One query returns at most `instancesReturned` times 10,000 entries. A window whose `total` reaches that is read again in halves, before anything from it is sent. A one-minute window that still reaches it is read with `instancesReturned` at its maximum of 25 (250,000 entries), and if it reaches even that, the bridge logs how many it couldn't read.
- Entries have no ID, so the bridge drops repeats by a hash of the whole entry. Each window's end is saved once every page of it was sent, and never past the time of the run.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. A refused token request (400 `invalid_grant` for the refresh token, `invalid_request` for the tenant, 401 `invalid_client` for the client) stops the run with what to check, as do a 403 (scope or System Auditing permissions), a 404 (host or tenant) and a 400, with Workday's message. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Workday or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the refresh token, an access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/workday-user-activity -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, the activityLogging resource and HTTP Ingest, built from the documented shapes, and check the token request and its renewal, the query and headers, paging with `offset` and `total`, windows, the second before each one, overlaps and repeats, halving a window that reaches the `instancesReturned` cap, the lookback and the 30-day limit, that a window ends only after HTTP Ingest accepted it and never past now, Workday's errors, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, times on Python 3.9 to 3.13, and that no secret reaches the log.

## References

- Workday REST API directory, Privacy service v1 (the activityLogging resource, its parameters, the userActivityTracking entry, errors, the System Auditing domain and System scope): https://community.workday.com/sites/default/files/file-hosting/restapi/privacy_v1_20261003_oas2.json
- User activity logging (activity categories, writes about every 2 minutes, up to 250,000 results, 30 days kept): https://doc.workday.com/admin-guide/en-us/manage-workday/tenant-configuration/user-activity-logging/unv1636547598141.html
- Limitations and availability (429 when a tenant is busy, the first page builds a cache): https://doc.workday.com/admin-guide/en-us/manage-workday/tenant-configuration/it-administrator-resources/limitations-and-availability/dan1370797408285.html
- Registering an API client with a refresh token (Data Lake, the same steps): https://doc.workday.com/admin-guide/en-us/workday-data-cloud/data-out/workday-data-lake/register-api-client-for-data-lake--refresh-token-g.html
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
