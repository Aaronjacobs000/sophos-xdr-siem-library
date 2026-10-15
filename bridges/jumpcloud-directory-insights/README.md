# JumpCloud Directory Insights bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real JumpCloud organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from JumpCloud's Directory Insights API reference. Run it with `--dry-run` first and check what it would send.

JumpCloud offers its Directory Insights events (Admin Portal and User Portal sign-ins and changes, SSO, RADIUS, LDAP and device sign-ins, MDM, password manager and more) through its REST API, which is pull only. This script reads them and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"jumpcloud_record": "directory_insights"` in front of each event, and the library parsers in `parsers/jumpcloud/directory-insights` normalize them. Sophos Fusion has no JumpCloud integration.

| Data | Endpoint | Headers |
| --- | --- | --- |
| Directory Insights events from the services in `JUMPCLOUD_SERVICES` | `POST /insights/directory/v1/events` | `x-api-key`, and `x-org-id` for each client organization of an MSP |

Python 3.9 or later, standard library only. One file: `jumpcloud_di_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/jumpcloud/directory-insights` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**JumpCloud.** The Directory Insights API takes an administrator's API key, and a key can do anything its administrator's role can. JumpCloud turns API access off for administrators by default, and only an Administrator with Billing can turn it on.

1. In the Admin Portal, go to Settings > Administrators and add an administrator for the bridge with the Read Only role. Read Only can view and query Directory Insights and change nothing.
2. As an Administrator with Billing, open that administrator and turn on Enable API access.
3. Sign in as the bridge's administrator, choose your account name and My API Key, and generate a key. Set its expiration under Expiration Date, and generate a new key before it expires: generating one revokes the old one.
4. For an MSP: use an MSP administrator's key from the Multi-Tenant Portal (launch a client organization, then your account icon and API Settings), and list the client organizations' IDs in `JUMPCLOUD_ORG_IDS`. Each organization is read on its own with `x-org-id`.

JumpCloud keeps Directory Insights events for 90 days. An organization outside the US uses its region's API URL: `https://api.eu.jumpcloud.com` or `https://api.in.jumpcloud.com`.

## Configuration

Everything comes from environment variables. Keep the API key and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `JUMPCLOUD_API_KEY` | none | The administrator's API key, sent as `x-api-key`. |
| `JUMPCLOUD_API_URL` | `https://api.jumpcloud.com` | The API URL for the organization's region. |
| `JUMPCLOUD_ORG_IDS` | none | For an MSP key, the client organization IDs to read, comma separated. Empty reads the key's own organization. |
| `JUMPCLOUD_SERVICES` | `all` | The Directory Insights services to read, comma separated, such as `directory,sso,radius,ldap,systems`. `all` reads every service. |
| `JUMPCLOUD_PAGE_LIMIT` | `1000` | Events per request, 1 to 10000. |
| `BRIDGE_STATE_FILE` | `jumpcloud_di_state.json` | Each organization's last window end and the events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 2160 (the 90 days JumpCloud keeps). |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for events JumpCloud lists late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 jumpcloud_di_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 jumpcloud_di_bridge.py                   # one pass, for cron or a systemd timer
python3 jumpcloud_di_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every organization was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

As a systemd service that polls, with the variables in `/etc/jumpcloud-directory-insights.env` (owned by root, mode 600):

```ini
[Unit]
Description=JumpCloud Directory Insights bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/jumpcloud-directory-insights/jumpcloud_di_bridge.py --interval 300
EnvironmentFile=/etc/jumpcloud-directory-insights.env
DynamicUser=yes
StateDirectory=jumpcloud-directory-insights
WorkingDirectory=/var/lib/jumpcloud-directory-insights
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads each organization, the key's own or each one in `JUMPCLOUD_ORG_IDS`, from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now, and never from more than 90 days back. The body is `{"service": [...], "start_time": "<start>", "end_time": "<end>", "limit": <JUMPCLOUD_PAGE_LIMIT>, "sort": "ASC"}`, with times in RFC 3339 UTC.
- JumpCloud answers with a JSON array of events, oldest first, and paging values in the response headers. While `X-Result-Count` equals `X-Limit` there may be more, so the bridge sends the same query again with `search_after` set to the `X-Search_after` value of the page before, as JumpCloud's reference describes, until a page holds fewer events than `X-Limit`. A full page without `X-Search_after`, or with the same value twice, stops the run.
- Every event has a unique `id`, so the bridge drops repeats by `id`. A window's end is saved only after every page of it was sent, and never past the time of the run.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. A 400 shows JumpCloud's message, which for an unknown service lists the services it takes. A 401 means the key was refused, a 402 that Directory Insights isn't enabled for the organization, and a 403 that the administrator's role can't read it. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from JumpCloud or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the API key, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/jumpcloud-directory-insights -p 'test_*.py' -v
```

The tests start a local mock of the Directory Insights events endpoint and HTTP Ingest, built from the documented shapes, and check the request body and headers, paging with `X-Result-Count`, `X-Limit` and `X-Search_after`, MSP organizations with `x-org-id`, windows, overlaps and repeats, the lookback and the 90-day limit, that a window ends only after HTTP Ingest accepted it and never past now, the services setting, refused keys and permissions, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Directory Insights API reference (request body, response headers, paging, MSP headers, retention, event schemas): https://docs.jumpcloud.com/api/insights/directory/1.0/index.html
- Directory Insights event types: https://docs.jumpcloud.com/new/others/siem-event-types/index.html
- JumpCloud APIs (API keys, API access off by default, key expiration): https://jumpcloud.com/support/jumpcloud-apis
- Admin Portal roles (Read Only can view and query Directory Insights): https://jumpcloud.com/support/admin-portal-roles
- JumpCloud data centers and regional URLs: https://jumpcloud.com/support/jumpcloud-data-centers-login-urls-and-service-endpoints
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
