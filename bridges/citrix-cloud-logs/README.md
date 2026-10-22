# Citrix Cloud logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Citrix Cloud account, Citrix DaaS site or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Citrix's System Log, DaaS REST API and Monitor OData API references. Run it with `--dry-run` first and check what it would send.

Citrix Cloud and Citrix DaaS offer their audit and session logs through REST APIs, which are pull only. This script reads three of them and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"citrix_record"` and `"citrix_customer_id"` in front of each record, and `"citrix_site_id"` for Configuration Logging, and the library parsers in `parsers/citrix/citrix-daas-and-citrix-cloud` normalize them. Sophos Fusion has no Citrix Cloud or Citrix DaaS integration; its NetScaler integration covers NetScaler ADC only.

| Data | `citrix_record` | Endpoint | Headers |
| --- | --- | --- | --- |
| Citrix Cloud System Log: administrators, secure clients, identity providers, domains, connectors, Workspace and other platform events | `systemlog` | `GET /systemlog/records` | `Citrix-CustomerId` |
| DaaS sites, when `CITRIX_SITE_IDS` is empty | none | `GET /cvad/manage/me` | `Citrix-CustomerId` |
| DaaS Configuration Logging: each administrator change in Studio, Web Studio, PowerShell and the APIs, such as delivery groups, machine catalogs, policies, hosting and administrators | `configlog` | `GET /cvad/manage/ConfigLog/Operations` | `Citrix-CustomerId`, `Citrix-InstanceId` (the site), `X-TimeZone: UTC` |
| DaaS Monitor: each session connection, with its client, session, user and machine | `connection` | `GET /monitorodata/Connections` | `Citrix-CustomerId` |

Every request carries `Authorization: CwsAuth Bearer=<token>`. The bridge writes each System Log record's keys with a capital first letter, as Citrix's examples show them, since its API reference spells them in camelCase.

Python 3.9 or later, standard library only. One file: `citrix_cloud_logs_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/citrix/citrix-daas-and-citrix-cloud` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Citrix Cloud.**

1. As a full access administrator, go to Identity and Access Management > API Access > Service principals, choose Create service principal, and copy its client ID and secret; the secret is shown once, and expires on the date you choose. A service principal has roles of its own, not those of the administrator who creates it, so give it only read access: Citrix's Configuration Logging page says the DaaS Read Only Administrator role can view configuration logs, and Monitor needs a role that can view Monitor data. Citrix doesn't document which access the System Log API needs; if the service principal is refused it, the bridge says so, and you can leave `systemlog` out of `CITRIX_LOGS`. Citrix also lets you limit the addresses a service principal's token can be requested from.
2. The Customer ID is shown on the API Access page.
3. A Citrix Cloud account in the Japan region uses `https://api.citrixcloud.jp` as `CITRIX_API_URL`; the US, EU and Asia Pacific South regions use `https://api.cloud.com`.

Citrix keeps System Log records for 90 days and Configuration Logging for 180 days. Monitor keeps up to 90 days, depending on the DaaS edition.

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `CITRIX_CUSTOMER_ID` | none | The Citrix Cloud Customer ID. |
| `CITRIX_CLIENT_ID` | none | The service principal's client ID. |
| `CITRIX_CLIENT_SECRET` | none | The service principal's secret. |
| `CITRIX_API_URL` | `https://api.cloud.com` | The API's scheme and host for your region. |
| `CITRIX_LOGS` | `systemlog,configlog,connections` | The logs to read, comma separated. |
| `CITRIX_SITE_IDS` | none | The DaaS site IDs to read Configuration Logging for, comma separated. Empty reads every site `/cvad/manage/me` lists for the customer. |
| `BRIDGE_STATE_FILE` | `citrix_cloud_logs_state.json` | Each log's last window end and the records sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 2160 (90 days). |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for records Citrix lists late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 citrix_cloud_logs_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 citrix_cloud_logs_bridge.py                   # one pass, for cron or a systemd timer
python3 citrix_cloud_logs_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every log was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/citrix-cloud-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Citrix Cloud logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/citrix-cloud-logs/citrix_cloud_logs_bridge.py --interval 300
EnvironmentFile=/etc/citrix-cloud-logs.env
DynamicUser=yes
StateDirectory=citrix-cloud-logs
WorkingDirectory=/var/lib/citrix-cloud-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the APIs

- The bridge gets a token with `POST /cctrustoauth2/<customerId>/tokens/clients` and the form fields `grant_type=client_credentials`, `client_id` and `client_secret`, keeps it until a minute before `expires_in` runs out, and gets a new one if Citrix refuses it.
- Each run reads each log from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now.
- System Log: `StartDateTime` and `EndDateTime` in UTC, `Limit=200`, then each `ContinuationToken` until a page has none. The same token twice stops the run.
- Configuration Logging, for each site: `days` (whole days back from now, enough to cover the window), `limit=250` and each `continuationToken`. Citrix lists the most recent operations first, so the bridge stops at the first page that reaches past the window's start, and leaves operations dated after the window's end for the next run. Times come from `FormattedStartTime`, or `StartTime`, in UTC since the bridge sends `X-TimeZone: UTC`.
- Monitor: `$filter=CreatedDate ge <start> and CreatedDate lt <end>`, `$orderby=CreatedDate` and `$expand=Session($expand=User,Machine)`, following `@odata.nextLink` only while it stays on `CITRIX_API_URL`'s host and the `/monitorodata/` path.
- A connection keeps its `Id` as it changes, so it is sent once, when it is created. A System Log record can have no `RecordId`, and an operation changes when it completes, so those are known by a hash of the whole record: an operation that completes after it was sent is sent again. A window's end is saved only after every page of it was sent, and never past the time of the run.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. A 401 or 403 means the client was refused or its administrator can't read the log, a 404 that the URL, customer or site is wrong, and a 400 shows Citrix's message. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Citrix or HTTP Ingest is refused, not followed, so no token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

Citrix Analytics for Security isn't covered: it exports to SIEMs only over Kafka, which a standard library script can't reasonably consume.

The bridge never logs the client secret, the token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/citrix-cloud-logs -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, the System Log, the DaaS `me`, Configuration Logging and Monitor OData endpoints, built from the documented shapes, and of HTTP Ingest, and check the token request, its reuse and renewal, the headers, paging with continuation tokens and `@odata.nextLink`, camelCase answers, the sites, the days asked for and where Configuration Logging stops, the time formats, overlaps and repeats, that a window ends only after HTTP Ingest accepted it and never past now, refused credentials and access, dry-run, retries, batching and gzip, refused redirects and next pages on another host, the response size cap, settings, and that no secret reaches the log.

## References

- Citrix Cloud System Log API (requests, records, continuation tokens): https://developer-docs.citrix.com/en-us/citrix-cloud/citrix-cloud-systemlog/gettingstarted
- Citrix Cloud System Log (what it records, retention): https://docs.citrix.com/us/en/citrix-cloud/system-log.html
- Citrix Cloud System Log event types: https://docs.citrix.com/us/en/citrix-cloud/events.html
- Citrix Cloud APIs, service principals and the token request: https://developer-docs.citrix.com/en-us/citrix-cloud/citrix-cloud-api-overview/get-started-with-citrix-cloud-apis.html
- Citrix DaaS REST API, the site ID: https://developer-docs.citrix.com/en-us/citrix-daas-service-apis/citrix-daas-rest-apis/how-to-get-site-id
- Citrix DaaS REST API, configuration operations: https://developer-docs.citrix.com/en-us/citrix-daas-service-apis/citrix-daas-rest-apis/how-to-get-configuration-operations.html
- Citrix DaaS Configuration Logging (what is logged, retention, permissions): https://docs.citrix.com/us/en/citrix-daas/manage-deployment/configuration-logging.html
- Citrix Monitor OData API, connections: https://developer-docs.citrix.com/en-us/monitor-service-odata-api/how-to-get-connections
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
