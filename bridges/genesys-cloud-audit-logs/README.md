# Genesys Cloud audit logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Genesys Cloud organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the Genesys Cloud Platform API reference and its Audit pages. Run it with `--dry-run` first and check what it would send.

Genesys Cloud CX records an audit event for sign-ins and failed sign-ins, roles and permissions, OAuth clients, users, queues, trunks, phone numbers, recordings, integrations and most other changes in an organization. Its push options are notifications and Amazon EventBridge, neither of which can post to HTTP Ingest. The Audit API's asynchronous query keeps 365 days of events and is the only API path that returns successful sign-ins and every service; the real-time query keeps 14 days and leaves some out. So this script runs an asynchronous query each run with an OAuth client that uses the Client Credentials grant, and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/genesys/genesys-cloud-cx` normalize them.

Each event goes on as Genesys sends it (an `AuditLogMessage`: `id`, `user`, `client`, `remoteIp`, `serviceName`, `level`, `eventDate`, `message`, `action`, `entity`, `entityType`, `status`, `propertyChanges` and the rest), with `"genesys_record": "audit"` first.

Python 3.9 or later, standard library only. One file: `genesys_audit_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/genesys/genesys-cloud-cx` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Genesys Cloud.** Create a role with only the Audits > Audit > View permission (`audits:audit:view`). Then go to Admin > Integrations > OAuth, choose Add Client, pick the Client Credentials grant type, and on the Roles tab give the client only that role. Save, and copy the Client ID and Client Secret. A Client Credentials client isn't limited by scopes (Genesys authorizes it for every scope), so the role is what keeps it to reading audits. Genesys documents no license or add-on for the Audit API.

Set `GENESYS_REGION` to the region domain of your organization, the part after `apps.` in the address you sign in at:

| Region (AWS region) | `GENESYS_REGION` |
| --- | --- |
| US East (Virginia), us-east-1 | `mypurecloud.com` |
| US East 2 (Ohio), us-east-2, FedRAMP | `use2.us-gov-pure.cloud` |
| US West (Oregon), us-west-2 | `usw2.pure.cloud` |
| Canada (Central), ca-central-1 | `cac1.pure.cloud` |
| South America (Sao Paulo), sa-east-1 | `sae1.pure.cloud` |
| Mexico (Central), mx-central-1 | `mxc1.pure.cloud` |
| Europe (Ireland), eu-west-1 | `mypurecloud.ie` |
| Europe (London), eu-west-2 | `euw2.pure.cloud` |
| Europe (Frankfurt), eu-central-1 | `mypurecloud.de` |
| Europe (Zurich), eu-central-2 | `euc2.pure.cloud` |
| Middle East (UAE), me-central-1 | `mec1.pure.cloud` |
| EU sovereign cloud, eusc-de-east-1 | `edee1.eusc-pure.cloud` |
| Asia Pacific (Sydney), ap-southeast-2 | `mypurecloud.com.au` |
| Asia Pacific (Singapore), ap-southeast-1 | `apse1.pure.cloud` |
| Asia Pacific (Tokyo), ap-northeast-1 | `mypurecloud.jp` |
| Asia Pacific (Seoul), ap-northeast-2 | `apne2.pure.cloud` |
| Asia Pacific (Osaka), ap-northeast-3 | `apne3.pure.cloud` |
| Asia Pacific (Mumbai), ap-south-1 | `aps1.pure.cloud` |

The bridge calls `https://login.<region>/oauth/token` and `https://api.<region>`. For a region that isn't in the list yet, set `GENESYS_API_URL` and `GENESYS_TOKEN_URL` instead.

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `GENESYS_REGION` | none | The organization's region domain, from the table above. |
| `GENESYS_CLIENT_ID` | none | The OAuth client's Client ID. |
| `GENESYS_CLIENT_SECRET` | none | The OAuth client's Client Secret. With the client ID it is sent as `Authorization: Basic` to the token endpoint only. |
| `GENESYS_SERVICES` | none | Service names to query one at a time, comma separated, such as `PeoplePermissions,Telephony`. Empty means one query for every service. |
| `GENESYS_PAGE_SIZE` | `500` | Events per results page, 1 to 500. |
| `GENESYS_QUERY_WAIT_SECONDS` | `600` | How long to wait for a query to run before the run stops and the next one asks again. |
| `GENESYS_API_URL` | `https://api.<region>` | The API host. |
| `GENESYS_TOKEN_URL` | `https://login.<region>/oauth/token` | The OAuth token endpoint. |
| `BRIDGE_STATE_FILE` | `genesys_audit_state.json` | The last window end, and the IDs of events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. Genesys keeps audit events for 365 days. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for events that appear late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 genesys_audit_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 genesys_audit_bridge.py                   # one pass, for cron or a systemd timer
python3 genesys_audit_bridge.py --interval 600    # keep polling every 10 minutes
```

Exit code 0 means every query ran and every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, an answer cut off partway, and a query that failed, was cancelled or didn't finish in time count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/genesys-cloud-audit-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Genesys Cloud audit logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/genesys-cloud-audit-logs/genesys_audit_bridge.py --interval 600
EnvironmentFile=/etc/genesys-cloud-audit-logs.env
DynamicUser=yes
StateDirectory=genesys-cloud-audit-logs
WorkingDirectory=/var/lib/genesys-cloud-audit-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- The bridge gets an access token from the token endpoint with the client credentials grant, and renews it five minutes before Genesys says it expires (a day by default), and once more if Genesys refuses it.
- Each run creates one query (`POST /api/v2/audits/query`) for the window from the last window's end, less the overlap, to now, in UTC, oldest event first. A longer window, such as the first run's lookback, is read as queries of up to 14 days: the Audits Query page gives 14 days as the longest interval and the retention page 30, so the bridge uses the shorter. A query's end is saved only after every page of its results was sent.
- The query names no service, so it covers every one. Genesys's API reference marks `serviceName` optional and Splunk's Genesys Cloud add-on queries without it, but the Audits Query page calls it required. If Genesys refuses the query, the error says to set `GENESYS_SERVICES`; the bridge then runs one query per named service, in turn, and keeps each one's window apart. `GET /api/v2/audits/query/servicemapping` lists the service names, and so does the Action Catalog.
- The bridge checks the query's state (`GET /api/v2/audits/query/{transactionId}`) after 1 second, then 2, 4 and 8, then every 10, until it is Succeeded, for up to `GENESYS_QUERY_WAIT_SECONDS`. Failed, Cancelled or still running at the end of the wait stops the run, and the next run asks again.
- It reads the results (`GET /api/v2/audits/query/{transactionId}/results`) 500 at a time and follows `cursor` until a page has none. A page Genesys says is too large (`response.entity.too.large`) is asked for again at half the size, down to 25. The bridge doesn't ask for a download URL (`allowRedirect`), whose file isn't documented and doesn't expand fields.
- An event is identified by its `id`, so an event read again in the overlap is dropped. Genesys doesn't say how soon an event shows up in a query; the overlap reads the last 15 minutes again by default.
- Genesys runs one audit query at a time for an organization, and allows 10 new queries a minute and 300 state and results reads a minute, for the whole organization. Another tool that queries audits in the same organization shares those limits. A 409 when the query is created (inferred to mean another query is running) stops the run, and the next run asks again. The bridge retries 429, 408, 500, 502, 503 and 504 with backoff, honoring `Retry-After` (Genesys sends it, in seconds, with every 429), up to 6 times. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Genesys or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/genesys-cloud-audit-logs -p 'test_*.py' -v
```

The tests start a local mock of the Genesys token endpoint, the audit query, its state and its results, and HTTP Ingest, built from the documented shapes, and check the token request, the query body, waiting for the query, paging by cursor and tagging, the window read again from the last end less the overlap with repeats dropped, 14-day queries within the 365 days Genesys keeps, a query per named service, a refused service name, a failed, cancelled, slow or blocked query, a page too large, a transaction ID that can't be used, that a window ends only after HTTP Ingest accepted it, a refused token, refused credentials and a missing permission, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings and regions, and that no secret reaches the log.

## References

- Audit API, Audits Query, Cursor and Page Size, Allowed time interval and Data retention period, Sample Usage, Action Catalog: https://developer.genesys.cloud/platform/audit/
- Platform API reference (`AuditQueryRequest`, `AuditQueryExecutionStatusResponse`, `AuditQueryExecutionResultsResponse`, `AuditLogMessage`): https://developer.genesys.cloud/platform/api/ and https://api.mypurecloud.com/api/v2/docs/swagger
- Client Credentials grant: https://developer.genesys.cloud/authorization/platform-auth/use-client-credentials
- Scopes (a Client Credentials client is authorized for every scope): https://developer.genesys.cloud/authorization/platform-auth/scopes
- Create an OAuth client: https://help.mypurecloud.com/articles/create-an-oauth-client/
- Regions: https://developer.genesys.cloud/platform/api/ and https://help.genesys.cloud/articles/aws-regions-for-genesys-cloud-deployment/ (Mexico and Singapore), and the region list in Genesys's Python SDK (the EU sovereign cloud): https://github.com/MyPureCloud/platform-client-sdk-python
- Limits (audit query concurrency, creates and reads a minute): https://developer.genesys.cloud/organization/organization/limits
- Rate limits and `Retry-After`: https://developer.genesys.cloud/platform/api/rate-limits
- Splunk's Genesys Cloud add-on (Apache-2.0), which queries without a service name: https://github.com/splunk/genesys_cloud_ta
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
