# Microsoft Teams Phone call logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Microsoft 365 tenant or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Microsoft's Graph reference. Run it with `--dry-run` first and check what it would send.

Teams Phone lists each PSTN call (Calling Plans and Operator Connect) and each Direct Routing call in call logs that Microsoft Graph offers, pull only. The Sophos Fusion Microsoft 365 integration takes Teams admin and user activity, but not these call logs. This script reads them through Graph and sends each row as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"teams_record"` (`pstn` or `direct_routing`) and the tenant ID in front of each row, and the library parsers in `parsers/microsoft/teams-phone-call-logs` normalize them.

| Data | Endpoint |
| --- | --- |
| Access token (client credentials) | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| PSTN calls (`pstnCallLogRow`) | `GET https://graph.microsoft.com/v1.0/communications/callRecords/getPstnCalls(fromDateTime=...,toDateTime=...)` |
| Direct Routing calls (`directRoutingLogRow`) | `GET https://graph.microsoft.com/v1.0/communications/callRecords/getDirectRoutingCalls(fromDateTime=...,toDateTime=...)` |

Every Graph request carries the access token as `Authorization: Bearer`. Python 3.9 or later, standard library only. One file: `teams_call_logs_bridge.py`.

Microsoft says getPstnCalls doesn't return Telstra Calling Plan calls.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/microsoft/teams-phone-call-logs` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Microsoft Entra.**

1. In the Microsoft Entra admin center, go to App registrations and choose New registration. Name it, keep "Accounts in this organizational directory only", and register it.
2. Under API permissions, choose Add a permission > Microsoft Graph > Application permissions, add `CallRecords.Read.All`, and choose Grant admin consent. It is the permission Microsoft's pages for both functions list. It also reads every call record and online meeting, so keep the app's secret as safe as the HTTP Ingest key. Microsoft's permission reference also lists `CallRecord-PstnCalls.Read.All`, for the PSTN and Direct Routing logs only, but the function pages don't name it, and the bridge hasn't been tried with it.
3. Under Certificates & secrets, add a client secret and copy its value. Note its expiry: the bridge stops with a refused token request once it expires.
4. Note the Application (client) ID and the Directory (tenant) ID on the app's Overview page.

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `TEAMS_TENANT_ID` | none | The Directory (tenant) ID, or a verified domain such as `contoso.onmicrosoft.com`. |
| `TEAMS_CLIENT_ID` | none | The app's Application (client) ID. |
| `TEAMS_CLIENT_SECRET` | none | The client secret's value. It is sent to the token endpoint only. |
| `TEAMS_LOGS` | `pstn,direct_routing` | The logs to read, comma separated. |
| `TEAMS_GRAPH_URL` | `https://graph.microsoft.com` | The Graph host. The token's scope is this host plus `/.default`. |
| `TEAMS_LOGIN_URL` | `https://login.microsoftonline.com` | The Microsoft Entra token host. |
| `BRIDGE_STATE_FILE` | `teams_call_logs_state.json` | Each log's last window end and the rows sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. A window over 89 days is read in parts, since Graph takes at most 90 days a query. |
| `BRIDGE_OVERLAP_SECONDS` | `21600` | How far before the last window's end each run reads again, for calls Graph lists late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

Graph lists a call by its start time, and only once it has ended. Microsoft doesn't say how soon a call reaches the log, so each run reads the last 6 hours again by default and drops the rows it already sent. Raise `BRIDGE_OVERLAP_SECONDS` if your calls run longer, or if calls arrive later than that.

## Run it

```bash
python3 teams_call_logs_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 teams_call_logs_bridge.py                   # one pass, for cron or a systemd timer
python3 teams_call_logs_bridge.py --interval 900    # keep polling every 15 minutes
```

Exit code 0 means every log was read and sent. On an error the bridge logs it with the HTTP status and Microsoft's error code, stops, and leaves that log's window where it was, so the next run reads the same rows again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration, credential or permission error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them. A certificate that isn't trusted, or that doesn't name the host, stops the run at once.

As a systemd service that polls, with the variables in `/etc/teams-phone-call-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Microsoft Teams Phone call logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/teams-phone-call-logs/teams_call_logs_bridge.py --interval 900
EnvironmentFile=/etc/teams-phone-call-logs.env
DynamicUser=yes
StateDirectory=teams-phone-call-logs
WorkingDirectory=/var/lib/teams-phone-call-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run gets an app-only access token with the client credentials grant (`client_id`, `client_secret`, `scope` set to the Graph host plus `/.default`, `grant_type=client_credentials`, form encoded) and keeps it until a minute before the `expires_in` Microsoft gives. When Graph answers 401, the bridge gets a new token and sends the request once more.
- Each log is read from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now. `fromDateTime` and `toDateTime` are UTC times to the second, and the window is split into parts of at most 89 days. Pages follow `@odata.nextLink`, 1,000 rows each, until a page has none. A next link to a host other than `TEAMS_GRAPH_URL` is refused, so the token only goes there.
- Every row has a unique `id`, so the bridge drops repeats by `id`. A part's end is saved only after every page of it was sent, and never past the time of the run.
- A refused token request (HTTP 400, 401 or 403) stops the run with Microsoft's error and AADSTS code, such as `invalid_client, AADSTS7000215` for a wrong secret, without the trace and correlation IDs. A Graph 401 after a new token, or a 403, stops it with a pointer to the permission. A 400 or 404 stops it with Graph's error code and message.
- Graph allows 50 requests a minute for each of these logs, so the bridge spaces its requests 1.25 seconds apart. It waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Microsoft or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

Each row goes out as Graph returns it, after these fields:

| Field | Value |
| --- | --- |
| `teams_record` | `pstn` or `direct_routing` |
| `teams_tenant_id` | `TEAMS_TENANT_ID` |

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/teams-phone-call-logs -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, both Graph functions and HTTP Ingest, built from the documented shapes, and check the token request and its reuse and renewal, the bearer header, paging with `@odata.nextLink` and a next link to another host, the function parameters and the 89-day parts, the record fields, windows, overlaps and repeats, the lookback, that a window ends only after HTTP Ingest accepted it and never past now, the logs setting, token and Graph errors, request spacing, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- getPstnCalls: https://learn.microsoft.com/en-us/graph/api/callrecords-callrecord-getpstncalls?view=graph-rest-1.0
- getDirectRoutingCalls: https://learn.microsoft.com/en-us/graph/api/callrecords-callrecord-getdirectroutingcalls?view=graph-rest-1.0
- pstnCallLogRow: https://learn.microsoft.com/en-us/graph/api/resources/callrecords-pstncalllogrow?view=graph-rest-1.0
- directRoutingLogRow: https://learn.microsoft.com/en-us/graph/api/resources/callrecords-directroutinglogrow?view=graph-rest-1.0
- Client credentials flow: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
- Graph throttling limits (call records and PSTN logs): https://learn.microsoft.com/en-us/graph/throttling-limits
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
