# Cisco Webex audit and call history bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Webex organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Webex's API reference. Run it with `--dry-run` first and check what it would send.

Webex Control Hub keeps admin audit events (who changed what, from which address) and, with Pro Pack, sign-in and sign-out events, and Webex Calling keeps each call's detailed call history record. Webex offers all three through its REST APIs, which are pull only. This script reads them and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"webex_record"` (`admin_audit`, `security_audit` or `cdr`) in front of each record, and the library parsers in `parsers/cisco/webex` normalize them. Sophos Fusion has no Webex integration.

| Data (`WEBEX_LOGS`) | Endpoint | Scope |
| --- | --- | --- |
| Access token | `POST https://webexapis.com/v1/access_token` (refresh token grant) | |
| `admin_audit` | `GET https://webexapis.com/v1/adminAudit/events` | `audit:events_read` |
| `security_audit` | `GET https://webexapis.com/v1/admin/securityAudit/events` (sign-ins and sign-outs) | `audit:events_read` |
| `cdr` | `GET https://analytics-calling.webexapis.com/v1/cdr_stream` (detailed call history, live stream) | `spark-admin:calling_cdr_read` |

Every request carries the access token as `Authorization: Bearer`. Python 3.9 or later, standard library only. One file: `webex_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/cisco/webex` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Webex.** Both audit APIs need a Full Admin's authorization, and the call history needs the Webex Calling Detailed Call History API access permission.

1. In the Webex Developer Portal, choose Create a New App, then Create a Service App. Select only the scopes for the logs you read: `audit:events_read` for the two audit logs and `spark-admin:calling_cdr_read` for the call history. Copy the Client ID and Client Secret; the secret is shown once.
2. Choose Request Admin Authorization. A Full Admin of your organization then authorizes the app in Control Hub under Management > Apps > Service Apps.
3. Back on the app's page in the Developer Portal, under Org Authorizations, select your organization, paste the client secret and copy the refresh token.
4. For the call history, Webex asks for a custom admin role with the Webex Calling Detailed Call History API access permission. Webex documents that permission for admins, and says Analytics scopes don't work with Service Apps. If the call history answers 403 with a Service App, use an Integration instead (a Webex OAuth app that an admin with that role and Full Admin authorizes), and give the bridge its client ID, secret and refresh token.
5. For sign-ins and sign-outs, Control Hub needs Pro Pack, and a Full Admin turns on Allow user authentication data under Management > Organization Settings > User authentication data.
6. Note the organization ID: Control Hub shows it as a UUID on its Account page. The bridge encodes a UUID the way Webex's Service Apps guide shows (`ciscospark://us/ORGANIZATION/<UUID>` in base64), or takes the long form the APIs return as it is.
7. Webex Calling keeps each organization's call history in one region. Set `WEBEX_CDR_URL` to your region's host: `https://analytics-calling.webexapis.com` (United States and Canada), `https://analytics-calling-eu.webexapis.com` (Europe), `https://analytics-calling-in.webexapis.com` (India), `https://analytics-calling-au.webexapis.com` (Australia) or `https://analytics-calling-gov.webexapis.com` (Webex for Government). The wrong host answers 451.

Access tokens last about 14 days and refresh tokens about 90. Webex can hand back a new refresh token with an access token, so the bridge keeps the newest one in `WEBEX_TOKEN_FILE` and uses it from then on. When Webex says the refresh token expires within 14 days, the bridge logs a warning on every run: authorize the app again and set `WEBEX_REFRESH_TOKEN` to the new refresh token. A new `WEBEX_REFRESH_TOKEN` replaces the saved one.

## Configuration

Everything comes from environment variables. Keep the client secret, the refresh token and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `WEBEX_CLIENT_ID` | none | The Service App's (or Integration's) Client ID. |
| `WEBEX_CLIENT_SECRET` | none | The client secret. It is sent to the token endpoint only. |
| `WEBEX_REFRESH_TOKEN` | none | The refresh token from the app's authorization. |
| `WEBEX_ORG_ID` | none | The organization ID, as a UUID or the long form. Required for `admin_audit` and `security_audit`. |
| `WEBEX_LOGS` | `admin_audit,security_audit,cdr` | The logs to read, comma separated. |
| `WEBEX_API_URL` | `https://webexapis.com` | The Webex API host, for the token and the audit logs. |
| `WEBEX_CDR_URL` | `https://analytics-calling.webexapis.com` | The call history host for your organization's region. |
| `WEBEX_TOKEN_FILE` | `webex_tokens.json` | Where the newest refresh token is kept, readable by its owner only. It holds a credential: keep it with the state file, out of backups others can read. |
| `BRIDGE_STATE_FILE` | `webex_state.json` | Each log's last window end and the records sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. The call history goes back at most 12 hours. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for records listed late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 webex_bridge.py --dry-run         # print the NDJSON it would send; sends nothing and saves no state
python3 webex_bridge.py                   # one pass, for cron or a systemd timer
python3 webex_bridge.py --interval 300    # keep polling every 5 minutes
```

A dry run saves no state, but it does save a new refresh token Webex hands back, since the old one may stop working.

Exit code 0 means every log was read and sent. On an error the bridge logs it with the HTTP status and Webex's message, stops, and leaves that log's window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration, credential or permission error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them. A certificate that isn't trusted, or that doesn't name the host, stops the run at once.

As a systemd service that polls, with the variables in `/etc/webex-audit-and-call-history.env` (owned by root, mode 600):

```ini
[Unit]
Description=Cisco Webex audit and call history bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/webex-audit-and-call-history/webex_bridge.py --interval 300
EnvironmentFile=/etc/webex-audit-and-call-history.env
DynamicUser=yes
StateDirectory=webex-audit-and-call-history
WorkingDirectory=/var/lib/webex-audit-and-call-history
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet. With `DynamicUser=yes`, the state and token files in the state directory belong to the service alone.

## How it reads the API

- Each run gets an access token with the refresh token grant (`grant_type=refresh_token`, `client_id`, `client_secret`, `refresh_token`, form encoded) and keeps it until 5 minutes before the `expires_in` Webex gives. When an API answers 401, the bridge gets a new token and sends the request once more.
- The admin audit log is read with `orgId`, `from`, `to` and `max=200`, and the security audit log with `orgId`, `startTime`, `endTime` and `max=1000`, from the end of the last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now. Times are UTC to the millisecond. Pages follow the `Link` header's `rel="next"` URL; a full admin audit page without one asks for the next page with `offset`, which that API documents.
- The call history comes from the live stream endpoint, which Webex recommends for continuous collection: it goes by the time each record reached Webex and sends records that arrive late in later windows. Webex takes an end at least a minute ago, a start at most 12 hours ago, and at most 2 hours between them, so the bridge reads to a minute and a half before now, in parts of at most 2 hours, and never more than 12 hours back. A window that starts earlier than that, after the bridge was stopped for longer, is cut at 12 hours with a warning, since older records can't be read from the stream.
- Webex allows the call history 1 first request a minute per token and 10 more for its other pages, so each part's first request waits at least 61 seconds after the last one, and each next page 6.5 seconds. Catching up 12 hours takes about 6 minutes. The other requests are spaced 0.2 seconds apart.
- Audit events have a unique `id` and call records a `Report ID`, so the bridge drops repeats by them. A window's end is saved only after every page of it was sent, and never past the time of the run. A next link to a host other than the one it was set up for is refused, so the token only goes there.
- A refused token request (HTTP 400, 401 or 403) stops the run with Webex's message. A 401 after a new token, or a 403, stops it with the scope, role or setting that log needs. A 451 from the call history names `WEBEX_CDR_URL`. A 400 or 404 stops it with Webex's message. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Webex or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

Each record goes out as Webex returns it, after `webex_record` (`admin_audit`, `security_audit` or `cdr`).

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the refresh or access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/webex-audit-and-call-history -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, both audit APIs, the call history stream and HTTP Ingest, built from the documented shapes, and check the refresh token grant, the access token's reuse and renewal, a new refresh token saved and used from then on (in a dry run too) and a new `WEBEX_REFRESH_TOKEN` taking over, the expiry warning, paging with the `Link` header and with `offset`, a next link to another host, the call history's 2-hour parts, 12-hour limit and request spacing, the region answer, the org ID forms, the record field, windows, overlaps and repeats, that a window ends only after HTTP Ingest accepted it and never past now, the logs setting, token and API errors, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- List Admin Audit Events: https://developer.webex.com/admin/docs/api/v1/admin-audit-events/list-admin-audit-events
- List Security Audit Events: https://developer.webex.com/admin/docs/api/v1/security-audit-events/list-security-audit-events
- Get Live Stream Detailed Call History and Get Detailed Call History: https://developer.webex.com/calling/docs/api/v1/reports-detailed-call-history/get-detailed-call-history
- Webex OpenAPI specs (webex-admin.json and webex-cloud-calling.json): https://github.com/webex/webex-openapi-specs
- Service Apps: https://developer.webex.com/docs/service-apps
- Integrations and the refresh token: https://developer.webex.com/docs/integrations
- Log and analyze user sign-ins and sign-outs: https://help.webex.com/en-us/article/pf66vg/Log-and-analyze-user-sign-ins-and-sign-outs
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
