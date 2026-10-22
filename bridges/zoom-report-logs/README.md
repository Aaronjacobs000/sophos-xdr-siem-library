# Zoom report logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Zoom account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Zoom's API references and OpenAPI documents. Run it with `--dry-run` first and check what it would send.

Zoom's sign-in and sign-out activity report and its operation logs (admin and user changes, such as users added, settings changed and recordings deleted) are available through the Reports API. Zoom can also send webhooks, but a webhook endpoint has to answer Zoom's URL validation challenge within 3 seconds, which HTTP Ingest can't, and the sign-in webhook has no IP address. So this script polls the two reports with a Server-to-Server OAuth app and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/zoom/zoom-sign-in-and-operation-logs` normalize them.

It also reads Zoom Phone and Zoom Contact Center reports, but only the ones you name in `ZOOM_REPORTS`, since each needs that product and its own scopes: the phone system operation logs and the account's call history, and the Contact Center operation logs and voice call logs. The library parsers in `parsers/zoom/zoom-phone` and `parsers/zoom/zoom-contact-center` normalize those.

| Report (`ZOOM_REPORTS`) | Endpoint | `zoom_record` |
| --- | --- | --- |
| `activities`: sign-ins and sign-outs, with email, IP address, client type and version | `GET /v2/report/activities` | `signin` |
| `operationlogs`: who changed what in the account, by category | `GET /v2/report/operationlogs` | `operation` |
| `phone_operationlogs`: Zoom Phone admin changes, such as call forwarding, phone numbers and users | `GET /v2/phone/reports/operationlogs` | `phone_operation` |
| `phone_call_history`: every Zoom Phone call on the account, with direction, the international flag, caller and callee, country and result | `GET /v2/phone/call_history` | `phone_call` |
| `cc_operation_logs`: Zoom Contact Center admin and agent operations, such as Unmask, Download, Listen and Export | `GET /v2/contact_center/reports/operation_logs` | `cc_operation` |
| `cc_voice_calls`: Zoom Contact Center voice calls, with caller, callee, direction, country, result and charge | `GET /v2/contact_center/voice_calls` | `cc_voice_call` |

Each record goes on as Zoom sends it, with `zoom_record` first and `account_id`, the Zoom account ID, so records from several accounts can be told apart.

Python 3.9 or later, standard library only. One file: `zoom_report_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/zoom/zoom-sign-in-and-operation-logs` (and `parsers/zoom/zoom-phone` or `parsers/zoom/zoom-contact-center` for those reports) under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Zoom.** The reports need a Pro plan or higher. In the Zoom App Marketplace, open Developers > Created Apps, choose Build an app, then Server-to-Server OAuth app, and copy the Account ID, Client ID and Client Secret. Under Scopes, add only the read-only report scopes: `report:read:user_activities:admin` and `report:read:operation_logs:admin` (or the classic `report:read:admin`). Fill in the required information and activate the app. Creating the app needs the role permission to view and edit Server-to-Server OAuth apps, and an admin role that allows the report scopes.

For the Zoom Phone and Contact Center reports, add only the read scopes for the reports you name:

| Report | Granular scope (classic scope) | Zoom needs |
| --- | --- | --- |
| `phone_operationlogs` | `phone:read:operation_logs:admin` (`phone:read:admin`) | A Pro plan or higher and a Zoom Phone plan |
| `phone_call_history` | `phone:read:list_call_logs:admin` (`phone:read:admin` or `phone_call_log:read:admin`) | A Business or Enterprise account, Zoom Phone licenses, and an app creator who is the account owner or has a role with Zoom Phone management |
| `cc_operation_logs` | `contact_center:read:operation_logs:admin` (`contact_center_operation_logs:read:admin`) | Zoom Contact Center, and an app creator whose Contact Center role has the privilege |
| `cc_voice_calls` | `contact_center:read:voice_call_log:admin` (`contact_center_voice_call:read:admin`) | Zoom Contact Center, and an app creator whose Contact Center role has the privilege |

The same app can hold all of them. A report Zoom refuses stops the run with an error that names what it needs.

`https://api.zoom.us` works for every account. Zoom also lists regional hosts, such as `https://api-au.zoom.us` for Australia, and names the account's in the token response's `api_url`; set `ZOOM_API_URL` to it to send requests straight to that region. The bridge never takes a host from a response.

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `ZOOM_ACCOUNT_ID` | none | The Server-to-Server OAuth app's Account ID. |
| `ZOOM_CLIENT_ID` | none | The app's Client ID. |
| `ZOOM_CLIENT_SECRET` | none | The app's Client Secret. With the client ID it is sent as `Authorization: Basic` to the token endpoint only. |
| `ZOOM_REPORTS` | `activities,operationlogs` | The reports to read, comma separated: `activities`, `operationlogs`, `phone_operationlogs`, `phone_call_history`, `cc_operation_logs` and `cc_voice_calls`. |
| `ZOOM_OPERATION_CATEGORY` | `all` | The `operationlogs` category to read: `all`, `user`, `user_settings`, `account`, `billing`, `im`, `recording`, `phone_contacts`, `webinar`, `sub_account`, `role` or `zoom_rooms`. |
| `ZOOM_PAGE_SIZE` | `300` | Records per page, 1 to 300. Contact Center voice calls are read at most 100 a page, the most Zoom serves. |
| `ZOOM_API_URL` | `https://api.zoom.us` | The API host. |
| `ZOOM_TOKEN_URL` | `https://zoom.us/oauth/token` | Zoom's OAuth token endpoint. |
| `BRIDGE_STATE_FILE` | `zoom_report_state.json` | Each report's last window end and the records sent within the days it reads again. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. Zoom keeps these reports for six months. |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How far before the last window's end each run reads again, for records that appear late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 zoom_report_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 zoom_report_bridge.py                   # one pass, for cron or a systemd timer
python3 zoom_report_bridge.py --interval 600    # keep polling every 10 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/zoom-report-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Zoom sign-in and operation logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/zoom-report-logs/zoom_report_bridge.py --interval 600
EnvironmentFile=/etc/zoom-report-logs.env
DynamicUser=yes
StateDirectory=zoom-report-logs
WorkingDirectory=/var/lib/zoom-report-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- The bridge gets an access token from the token endpoint with the account credentials grant, and renews it a minute before its hour runs out, and once more if Zoom refuses it.
- The reports' `from` and `to` are dates with no time. Zoom's reference doesn't give their time zone; on the developer forum a Zoom staff member advises UTC for date parameters, since that is how Zoom stores times, so the bridge sends UTC dates. Each run reads whole days, from the day the last window ended in, less the overlap, to today, in ranges of up to 30 days (Zoom gives at most a month per request), and follows `next_page_token` to the last page. A record is identified by its fields (time, user, type and the rest) and by how many identical records came before it in the window, so a repeat read is dropped but two identical records in the same second both go on. A window's end is saved only after every page of it was sent.
- The two call reports take a time of day as well as a date, so the bridge asks for the first and last second of each day in UTC rather than leave Zoom to decide what a date alone means. Zoom Phone calls are read by end time (`time_type=end_time`), so a call shows up once it is over. Zoom reads the `Z` in a Contact Center time as a plain letter, so voice calls are asked for with `+00:00` instead, and their times come back with that offset. Zoom's reference doesn't say which time the voice call range filters on; it says a call is listed once it is completed. A call is identified by its ID and end time, and remembered until its end time is older than the days read again, so a call that ran for hours isn't sent twice. Contact Center operation logs carry their own ID; the Zoom Phone operation logs are identified by their fields, like the account operation logs.
- Zoom's reference gives the call history's `recording_status` filter a default of `recorded`. The bridge doesn't send it, and whether Zoom then lists only recorded calls isn't documented, so compare a dry run with the call history in the Zoom web portal before you rely on it.
- Every report is rated Heavy: Zoom allows 10 requests a second on Pro and 40 on Business and higher, with a daily cap shared by all of an account's apps (30,000 on Pro). The bridge retries a per-second 429, 408, 500, 502, 503 and 504 with backoff, honoring `Retry-After`, up to 6 times. Zoom's daily limit lasts until the next day, so the run stops with an error that says so, and with `--interval` the bridge tries again at the next interval. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Zoom or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/zoom-report-logs -p 'test_*.py' -v
```

The tests start a local mock of Zoom's token endpoint, the six reports and HTTP Ingest, built from the documented shapes, and check the token request, paging and tagging, the Zoom Phone and Contact Center reports read only when named, their time formats and page sizes, calls read by end time and not sent twice, a refused report that names what it needs, whole days read again and repeats dropped, identical records in the same second, month-long ranges within the six months Zoom keeps, that a window ends only after HTTP Ingest accepted it, a refused token and refused credentials, dry-run, retries, the daily limit, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Reports API, sign-in and sign-out activity and operation logs (parameters, responses, scopes): https://developers.zoom.us/docs/api/meetings/ and the OpenAPI document https://developers.zoom.us/api-hub/meetings/methods/endpoints.json
- Zoom Phone API, phone system operation logs and account call history (parameters, responses, scopes, plans): https://developers.zoom.us/docs/api/phone/ and the call history migration guide https://developers.zoom.us/docs/phone/migrate/
- Zoom Contact Center API, operation logs and voice call logs (parameters, responses, scopes, time formats): https://developers.zoom.us/docs/api/contact-center/
- Server-to-Server OAuth (token request and response): https://developers.zoom.us/docs/internal-apps/s2s-oauth/
- Creating a Server-to-Server OAuth app: https://developers.zoom.us/docs/internal-apps/create/
- Rate limits: https://developers.zoom.us/docs/api/rate-limits/
- Webhooks (URL validation, why they need a relay): https://developers.zoom.us/docs/api/webhooks/
- Date parameters have no time and are UTC (Zoom staff answer on the developer forum, about another endpoint): https://devforum.zoom.us/t/from-and-to-date-parameters-in-the-zoom-api/26566
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
