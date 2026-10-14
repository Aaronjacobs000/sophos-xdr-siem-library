# IBM MaaS360 administrator audit bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real MaaS360 account or Sophos NG-SIEM HTTP Ingest integration. IBM's per-endpoint API reference is inside the MaaS360 Portal, behind a login, so its unit tests use a local mock server built from IBM's public authentication page and the response shapes in the MIT-licensed Cortex XSOAR IBM MaaS360 Security event collector and its test data. Run it with `--dry-run` first and check what it would send.

MaaS360 has no syslog export or webhook for portal audit data (the Mobile Enterprise Gateway's syslog covers gateway authentication only), so this script authenticates to the MaaS360 web services, reads two administrator reports by time window, and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds a `maas360_record` key naming the report, and the library parsers in `parsers/ibm/maas360` normalize the records.

| Source (`MAAS360_SOURCES`) | Report | `maas360_record` | Schema |
| --- | --- | --- | --- |
| `admin_login` | `GET /account-provisioning/administrator/1.0/getAdminLoginReports/customer/{billingId}`: portal administrator logins, with status, IP address, browser and operating system | `admin_login` | Auth |
| `admin_change` | `GET /account-provisioning/administrator/1.0/getAdminChangesAudit/customer/{billingId}`: changes to administrator accounts, such as roles added or removed | `admin_change` | ManagementEvent |

Device compliance events, device actions and policy audit reports aren't collected.

Python 3.9 or later, standard library only. One file: `maas360_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/ibm/maas360` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**MaaS360.** In the MaaS360 Portal, go to Setup > Manage Access Keys and generate a web services access key; note its App ID, App Version, Platform ID and App Access Key. Create an administrator for the bridge with read-only access, and note its user name and password. Your billing ID is the Account ID in the portal's profile menu. The API base is your account's services host, for example `https://services.m3.maas360.com`.

## Configuration

Everything comes from environment variables. Keep keys and passwords in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `MAAS360_API_URL` | none | Your MaaS360 services host, for example `https://services.m3.maas360.com`. |
| `MAAS360_BILLING_ID` | none | The account's billing ID. |
| `MAAS360_APP_ID` | none | App ID from the access key. |
| `MAAS360_APP_VERSION` | `1.0` | App Version from the access key. |
| `MAAS360_PLATFORM_ID` | `3` | Platform ID from the access key. |
| `MAAS360_APP_ACCESS_KEY` | none | App Access Key. |
| `MAAS360_USERNAME` | none | The bridge's administrator user name. |
| `MAAS360_PASSWORD` | none | That administrator's password. |
| `MAAS360_SOURCES` | `admin_login,admin_change` | Comma-separated: `admin_login`, `admin_change`. |
| `BRIDGE_STATE_FILE` | `maas360_state.json` | Cursors and fingerprints of recently sent records. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. MaaS360 keeps these reports for 60 days. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much before the cursor each run re-reads. The reports have no record ID, so repeats are dropped by content. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 maas360_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 maas360_bridge.py                   # one pass, for cron or a systemd timer
python3 maas360_bridge.py --interval 900    # keep polling every 15 minutes
```

Exit code 0 means every report was read and sent. On an error the bridge logs the report and the HTTP status, stops, and leaves that report's cursor where it was, so the next run reads the same window again.

## How it reads the API

- It authenticates with `POST /auth-apis/auth/2.0/authenticate/customer/{billingId}` (JSON `authRequest.maaS360AdminAuth`) and sends the token as `Authorization: MaaS token="<token>"`. MaaS360 tokens last 60 minutes; on a 401, `Token invalid` or `Token expired` the bridge authenticates again once. A failed authentication can come back as HTTP 200 with an `errorCode`, and the bridge stops on it.
- For each report it asks for `fromDate` (the cursor minus the overlap) to `toDate` (now), in epoch milliseconds, 250 records a page from `pageNumber` 1 until a page comes back short. A single record can come back as an object rather than a list.
- It sends the records it hasn't sent, oldest first, then moves the cursor to the newest `loginAttemptTime` or `updateDate`.

IBM doesn't publish a rate limit for these reports. The bridge waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After`. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the MaaS360 API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the password, the access key, the MaaS360 token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/ibm-maas360 -p 'test_*.py' -v
```

The tests start a local mock of the MaaS360 authentication and report endpoints and HTTP Ingest, built from the documented shapes, and check paging, single-record objects, tagging, oldest-first order, the lookback, the cursor, a failed authentication inside HTTP 200, renewing an expired token, dry-run, retries, batching and gzip, and that no secret reaches the log.

## References

- IBM MaaS360 API reference for web services (authentication, token format; the full endpoint reference is in the MaaS360 Portal under Setup > Web Services API > Documentation): https://www.ibm.com/docs/en/maas360?topic=services-maas360-api-reference-web
- IBM MaaS360 administrator login report (report fields): https://www.ibm.com/docs/en/SS8H2S/com.ibm.mc.doc/pag_source/tasks/pag_setup_view_admin_login_report.htm
- IBM MaaS360 administrator and roles audit reports: https://www.ibm.com/docs/en/SS8H2S/com.ibm.mc.doc/pag_source/concepts/audit_data_reports_portal_administration.htm
- Cortex XSOAR IBM MaaS360 Security event collector (MIT; endpoint paths and response shapes): https://github.com/demisto/content/tree/master/Packs/IBMMaaS360Security
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
