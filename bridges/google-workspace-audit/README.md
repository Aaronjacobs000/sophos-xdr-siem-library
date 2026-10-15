# Google Workspace audit log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Google Workspace domain or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Google's Reports API reference, and sign every token request with a test RSA key the mock checks. Run it with `--dry-run` first and check what it would send.

Google Workspace's audit logs (sign-ins, admin console changes, OAuth token grants, SAML sign-ins, Drive activity and Chrome security events) reach other tools through the Admin SDK Reports API, which is pull only. Its push channels expire every 6 hours and Google says they aren't fully reliable, so this script polls each application with a service account and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/google/google-workspace-audit-logs` normalize them. Sophos Fusion's own Google Workspace integration takes Alert Center alerts only.

| Data | Endpoint | What the bridge adds |
| --- | --- | --- |
| Audit activities, one application at a time (`GWS_APPLICATIONS`) | `GET /admin/reports/v1/activity/users/all/applications/{app}` | `"google_workspace_record": "activity"` first, one record per event, and `params` |

An activity can hold several events, so the bridge sends one record per event: the activity with only that event in `events`. It also adds `params`, the event's `parameters` list as one object keyed by name (`{"login_type": "google_password", "is_suspicious": false}`), with each value as Google sends it: `value` and `intValue` as text, `multiValue` as a list, `boolValue` as true or false, and `messageValue` as an object.

Python 3.9 or later, standard library only. One file: `google_workspace_audit_bridge.py`. The service account signs its token request with RS256, so the script has a small RSA signer of its own.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/google/google-workspace-audit-logs` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Google Cloud.** In a Google Cloud project, turn on the Admin SDK API. Under IAM & Admin > Service Accounts, create a service account (it needs no IAM roles), then Keys > Add Key > Create new key > JSON, and save the file where only the bridge's account can read it. Note the service account's client ID (Unique ID). If an organization policy blocks key creation (`iam.disableServiceAccountKeyCreation`), an organization administrator has to allow it for this project.

**Google Workspace.** A super admin opens the Admin console, Security > Access and data control > API controls > Manage Domain Wide Delegation > Add new, enters the client ID, and grants only this scope, which is read-only:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly
```

The service account acts as an administrator, `GWS_ADMIN_EMAIL`. Give that account a custom admin role with only the Reports privilege, rather than a super admin. Drive activity is reported for Business and Enterprise editions only. Chrome browser events such as password reuse and malware downloads appear only for managed browsers with event reporting turned on (Chrome browser > Settings > Browser reporting > Event reporting).

## Configuration

Everything comes from environment variables. Keep the key file and the HTTP Ingest key in a secrets manager or a location only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `GWS_SERVICE_ACCOUNT_KEY_FILE` | none | Path to the service account's JSON key file. |
| `GWS_SERVICE_ACCOUNT_KEY` | none | The JSON key itself, instead of a file. Set one of the two. |
| `GWS_ADMIN_EMAIL` | none | The administrator the service account acts as, with the Reports privilege. |
| `GWS_APPLICATIONS` | `login,admin,token,saml,chrome,drive` | Reports API applications to read, comma separated. Drive is usually the busiest; leave it out if you don't need it. |
| `GWS_CUSTOMER_ID` | none | A customer ID to read, such as `C03az79cb`, sent as `customerId`. Leave it unset to read the administrator's own account. |
| `GWS_PAGE_SIZE` | `1000` | Activities per page, 1 to 1000. |
| `GWS_TOKEN_OVERLAP_SECONDS` | `14400` | How far before the last window's end the token application is read again. Google says OAuth token events can take a couple of hours to appear. |
| `GWS_API_URL` | `https://admin.googleapis.com` | The Reports API host. |
| `GWS_TOKEN_URL` | `https://oauth2.googleapis.com/token` | Google's OAuth 2.0 token endpoint. The key file's own `token_uri` is not used. |
| `BRIDGE_STATE_FILE` | `google_workspace_audit_state.json` | Each application's last window end and the events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. The Reports API keeps 180 days. |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How far before the last window's end the other applications are read again, for late events. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 google_workspace_audit_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 google_workspace_audit_bridge.py                   # one pass, for cron or a systemd timer
python3 google_workspace_audit_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 429 or 5xx that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.

## How it reads the API

- The bridge signs a JWT with the service account's key (issuer the service account, subject `GWS_ADMIN_EMAIL`, only the read-only audit scope) and trades it at the token endpoint for an access token, which lasts an hour. It renews the token a minute before it expires, and once more if Google refuses it.
- Each run reads every application in `GWS_APPLICATIONS` from the end of its last window, less the overlap, to now (`startTime` and `endTime`, RFC 3339), and follows `nextPageToken` to the last page. Google says most audit data appears within a couple of minutes, user account events within tens of minutes, and OAuth token events within a couple of hours, so each window starts before the last one ended, and ends a minute before now. Every event is keyed by its activity's time and unique qualifier and its place in the activity, and the bridge drops the ones it sent before. A window's end is saved only after every page of it was sent.
- The Reports API allows 2,400 queries a minute per user per Google Cloud project, and answers 503 when that is used up. The bridge retries 503, 429, 408 and other 5xx responses with backoff from about 5 seconds, as Google advises, up to 6 times. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Google or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the service account key, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/google-workspace-audit -p 'test_*.py' -v
```

The tests make their own RSA key and start a local mock of Google's token endpoint, the Reports API and HTTP Ingest, built from the documented shapes. They check the signed token request and its claims, PKCS #8 and PKCS #1 keys, paging, one record per event and the `params` object, windows, overlaps and repeats, the lookback and the 180-day limit, that a window ends only after HTTP Ingest accepted it, refused credentials and privileges, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Reports API activities.list (request, Activity resource, application names): https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
- Event names and parameters per application, for example login: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login , token: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token , SAML: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/saml , Chrome: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/chrome and Drive: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/drive
- Admin activity sample response: https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-admin
- Reports API limits and quotas: https://developers.google.com/workspace/admin/reports/v1/limits
- Push notifications (channels expire after 6 hours): https://developers.google.com/workspace/admin/reports/v1/guides/push
- Data retention and lag times: https://knowledge.workspace.google.com/admin/reports/data-retention-and-lag-times
- Service accounts and domain-wide delegation: https://developers.google.com/identity/protocols/oauth2/service-account
- Administrator privilege definitions (Reports): https://knowledge.workspace.google.com/admin/users/administrator-privilege-definitions
- Chrome browser event reporting: https://support.google.com/chrome/a/answer/9301421
- RSASSA-PKCS1-v1_5 (RFC 8017) and JWT (RFC 7519): https://www.rfc-editor.org/rfc/rfc8017 , https://www.rfc-editor.org/rfc/rfc7519
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
