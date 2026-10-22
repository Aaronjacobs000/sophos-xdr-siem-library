# Slack audit logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Slack organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Slack's Audit Logs API reference. Run it with `--dry-run` first and check what it would send.

Slack offers the audit logs of an Enterprise organization (sign-ins and sign-outs, member, role and session changes, channel, file, canvas and app actions, workspace and organization settings, and Slack's own anomaly detections) through its Audit Logs API, which is pull only. This script reads them and sends each entry as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"slack_record": "audit"` in front of each entry, and the library parsers in `parsers/slack/slack-audit-logs` normalize them. Sophos Fusion has no Slack integration.

| Data | Endpoint | Headers |
| --- | --- | --- |
| Audit log entries, all of them or the actions in `SLACK_ACTIONS` | `GET /audit/v1/logs` | `Authorization: Bearer xoxp-...` |

Python 3.9 or later, standard library only. One file: `slack_audit_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/slack/slack-audit-logs` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own entries before you turn them on.

**Slack.** The Audit Logs API is for Enterprise plans only, and reads the whole organization, not one workspace. It takes a user token (`xoxp-`) with the `auditlogs:read` scope, from an app that an Owner of the Enterprise organization installed on the organization itself. The scope only reads audit logs, and the API has no write methods.

1. Create an app at https://api.slack.com/apps, from scratch.
2. Under OAuth & Permissions, add `auditlogs:read` under User Token Scopes, and add a Redirect URL (https) for the code Slack sends back. Leave token rotation off: with it on, the token expires every 12 hours, and the bridge doesn't refresh tokens.
3. Under Manage Distribution, make sure the four items under Share Your App with Other Workspaces are checked, then choose Activate Public Distribution.
4. Signed in as an Owner of the Enterprise organization, open the Sharable URL under Share Your App with Your Workspace. In the drop-down at the top right of the install screen, choose the Enterprise organization, not a workspace in it. Slack's docs say you may need to add a bot scope before it installs on an organization.
5. Slack sends you to the Redirect URL with a `code`. Exchange it within 10 minutes with `oauth.v2.access` (your app's Client ID and Client Secret are under Basic Information). The token is `authed_user.access_token` in the answer.

The token can read everything in the organization's audit logs, so keep it as you would an admin password, and revoke it by uninstalling the app.

## Configuration

Everything comes from environment variables. Keep the Slack token and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `SLACK_TOKEN` | none | The user token (`xoxp-`) with `auditlogs:read`, sent as `Authorization: Bearer`. |
| `SLACK_API_URL` | `https://api.slack.com` | The Audit Logs API host. |
| `SLACK_ACTIONS` | none | Up to 30 actions to read, comma separated, such as `user_login,user_login_failed,anomaly`. Empty reads every action. |
| `SLACK_PAGE_LIMIT` | `1000` | Entries per request, 1 to 9999. |
| `BRIDGE_STATE_FILE` | `slack_audit_state.json` | The last window end and the entries sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. Slack's audit logs start in March 2018, and no window starts before that. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for entries Slack lists late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 slack_audit_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 slack_audit_bridge.py                   # one pass, for cron or a systemd timer
python3 slack_audit_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status and Slack's error code, stops, and leaves the window where it was, so the next run reads the same entries again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or token error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/slack-audit-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Slack audit logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/slack-audit-logs/slack_audit_bridge.py --interval 300
EnvironmentFile=/etc/slack-audit-logs.env
DynamicUser=yes
StateDirectory=slack-audit-logs
WorkingDirectory=/var/lib/slack-audit-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now: `GET /audit/v1/logs?oldest=<start>&latest=<end>&limit=<SLACK_PAGE_LIMIT>`, with `action=<SLACK_ACTIONS>` when it is set. `oldest` and `latest` are Unix times in seconds, and Slack includes both.
- Slack answers `{"ok": true, "entries": [...], "response_metadata": {"next_cursor": "..."}}`, newest first. While `next_cursor` holds a value there are more, so the bridge sends the same query again with `cursor` set to it, until `next_cursor` is empty, null or missing, as Slack's pagination docs describe. A page can hold fewer entries than the limit and still have more after it. The same `next_cursor` twice stops the run. Each page goes to HTTP Ingest oldest first.
- Every entry has a unique `id`, so the bridge drops repeats by `id`. A window's end is saved only after every page of it was sent, and never past the time of the run. Cursors aren't saved, since Slack says they expire.
- The Audit Logs API is rated Tier 3, about 50 calls a minute, counted for the whole organization. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. Slack's error codes stop the run with what to check: `invalid_authentication` (the token), `user_not_authorized` (an Org Owner must install the app), `team_not_authorized` (the app is on a workspace, not the organization), `feature_not_enabled` (no Enterprise plan), `invalid_action`, `invalid_range` and `invalid_cursor`. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Slack or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the Slack token, the HTTP Ingest key, the HTTP Ingest URL path, or a paging cursor.

## Tests

```bash
python3 -m unittest discover -s bridges/slack-audit-logs -p 'test_*.py' -v
```

The tests start a local mock of the Audit Logs API and HTTP Ingest, built from the documented shapes, and check the query and headers, paging with `next_cursor` (encoded in the URL) until it is empty, null or missing, windows, overlaps and repeats, the lookback and the March 2018 start, that a window ends only after HTTP Ingest accepted it and never past now, the actions setting, Slack's error codes, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Using the Audit Logs API (Enterprise plans, installing on the organization, the auditlogs:read user token, the entry shape): https://docs.slack.dev/admins/audit-logs-api/
- Audit Logs API methods and actions (the logs endpoint, filters, limits, rate limits, actions and errors): https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference/
- Anomalous events (the anomaly action and its details): https://docs.slack.dev/reference/audit-logs-api/anomalous-events-reference/
- The auditlogs:read scope: https://docs.slack.dev/reference/scopes/auditlogs.read/
- Pagination (next_cursor, and cursors that expire): https://docs.slack.dev/apis/web-api/pagination/
- Rate limits (429 and Retry-After): https://docs.slack.dev/apis/web-api/rate-limits/
- Installing with OAuth (oauth.v2.access and authed_user.access_token): https://docs.slack.dev/authentication/installing-with-oauth/
- Token rotation (tokens that expire every 12 hours): https://docs.slack.dev/authentication/using-token-rotation/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
