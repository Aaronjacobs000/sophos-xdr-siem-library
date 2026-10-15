# Dynatrace audit events bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Dynatrace environment or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Dynatrace's Platform API reference. Run it with `--dry-run` first and check what it would send.

Dynatrace records who changed settings and who called the API gateway, sign-ins and sign-outs included, as audit events in Grail: `dt.system.events` with `event.kind` `AUDIT_EVENT`, kept for a year. Dynatrace has no push for them: the classic audit logs API (`/api/v2/auditlogs`) isn't available in the latest Dynatrace environments, and OpenPipeline forwards only the app lifecycle audit events, not the settings and API gateway ones. So this script runs a DQL query for each new window with the Grail Query API and sends each audit event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser in `parsers/dynatrace/dynatrace-audit-events` normalizes them.

Each record goes on as Dynatrace returns it, flat keys such as `event.provider` and `user.id` included, with `dynatrace_record` (`audit`) and `dynatrace_environment` (the environment ID from `DYNATRACE_ENV_URL`) first, so records from several environments can be told apart.

Account-level changes (groups, policies, SSO) are in Dynatrace's separate Account Management audit log, which this bridge doesn't read.

Python 3.9 or later, standard library only. One file: `dynatrace_audit_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/dynatrace/dynatrace-audit-events` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Dynatrace.** The Grail Query API is a SaaS platform API at `https://<environment ID>.apps.dynatrace.com`. Give the bridge a service user in Account Management with a policy that has only these two statements:

```
ALLOW storage:system:read WHERE storage:event.kind="AUDIT_EVENT";
ALLOW storage:buckets:read WHERE storage:bucket-name="dt_system_events";
```

Keep the built-in policies Storage Default Monitoring Read, Read System Events and All Grail data read access off that user: each grants `storage:system:read` with no condition, which Dynatrace says overrides the narrower statement, so the user would read every system event.

Then either:

- **Platform token.** Create a platform token for the service user with the scopes `storage:system:read` and `storage:buckets:read`, and set `DYNATRACE_PLATFORM_TOKEN`. It goes as `Authorization: Bearer` on each request. A platform token works only within its user's permissions.
- **OAuth client.** Create an OAuth client in Account Management for the service user, with the same two scopes, and set `DYNATRACE_CLIENT_ID`, `DYNATRACE_CLIENT_SECRET` and `DYNATRACE_ACCOUNT_URN` (`urn:dtaccount:<account UUID>`). The bridge gets an access token with the client credentials grant from `https://sso.dynatrace.com/sso/oauth2/token`, asking only for those two scopes.

## Configuration

Everything comes from environment variables. Keep the token, the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `DYNATRACE_ENV_URL` | none | The environment's platform URL with no path, such as `https://abc12345.apps.dynatrace.com`. Its first label is the environment ID. |
| `DYNATRACE_PLATFORM_TOKEN` | none | A platform token. Set this, or the three OAuth client settings. |
| `DYNATRACE_CLIENT_ID` | none | The OAuth client's ID (`dt0s02.` and the rest). |
| `DYNATRACE_CLIENT_SECRET` | none | The OAuth client's secret. It goes in the token request's form body only. |
| `DYNATRACE_ACCOUNT_URN` | none | `urn:dtaccount:` and the account UUID, the token request's `resource`. |
| `DYNATRACE_TOKEN_URL` | `https://sso.dynatrace.com/sso/oauth2/token` | Dynatrace's OAuth token endpoint. |
| `DYNATRACE_PAGE_SIZE` | `1000` | Records per query, 1 to 100,000. |
| `DYNATRACE_QUERY_TIMEOUT` | `300` | Seconds a query may run before the bridge cancels it, 1 to 3,600. |
| `BRIDGE_STATE_FILE` | `dynatrace_audit_state.json` | Where each environment's window ended. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 8,760 (a year, how long Dynatrace keeps audit events). |
| `BRIDGE_DELAY_SECONDS` | `300` | How far behind now each window ends, so events Grail stores a little late are still in it. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 dynatrace_audit_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 dynatrace_audit_bridge.py                   # one pass, for cron or a systemd timer
python3 dynatrace_audit_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same records again from where the last accepted page ended. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, an answer cut off partway, a query that doesn't finish within `DYNATRACE_QUERY_TIMEOUT` and a query result that has expired count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

As a systemd service that polls, with the variables in `/etc/dynatrace-audit-events.env` (owned by root, mode 600):

```ini
[Unit]
Description=Dynatrace audit events bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/dynatrace-audit-events/dynatrace_audit_bridge.py --interval 300
EnvironmentFile=/etc/dynatrace-audit-events.env
DynamicUser=yes
StateDirectory=dynatrace-audit-events
WorkingDirectory=/var/lib/dynatrace-audit-events
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads one window: from where the last one ended (or `BRIDGE_LOOKBACK_HOURS` back, the first time) to `BRIDGE_DELAY_SECONDS` before now. The query is:

  ```
  fetch dt.system.events
  | filter event.kind == "AUDIT_EVENT"
  | filter timestamp >= toTimestamp(<start>) and timestamp < toTimestamp(<end>)
  | sort timestamp asc, event.id asc
  | limit <DYNATRACE_PAGE_SIZE>
  ```

  with the bounds in nanoseconds since the epoch, and `defaultTimeframeStart` and `defaultTimeframeEnd` a second wider than the filter, since Dynatrace doesn't say whether the timeframe's bounds are inclusive.
- A full page means there may be more, so the next page starts at the time of the page's last record and skips the records at that time it already sent. If every record of a full page has the same time, the next page is twice as large, up to 100,000, until it gets past them. The position is saved after each page HTTP Ingest accepted, so each run queries only its new window.
- `POST .../query:execute` asks Dynatrace to answer within 10 seconds. A query that is still running is polled with `GET .../query:poll` until it finishes. One that hasn't finished after `DYNATRACE_QUERY_TIMEOUT` seconds is cancelled with `POST .../query:cancel`, and the run ends with a network error. A query that ends in any state but SUCCEEDED stops the run with that state.
- Dynatrace doesn't say how late Grail can store an audit event. An event stored after its window was read is missed, so raise `BRIDGE_DELAY_SECONDS` if you find gaps. Dynatrace also says the Query API isn't meant for large-scale export; audit events are a small share of a typical environment's data.
- 408, 429, 500, 502, 503 and 504 are retried with backoff, honoring `Retry-After`, up to 6 times. A refused platform token stops the run at once. With an OAuth client, the access token is renewed a minute before it expires (Dynatrace's example gives 300 seconds), and once more if Dynatrace refuses it. A 400 (such as a query Grail can't run), 401 or 403 stops the run with Dynatrace's message and any scopes or permissions it says are missing. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Dynatrace or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

Grail stores the user's ID in `user.id`; whether `user.name` (the email address) is filled in depends on the environment. The parser falls back to the ID.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the platform token, the client secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/dynatrace-audit-events -p 'test_*.py' -v
```

The tests start a local mock of the Grail Query API (execute, poll and cancel, running the bridge's own DQL filter, sort and limit), Dynatrace's OAuth token endpoint and HTTP Ingest, built from the documented shapes, and check tagging and order, the window's end and start, paging past records that share a time, the next run starting where the last ended, that the position moves only after HTTP Ingest accepted a page, polling, cancelling a query that runs too long, failed and expired queries, Dynatrace's error messages, platform tokens and OAuth clients (the scopes asked for, renewal, refused credentials), dry-run, retries, batching and gzip, state per environment, the year of retention, settings, nanosecond times, refused redirects, the response size cap, and that no secret reaches the log.

## References

- Audit logs on Grail (permissions, providers, queries): https://docs.dynatrace.com/docs/manage/data-privacy-and-security/configuration/audit-logs-grail
- Upgrade from classic audit logs (field mapping, the Query API call, the built-in policies that override narrower ones): https://docs.dynatrace.com/docs/platform/upgrade/set-up-your-environment/upgrade-from-audit-logs-classic
- Audit event fields (semantic dictionary): https://docs.dynatrace.com/docs/semantic-dictionary/model/dt-system-events
- Grail Query API (execute, poll, cancel, states, errors): https://docs.dynatrace.com/docs/dynatrace-api/platform-api/platform-storage-query-v1
- Platform tokens: https://docs.dynatrace.com/docs/manage/identity-access-management/access-tokens-and-oauth-clients/platform-tokens
- OAuth clients (client credentials grant): https://docs.dynatrace.com/docs/manage/identity-access-management/access-tokens-and-oauth-clients/oauth-clients
- Supported system events in OpenPipeline (app lifecycle audit events only): https://docs.dynatrace.com/docs/platform/openpipeline/reference/api-ingestion-reference
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
