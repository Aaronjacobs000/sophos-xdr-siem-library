# WithSecure Elements events bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real WithSecure Elements account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from WithSecure's Elements API reference. Run it with `--dry-run` first and check what it would send.

WithSecure Elements has no webhook for its security events, and its Elements Connector forwards syslog in a layout WithSecure doesn't publish. Its Elements API is public and pull only, so this script reads security events and audit logs from the API with a read-only API client and sends each item as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds a `withsecure_record` key in front of each item, and the library parsers in `parsers/withsecure/elements` normalize them.

| Data | Endpoint | `withsecure_record` |
| --- | --- | --- |
| Security events: malware found by real-time, manual and scheduled scanning, AMSI, DeepGuard, firewall, browsing protection, web content control, application and device control, DataGuard, tamper protection, EDR (Broad Context Detection) incidents, Collaboration Protection and Exposure Management | `POST /security-events/v1/security-events` | `security_event` |
| Audit logs: administrator logins and actions in Elements, such as profile changes, device isolation and response actions | `GET /audit-logs/v1/audit-logs` | `audit_log` |

API credentials made at partner level read every company under the partner, so one bridge serves a whole MSP account. Each item names its company in `organization.name` and `organization.id`.

Python 3.9 or later, standard library only. One file: `withsecure_elements_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/withsecure/elements` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**WithSecure Elements.** An EPP administrator with security management rights signs in to Elements Security Center, goes to Management > Organization Settings > API clients, picks the scope (the partner, to read every company, or one company), chooses Add new, enters a description, keeps Read-only selected, and saves the client ID and secret. The secret is shown once. A read-only client can only request the `connect.api.read` scope, which is all the bridge asks for.

EDR, Collaboration Protection and Exposure Management events appear only for companies with those products. WithSecure keeps security events for 13 to 14 months, depending on severity.

## Configuration

Everything comes from environment variables. Keep the secret and key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `WITHSECURE_CLIENT_ID` | none | The API client's ID. |
| `WITHSECURE_CLIENT_SECRET` | none | The API client's secret. |
| `WITHSECURE_ORGANIZATION_ID` | none | One company's organization UUID, to read only that company. Leave it unset to read every company the credentials can read. |
| `WITHSECURE_SOURCES` | `security_events,audit_logs` | What to read: `security_events`, `audit_logs` or both. |
| `WITHSECURE_ENGINE_GROUPS` | `epp,edr,ecp,xm` | Security event engine groups to read: `epp` (Endpoint Protection), `edr` (Detection and Response), `ecp` (Collaboration Protection) and `xm` (Exposure Management). |
| `WITHSECURE_PAGE_SIZE` | `200` | Items per request, 1 to 200. |
| `WITHSECURE_API_URL` | `https://api.connect.withsecure.com` | The Elements API host. |
| `BRIDGE_STATE_FILE` | `withsecure_elements_state.json` | Each source's last window end and the items sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. A query can span 31 days at most, so the bridge reads 30 days back at most. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How far before the last window's end each run reads again, for items written late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 withsecure_elements_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 withsecure_elements_bridge.py                   # one pass, for cron or a systemd timer
python3 withsecure_elements_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every source was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same items again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

## How it reads the API

- It gets an access token from `POST /as/token.oauth2` with `Authorization: Basic base64(<client ID>:<secret>)` and the form body `grant_type=client_credentials&scope=connect.api.read`, and sends it as `Authorization: Bearer`. Tokens last about 30 minutes; the bridge renews one a minute before it expires, and once more if WithSecure refuses it. Every request carries a `User-Agent`, which WithSecure requires.
- Security events are read by `persistenceTimestamp`, the time each one was written to WithSecure's database, so an event that reaches WithSecure late is still read. The form body is `persistenceTimestampStart`, `persistenceTimestampEnd`, `engineGroup` once for each group, `order=asc`, `limit` and, when set, `organizationId`. Audit logs are read the same way by `serverTimestamp`, with query parameters.
- Each run reads each source from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now, oldest first, following `nextAnchor` until a page has none. The bridge drops items whose `id` it already sent. A window's end is saved only after every page of it was sent, and never past the time of the run.
- WithSecure allows 300 requests a minute per IP address for security events, audit logs and its other EDR endpoints. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from WithSecure or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

WithSecure documents the event fields per event type, and the API returns them in `details`, mostly as text. The engine names in the API (such as `emailScan` and `amsi`) differ from the event type reference (`collaborationProtectionEmailScan`, `AMSI`); the library parsers read both. Audit log entries describe each action in `description`, in English unless the API is asked for another language; the bridge doesn't ask.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the client ID, secret, access token, HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/withsecure-elements-events -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, the security events and audit logs endpoints and HTTP Ingest, built from the documented shapes, and check Basic authentication with the read scope and a User-Agent, the form body with `engineGroup` repeated, paging with `nextAnchor`, tagging and order, windows, overlaps and repeats, the lookback and the 31-day limit, the organization filter, the sources and engine group settings, that a window ends only after HTTP Ingest accepted it, refused credentials and sources, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Elements API getting started (API clients, authentication, security events, audit logs, partner scope, rate limits): https://connect.withsecure.com/getting-started/elements/
- Elements API reference (token, security events and audit logs endpoints): https://connect.withsecure.com/api-reference/elements/
- Security events reference (event types and their `details` fields): https://connect.withsecure.com/api-reference/security-events/
- Security events overview: https://connect.withsecure.com/getting-started/security-events/
- Retention periods for security events (KB 31635): https://community.withsecure.com/en/kb/articles/31635-withsecure-elements-retention-periods-for-security-events
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
