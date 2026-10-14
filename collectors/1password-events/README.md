# 1Password Events API collector

> **Unofficial, and tested against documented response shapes only.** This collector has not run against a real 1Password account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from 1Password's Events API reference. Run it with `--dry-run` first and check what it would send.

1Password Business offers sign-in attempts, item usage and audit events only through the 1Password Events API, which is pull only. This script reads each feature with the API's cursor and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds a `onepassword_record` key naming the feature, and the library parsers in `parsers/1password/1password-business` normalize the events.

| Feature (`ONEPASSWORD_FEATURES`) | Endpoint | `onepassword_record` | Schema |
| --- | --- | --- | --- |
| `signinattempts` | `POST /api/v2/signinattempts`: successful and failed sign-in attempts, with the failure cause, client and IP address | `signin_attempt` | Auth |
| `itemusages` | `POST /api/v2/itemusages`: items in shared vaults that were revealed, copied, filled, edited, shared or exported | `item_usage` | CloudAudit |
| `auditevents` | `POST /api/v2/auditevents`: actions team members take in the account, such as vault access grants, invitations, policy and SSO changes | `audit_event` | CloudAudit |

Python 3.9 or later, standard library only. One file: `onepassword_events_collector.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/1password/1password-business` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**1Password.** An owner or administrator signs in to 1Password.com and selects Integrations (then Directory, if other integrations exist). In the Events Reporting section, choose Other, name the integration and select Add Integration. Set up a bearer token: a token name, an expiry (Never, 30, 90 or 180 days), and the Events to Report (sign-in attempts, item usages and audit events by default). Select Issue Token and save it. The collector checks the token's events with `GET /api/v2/auth/introspect` before it reads anything.

The events URL depends on where the account is hosted:

| Account sign-in address | `ONEPASSWORD_EVENTS_URL` |
| --- | --- |
| `*.1password.com` | `https://events.1password.com` (default) |
| `*.ent.1password.com` | `https://events.ent.1password.com` |
| `*.1password.ca` | `https://events.1password.ca` |
| `*.1password.eu` | `https://events.1password.eu` |

## Configuration

Everything comes from environment variables. Keep the token and key in a secrets manager or an environment file only the collector's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `ONEPASSWORD_EVENTS_URL` | `https://events.1password.com` | The events URL for the account's region (see above). |
| `ONEPASSWORD_EVENTS_TOKEN` | none | The Events Reporting bearer token. |
| `ONEPASSWORD_FEATURES` | `signinattempts,itemusages,auditevents` | Comma-separated: `signinattempts`, `itemusages`, `auditevents`. The token must allow each one. |
| `COLLECTOR_STATE_FILE` | `onepassword_events_state.json` | The cursor for each feature. |
| `COLLECTOR_LOOKBACK_HOURS` | `24` | How far back the first run starts, for a feature with no saved cursor. The Events API keeps the last 120 days. |
| `COLLECTOR_PAGE_LIMIT` | `1000` | Events per page, 1 to 1000. |
| `COLLECTOR_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `COLLECTOR_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `COLLECTOR_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `COLLECTOR_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 onepassword_events_collector.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 onepassword_events_collector.py                   # one pass, for cron or a systemd timer
python3 onepassword_events_collector.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every feature was read and sent. On an error the collector logs the feature and the HTTP status and stops. Each feature's cursor moves only after HTTP Ingest accepted that page, so the next run continues from the last page that was sent.

## How it reads the API

- It sends the token as `Authorization: Bearer`. A 401 means the token is wrong, expired or revoked, or `ONEPASSWORD_EVENTS_URL` is for another region.
- The first request for a feature is a ResetCursor: `{"limit": 1000, "start_time": "<now minus the lookback>"}`. Every later request sends the `cursor` from the last response. 1Password says the cursor stays valid across sessions, so the collector saves it and resumes from it on the next run.
- It reads pages until `has_more` is false, sending each page and then saving its cursor.

1Password allows 600 requests a minute and 30,000 an hour. The collector waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After`. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the Events API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a page and saving its cursor can send that page again; HTTP Ingest does not remove duplicates.

The collector never logs the 1Password token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s collectors/1password-events -p 'test_*.py' -v
```

The tests start a local mock of the Events API (introspection and the three features, with cursors) and HTTP Ingest, built from the documented shapes, and check paging, tagging, the ResetCursor and lookback, resuming from the saved cursor, that a cursor moves only after HTTP Ingest accepted its page, a token that lacks a feature, a refused token, dry-run, retries, batching and gzip, that redirects are refused, and that no secret reaches the log.

## References

- 1Password Events API reference (endpoints, request and response objects): https://www.1password.dev/events-api/reference/
- 1Password Events API overview: https://www.1password.dev/events-api/introduction
- Get started (setting up an Events Reporting integration and token): https://www.1password.dev/events-api/get-started
- Servers and base URLs: https://www.1password.dev/events-api/servers
- Pagination and cursors: https://www.1password.dev/events-api/pagination
- Rate limits: https://www.1password.dev/events-api/rate-limits
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
