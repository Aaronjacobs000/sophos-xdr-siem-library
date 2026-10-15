# Atlassian organization audit log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Atlassian organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Atlassian's Organizations REST API reference and OpenAPI document. Run it with `--dry-run` first and check what it would send.

The Atlassian organization audit log records organization admin and security policy changes, sign-ins and, with Atlassian Guard Premium or a Cloud Enterprise plan, activity in the apps. Its SIEM route is the Organizations REST API, which is pull only (audit log webhooks need Guard Premium or an Enterprise plan, and can only send a Basic authorization header, not the Bearer key HTTP Ingest needs). This script polls the events stream with an organization admin API key and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/atlassian/atlassian-organization-audit-log` normalize them.

| Data | Endpoint | What the bridge adds |
| --- | --- | --- |
| Organization audit log events | `GET /admin/v1/orgs/{orgId}/events-stream` | `"atlassian_record": "event"` first, and `orgId` |
| The name of each action | `GET /admin/v1/orgs/{orgId}/event-actions` | `actionDisplayName` and `actionGroup`, such as `Logged in to account` in its group |

Atlassian doesn't publish its action keys; the event actions list is the only place they're named. The bridge reads it once per run in which there are new events, and adds the display name and group of each event's action. Turn this off with `ATLASSIAN_ACTION_NAMES=0`.

Python 3.9 or later, standard library only. One file: `atlassian_org_audit_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/atlassian/atlassian-organization-audit-log` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Atlassian.** The organization audit log needs Atlassian Guard (Standard or Premium) or a Cloud Enterprise plan; without one, the organization log stores no events. An organization admin goes to admin.atlassian.com, then Organization settings > API keys > API keys with scopes > Create API key, names the key, and selects only the `read:events:admin` scope, which covers the events and event actions endpoints. Keys with scopes last at most a year, so note when to replace it. Don't use a key without scopes: it can call every admin API. The organization ID is in the Atlassian Administration URL (`admin.atlassian.com/o/<orgId>/...`) and is shown when you create the key.

## Configuration

Everything comes from environment variables. Keep the API key and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `ATLASSIAN_API_KEY` | none | The organization API key, sent as `Authorization: Bearer`. |
| `ATLASSIAN_ORG_ID` | none | The organization ID. |
| `ATLASSIAN_API_URL` | `https://api.atlassian.com` | The Organizations REST API host. |
| `ATLASSIAN_ACTION_NAMES` | `1` | Add each action's display name and group from the event actions list. |
| `ATLASSIAN_PAGE_LIMIT` | `500` | Events per page, 1 to 500. |
| `BRIDGE_STATE_FILE` | `atlassian_org_audit_state.json` | The stream cursor, the last event time and the IDs of recently sent events. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much before the last event a run reads again if Atlassian refuses the saved cursor. Repeats are dropped by event `id`. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 atlassian_org_audit_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 atlassian_org_audit_bridge.py                   # one pass, for cron or a systemd timer
python3 atlassian_org_audit_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same events again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.

## How it reads the API

- The first run asks `/events-stream` for events from the lookback (`from`, in epoch milliseconds) in ascending order. Every later request sends the `cursor` from the last page's `meta.next`, which Atlassian says keeps the sort order and can be used after the last page to poll for new events. The bridge saves the cursor after each page is sent, and stops when a page comes back empty or without a cursor.
- If Atlassian refuses the saved cursor (`ADMIN-400-1`), the bridge reads again from the last event's time minus the overlap. Events carry a unique `id`, so the bridge drops ones it has sent.
- The events stream allows 60 requests a minute per user and 50 per API path. On 429 the bridge waits until the `X-RateLimit-Reset` time Atlassian sends, and retries 408 and 5xx with backoff, up to 6 times. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Atlassian or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the API key, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/atlassian-org-audit -p 'test_*.py' -v
```

The tests start a local mock of the events stream, the event actions list and HTTP Ingest, built from the documented shapes, and check paging with the cursor, tagging and action names, resuming from the saved cursor, the lookback, a refused cursor and repeats, that the cursor moves only after HTTP Ingest accepted a page, a refused key and an unknown organization, dry-run, retries and the rate limit reset time, batching and gzip, refused redirects, and that no secret reaches the log.

## References

- Organizations REST API, events (events stream, event actions, parameters, responses): https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/
- Organizations REST API introduction (API key, rate limit headers): https://developer.atlassian.com/cloud/admin/organization/rest/intro/
- Admin API scopes: https://developer.atlassian.com/cloud/admin/scopes/
- Creating API keys: https://support.atlassian.com/organization-administration/docs/manage-an-organization-with-the-admin-apis/
- Which plans include audit log activities: https://support.atlassian.com/security-and-access-policies/docs/accessing-audit-log-activities/
- The audit log activities and their names: https://support.atlassian.com/security-and-access-policies/docs/audit-log-activities-database/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
