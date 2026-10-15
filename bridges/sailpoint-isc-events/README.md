# SailPoint Identity Security Cloud events bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real SailPoint tenant or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from SailPoint's API reference. Run it with `--dry-run` first and check what it would send.

SailPoint Identity Security Cloud keeps its audit events (sign-ins and sign-outs, MFA checks, SSO app launches, password changes, provisioning, access item and source changes, admin rights and API clients) in the events index of its Search API, and has no syslog or push stream for them. Its event triggers send selected events, such as access requests and identity changes, not the audit log. This script reads the events index and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds a `"sailpoint_record": "event"` key in front of each event, and the library parsers in `parsers/sailpoint/identity-security-cloud` normalize them.

| Endpoint | What it returns |
| --- | --- |
| `POST /v3/search` with `"indices": ["events"]` | Audit events (EventDocument): `id`, `created`, `type`, `action`, `technicalName`, `name`, `operation`, `status`, `actor.name`, `target.name`, `ipAddress`, `trackingNumber`, `objects`, `attributes` and the rest, as a JSON list |

Python 3.9 or later, standard library only. One file: `sailpoint_isc_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/sailpoint/identity-security-cloud` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**SailPoint.** The search endpoint needs the `sp:search:read` scope and a user level that can search events, such as Report Admin, and SailPoint's guide says an endpoint that needs a user level needs a personal access token. Sign in as a user with the Report Admin level (rather than Org Admin, since a token takes its user's level), choose Preferences under the user name, then Personal Access Tokens > New Token, and turn on only the `sp:search:read` scope. Save the client ID and secret; the secret is shown once. Scopes that end in `read` can only read data. A user can have 10 tokens.

The API host is `https://<tenant>.api.identitynow.com`, where `<tenant>` is the first part of the tenant's URL (`acme` for `acme.identitynow.com`). A tenant on another domain sets `SAILPOINT_API_URL` instead. If the tenant restricts API access by IP address, add the bridge's public address.

## Configuration

Everything comes from environment variables. Keep the secret and key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `SAILPOINT_TENANT` | none | The tenant name, such as `acme`. The API URL is `https://<tenant>.api.identitynow.com`. |
| `SAILPOINT_API_URL` | none | The full API URL, for a tenant on another domain. Set this or `SAILPOINT_TENANT`. |
| `SAILPOINT_CLIENT_ID` | none | The personal access token's client ID. |
| `SAILPOINT_CLIENT_SECRET` | none | Its secret. |
| `SAILPOINT_EVENT_TYPES` | all | Event types to send, comma separated, such as `AUTH,SSO,PASSWORD_ACTIVITY,PROVISIONING,USER_MANAGEMENT`. Empty sends every type. |
| `SAILPOINT_PAGE_SIZE` | `1000` | Events per search request, 1 to 10000. |
| `BRIDGE_STATE_FILE` | `sailpoint_isc_state.json` | The end of the last window and the ids of the events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. SailPoint keeps events in search for a year plus the current month. |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How far before the last window's end each run reads again, for events that reach search late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 sailpoint_isc_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 sailpoint_isc_bridge.py                   # one pass, for cron or a systemd timer
python3 sailpoint_isc_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/sailpoint-isc-events.env` (owned by root, mode 600):

```ini
[Unit]
Description=SailPoint Identity Security Cloud events bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/sailpoint-isc-events/sailpoint_isc_bridge.py --interval 300
EnvironmentFile=/etc/sailpoint-isc-events.env
DynamicUser=yes
StateDirectory=sailpoint-isc-events
WorkingDirectory=/var/lib/sailpoint-isc-events
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- It gets an access token from `POST /oauth/token` with the form body `grant_type=client_credentials`, `client_id` and `client_secret`, and sends it as `Authorization: Bearer`. It renews the token a minute before it expires, and once more if SailPoint refuses it.
- Each run reads one window, from the end of the last one less `BRIDGE_OVERLAP_SECONDS` to a minute before now. The search body is `{"indices": ["events"], "queryType": "DSL", "queryDsl": {"bool": {"must": [{"range": {"created": {"gte": ..., "lte": ...}}}]}}, "sort": ["id"]}`, with a `match` on `type` for each of `SAILPOINT_EVENT_TYPES` when set. It pages with `searchAfter` set to the last event's `id`, as SailPoint's paging guide describes, until a page comes back short, so a window can hold more than 10,000 events.
- Events enter search a little after they happen, so each window starts before the last one ended, and the bridge drops events whose `id` it already sent. An event with no `id` is known by a hash of the whole event. Within a page, events go oldest first. A window's end is saved only after every page of it was sent, and never past the time of the run.
- SailPoint allows 100 requests per 10 seconds for each client ID and API version, and answers 429 with `Retry-After` past that. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from SailPoint or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the client ID, client secret, access token, HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/sailpoint-isc-events -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, the Search API and HTTP Ingest, built from the documented shapes, and check the form body of the token request, the search body and `searchAfter` paging, tagging and order, windows, overlaps and repeats, events with no `id`, the lookback and the retention limit, that a window ends only after HTTP Ingest accepted it and never past now, the event type filter, refused credentials and scopes, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Search API, perform search (`POST /v3/search`, EventDocument, `limit`, `searchAfter`): https://developer.sailpoint.com/docs/api/v3/search-post
- Searching audit events (query DSL, date range, key fields): https://developer.sailpoint.com/docs/guides/searching-audit-events
- Audit events reference (event names and types): https://developer.sailpoint.com/docs/guides/audit-events-reference
- Standard collection parameters (paging past 10,000 results with `searchAfter`): https://developer.sailpoint.com/docs/api/standard-collection-parameters
- Authentication (client credentials, personal access tokens): https://developer.sailpoint.com/docs/api/authentication
- Authorization (scopes and user levels): https://developer.sailpoint.com/docs/api/authorization
- Rate limits: https://developer.sailpoint.com/docs/api/rate-limit
- Searchable fields for events and retention: https://documentation.sailpoint.com/saas/help/search/searchable-fields.html
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
