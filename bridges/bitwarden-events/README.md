# Bitwarden event logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Bitwarden organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Bitwarden's Public API reference and OpenAPI document. Run it with `--dry-run` first and check what it would send.

Bitwarden offers its organization event logs to other tools only through the Public API, which is pull only. This script signs in with the organization's API key, reads the events by time window, and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/bitwarden/bitwarden-event-logs` normalize them.

| Data | Endpoint | What the bridge adds |
| --- | --- | --- |
| Organization events: sign-ins, item views and changes, collections, groups, members, organization settings, policies, domains, Secrets Manager and Send | `GET /public/events` | `"bitwarden_record": "event"` first, and `organizationId` from the API key |
| The members, to name the users in each event | `GET /public/members` | `actingUserEmail` and `actingUserName` (the user who acted), `memberEmail` and `memberName` (the member the event is about) |

An event names users only by ID: `actingUserId` is the user's Bitwarden ID and `memberId` the member's ID in the organization. The bridge reads the member list once per run in which there are new events, and adds the email and name of each when the member list has them. Turn this off with `BITWARDEN_MEMBER_LOOKUP=0`.

Python 3.9 or later, standard library only. One file: `bitwarden_events_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/bitwarden/bitwarden-event-logs` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Bitwarden.** The Public API needs a Teams or Enterprise organization. An owner opens the Admin Console, goes to Settings > Organization info, and scrolls to the API key section, which shows a `client_id` (`organization.<organization id>`) and a `client_secret`. Bitwarden has no read-only key: this one gives full access to the organization's Public API, including members, groups and collections, so keep it as tightly as an owner's password. Rotate API key on the same screen replaces it and stops the old one working.

An MSP that manages clients through the Bitwarden Provider Portal runs one bridge per client organization, each with that organization's API key: the Public API has no provider-wide event log, and the provider event log doesn't include the client organizations' events.

| Where the organization is hosted | `BITWARDEN_API_URL` | `BITWARDEN_IDENTITY_URL` |
| --- | --- | --- |
| Bitwarden cloud, US | `https://api.bitwarden.com` (default) | `https://identity.bitwarden.com` (default) |
| Bitwarden cloud, EU | `https://api.bitwarden.eu` | `https://identity.bitwarden.eu` |
| Self-hosted | `https://<your server>/api` | `https://<your server>/identity` |

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `BITWARDEN_CLIENT_ID` | none | The organization API key's `client_id`, `organization.<organization id>`. |
| `BITWARDEN_CLIENT_SECRET` | none | The organization API key's `client_secret`. |
| `BITWARDEN_API_URL` | `https://api.bitwarden.com` | The Public API base URL (see above). |
| `BITWARDEN_IDENTITY_URL` | `https://identity.bitwarden.com` | The identity server base URL (see above). |
| `BITWARDEN_MEMBER_LOOKUP` | `1` | Add the emails and names from `GET /public/members`. |
| `BRIDGE_STATE_FILE` | `bitwarden_events_state.json` | The cursor and the hashes of recently sent events. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 8784 (366 days). |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How much before the cursor each run reads again, for events that reach Bitwarden late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 bitwarden_events_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 bitwarden_events_bridge.py                   # one pass, for cron or a systemd timer
python3 bitwarden_events_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same window again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.

## How it reads the API

- It gets an access token from `POST /connect/token` on the identity server (form fields `grant_type=client_credentials`, `scope=api.organization`, `client_id` and `client_secret`) and sends it as `Authorization: Bearer`. Tokens last an hour; the bridge gets a new one a minute before that, and once more if the API answers 401.
- Each run asks `GET /public/events` for events from the cursor minus the overlap (`start`) up to the start of the run (`end`), and repeats the same `start` and `end` with each `continuationToken` until a page comes back without one. The API returns the newest events first, 50 to a page.
- Events have no ID, so the bridge drops repeats by a hash of the whole event, keeping the hashes of the events inside the overlap. It sends the new events oldest first, then moves the cursor to the start of the run.
- Most events come from Bitwarden's apps, which send them in batches about every 60 seconds and retry when they can't, with the time the event happened on the device. An event that reaches Bitwarden later than the overlap is missed; raise `BRIDGE_OVERLAP_SECONDS` if your users are often offline.
- The API takes a range of at most 366 days, so the first run's lookback is capped there.

Bitwarden doesn't publish its cloud rate limits; it answers 429 when a client asks too often. The bridge waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Bitwarden or HTTP Ingest is refused, not followed, so no secret, token or key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the client secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/bitwarden-events -p 'test_*.py' -v
```

The tests start a local mock of the Bitwarden identity server, the events and members endpoints, and HTTP Ingest, built from the documented shapes, and check paging with the continuation token, tagging and the member names, oldest-first order, the lookback, a late event inside the overlap, repeats, that the cursor moves only after HTTP Ingest accepted the events, renewing a rejected token, a refused API key, the 366-day range, dry-run, retries, batching and gzip, refused redirects, and that no secret reaches the log.

## References

- Bitwarden Public API (API key, token request, base URLs): https://bitwarden.com/help/public-api/
- Public API reference and OpenAPI document (`/public/events`, `/public/members`, event and device types): https://bitwarden.com/help/api/
- Event logs (what each event type means): https://bitwarden.com/help/event-logs/
- Providers (client organizations and the provider event log): https://bitwarden.com/help/providers/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
