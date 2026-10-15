# Cisco Secure Endpoint events bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Cisco Secure Endpoint organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Cisco's Secure Endpoint API v1 reference and OpenAPI files. Run it with `--dry-run` first and check what it would send.

Cisco Secure Endpoint (formerly AMP for Endpoints) has no syslog output and no webhook to an arbitrary HTTPS endpoint. Its event streams are AMQP queues a consumer has to drain, so this script polls the events list instead, with a read-only API credential, and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/cisco/cisco-secure-endpoint` normalize them.

| Data | Endpoint | What the bridge adds |
| --- | --- | --- |
| Events (detections, quarantines, Cloud IOCs, network detections, scans, policy updates, isolation and the rest of the console's Events view) | `GET /v1/events` | `"cisco_se_record": "event"` first, and `event_id` |

Event IDs are 64-bit numbers, larger than a 64-bit float holds exactly, so the bridge also sends each one as text in `event_id`. The event itself goes on unchanged.

Python 3.9 or later, standard library only. One file: `cisco_secure_endpoint_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/cisco/cisco-secure-endpoint` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Cisco Secure Endpoint.** In the Secure Endpoint console, go to Administration > Organization Settings > Configure API Credentials (or Accounts > API Credentials) and choose New API Credential. Name it, choose the **Read-only** scope, and save. Copy the 3rd party API client ID and the API key; the key isn't shown again. Leave Command Line Capture off unless you want command lines in events, which needs an administrator account with single sign-on or two-factor authentication. Don't reuse the read and write credentials that Cisco XDR and other integrations create for themselves.

The API host depends on the organization's region:

| Region | `CISCO_SE_API_URL` |
| --- | --- |
| North America | `https://api.amp.cisco.com` (default) |
| Asia Pacific, Japan and China | `https://api.apjc.amp.cisco.com` |
| Europe | `https://api.eu.amp.cisco.com` |

## Configuration

Everything comes from environment variables. Keep the API key and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `CISCO_SE_CLIENT_ID` | none | The API credential's 3rd party API client ID. |
| `CISCO_SE_API_KEY` | none | The API credential's key. With the client ID it is sent as `Authorization: Basic`. |
| `CISCO_SE_API_URL` | `https://api.amp.cisco.com` | The API host for the organization's region. |
| `CISCO_SE_EVENT_TYPES` | all | Event type IDs to read, comma separated, such as `1090519054,553648143`. `GET /v1/event_types` lists them. |
| `CISCO_SE_GROUP_GUIDS` | all | Group GUIDs to read, comma separated. |
| `CISCO_SE_PAGE_SIZE` | `500` | Events per page, 1 to 500. |
| `BRIDGE_STATE_FILE` | `cisco_secure_endpoint_state.json` | The last window's end and the IDs of events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How far before the last window's end each run reads again, for events that arrive late. Repeats are dropped by event ID. Raise it if endpoints are often offline. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 cisco_secure_endpoint_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 cisco_secure_endpoint_bridge.py                   # one pass, for cron or a systemd timer
python3 cisco_secure_endpoint_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.

## How it reads the API

- Each run asks `/v1/events` for events from the end of the last window, less the overlap (`start_date`, ISO 8601, which Cisco includes), and reads every page. Cisco lists the newest first and pages by offset, so an event that arrives during the walk moves the rest along and appears twice; the bridge drops repeats by event ID. It works out each page's offset itself rather than following `links.next`, so the credential only goes to `CISCO_SE_API_URL`. A window's end is saved only after every page of it was sent.
- Cisco doesn't say whether `start_date` matches the time an event happened or the time Cisco received it. An endpoint that was offline can send old events late, and an event older than the overlap when it arrives would be missed if `start_date` matches the event time. Raise `BRIDGE_OVERLAP_SECONDS` to cover the longest time your endpoints stay offline.
- Cisco limits API requests per hour and sends `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` (seconds until the limit resets). On 429 the bridge waits until the reset when that is at most 5 minutes away; otherwise the run stops with an error that says when the limit resets, and with `--interval` the bridge tries again at the next interval. It retries 408 and 5xx with backoff, up to 6 times. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Cisco or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the API key, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/cisco-secure-endpoint-events -p 'test_*.py' -v
```

The tests start a local mock of the events list and HTTP Ingest, built from the documented shapes, and check paging by offset, tagging and the exact 64-bit ID, that `links.next` is never followed to another host, the event type and group filters, an event arriving mid-walk, windows, overlaps and repeats, the lookback, that a window ends only after HTTP Ingest accepted it, a refused credential, dry-run, retries and the rate limit reset, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Secure Endpoint API v1, events (parameters, response, example): https://developer.cisco.com/docs/secure-endpoint/v1-api-reference-event/ and its OpenAPI file https://pubhub.devnetcloud.com/media/secure-endpoint-api/docs/legacy-apis/v1/event_oas.yaml
- Event types: https://pubhub.devnetcloud.com/media/secure-endpoint-api/docs/legacy-apis/v1/event_type_oas.yaml
- API overview (authentication, rate limit headers, pagination, errors): https://developer.cisco.com/docs/secure-endpoint/
- Event streams (AMQP), for comparison: https://pubhub.devnetcloud.com/media/secure-endpoint-api/docs/legacy-apis/v1/eventstream_oas.yaml
- Secure Endpoint user guide (API credentials, read-only scope, severities): https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
