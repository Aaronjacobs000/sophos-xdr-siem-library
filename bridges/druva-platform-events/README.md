# Druva Cloud Platform events bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Druva account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Druva's API reference. Run it with `--dry-run` first and check what it would send.

Druva offers its cybersecurity and administrator audit events (data anomaly alerts, Threat Watch IOC matches, admin logins, restores and downloads, quarantine changes, API credential and administrator changes, rollback actions and the rest) only through the Druva Cloud Platform Events API, which is pull only. This script reads the API with its page token and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds a `"druva_record": "platform_event"` key in front of each event, and the library parsers in `parsers/druva/druva-cloud-platform-events` normalize them.

| Endpoint | What it returns |
| --- | --- |
| `GET /platform/eventmanagement/v3/events` | Druva Cloud Platform events in the v3 shape: `category`, `details` (an object), `feature`, `globalID`, `timeStamp`, `productID`, `syslogFacility`, `syslogSeverity` and `type`, up to 500 a page, with a `nextPageToken` |

Python 3.9 or later, standard library only. One file: `druva_events_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/druva/druva-cloud-platform-events` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Druva.** A Druva Cloud Administrator goes to the Druva Cloud Platform Console, Global Navigation > Integration Center > API Credentials, chooses New Credentials, names them (for example `sophos-ngsiem-bridge`) and saves the Client ID and Secret Key; the Secret Key is shown once. Druva requires a Druva Cloud Administrator to set up credentials for its Endpoints, Data Governance and Cyber Resilience APIs, its credentials have every OAuth scope, and it documents no read-only role for these events. So keep these credentials for the bridge alone, turn on Network Restriction for them with the bridge's public address, and keep the Secret Key in a secrets manager.

The API URL depends on the cloud the account is in:

| Druva cloud | `DRUVA_API_URL` |
| --- | --- |
| Enterprise Workloads, Endpoints and Data Governance cloud | `https://apis.druva.com` (default) |
| Endpoints and Data Governance GovCloud | `https://govcloudapis.druva.com` |
| Enterprise Workloads GovCloud | `https://govapis.druva.com` |

Druva only accepts a token on the cloud that issued it.

## Configuration

Everything comes from environment variables. Keep the secret and key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `DRUVA_API_URL` | `https://apis.druva.com` | The API URL for the account's cloud (see above). |
| `DRUVA_CLIENT_ID` | none | The API credentials' Client ID. |
| `DRUVA_SECRET_KEY` | none | The API credentials' Secret Key. |
| `DRUVA_FEATURES` | all | Comma-separated `feature` values to send, for example `Alerts And Notifications,Threat Watch,Admin Event,API,Data Access,Data Anomalies,Ransomware Recovery`. Empty sends every event. The filter runs in the bridge: the API can't filter and page at the same time. |
| `BRIDGE_STATE_FILE` | `druva_events_state.json` | The saved page token. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | On the first run, with no saved page token, events older than this aren't sent. |
| `BRIDGE_PAGE_SIZE` | `500` | Events per page on the first request, 1 to 500. Later requests carry only the page token. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 druva_events_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 druva_events_bridge.py                   # one pass, for cron or a systemd timer
python3 druva_events_bridge.py --interval 300    # keep polling every 5 minutes
python3 druva_events_bridge.py --reset           # forget the saved page token and start again
```

Exit code 0 means the events were read and sent. On an error the bridge logs it and stops. The page token moves only after HTTP Ingest accepted that page, so the next run continues from the last page that was sent.

## How it reads the API

- It gets an access token from `POST /token` with `Authorization: Basic base64(<Client ID>:<Secret Key>)` and the form body `grant_type=client_credentials&scope=read`. Druva's tokens last 30 minutes (15 on inSync GovCloud); the bridge renews one a minute before it expires, and once more if Druva refuses it.
- The first request is `GET /platform/eventmanagement/v3/events?pageSize=500`, which starts at the oldest event Druva keeps; the bridge walks forward and sends only the events inside `BRIDGE_LOOKBACK_HOURS`. Every later request sends only `pageToken` with the `nextPageToken` from the last response, since Druva doesn't accept a page token and other parameters together.
- It reads pages until a page brings no events. Druva returns the same page token when there is nothing new, and the bridge saves it, so the next run starts where this one stopped.
- If Druva refuses a saved page token (HTTP 400 or 403), the run stops and says so. Run once with `--reset` to start again from the lookback.

Druva doesn't publish rate limits or how long it keeps events. The bridge waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Druva or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a page and saving its token can send that page again; HTTP Ingest does not remove duplicates.

The bridge never logs the Client ID, Secret Key, access token, HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/druva-platform-events -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint, the Events API (pages, page tokens, an expired access token, a refused page token) and HTTP Ingest, built from the documented shapes, and check paging and tagging, Basic authentication and the form body, resuming from the saved token, the first-run lookback with numeric and RFC 3339 times, the features filter, that the token moves only after HTTP Ingest accepted its page, `--reset`, dry-run, retries, batching and gzip, that redirects are refused, and that no secret reaches the log.

## References

- Druva API authentication (API credentials, the token request): https://developer.druva.com/docs/authentication
- Create and manage API credentials: https://help.druva.com/en/articles/8580838-create-and-manage-api-credentials
- List Events (Druva Cloud Platform, `pageToken`, `pageSize`, versions): https://developer.druva.com/reference/listeventsrequest-1
- Cybersecurity events: https://developer.druva.com/reference/cybersecurity-events
- Druva Cloud Platform events (v3): https://developer.druva.com/reference/druva-cloud-platform-events-v3
- Events API for Cyber Resilience: https://developer.druva.com/docs/events-api-for-cyber-resilience
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
