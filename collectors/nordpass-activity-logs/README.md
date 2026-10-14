# NordPass activity logs collector

> **Unofficial, and tested against documented response shapes only.** This collector has not run against a real NordPass organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from NordPass's Activity Logs API article. Run it with `--dry-run` first and check what it would send.

NordPass Enterprise offers its activity log to other tools only through the Activity Logs API, which is pull only. This script reads the activities by time window and sends each one as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It puts `"nordpass_record": "activity"` first in each record, and the library parsers in `parsers/nordpass/nordpass-activity-logs` normalize them.

| Data | Endpoint | `nordpass_record` |
| --- | --- | --- |
| Activity log: sign-ins, vault unlocks, item access, sharing and deletion, members, invites, roles, groups, organization settings and integrations | `POST /activities/query` on `https://api-activities.<eu or us>.nordpass.com` | `activity` |

Python 3.9 or later, standard library only. One file: `nordpass_activity_collector.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/nordpass/nordpass-activity-logs` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**NordPass.** The Activity Logs API needs NordPass Enterprise. An Owner or Admin signs in to the NordPass Admin Panel, selects Integrations, chooses Custom under Events reporting, then Create Token. Name the token, copy the URL and the token, and save them. The URL shows the organization's data center: `api-activities.eu.nordpass.com` is `eu` and `api-activities.us.nordpass.com` is `us`. Tokens last two years; NordPass emails Owners and Admins before one expires, and Reset keeps the name with a new value. The token is for events reporting, which is how NordPass's Splunk, Microsoft Sentinel and CrowdStrike integrations read the same log.

## Configuration

Everything comes from environment variables. Keep the token and the HTTP Ingest key in a secrets manager or an environment file only the collector's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `NORDPASS_TOKEN` | none | The events reporting token, sent as the whole `Authorization` header as NordPass documents. |
| `NORDPASS_REGION` | `eu` | The organization's data center: `eu` or `us`. |
| `NORDPASS_API_URL` | from the region | Overrides `https://api-activities.<region>.nordpass.com`. |
| `NORDPASS_PER_PAGE` | `100` | Activities per page, 1 to 100. |
| `COLLECTOR_STATE_FILE` | `nordpass_activity_state.json` | The cursor and the hashes of recently sent activities. |
| `COLLECTOR_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `COLLECTOR_OVERLAP_SECONDS` | `600` | How much before the cursor each run reads again, for activities that reach NordPass late. Repeats are dropped. |
| `COLLECTOR_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `COLLECTOR_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `COLLECTOR_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `COLLECTOR_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 nordpass_activity_collector.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 nordpass_activity_collector.py                   # one pass, for cron or a systemd timer
python3 nordpass_activity_collector.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the collector logs it with the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same window again.

## How it reads the API

- Each run posts `{"timestamp_from", "timestamp_to", "per_page", "page"}` to `/activities/query` for the window from the cursor minus the overlap to a few seconds before now (NordPass refuses a `timestamp_to` in the future), and reads every page of that one window. NordPass documents the timestamps only as integers; the collector uses Unix seconds, the unit the activity records carry in the sample data of Microsoft Sentinel's NordPass solution.
- NordPass refuses a window longer than 90 days, and a query can only page through its 10,000 most recent results. The collector splits a longer window into 90-day parts, and splits any part that holds more than 10,000 activities in half until each half fits.
- Activities have no ID, so repeats inside the overlap are dropped by a hash of the activity. The collector sends the new activities oldest first, then moves the cursor past the end of the window. This is the timestamp cursor NordPass asks integrations to keep: it doesn't replay or push missed activities.

NordPass allows 2,000 requests per 5 minutes per IP address. The collector waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After`. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from NordPass or HTTP Ingest is refused, not followed, so no token or key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The collector never logs the token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s collectors/nordpass-activity-logs -p 'test_*.py' -v
```

The tests start a local mock of the Activity Logs API and HTTP Ingest, built from the documented shapes and errors, and check paging, tagging, oldest-first order, the lookback, splitting a window over 90 days and one past the 10,000-result limit, a late activity inside the overlap, repeats, that the cursor moves only after HTTP Ingest accepted the activities, a refused token, a rejected query, dry-run, retries, batching and gzip, the regions, refused redirects, and that no secret reaches the log.

## References

- NordPass Activity Logs API (URLs, header, filters, paging, response, limits, errors): https://support.nordpass.com/hc/en-us/articles/23485641117329-Activity-Logs-API
- Managing NordPass tokens: https://support.nordpass.com/hc/en-us/articles/28596887810065-How-to-manage-NordPass-Tokens
- The Activity Log and its action types: https://support.nordpass.com/hc/en-us/articles/4418022658705-How-to-use-the-Activity-Log
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
