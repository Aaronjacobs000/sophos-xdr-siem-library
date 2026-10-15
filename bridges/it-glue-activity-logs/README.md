# IT Glue activity log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real IT Glue account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the response shapes in the IT Glue API documentation. Run it with `--dry-run` first and check what it would send.

IT Glue holds client credentials and documentation, so its activity log matters to a SOC: who created, changed or deleted passwords, documents and configurations, from which address and browser. IT Glue has no syslog or log push; its workflow webhooks only send a payload you write and can't add an authorization header. This script polls `GET /logs`, keeps a cursor, and sends each record unchanged as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser `ITGLUE_ACTIVITY_JSON_STANDALONE_CLOUDAUDIT` in `parsers/it-glue/activity-logs` then normalizes it to CloudAudit.

Python 3.9 or later, standard library only. One file: `it_glue_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/it-glue/activity-logs` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**IT Glue.** Sign in with an Administrator role and generate an API key under Account > Settings > API Keys. You can't view it again, so store it straight away. IT Glue revokes keys that go unused for 90 days, so run the bridge at least that often. Use the API host for your data center: `https://api.itglue.com`, `https://api.eu.itglue.com` or `https://api.au.itglue.com`.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `ITGLUE_API_URL` | `https://api.itglue.com` | Your data center's API host. |
| `ITGLUE_API_KEY` | none | The IT Glue API key, sent as `x-api-key`. |
| `ITGLUE_PAGE_SIZE` | `1000` | Records per page, up to 1000. |
| `BRIDGE_STATE_FILE` | `it_glue_state.json` | Cursor and recently seen IDs. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, at most 720: `GET /logs` covers the last 30 days. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much of the previous window each run re-reads, to catch late records. Repeats are dropped by ID. |
| `BRIDGE_SETTLE_SECONDS` | `60` | Each window stops this far before now. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 it_glue_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 it_glue_bridge.py                  # one pass, for cron or a systemd timer
python3 it_glue_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means the window was read and sent. On an error the bridge logs the step and the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same window again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.

## How it reads the API

- It asks for `filter[created_at]=<start>,<end>` with `sort=created_at`, from the cursor minus the overlap to now minus the settle time, in windows of at most a week (IT Glue may refuse longer ranges).
- IT Glue returns at most 5 pages per query. It reads pages 1 to 5 using `meta.total-pages`; when a window has more, the next query starts at the newest record it received, and repeats are dropped by ID.
- It sends new records oldest first, then saves the cursor and the IDs inside the overlap.

Rate limit: 3000 requests in 5 minutes. The bridge waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After` up to 5 minutes, and stops on 401 or 403. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the IT Glue API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

The API and HTTP Ingest both deliver at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the IT Glue key, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/it-glue-activity-logs -p 'test_*.py' -v
```

The tests start a local mock of `GET /logs` and HTTP Ingest, built from the documented shapes, and check paging, the 5-page limit, week-long windows, the cursor and overlap, dry-run, retries, the stop on a bad key, batching and gzip, and that no secret reaches the log.

## References

- IT Glue API (Logs, authentication, rate limiting, data centers): https://api.itglue.com/developer/
- Pagination in the IT Glue API: https://help.itglue.kaseya.com/help/Content/1-admin/it-glue-api/pagination-in-the-it-glue-api.html
- IT Glue activity logs: https://help.itglue.kaseya.com/help/Content/1-admin/account-administration/activity-logs.html
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
