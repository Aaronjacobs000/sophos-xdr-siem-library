# Red Sift OnDMARC collector

> **Unofficial, and tested against documented response shapes only.** This collector has not run against a real OnDMARC account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the response shapes in Red Sift's public OnDMARC API v2 specification. Run it with `--dry-run` first and check what it would send.

OnDMARC has no syslog export. Red Sift's Event Hub can push events to webhooks and SIEMs, but its record format isn't published, so this script reads the public OnDMARC API v2 instead, keeps a cursor for each source, and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds an `ondmarc_record` key naming the source, and the library parsers in `parsers/red-sift/ondmarc` normalize the records.

| Source (`ONDMARC_SOURCES`) | API | `ondmarc_record` | Schema |
| --- | --- | --- | --- |
| `guardian` (default) | `GET /dmarc-guardian`: DMARC Guardian issues, such as dangling DNS records and SPF subdomain takeover risks | `dmarc_guardian_issue` | Third-party alert |
| `dns_history` (default) | `GET /dns-history`: DMARC, SPF and MX record changes on the account's domains | `dns_history` | Third-party alert |
| `aggregate` | `GET /reports/aggregate/analyst`: DMARC aggregate report rows, one day at a time per domain. Needs OnDMARC's DMARC Analyst feature. | `aggregate_record` | Email |

The API v2 has no forensic (failure) report endpoint, so forensic reports aren't collected.

Python 3.9 or later, standard library only. One file: `ondmarc_collector.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/red-sift/ondmarc` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**OnDMARC.** API access is a business-tier add-on; Red Sift turns it on for the account. A super-user creates an API key in the Red Sift IAM console (`iam.redsift.cloud/profile?tab=ondmarc`, or the EU or US console). Use the API base URL from the same region as the key: `https://rpc.redsift.cloud/api/ondmarc/v2` (UK, the default), `https://rpc.eu.redsift.cloud/api/ondmarc/v2` or `https://rpc.us.redsift.cloud/api/ondmarc/v2`. The `aggregate` source also needs the DMARC Analyst feature; without it the API answers 402 and the collector stops with that message.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the collector's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `ONDMARC_API_KEY` | none | The OnDMARC API key, sent as `Authorization: Api-Key`. |
| `ONDMARC_API_URL` | `https://rpc.redsift.cloud/api/ondmarc/v2` | The API base for your region. |
| `ONDMARC_SOURCES` | `guardian,dns_history` | Comma-separated: `guardian`, `dns_history`, `aggregate`. |
| `ONDMARC_AGGREGATE_DOMAINS` | every domain | Domains to read aggregate rows for. Empty reads `GET /domains/flat`. |
| `ONDMARC_AGGREGATE_LOOKBACK_DAYS` | `7` | How many days of aggregate rows the first run reads per domain. |
| `ONDMARC_AGGREGATE_SETTLE_DAYS` | `2` | How old a day must be before it is read. Reporters send aggregate reports a day or two late. |
| `COLLECTOR_STATE_FILE` | `ondmarc_state.json` | Cursors and recently seen IDs. |
| `COLLECTOR_LOOKBACK_HOURS` | `24` | How far back the first DNS history run starts. |
| `COLLECTOR_OVERLAP_SECONDS` | `3600` | How much before the DNS history cursor each run re-reads. Repeats are dropped by ID. |
| `COLLECTOR_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `COLLECTOR_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `COLLECTOR_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `COLLECTOR_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 ondmarc_collector.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 ondmarc_collector.py                   # one pass, for cron or a systemd timer
python3 ondmarc_collector.py --interval 900    # keep polling every 15 minutes
```

Exit code 0 means every source was read and sent. On an error the collector logs the source and the HTTP status, stops, and leaves that source's cursor where the last accepted batch left it, so the next run picks up from there.

## How it reads each API

- **guardian:** reads every page of the active issue list (pages count from 0, up to `pagination.page_count`). An issue is sent when it first appears and again whenever its `lastUpdated` changes. The issue's `emails.list` (threat-intelligence rows) and `imageUrl` are left out; everything else is sent as the API returns it.
- **dns_history:** reads from the UTC day of the cursor minus the overlap, sorted by `observedAt`, and sends the changes it hasn't sent, oldest first. The API filters by whole days, so the collector remembers the IDs from that day. `diffSegments`, which is for display, is left out.
- **aggregate:** for each domain and each day from the cursor to `ONDMARC_AGGREGATE_SETTLE_DAYS` ago, reads the raw rows with `from_date` and `to_date` set to that day, pages with `pagination_model`, and adds `ondmarc_domain`. Each day is read once.

The OnDMARC API doesn't publish a rate limit. The collector waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After`, and stops on 401, 402 or 403. HTTP Ingest 400, 401, 403 and 413 are not retried.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The collector never logs the API key, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s collectors/red-sift-ondmarc -p 'test_*.py' -v
```

The tests start a local mock of the four OnDMARC endpoints and HTTP Ingest, built from the documented shapes, and check paging, the tagging and trimming of records, resending updated Guardian issues, DNS history cursors and the lookback, one read per settled aggregate day, the stop on 402, dry-run, retries, the stop on a bad key, batching and gzip, and that no secret reaches the log.

## References

- OnDMARC API v2 reference and OpenAPI specification: https://docs.redsift.com/api/ondmarc/ and https://docs.redsift.com/ondmarc.yaml
- Red Sift API authentication and regions: https://docs.redsift.com/authentication/
- Getting started with the OnDMARC API: https://docs.redsift.com/ondmarc/guides/getting-started/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
