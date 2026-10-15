# N-able N-sight RMM failing check bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real N-sight RMM account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the XML response in N-able's Data Extraction API documentation. Run it with `--dry-run` first and check what it would send.

N-sight RMM has no syslog, webhook or audit log export, and its Data Extraction API has no technician activity log. What it does return is the list of checks failing right now (`list_failing_checks`): antivirus, event log, Windows service, backup, disk and the other monitoring checks. This script polls that list, compares it with the previous poll, and sends one JSON record when a check starts failing (`"State":"failing"`) and one when it clears (`"State":"cleared"`) to a Sophos NG-SIEM HTTP Ingest integration. The library parser `NSIGHT_FAILING_CHECK_JSON_STANDALONE_THIRDPARTYALERT` in `parsers/n-able/n-sight-rmm` then normalizes them to the third-party alert schema.

Logins, remote sessions and script runs aren't available from N-sight, so this doesn't cover them.

Python 3.9 or later, standard library only. One file: `n_sight_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/n-able/n-sight-rmm` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**N-sight RMM.** In the All Devices view, go to Settings > General Settings > API. N-sight has one API key per account and regenerating it breaks everything that uses the old one, so use the existing key if there is one. Find the API server for your account's territory on N-able's "Determine the server for your API query" page, for example `https://www.system-monitor.com` for Australia.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `NSIGHT_API_URL` | none | Your territory's API server, for example `https://www.system-monitor.com`. |
| `NSIGHT_API_KEY` | none | The N-sight API key. The API takes it in the query string. |
| `NSIGHT_CLIENT_IDS` | all clients | Comma-separated client IDs to query one at a time, which N-able suggests for large accounts. |
| `NSIGHT_CHECK_TYPE` | `random` | `checks`, `tasks` (Windows Automated Tasks) or `random` (both), as the API defines them. |
| `NSIGHT_SEND_EXISTING` | `1` | `0` makes the first run record the current failures without sending them. |
| `BRIDGE_STATE_FILE` | `n_sight_state.json` | The failing checks seen at the last poll. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `120` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 n_sight_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 n_sight_bridge.py                  # one poll, for cron or a systemd timer
python3 n_sight_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means the list was read and the changes sent. On an error the bridge logs the step and the HTTP status, stops, and keeps the previous list, so the next run sends the same changes.

## How it reads the API

- It calls `https://<server>/api/?apikey=<key>&service=list_failing_checks&check_type=<type>`, once for all clients or once per configured client ID, and reads the XML: client, site, workstations and servers, and each device's `failed_checks`.
- A check is identified by device type, device ID and check ID. Each record holds the client, site and device, the check ID, type, description, output and status, the check's date and time as the API gives them, and `ObservedAt`, the UTC time the bridge saw the change, which the parser uses as the event time.
- A record only says what changed between two polls, so a check that fails and clears between polls isn't seen.

The documentation gives no rate limits. The bridge waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After` up to 5 minutes. An XML result whose status isn't OK, such as a wrong key, stops the run. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the N-sight API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

The API key is part of every request URL, so the bridge never logs URLs, only host names. It never logs the HTTP Ingest key or URL path either.

## Tests

```bash
python3 -m unittest discover -s bridges/n-able-n-sight-failing-checks -p 'test_*.py' -v
```

The tests start a local mock of `list_failing_checks` and HTTP Ingest, built from the documented XML, and check the flattening, the failing and cleared records between polls, the quiet first run, per-client queries, dry-run, retries, the stop on a bad key, and that no secret reaches the log.

## References

- N-sight Data Extraction API, Listing Failing Checks: https://developer.n-able.com/n-sight/docs/listing-failing-checks
- Getting started with the N-sight API: https://developer.n-able.com/n-sight/docs/getting-started-with-the-n-sight-api
- Determine the server for your API query: https://developer.n-able.com/n-sight/docs/determine-server-for-api-query
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
