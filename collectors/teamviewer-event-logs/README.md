# TeamViewer event log collector

> **Unofficial, and tested against documented response shapes only.** This collector has not run against a real TeamViewer company account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the request and response shapes in TeamViewer's Web API specification. Run it with `--dry-run` first and check what it would send.

Remote access tools are a common way into a network, and TeamViewer's event log records who started, joined and ended remote sessions, sent or received files, recorded sessions or blanked the remote screen, plus user, role, policy, script token, SSO, conditional access and device management changes. TeamViewer has no syslog or push export for it. This script polls `POST /api/v2/EventLogging`, keeps a cursor, and sends each event unchanged as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser `TEAMVIEWER_EVENTLOG_JSON_STANDALONE_CLOUDAUDIT` in `parsers/teamviewer/event-log` then normalizes it to CloudAudit.

Python 3.9 or later, standard library only. One file: `teamviewer_collector.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/teamviewer/event-log` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**TeamViewer.** Event logging needs a Tensor license and TeamViewer 14.1 or later, and is off by default. A company administrator turns it on in the TeamViewer web client under Admin Settings > General > Event logging. Then create a script token for the collector with the event logging permission only, and copy it. TeamViewer keeps event data for one year.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the collector's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `TEAMVIEWER_SCRIPT_TOKEN` | none | The script token, sent as `Authorization: Bearer`. |
| `TEAMVIEWER_API_URL` | `https://webapi.teamviewer.com` | The Web API host. |
| `TEAMVIEWER_EVENT_TYPES` | all | Optional comma-separated event types, for example `Session,UserProfile,Policy`. |
| `COLLECTOR_STATE_FILE` | `teamviewer_state.json` | Cursor and recently seen events. |
| `COLLECTOR_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `COLLECTOR_OVERLAP_SECONDS` | `300` | How much of the previous window each run re-reads, to catch late events. Repeats are dropped. |
| `COLLECTOR_SETTLE_SECONDS` | `60` | Each window stops this far before now. |
| `COLLECTOR_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `COLLECTOR_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `COLLECTOR_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `COLLECTOR_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 teamviewer_collector.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 teamviewer_collector.py                  # one pass, for cron or a systemd timer
python3 teamviewer_collector.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means the window was read and sent. On an error the collector logs the step and the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same window again.

## How it reads the API

- It posts `StartDate` (the cursor minus the overlap) and `EndDate` (now minus the settle time) in UTC, with `EventTypes` when set, and repeats the request with each `PaginationToken` until the response has none.
- TeamViewer events have no ID, so repeats inside the overlap are recognized by a hash of the whole event. Two events that are identical in every field are sent once.
- It sends the new events oldest first, then saves the cursor and the hashes inside the overlap.

TeamViewer doesn't publish rate limits for this endpoint. The collector waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After`, and stops on 401 or 403. HTTP Ingest 400, 401, 403 and 413 are not retried.

The API and HTTP Ingest both deliver at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The collector never logs the script token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s collectors/teamviewer-event-logs -p 'test_*.py' -v
```

The tests start a local mock of the EventLogging endpoint and HTTP Ingest, built from the documented shapes, and check paging with `PaginationToken`, the event type filter, the cursor and overlap, dry-run, retries, the stop on a bad token, batching and gzip, and that no secret reaches the log.

## References

- TeamViewer Web API specification (EventLogging v2, AuditLogParameters, AuditEvent): https://webapi.teamviewer.com/api/v1/docs/index
- TeamViewer event log (auditability): https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-tensor/security/auditability-event-log/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
