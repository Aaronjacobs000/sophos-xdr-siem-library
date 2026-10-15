# Kaseya VSA 9.5 Data Warehouse bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real VSA 9.5 server or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the dataset schemas and sample responses in the Kaseya Data Warehouse API reference (R95). Run it with `--dry-run` first and check what it would send.

VSA 9.5 has no syslog or webhook export for who connected to which agent and what they changed. Its Data Warehouse API has it. This script reads five datasets, keeps a cursor for each, adds the dataset name as the first key (`"Dataset"`) of each record, and sends the records as JSON lines to a Sophos NG-SIEM HTTP Ingest integration. The library parser `KASEYA_VSA95_DW_JSON_STANDALONE_CLOUDAUDIT` in `parsers/kaseya/vsa-9-5` then normalizes them to CloudAudit.

| Dataset | What it holds | Time field |
| --- | --- | --- |
| `RemoteControlSessions` | Kaseya Remote Control sessions and the technician | `SessionStartTime` |
| `RemoteControlFileTransferSessions` | Files and folders moved in a session, with the technician's address | `TransferTime` |
| `AgentLiveConnectAuditLogs` | Live Connect audit entries, with login name and address | `EntryTimeStamp` |
| `LiveConnectOnDemandAudit` | Live Connect on Demand sessions | `CreationDateTime` |
| `ConfigurationChangeEvents` | Agent configuration changes | `ChangeEventDateTime` |

VSA 10 is a different product with a different API; use `bridges/kaseya-vsa10-audit-logs` for it.

Python 3.9 or later, standard library only. One file: `kaseya_vsa95_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/kaseya/vsa-9-5` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**VSA 9.5.** Create a VSA user for the bridge whose role and scope cover the machines you want, and create a user token for it with the Data Warehouse API scope. The API returns only the data that user's role and scope can see, in that user's partition.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `VSA95_API_URL` | none | `https://<your VSA server>/api/odata/1.0`. |
| `VSA95_USERNAME` | none | The VSA user name. |
| `VSA95_USER_TOKEN` | none | The user token with the Data Warehouse API scope. |
| `VSA95_DATASETS` | all five | Comma-separated datasets to read. |
| `VSA95_PAGE_SIZE` | `1000` | Records per request (`$top`). |
| `VSA95_QUOTE_TIMES` | `0` | `1` sends the time in `$filter` as a quoted string, if your server refuses the unquoted form. |
| `BRIDGE_STATE_FILE` | `kaseya_vsa95_state.json` | Cursors and recently seen records. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much before each cursor a run re-reads, to catch late records. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 kaseya_vsa95_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 kaseya_vsa95_bridge.py                  # one pass, for cron or a systemd timer
python3 kaseya_vsa95_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means every dataset was read and sent. On an error the bridge logs the dataset and the HTTP status, stops, and leaves that dataset's cursor where it was.

## How it reads the API

- It authenticates with HTTP Basic, user name and user token, as the API reference shows.
- For each dataset it asks for `$filter=<time field> gt <cursor minus the overlap>`, `$orderby=<time field> asc`, `$top` and `$skip`, and reads pages until one comes back short. The reference documents standard OData expressions but types the time fields as strings, so `VSA95_QUOTE_TIMES` switches to a quoted literal if the server wants one. This hasn't been checked against a live server.
- Records have no shared ID field, so repeats inside the overlap are recognized by the fields that identify each dataset's records (for example `SessionId`, or `AgentId` and `EventId`).
- Each dataset's cursor moves to the newest time read, but never past the time of the run, so a record dated in the future can't stop that dataset.

The reference gives no rate limits. The bridge waits and retries 408, 429 and 5xx up to 6 times, honoring `Retry-After` up to 5 minutes, and stops on 400, 401 or 403. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the Data Warehouse API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the user token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/kaseya-vsa95-data-warehouse -p 'test_*.py' -v
```

The tests start a local mock of the five datasets and HTTP Ingest, built from the documented shapes, and check that each dataset is read and tagged, `$skip` paging, the cursor and overlap, the quoted-time option, dry-run, retries, the stop on a bad token, and that no secret reaches the log.

## References

- Kaseya Data Warehouse API reference (R95): https://help.vsa9.kaseya.com/help/Content/Resources/PDFs/EN_DataWarehouseAPI_R95.pdf
- Data Warehouse API sample request and response: https://help.vsa9.kaseya.com/help/Content/Modules/data-warehouse-api/42065.htm
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
