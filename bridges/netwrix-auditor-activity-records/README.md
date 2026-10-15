# Netwrix Auditor activity records bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Netwrix Auditor Server or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Netwrix's Integration API reference. Run it with `--dry-run` first and check what it would send.

Netwrix Auditor keeps what it audits (Active Directory, Microsoft Entra ID, Exchange and Exchange Online, SharePoint, file servers and NAS, Windows Server, SQL Server, VMware, logon activity and its other data sources) in its Audit Database, on your own network. Its Integration API is pull only, so this script runs on a host that can reach Netwrix Auditor Server, searches the activity records by time, and sends each one as a JSON line to a Sophos NG-SIEM HTTP Ingest integration. It puts `"netwrix_auditor_record": "activity_record"` in front of each record, and the library parser in `parsers/netwrix/netwrix-auditor` normalizes them. Sophos Fusion has no Netwrix integration.

| Data | Endpoint |
| --- | --- |
| Activity records (who changed or accessed what, when, where and from which workstation, with before and after values) | `POST /netwrix/api/v1/activity_records/search?format=json&count=<n>` |

Python 3.9 or later, standard library only. One file: `netwrix_auditor_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/netwrix/netwrix-auditor` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Netwrix Auditor.** Netwrix Auditor 9.0 or later, where activity records carry `DataSource` and `MonitoringPlan`, with the Audit Database configured.

1. In Netwrix Auditor, open Settings > Integrations and make sure Leverage Integration API is on (it is by default). Modify settings shows the port, TCP 9699 by default, and the minimum TLS version. Allow that port from the bridge's host to Netwrix Auditor Server.
2. Create a domain account for the bridge and give it the least role that covers what you want to send: the Reviewer role on the monitoring plans or folders to forward, or the Global reviewer role for every plan. Netwrix returns only the records in the account's delegated scope. The bridge only reads, so it needs no Contributor or administrator role.
3. The API uses HTTPS with a self-signed certificate that Netwrix Auditor generates, unless you assigned another with `APIAdminTool.exe api https certificate`, as Netwrix recommends. Export the certificate in use (or the CA that issued it) as a Base-64 encoded `.cer` or `.pem` file from the Personal store on Netwrix Auditor Server, copy it to the bridge's host, and set `NETWRIX_CA_FILE` to it. Use the host name the certificate gives in `NETWRIX_API_URL`; Netwrix says to give the computer name as it appears in the certificate's properties.

The bridge signs in with Basic authentication over HTTPS. Netwrix lists NTLM (recommended), Negotiate, Digest and Basic for the Integration API, and Python's standard library speaks only Basic. The password travels in every request, inside the TLS connection, so keep `NETWRIX_CA_FILE` set to the right certificate and never switch the API to plain HTTP.

## Configuration

Everything comes from environment variables. Keep the password and key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `NETWRIX_API_URL` | none | Netwrix Auditor Server and the API port, such as `https://nwxserver.corp.example.com:9699`, with the host name the certificate gives. |
| `NETWRIX_USERNAME` | none | The bridge's account, as `DOMAIN\user`. |
| `NETWRIX_PASSWORD` | none | Its password. |
| `NETWRIX_CA_FILE` | system store | A PEM file with the certificate Netwrix Auditor Server uses, or the CA that issued it. It is trusted for Netwrix Auditor Server only; HTTP Ingest keeps the system store. |
| `NETWRIX_DATA_SOURCES` | all | Data sources to send, comma separated, as Netwrix names them, such as `Active Directory,Entra ID,File Servers,Logon Activity`. Netwrix matches each one as Contains, its default, so `Exchange` also takes `Exchange Online`. Empty sends every data source the account can review. |
| `NETWRIX_PAGE_SIZE` | `1000` | Records per request, 1 to 5000. |
| `BRIDGE_STATE_FILE` | `netwrix_auditor_state.json` | The last window's end and the RIDs sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `3600` | How far before the last window's end each run searches again, for records Netwrix wrote late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `120` | Seconds per request. A search over a large Audit Database can take a while. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 netwrix_auditor_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 netwrix_auditor_bridge.py                   # one pass, for cron or a systemd timer
python3 netwrix_auditor_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration, password or certificate error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/netwrix-auditor-activity-records.env` (owned by root, mode 600) and the certificate where that file points:

```ini
[Unit]
Description=Netwrix Auditor activity records bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/netwrix-auditor-activity-records/netwrix_auditor_bridge.py --interval 300
EnvironmentFile=/etc/netwrix-auditor-activity-records.env
DynamicUser=yes
StateDirectory=netwrix-auditor-activity-records
WorkingDirectory=/var/lib/netwrix-auditor-activity-records
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run searches from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now. The body is `{"FilterList": {"When": {"From": "<start>", "To": "<end>"}}}`, with `"DataSource": [...]` added when `NETWRIX_DATA_SOURCES` is set. Times go in UTC as `YYYY-MM-DDTHH:mm:ssZ`, a format Netwrix lists for `When`.
- It pages with the `ContinuationMark` each answer carries, sending it back with the same filters, until an answer has no records, which Netwrix says marks the end. Records come in `ActivityRecordList`; Netwrix's docs also name the array `ActivityRecordSearch` for the later pages, so the bridge reads either.
- `When` is the time of the change, and Netwrix writes a record when its data collection for that source runs, so a record can reach the Audit Database after a run has passed its time. The overlap reads the last hour again by default; raise it to cover your monitoring plans' collection delay. Repeats are dropped by `RID`, the record's unique key in the Audit Database (a hash of the whole record if a record has none). A window's end is saved only after every page of it was sent, and never past the time of the run.
- Netwrix's own SIEM add-ons work the same way: they save a timestamp after each run and start the next one there.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. Netwrix answers 500 when its license has expired, the Archive Service can't be reached or it hit an internal error; one that outlasts the retries is logged with Netwrix's error description. 401 (wrong account or password, or Basic authentication refused), 403, 404, 405 and 400 stop the run with Netwrix's error, and so does a certificate that isn't trusted or doesn't name the host, without a retry. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Netwrix Auditor Server or HTTP Ingest is refused, not followed, so no password or key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the account's name or password, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/netwrix-auditor-activity-records -p 'test_*.py' -v
```

The tests start a local mock of the Integration API search endpoint and HTTP Ingest, built from the documented shapes, and check Basic authentication with the domain account, the `When` filter and `ContinuationMark` paging, the later pages' `ActivityRecordSearch` name, tagging, the data source setting, windows, overlaps and repeats by `RID` or hash, the lookback, that a window ends only after HTTP Ingest accepted it and never past now, refused accounts, roles and URLs, Netwrix's error messages, dry-run, retries, batching and gzip, refused redirects, the response size cap, and settings. When openssl is installed they also start an HTTPS mock with a certificate made for the test, and check that `NETWRIX_CA_FILE` trusts it, that it is refused without that setting or for another host name, and that no secret reaches the log.

## References

- Integration API overview and endpoints (authentication methods, roles): https://docs.netwrix.com/docs/auditor/10_9/api/endpoints
- Retrieve activity records: https://docs.netwrix.com/docs/auditor/10_9/api/retrieveactivityrecords
- Search activity records: https://docs.netwrix.com/docs/auditor/10_9/api/searchactivityrecords
- Search parameters, filters and operators: https://docs.netwrix.com/docs/auditor/10_9/api/postdata/searchparameters
- Continuation mark: https://docs.netwrix.com/docs/auditor/10_9/api/postdata/continuationmark
- Activity record reference (RID, When formats): https://docs.netwrix.com/docs/auditor/10_9/api/activityrecordreference
- Response status codes and error details: https://docs.netwrix.com/docs/auditor/10_9/api/responsestatuscodes and https://docs.netwrix.com/docs/auditor/10_9/api/errordetails
- Security (HTTPS, the self-signed certificate, APIAdminTool.exe): https://docs.netwrix.com/docs/auditor/10_9/api/security
- Integration API prerequisites (Leverage Integration API, port and TLS settings): https://docs.netwrix.com/docs/auditor/10_9/api/prerequisites
- Integration API port: https://docs.netwrix.com/docs/auditor/10_9/api/ports
- How Netwrix's add-ons resume from a timestamp: https://docs.netwrix.com/docs/auditor/10_9/addon/siem/activityrecords
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
