# TP-Link Omada logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Omada controller or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from TP-Link's Omada Open API reference and Open API Access Guide. Run it with `--dry-run` first and check what it would send.

An Omada controller (software, hardware such as the OC200 and OC300, or cloud-based) keeps event, alert and audit logs for itself, for the MSP view and for each site, and offers them through its Open API, which is pull only. Its syslog output has no published format, and its webhook sends only the log text and can't add the `Authorization` header HTTP Ingest needs. This script reads the logs through the Open API and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"omada_record"` (`event`, `alert` or `audit`) in front of each record, and where it came from, and the library parsers in `parsers/tp-link/omada` normalize them. Sophos Fusion has no TP-Link integration.

| Data | Endpoint |
| --- | --- |
| Access token (client credentials) | `POST /openapi/authorize/token?grant_type=client_credentials` |
| Sites | `GET /openapi/v1/{omadacId}/sites`, or `GET /openapi/v1/msp/{mspId}/sites` and `/customers` in MSP mode |
| Each site's events, alerts and audit logs | `GET /openapi/v1/{omadacId}/sites/{siteId}/logs/events`, `/logs/alerts` and `/audit-logs` |
| The controller's (or each customer's) events, alerts and audit logs | `GET /openapi/v1/{omadacId}/logs/events`, `/logs/alerts` and `/audit-logs` |
| The MSP view's events, alerts and audit logs | `GET /openapi/v1/msp/{mspId}/logs/events`, `/logs/alerts` and `/audit-logs` |

Every request carries the access token as `Authorization: AccessToken=<token>`. Python 3.9 or later, standard library only. One file: `omada_logs_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/tp-link/omada` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Omada.** An older controller may not offer the log endpoints in its Open API; the bridge stops with HTTP 404 if it doesn't.

1. In the Global view (or the MSP view for an MSP), go to Settings > Platform Integration > Open API and add an application in client mode.
2. Give it the least it needs: a role that can only view, and only the sites (and, for an MSP, the customers) it should read. Reading logs needs no write access.
3. Open the application and note its Client ID, Client Secret, Omada ID (or MSP ID) and Interface Access Address.
4. For a software or hardware controller with its own self-signed certificate, export that certificate (or the CA that issued yours) as PEM and set `OMADA_CA_FILE` to it. Use the host name the certificate gives in `OMADA_URL`. A cloud-based controller's address (`aps1-`, `euw1-` or `use1-omada-northbound.tplinkcloud.com`) needs no file.

Changing the application's permissions, or copying or importing sites, makes Omada drop its tokens; the bridge gets a new one when Omada answers that the old one isn't valid.

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `OMADA_URL` | none | The application's Interface Access Address: scheme, host and port only, such as `https://aps1-omada-northbound.tplinkcloud.com` or `https://omada.example.com:8043`. |
| `OMADA_ID` | none | The Omada ID (customer ID) shown with the application, or the MSP ID with `OMADA_MSP=1`. |
| `OMADA_CLIENT_ID` | none | The application's Client ID. |
| `OMADA_CLIENT_SECRET` | none | The application's Client Secret. |
| `OMADA_MSP` | `0` | `1` reads the MSP view, then each customer and each customer's sites, with the MSP application's token. Hardware controllers have no MSP mode. |
| `OMADA_LOGS` | `events,alerts,audit` | The logs to read, comma separated. |
| `OMADA_PAGE_SIZE` | `1000` | Rows per request, 1 to 1000. |
| `OMADA_CA_FILE` | none | A PEM certificate (or CA) to trust for a controller with its own certificate. It is used for Omada only. |
| `BRIDGE_STATE_FILE` | `omada_logs_state.json` | Each log's last window end and the records sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for records the controller lists late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 omada_logs_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 omada_logs_bridge.py                   # one pass, for cron or a systemd timer
python3 omada_logs_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every log was read and sent. On an error the bridge logs it with the HTTP status or Omada's error code, stops, and leaves that log's window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration, credential or permission error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them. A certificate that isn't trusted, or that doesn't name the host in `OMADA_URL`, stops the run at once.

As a systemd service that polls, with the variables in `/etc/tp-link-omada-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=TP-Link Omada logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/tp-link-omada-logs/omada_logs_bridge.py --interval 300
EnvironmentFile=/etc/tp-link-omada-logs.env
DynamicUser=yes
StateDirectory=tp-link-omada-logs
WorkingDirectory=/var/lib/tp-link-omada-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run gets an access token with the client credentials grant (`{"omadacId", "client_id", "client_secret"}` in the body) and keeps it until a minute before the `expiresIn` Omada gives. When Omada answers that the token expired or isn't valid (error -44112 or -44113, or HTTP 401), the bridge gets a new one and sends the request once more.
- Each run lists the sites again, so new sites are read from the run after they appear. In MSP mode it reads the MSP view, each customer from the customer list and the MSP site list, and each customer's sites with the customer's ID in the path, as TP-Link's guide says for other APIs in MSP mode.
- Each log of each scope is read from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now. Events and alerts take `filters.timeStart` and `filters.timeEnd` in milliseconds; audit logs take `filters.times=[{"timeStart", "timeEnd"}]` and `sorts.time=asc`. Pages start at 1 and run until the rows reach `totalRows` or a page is empty.
- Events and alerts have a unique `id`, so the bridge drops repeats by `id`; an audit log has none, so it is known by the hash of the whole record. A window's end is saved only after every page of it was sent, and never past the time of the run.
- Omada answers with `errorCode` in the body, 0 for success. Error -44106 means the client ID or secret is wrong, and -1505 or -1005 that the application can't read a site or customer; both stop the run with Omada's message. Any other non-zero code stops it with the code and message.
- TP-Link gives each controller and organization a budget of 10 Open API requests a second, so the bridge spaces its requests 0.15 seconds apart. It waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Omada or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

Each record goes out as the bridge read it, after these fields:

| Field | Value |
| --- | --- |
| `omada_record` | `event`, `alert` or `audit` |
| `omada_scope` | `site`, `global` (the controller), `customer` or `msp` |
| `omada_id` | The Omada ID, customer ID or MSP ID in the path |
| `omada_customer_id`, `omada_customer_name` | The customer, in MSP mode |
| `omada_site_id`, `omada_site_name` | The site, for site logs |

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/tp-link-omada-logs -p 'test_*.py' -v
```

The tests start a local mock of the Open API (token, site, customer and log endpoints) and HTTP Ingest, built from the documented shapes, and check the token request and its reuse and renewal, the access token header, paging with `page`, `pageSize` and `totalRows`, the time filters, MSP mode, the record fields, windows, overlaps and repeats, new sites, the lookback, that a window ends only after HTTP Ingest accepted it and never past now, the logs setting, Omada error codes and HTTP errors, request spacing, dry-run, retries, batching and gzip, refused redirects, the response size cap, a controller's own certificate, settings, and that no secret reaches the log.

## References

- Omada Open API reference (endpoints, parameters and response schemas): https://use1-omada-northbound.tplinkcloud.com/v3/api-docs
- Omada Open API Access Guide (client credentials, the AccessToken header, error codes, rate budget, log notification keys, audit log types): https://use1-omada-northbound.tplinkcloud.com/doc.html
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
