# Cortex Xpanse alerts bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Cortex Xpanse tenant or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Palo Alto's Cortex Xpanse REST API reference. Run it with `--dry-run` first and check what it would send.

Cortex Xpanse raises an alert for each attack surface issue it finds, such as an exposed service, an insecure TLS setup or an end-of-life server on the internet. It forwards alerts only by email, Slack or syslog, and Palo Alto documents no syslog format for them; its own docs point to the Get Alerts API for the full alert. So this script asks the API for the attack surface (ASM) alerts Xpanse created in each new window and sends each one as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser in `parsers/palo-alto-networks/cortex-xpanse` normalizes them.

Each alert goes on as Xpanse returns it (`alert_id`, `external_id`, `name`, `description`, `severity`, `resolution_status`, `ipv4_addresses`, `domain_names`, `port_number`, `port_protocol`, `attack_surface_rule_id`, `attack_surface_rule_name`, `remediation_guidance`, `asset_ids`, `service_ids`, `tags`, `certificate`, `local_insert_ts`, `detection_timestamp` and the rest), with `xpanse_record` (`alert`) and `xpanse_tenant` (the tenant's FQDN from `XPANSE_API_URL`) first.

Python 3.9 or later, standard library only. One file: `cortex_xpanse_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/palo-alto-networks/cortex-xpanse` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Cortex Xpanse.** The public API needs the Cortex Xpanse Expander license. Create a custom role for the bridge with View on Alerts and Incidents and the Public API permission (Palo Alto's Get Started page asks for View/Edit on the Public API), and nothing else; Palo Alto doesn't say whether the Viewer role alone can read alerts through the API. Then go to Settings > Configurations > Integrations > API Keys, choose + New Key, pick **Advanced**, give it that role and an expiry, and copy the key; it is shown once. The key's number is in the ID column, and View Examples on the key shows the API URL, such as `https://api-example.crtx.au.paloaltonetworks.com`.

With an advanced key, each request carries a new random 64-character nonce, the time in milliseconds, and the SHA-256 of the key, the nonce and the time, so the key itself never leaves this machine. A standard key also works (`XPANSE_API_KEY_TYPE=standard`); it is sent as is on each request.

## Configuration

Everything comes from environment variables. Keep the API key and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `XPANSE_API_URL` | none | The API URL with no path, such as `https://api-example.crtx.au.paloaltonetworks.com`. |
| `XPANSE_API_KEY` | none | The API key. |
| `XPANSE_API_KEY_ID` | none | The key's number, from the ID column, sent as `x-xdr-auth-id`. |
| `XPANSE_API_KEY_TYPE` | `advanced` | `advanced` or `standard`, as the key was created. |
| `XPANSE_SEVERITIES` | all | Only these severities, such as `high,critical`. Xpanse's are `informational`, `low`, `medium`, `high`, `critical` and `unknown`. |
| `XPANSE_PAGE_SIZE` | `100` | Alerts per page, 1 to 100 (Xpanse's limit). |
| `BRIDGE_STATE_FILE` | `cortex_xpanse_state.json` | Where each tenant's window ended. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 8,760. |
| `BRIDGE_DELAY_SECONDS` | `300` | How far behind now each window ends. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 cortex_xpanse_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 cortex_xpanse_bridge.py                   # one pass, for cron or a systemd timer
python3 cortex_xpanse_bridge.py --interval 600    # keep polling every 10 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status and Xpanse's message, stops, and leaves the window where it was, so the next run reads the same records again from where the last accepted page ended. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/cortex-xpanse-alerts.env` (owned by root, mode 600):

```ini
[Unit]
Description=Cortex Xpanse alerts bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/cortex-xpanse-alerts/cortex_xpanse_bridge.py --interval 600
EnvironmentFile=/etc/cortex-xpanse-alerts.env
DynamicUser=yes
StateDirectory=cortex-xpanse-alerts
WorkingDirectory=/var/lib/cortex-xpanse-alerts
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads one window: from where the last one ended (or `BRIDGE_LOOKBACK_HOURS` back, the first time) to `BRIDGE_DELAY_SECONDS` before now, in milliseconds. It posts `{"request_data": {...}}` to `/public_api/v2/alerts/get_alerts_multi_events/` with the filters `alert_source` in `["ASM"]`, `server_creation_time` `gte` the start and `lte` the end less a millisecond (so windows meet with no overlap), the severities if set, `search_from` 0, `search_to` the page size and `use_page_token: true`.
- `server_creation_time` is when Xpanse stored the alert, so an alert detected earlier but stored late is still in the next window. Palo Alto's reference lists it as a filter field but gives its operators only for other time fields; `gte` is what Palo Alto's own XSOAR integration sends, and `lte` follows it.
- Each next page sends the same request with the last answer's `next_page_token`; Xpanse doesn't sort a page token query, so the order of alerts within a window is Xpanse's. The position is saved after HTTP Ingest accepted each page, and a run that stopped partway goes on from the next page with the same window. If Xpanse refuses a saved page token, the bridge reads that window again from its first page, so some alerts can arrive twice.
- Each alert is sent once, when Xpanse creates it. A later change, such as its resolution status moving to resolved, isn't sent again.
- 408, 429, 500, 502, 503 and 504 are retried with backoff, honoring `Retry-After`, up to 6 times; Palo Alto uses 500 for API communication errors. A 401 (a wrong key, key ID or key type), 402 (no license for the API), 403 (a role that can't read alerts), 400 or 422 stops the run with Xpanse's `err_msg`. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Xpanse or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the API key, the signed `Authorization` header, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/cortex-xpanse-alerts -p 'test_*.py' -v
```

The tests start a local mock of the Get Alerts API (checking the standard and advanced keys, refusing a nonce it has seen, running the bridge's filters and paging by token) and HTTP Ingest, built from the documented shapes, and check the records, the filters and page size, the advanced key's signature and a new nonce on a retry, the standard key, refused keys and requests, severities, windows that meet, paging and going on from a stopped page, a refused page token, dry-run, retries, batching and gzip, state per tenant, settings, refused redirects, the response size cap, and that no secret reaches the log.

## References

- Get Alerts (`/public_api/v2/alerts/get_alerts_multi_events/`): https://cortex-docs.paloaltonetworks.com/xpanse-api/xpanse-public-api/incident-management
- Get started with the Cortex Xpanse APIs (keys, roles, the advanced key's signature): https://cortex-docs.paloaltonetworks.com/xpanse-api/get-started-with-cortex-xpanse-apis
- Generate an API key: https://cortex-docs.paloaltonetworks.com/cortex-xpanse/integrations/generate-an-api-key
- Log forwarding (email, Slack and syslog only): https://cortex-docs.paloaltonetworks.com/cortex-xpanse/onboard-and-configure-cortex-xpanse/post-deployment-steps/log-forwarding
- Cortex XSOAR CortexXpanse integration, the filters it sends: https://github.com/demisto/content/tree/master/Packs/CortexXpanse/Integrations/CortexXpanse
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
