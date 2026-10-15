# Syncro RMM alert bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Syncro account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the response shapes in Syncro's public API specification. Run it with `--dry-run` first and check what it would send.

Syncro raises RMM alerts from its monitors: antivirus, event log, services, failed scripts, offline assets and the rest. It has no syslog export, and its notification set webhook doesn't document a payload, so this script polls `GET /api/v1/rmm_alerts`, keeps a cursor, and sends each alert unchanged as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser `SYNCRO_RMM_ALERT_JSON_STANDALONE_THIRDPARTYALERT` in `parsers/syncro/rmm-alerts` then normalizes it to the third-party alert schema.

Syncro's API has no account audit log, so technician logins and script runs aren't available this way. The bridge sends each alert once, when it first appears; a later change to an alert, such as resolving it, isn't sent again.

Python 3.9 or later, standard library only. One file: `syncro_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/syncro/rmm-alerts` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Syncro.** Create an API token for the bridge with only the RMM Alerts - List permission, and copy it. Your API base is `https://<your subdomain>.syncromsp.com/api/v1`.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `SYNCRO_API_URL` | none | `https://<your subdomain>.syncromsp.com/api/v1`. |
| `SYNCRO_API_TOKEN` | none | The API token, sent as `Authorization: Bearer`. |
| `BRIDGE_STATE_FILE` | `syncro_state.json` | Cursor and recently seen alert IDs. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much before the cursor each run re-reads, to catch late alerts. Repeats are dropped by ID. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 syncro_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 syncro_bridge.py                  # one pass, for cron or a systemd timer
python3 syncro_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means every page was read and sent. On an error the bridge logs the step and the HTTP status, stops, and leaves the cursor where it was, so the next run reads the same alerts again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

As a systemd service that polls, with the variables in `/etc/syncro-rmm-alerts.env` (owned by root, mode 600):

```ini
[Unit]
Description=Syncro RMM alert bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/syncro-rmm-alerts/syncro_bridge.py --interval 300
EnvironmentFile=/etc/syncro-rmm-alerts.env
DynamicUser=yes
StateDirectory=syncro-rmm-alerts
WorkingDirectory=/var/lib/syncro-rmm-alerts
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- It asks for `status=all` and `created_after=<cursor minus the overlap>`, and reads every page (25 alerts each) up to `meta.total_pages`.
- It sends the alerts it hasn't sent before, oldest first, then moves the cursor to the newest `created_at`, but never past the time of the run, and remembers the IDs inside the overlap.

Rate limit: 180 requests a minute per address. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes, and stops on 401 or 403. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the Syncro API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the cursor can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the API token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/syncro-rmm-alerts -p 'test_*.py' -v
```

The tests start a local mock of the RMM alerts endpoint and HTTP Ingest, built from the documented shapes, and check paging, oldest-first order, the lookback, the cursor, dry-run, retries, the stop on a bad token, batching and gzip, and that no secret reaches the log.

## References

- Syncro API documentation and specification (RMM Alert): https://api-docs.syncromsp.com/
- Syncro notification sets: https://docs.syncrosecure.com/administration/create-notification-sets
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
