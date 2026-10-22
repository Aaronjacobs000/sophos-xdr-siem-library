# Tailscale logs bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real tailnet or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Tailscale's API reference and its logging docs. Run it with `--dry-run` first and check what it would send.

Tailscale keeps configuration audit logs (every change to the tailnet, and sign-ins to the admin console, the web interface and nodes) and, on the Premium and Enterprise plans, network flow logs. It streams them to Splunk HTTP Event Collector and other SIEMs, in a framing Sophos NG-SIEM HTTP Ingest doesn't document taking, and offers them through its API, which is pull only. This script reads them and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers in `parsers/tailscale/tailscale-logs` normalize them. Sophos Fusion has no Tailscale integration.

| Data | Endpoint | Scope |
| --- | --- | --- |
| Configuration audit logs | `GET /api/v2/tailnet/{tailnet}/logging/configuration` | `logs:configuration:read` |
| Network flow logs | `GET /api/v2/tailnet/{tailnet}/logging/network` | `logs:network:read` |

Each configuration audit event goes out with `"tailscale_record": "configuration"` first. A network flow log holds every connection a node saw in a few seconds, so the bridge sends one record per connection: `"tailscale_record": "network"`, then the log's `nodeId`, `logged`, `start` and `end`, `traffic` (`virtual`, `subnet`, `exit` or `physical`), the connection's `proto`, `src`, `dst` and counts, and `srcNode`, plus `dstNode` (or `peerNode` for physical traffic) when the log names the node at that address. Both carry `"tailscale_tailnet"`.

Python 3.9 or later, standard library only. One file: `tailscale_logs_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/tailscale/tailscale-logs` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Tailscale.**

1. In the admin console, open Settings > Trust credentials and generate an OAuth client with only the read scopes for the logs you want: `logs:configuration:read`, and `logs:network:read` for network flow logs. An OAuth client doesn't expire, and the bridge gets a new hour-long token from it as it needs one. Copy the client ID and secret; the secret is shown once.
2. For network flow logs, open Logs > Network flow logs and select Start logging; they are off by default and need the Premium or Enterprise plan.
3. Find your tailnet ID on Settings > General, or leave `TAILSCALE_TAILNET` as `-` for the tailnet the client belongs to.

An API access token (`tskey-api-...`) in `TAILSCALE_API_KEY` works instead of an OAuth client, with its user's permissions, but it expires after 1 to 90 days. Tailscale keeps configuration audit logs for 90 days and network flow logs for 30.

## Configuration

Everything comes from environment variables. Keep the client secret and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `TAILSCALE_OAUTH_CLIENT_ID` | none | The OAuth client's ID. |
| `TAILSCALE_OAUTH_CLIENT_SECRET` | none | The OAuth client's secret. |
| `TAILSCALE_API_KEY` | none | An API access token, instead of an OAuth client. |
| `TAILSCALE_TAILNET` | `-` | The tailnet ID, or `-` for the client's or token's own tailnet. |
| `TAILSCALE_LOGS` | `configuration,network` | The logs to read: `configuration` and `network`, comma separated. |
| `TAILSCALE_API_URL` | `https://api.tailscale.com` | The API's scheme and host. |
| `TAILSCALE_WINDOW_MINUTES` | `60` | The longest span one request asks for, 1 to 1440. Tailscale answers each request in one piece, so a backlog is read a window at a time. |
| `BRIDGE_STATE_FILE` | `tailscale_logs_state.json` | Each log's last window end and the records sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 2160, and never past what Tailscale keeps. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for logs that reach Tailscale late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 tailscale_logs_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 tailscale_logs_bridge.py                   # one pass, for cron or a systemd timer
python3 tailscale_logs_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every log was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same logs again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory; lower `TAILSCALE_WINDOW_MINUTES` if a busy tailnet's network flow logs reach that. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/tailscale-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=Tailscale logs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/tailscale-logs/tailscale_logs_bridge.py --interval 300
EnvironmentFile=/etc/tailscale-logs.env
DynamicUser=yes
StateDirectory=tailscale-logs
WorkingDirectory=/var/lib/tailscale-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- The bridge gets an access token with `POST /api/v2/oauth/token` and the form fields `client_id` and `client_secret`, keeps it until a minute before `expires_in` runs out, and gets a new one if Tailscale refuses it. Each request carries it, or the API access token, as `Authorization: Bearer`.
- Each run reads each log from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now, with `start` and `end` in RFC 3339 UTC, at most `TAILSCALE_WINDOW_MINUTES` at a time. The API returns every log of a window at once, oldest first, with no paging; a `null` list counts as none.
- No log has an ID of its own (`eventGroupID` is shared by every event of one operation), so the bridge knows each record it sends by a hash of all of it, and drops one it sent before. Each window's end is saved only after its records were sent, and never past the time of the run.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. A 401 means the client or token was refused, a 403 that it lacks the log's scope, and a 404 that the tailnet is wrong or network flow logs aren't available or turned on. A 400 shows Tailscale's message. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Tailscale or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the access token, the API access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/tailscale-logs -p 'test_*.py' -v
```

The tests start a local mock of the OAuth token endpoint and the two logging endpoints, built from the documented shapes, and of HTTP Ingest, and check the token request and its reuse and renewal, API access tokens, the tailnet in the path, the window bounds, a backlog read a window at a time, one record per connection with the nodes matched by address, overlaps and repeats, the retention limits, that a window ends only after HTTP Ingest accepted it and never past now, refused keys and scopes, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Tailscale API reference (logging endpoints, `start` and `end`, scopes), and its OpenAPI document: https://tailscale.com/api and https://api.tailscale.com/api/v2?outputOpenapiSchema=true
- Configuration audit logs (fields, events, retention, the API call): https://tailscale.com/docs/features/logging/audit-logging
- Network flow logs (fields, traffic types, plans, the API call): https://tailscale.com/docs/features/logging/network-flow-logs
- OAuth clients (token request, scopes, token lifetime): https://tailscale.com/docs/features/oauth-clients
- Log streaming (destinations): https://tailscale.com/docs/features/logging/log-streaming
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
