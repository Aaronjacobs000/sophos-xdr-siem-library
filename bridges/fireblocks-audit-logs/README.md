# Fireblocks audit log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Fireblocks workspace or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Fireblocks' API reference. Run it with `--dry-run` first and check what it would send.

Fireblocks has no syslog and no SIEM connector of its own. Its audit log (sign-ins, user and role changes, admin quorum, policy changes, address and IP allowlists, signing keys, key backups, vaults, webhooks and transactions) reaches other tools through one pull-only endpoint, `GET /v1/management/audit_logs`, which Fireblocks names as the route for SIEM platforms. This script reads it and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It puts `"fireblocks_record": "audit_log"` first in each event, and the library parsers in `parsers/fireblocks/fireblocks-platform` normalize the events.

Fireblocks' transaction, allowlist and vault webhooks come in another way, through the `/fireblocks` route of [bridges/webhook-relay](../webhook-relay/).

Python 3.9 or later, standard library only. One file: `fireblocks_audit_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/fireblocks/fireblocks-platform` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**Fireblocks.** Every API call is signed with an API user's RSA private key, so the bridge needs an API user of its own:

1. In the Fireblocks Console, go to Developer center > API users and choose Add API user.
2. Name it, and give it the Auditor, Security Auditor or Non-Signing Admin role. The audit log endpoint also takes Admin and Security Admin, but the bridge only reads, so pick the role with the least access your workspace offers. Any other role gets 403.
3. Choose Automatic CSR to have Fireblocks make the key pair and download the private key (`fireblocks_secret.key`), or Custom CSR to upload a CSR for a 4096-bit RSA key you made yourself. Adding an API user goes through your workspace's admin approval.
4. Copy the API key (API user ID) from the API users list.
5. If the API user has an IP allowlist, add the address the bridge connects from.

The API base URL depends on where the workspace is hosted:

| Workspace | `FIREBLOCKS_API_URL` |
| --- | --- |
| US mainnet and testnet | `https://api.fireblocks.io` (default) |
| EU mainnet and testnet | `https://eu-api.fireblocks.io` |
| EU2 mainnet and testnet | `https://eu2-api.fireblocks.io` |
| US developer sandbox | `https://sandbox-api.fireblocks.io` |

The base URL with `/v1` at the end, as Fireblocks writes it, works too.

## Configuration

Everything comes from environment variables. Keep the private key and the HTTP Ingest key in a secrets manager or in files only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `FIREBLOCKS_API_URL` | `https://api.fireblocks.io` | The API base URL for the workspace's region (see above). |
| `FIREBLOCKS_API_KEY` | none | The API key (API user ID). |
| `FIREBLOCKS_SECRET_KEY_FILE` | none | Path to the API user's private key, `fireblocks_secret.key`, in PEM (PKCS #8 or PKCS #1). |
| `FIREBLOCKS_SECRET_KEY` | none | The private key's PEM text itself, in place of `FIREBLOCKS_SECRET_KEY_FILE`. Set one, not both. |
| `FIREBLOCKS_CATEGORIES` | every category | Comma-separated audit log categories to read, such as `Administration,Security,Policies`. Fireblocks' names: Administration, Whitelist, Wallets, Exchanges, Settlements, Policies, Compliance, Transactions, Web3, Developers, Assets, Keys, Automation, Orders, Security. |
| `FIREBLOCKS_PAGE_SIZE` | `500` | Events per page, 1 to 500. |
| `BRIDGE_STATE_FILE` | `fireblocks_audit_state.json` | Where the last window's end and the event IDs inside the overlap are saved. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 8760 (a year, the furthest back Fireblocks takes). |
| `BRIDGE_OVERLAP_SECONDS` | `600` | How far each run reaches back before the last window's end, so an event recorded late still arrives. Repeats are dropped by event ID. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 fireblocks_audit_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 fireblocks_audit_bridge.py                   # one pass, for cron or a systemd timer
python3 fireblocks_audit_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means the window was read and sent. On an error the bridge logs it with the HTTP status and stops. A window's end is saved only after HTTP Ingest accepted every page in it, so the next run reads the same window again and drops the events it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/fireblocks-audit-logs.env` (owned by root, mode 600) and the private key at `/etc/fireblocks-audit-logs/fireblocks_secret.key`. systemd hands the key to the bridge and sets `FIREBLOCKS_SECRET_KEY_FILE`, so leave that variable out of the file:

```ini
[Unit]
Description=Fireblocks audit log bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/fireblocks-audit-logs/fireblocks_audit_bridge.py --interval 300
EnvironmentFile=/etc/fireblocks-audit-logs.env
LoadCredential=fireblocks_secret.key:/etc/fireblocks-audit-logs/fireblocks_secret.key
Environment=FIREBLOCKS_SECRET_KEY_FILE=%d/fireblocks_secret.key
DynamicUser=yes
StateDirectory=fireblocks-audit-logs
WorkingDirectory=/var/lib/fireblocks-audit-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Every request carries the API key in `X-API-Key` and `Authorization: Bearer <JWT>`. The JWT is signed with the private key (RS256) and holds the request's path and query as `uri`, a new random `nonce`, `iat` and an `exp` 29 seconds later, the API key as `sub`, and `bodyHash`, the hex SHA-256 of the empty body. A retried request gets a new JWT, since Fireblocks takes each nonce once. Keep the bridge host's clock in sync: a JWT from a clock that is off is refused. Fireblocks' authentication page says `exp` must be less than 30 seconds after `iat`, but both official SDKs set it 55 seconds out; the bridge keeps to the documented limit. Which one Fireblocks enforces hasn't been checked against a live workspace.
- A 401 means the API key and private key don't belong to the same API user, `FIREBLOCKS_API_URL` is for another region, the API user's IP allowlist leaves out this host, or the clock is off. A 403 means the API user's role can't read the audit log.
- Each run reads one window, from the last window's end less `BRIDGE_OVERLAP_SECONDS` to a minute before now: `GET /v1/management/audit_logs?startTime=<ms>&endTime=<ms>&order=ASC&pageSize=500`, plus `category` once for each category in `FIREBLOCKS_CATEGORIES`. It follows each response's `next` cursor as `pageCursor` until `next` is null. (It reads the older `cursor` field when `next` is missing.)
- Events already sent inside the overlap are dropped by their `id`, or by their whole content when they have none.

Fireblocks rate-limits API calls. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from the Fireblocks API or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a page and saving its progress can send that page again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the private key, the API key, the HTTP Ingest key, or the HTTP Ingest URL path.

## What it sends

Each event as Fireblocks returns it, with `fireblocks_record` first:

```json
{"fireblocks_record":"audit_log","id":"e06fa38a-75d4-4aa1-9e9b-4ce3e9af964b","timestamp":1793235947210,"createdAt":1793235947390,"user":"Sam Admin","subject":"Sign in","event":"Failed","category":"Administration","tenantId":"52020d9c-c625-45e1-91e5-b4faa015b982","userId":"4f04b1c0-aec7-4678-b398-507d62cebab1"}
```

Fireblocks' API reference gives `timestamp` as epoch milliseconds and its Audit Logs guide as ISO 8601; the bridge and the parsers read both. What a live workspace sends hasn't been checked. An audit event carries no source address, client or object ID, so neither does the record.

## Tests

```bash
python3 -m unittest discover -s bridges/fireblocks-audit-logs -p 'test_*.py' -v
```

The tests start a local mock of the audit log endpoint and HTTP Ingest, built from the documented shapes, with their own RSA keys. They check that every request's JWT verifies with the API user's public key and names that request's URI, a new nonce, the API key and the empty body's hash; paging oldest first by cursor (`next`, and the older `cursor`); the category filter; the lookback, the window and the overlap, and that repeats are dropped; that a window's end moves only after HTTP Ingest accepted its pages; a key or API key that isn't the API user's, and a role that can't read the log; PKCS #1 and PKCS #8 keys; dry-run, retries with a new JWT, batching and gzip; that redirects are refused; and that no secret reaches the log.

## References

- Fireblocks Audit Logs API (endpoint, roles, parameters, pagination, fields): https://developers.fireblocks.com/docs/audit-logs-api
- Get audit logs (API reference): https://developers.fireblocks.com/api-reference/audit-logs/get-audit-logs
- Audit log events (categories, subjects and events): https://developers.fireblocks.com/reference/audit-log-events
- Audit Log in the Help Center (export, retention, SIEM use): https://support.fireblocks.io/hc/en-us/articles/360015646820-Audit-Log
- Authenticating API requests (X-API-Key, the JWT and its claims, base URLs): https://developers.fireblocks.com/reference/signing-a-request-jwt-structure
- Fireblocks OpenAPI spec (AuditLogData, GetAuditLogsResponse): https://swagger.fireblocks.com/openapi.yaml
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
