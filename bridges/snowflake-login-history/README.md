# Snowflake login history bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Snowflake account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Snowflake's SQL API reference. Run it with `--dry-run` first and check what it would send.

Snowflake records every login attempt, failed or successful, in the Account Usage view `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`: the user, client IP, client type, first and second authentication factor, and the error for a failure. Snowflake has no push for it, so this script reads it with the Snowflake SQL API and sends each login attempt as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser in `parsers/snowflake/login-history` normalizes them. Sophos Fusion has no Snowflake integration.

Each row goes on as an object keyed by column name, with `snowflake_record` (`login_history`) and `snowflake_account` (the account from `SNOWFLAKE_ACCOUNT_URL`) first. Values are the strings the SQL API returns, so `EVENT_ID` keeps every digit, and `EVENT_TIMESTAMP` becomes an RFC 3339 time in UTC, such as `2026-10-14T16:12:44.123Z`.

Python 3.9 or later, standard library only. One file: `snowflake_login_history_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/snowflake/login-history` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Snowflake.** Give the bridge a service user whose role can read only the security views of the Account Usage schema and use one small warehouse. As ACCOUNTADMIN:

```sql
CREATE ROLE NGSIEM_LOGIN_READER;
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE NGSIEM_LOGIN_READER;
CREATE WAREHOUSE NGSIEM_WH WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 60 AUTO_RESUME = TRUE INITIALLY_SUSPENDED = TRUE;
GRANT USAGE ON WAREHOUSE NGSIEM_WH TO ROLE NGSIEM_LOGIN_READER;
CREATE USER NGSIEM_BRIDGE TYPE = SERVICE DEFAULT_ROLE = NGSIEM_LOGIN_READER DEFAULT_WAREHOUSE = NGSIEM_WH;
GRANT ROLE NGSIEM_LOGIN_READER TO USER NGSIEM_BRIDGE;
```

`SNOWFLAKE.SECURITY_VIEWER` reads LOGIN_HISTORY and the other security views. Snowflake suggests its database roles over IMPORTED PRIVILEGES on the SNOWFLAKE database, which reads every view in it.

By default, Snowflake takes a service user's programmatic access token only when the user is under a network policy, so put `NGSIEM_BRIDGE` under one that allows only the bridge host's public address (`ALTER USER NGSIEM_BRIDGE SET NETWORK_POLICY = <policy>`; see Snowflake's network policy docs). Then create the token, restricted to the reader role:

```sql
ALTER USER NGSIEM_BRIDGE ADD PROGRAMMATIC ACCESS TOKEN NGSIEM_BRIDGE_PAT
  ROLE_RESTRICTION = 'NGSIEM_LOGIN_READER' DAYS_TO_EXPIRY = 90;
```

Copy `token_secret` from the output; Snowflake shows it only once. A token expires after `DAYS_TO_EXPIRY` days (15 by default, 365 at most unless a policy lowers it), so rotate it before then with `ALTER USER ... ROTATE PROGRAMMATIC ACCESS TOKEN`.

Each run starts the warehouse if it is suspended, and Snowflake bills a warehouse by the second with a 60-second minimum each time it starts. Polling once an hour keeps that to about 24 starts a day.

## Configuration

Everything comes from environment variables. Keep the token and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `SNOWFLAKE_ACCOUNT_URL` | none | The account URL with no path, such as `https://myorg-myaccount.snowflakecomputing.com`. Its first label is the account name the records carry. |
| `SNOWFLAKE_TOKEN` | none | The programmatic access token, sent as `Authorization: Bearer`. |
| `SNOWFLAKE_WAREHOUSE` | the user's default | The warehouse that runs the query, as `SHOW WAREHOUSES` writes its name. |
| `SNOWFLAKE_ROLE` | the user's default | The role that runs the query. A token with a role restriction always uses that role. |
| `SNOWFLAKE_PAGE_SIZE` | `10000` | Login attempts per query, 1 to 100,000. |
| `SNOWFLAKE_QUERY_TIMEOUT` | `300` | Seconds the query may run, 1 to 3,600. Snowflake cancels it after that, and so does the bridge 30 seconds later. |
| `BRIDGE_STATE_FILE` | `snowflake_login_history_state.json` | Where each account's position was saved. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 8,760 (a year, how long Snowflake keeps login history). |
| `BRIDGE_DELAY_SECONDS` | `10800` | How far behind now each window ends, up to 86,400. Snowflake fills LOGIN_HISTORY with up to two hours of latency and calls that figure approximate, so the default is three hours. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 snowflake_login_history_bridge.py --dry-run          # print the NDJSON it would send; sends and saves nothing
python3 snowflake_login_history_bridge.py                    # one pass, for cron or a systemd timer
python3 snowflake_login_history_bridge.py --interval 3600    # keep polling every hour
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves its position where it was, so the next run reads the same login attempts again from where the last accepted page ended. A response over 64 MB, before or after a result partition is unpacked, also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, an answer cut off partway, and a query that reaches its timeout count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/snowflake-login-history.env` (owned by root, mode 600):

```ini
[Unit]
Description=Snowflake login history bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/snowflake-login-history/snowflake_login_history_bridge.py --interval 3600
EnvironmentFile=/etc/snowflake-login-history.env
DynamicUser=yes
StateDirectory=snowflake-login-history
WorkingDirectory=/var/lib/snowflake-login-history
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads one window: from where the last one ended (or `BRIDGE_LOOKBACK_HOURS` back, the first time) to `BRIDGE_DELAY_SECONDS` before now. Each page is one statement:

  ```sql
  SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
  WHERE EVENT_TIMESTAMP < ? AND (EVENT_TIMESTAMP > ? OR (EVENT_TIMESTAMP = ? AND EVENT_ID > ?))
  ORDER BY EVENT_TIMESTAMP, EVENT_ID LIMIT <SNOWFLAKE_PAGE_SIZE>
  ```

  with the window's end and the position (a time in nanoseconds and an `EVENT_ID`) as bind variables, so a page starts right after the last row of the one before and no row is read twice. The position is saved after each page HTTP Ingest accepted.
- `POST /api/v2/statements` returns the result within 45 seconds, or a statement handle. A statement still running is checked with `GET /api/v2/statements/{handle}`, at growing intervals of up to 5 seconds. One that hasn't finished 30 seconds after `SNOWFLAKE_QUERY_TIMEOUT` is cancelled with `POST /api/v2/statements/{handle}/cancel`, and the run ends with a network error. A result in several partitions is read whole, each later partition with `?partition=N`, before anything is sent.
- A login that LOGIN_HISTORY shows only after its window was read is missed, so raise `BRIDGE_DELAY_SECONDS` if you find gaps. With the defaults, a login reaches Sophos NG-SIEM three to four hours after it happened, so this feed suits investigation and reporting more than real-time alerts.
- 408, 429, 500, 502, 503 and 504 are retried with backoff, honoring `Retry-After`, up to 6 times. A refused token (401) stops the run at once with Snowflake's error code only, since its message can show part of the token. A 400, 403, 404 or 422 (such as a role that can't read the view, or no warehouse) stops the run with Snowflake's code and message. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Snowflake or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

`CLIENT_IP` is `INTERNAL_SNOWFLAKE_IP/0.0.0.0` for logins Snowflake makes itself, such as a Snowsight worksheet's session. `LOGIN_DETAILS` holds JSON as text, with the Malicious IP Protection result for a blocked address.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/snowflake-login-history -p 'test_*.py' -v
```

The tests start a local mock of the SQL API (submit, status, partitions and cancel, running the bridge's own statement and bind variables) and HTTP Ingest, built from the documented shapes, and check tagging and order, values kept as strings and times as RFC 3339, the window's end and start, paging past rows that share a time, the next run starting where the last ended, that the position moves only after HTTP Ingest accepted a page, checking on a running statement, cancelling one that runs too long, Snowflake's own timeout, refused statements and tokens (with no part of the token in the error), partitions (gzip, row counts and the unpacked size cap), dry-run, retries, batching and gzip, state per account, the year of retention, settings, nanosecond times, refused redirects, the response size cap, and that no secret reaches the log.

## References

- LOGIN_HISTORY view (columns, latency, internal client IP): https://docs.snowflake.com/en/sql-reference/account-usage/login_history
- SQL API: submitting requests (bind variables, timeout, 429): https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests
- SQL API: handling responses (202 and status checks, partitions, value formats): https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses
- SQL API reference (operations, response codes, QueryStatus, QueryFailureStatus): https://docs.snowflake.com/en/developer-guide/sql-api/reference
- SQL API authentication (`X-Snowflake-Authorization-Token-Type`): https://docs.snowflake.com/en/developer-guide/sql-api/authenticating
- Programmatic access tokens (network policy requirement, role restriction, expiry): https://docs.snowflake.com/en/user-guide/programmatic-access-tokens
- ALTER USER ... ADD PROGRAMMATIC ACCESS TOKEN: https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-programmatic-access-token
- SNOWFLAKE database roles (SECURITY_VIEWER and the views it reads): https://docs.snowflake.com/en/sql-reference/snowflake-db-roles
- Network policies: https://docs.snowflake.com/en/user-guide/network-policies
- Warehouse billing (60-second minimum): https://docs.snowflake.com/en/user-guide/warehouses-overview
- Malicious IP Protection (LOGIN_DETAILS): https://docs.snowflake.com/en/user-guide/malicious-ip-protection
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
