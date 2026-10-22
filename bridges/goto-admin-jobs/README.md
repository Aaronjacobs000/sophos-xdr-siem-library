# GoTo Admin jobs bridge

> **Unofficial, and tested against documented and inferred response shapes only.** This bridge has not run against a real GoTo account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from GoTo's Admin API spec and authentication guides. **GoTo documents the fields of a job and the query parameters of Get Jobs, but not the body of its answer**, so the bridge takes the two shapes GoTo's Admin API uses for other lists. Run it with `--dry-run` first and check what it reads.

GoTo Admin (admin.goto.com, which manages GoTo Connect and the other GoTo products in an account) records each change an admin makes as a job, which GoTo defines as "an audit record that represents a modification operation performed by an admin": the admin, the system (`ea` for GoTo Admin itself, or another system's name), the request method and URI, the outcome, and the users, devices and groups it touched. GoTo offers the jobs only through its Admin API, which is pull only. This script reads them and sends each one as a JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"goto_record": "admin_job"` and the account key in front of each job, and the library parsers in `parsers/goto/goto-connect-admin-activity` normalize them. Sophos Fusion has no GoTo integration.

| Data | Endpoint |
| --- | --- |
| Access token | `POST https://authentication.logmeininc.com/oauth/token`, with `grant_type=personal_access_token` or `grant_type=refresh_token` |
| The account key, when `GOTO_ACCOUNT_KEY` isn't set | `GET https://api.getgo.com/admin/rest/v1/me` (`accountKey`) |
| Jobs | `GET https://api.getgo.com/admin/rest/v1/accounts/{accountKey}/jobs?fromDate=...&toDate=...&metadata=true` |

Every API request carries the access token as `Authorization: Bearer <token>`. Python 3.9 or later, standard library only. One file: `goto_admin_jobs_bridge.py`.

## What isn't confirmed

- **The answer's shape.** GoTo's spec lists no 200 answer for Get Jobs, and no public example was found. The bridge takes a JSON array of jobs, as GoTo's other date-range log (Get Sync History) sends, or `{"results": [...], "total": n}`, as GoTo's paged lists send, and stops with an error that asks you to report any other shape. When an answer's `total` is above the jobs it holds, the bridge splits the window in two and reads each half, down to one millisecond.
- **Paging.** Get Jobs documents no page parameters, only `fromDate` and `toDate` ("recommended ... to get consistent pagination") and a default of the last hour. So the bridge asks for at most `GOTO_WINDOW_MINUTES` (60 by default) at a time.
- **GoTo Connect changes.** GoTo's support article says the Admin Activity page shows changes to GoTo Connect extensions under the system "PBX". That those are the same records as the jobs this API returns is inferred from the matching fields; GoTo doesn't say so. The article also says GoTo has no device or location activity history, and no GoTo document puts sign-ins in either.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/goto/goto-connect-admin-activity` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn them on.

**GoTo.** The Admin API only takes a user's access token with the `identity:` scope; GoTo has no client credentials grant for it. Use an admin account that can see the account's activity in GoTo Admin.

1. At https://developer.logmeininc.com/clients, create an OAuth client with the `identity:` scope only, and note its Client ID and Client Secret.
2. Then choose one:
   - **Personal access token.** On the client, under Grant types, turn on Personal Access Token. Signed in to https://myaccount.goto.com as the admin, go to Developer Tools, create a token with the `identity:` scope, and set it as `GOTO_PAT`. GoTo's guide presents this grant for local testing and doesn't say when a token expires.
   - **Refresh token.** Get an authorization code as GoTo's "How to obtain an OAuth access token" guide shows, signed in as the admin, exchange it for tokens, and set the `refresh_token` it returns as `GOTO_REFRESH_TOKEN`. GoTo's refresh tokens last 30 days, and GoTo sends a new one, invalidating the old, once 60% of that has passed. The bridge saves each new one to `BRIDGE_TOKEN_FILE` (mode 600) at once and reads that file first on the next start, so keep the file with the state file and back up neither somewhere others can read. If the bridge stops for more than 30 days, get a new refresh token.

## Configuration

Everything comes from environment variables. Keep the client secret, the token and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `GOTO_CLIENT_ID` | none | The OAuth client's Client ID. |
| `GOTO_CLIENT_SECRET` | none | The OAuth client's Client Secret. |
| `GOTO_PAT` | none | A personal access token. Set this or `GOTO_REFRESH_TOKEN`, not both. |
| `GOTO_REFRESH_TOKEN` | none | A refresh token from the authorization code grant, used until GoTo sends a new one. |
| `GOTO_ACCOUNT_KEY` | none | The account key, digits only. When it isn't set, the bridge reads `accountKey` from `/admin/rest/v1/me` for the token's admin. |
| `GOTO_METADATA` | `1` | Ask for each job's metadata (the names and emails of the users, devices and groups it touched). |
| `GOTO_WINDOW_MINUTES` | `60` | The most time one request covers, 1 to 1440. |
| `GOTO_API_URL` | `https://api.getgo.com` | The API host: scheme and host only. |
| `GOTO_AUTH_URL` | `https://authentication.logmeininc.com` | The authentication host: scheme and host only. |
| `BRIDGE_TOKEN_FILE` | `goto_refresh_token.json` | Where the bridge keeps the newest refresh token. Only used with `GOTO_REFRESH_TOKEN`. |
| `BRIDGE_STATE_FILE` | `goto_admin_jobs_state.json` | The last window's end and the jobs sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for jobs listed late or that changed state. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 goto_admin_jobs_bridge.py --dry-run         # print the NDJSON it would send; sends nothing and saves no state
python3 goto_admin_jobs_bridge.py                   # one pass, for cron or a systemd timer
python3 goto_admin_jobs_bridge.py --interval 300    # keep polling every 5 minutes
```

`--dry-run` still saves a new refresh token GoTo sends, since GoTo has invalidated the old one by then.

Exit code 0 means the jobs were read and sent. On an error the bridge logs it with the HTTP status and GoTo's error code, stops, and leaves the window where it was, so the next run reads the same jobs again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration, credential or permission error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/goto-admin-jobs.env` (owned by root, mode 600):

```ini
[Unit]
Description=GoTo Admin jobs bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/goto-admin-jobs/goto_admin_jobs_bridge.py --interval 300
EnvironmentFile=/etc/goto-admin-jobs.env
DynamicUser=yes
StateDirectory=goto-admin-jobs
WorkingDirectory=/var/lib/goto-admin-jobs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet. The state and token files live in `/var/lib/goto-admin-jobs`, which only the service can read.

## How it reads the API

- The bridge gets an access token from GoTo's token endpoint, sending the Client ID and Client Secret as Basic authentication, and keeps it until a minute before the `expires_in` GoTo gives (an hour). With `--interval` one token serves every run until it expires. When the API answers 401, or the 403 GoTo's gateway sends for a token it doesn't accept (`InvalidToken`), the bridge gets a new token and sends the request once more. Any other 403 is a missing permission, and stops the run.
- Each run reads from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now, in windows of `GOTO_WINDOW_MINUTES`, with `fromDate` and `toDate` in epoch milliseconds, both included. Each window's end is saved after its jobs were sent, and never past the time of the run.
- A job is known by its `id` and `status`, so a job read again in the same state is dropped, and one read again after it completed or failed is sent once more in its new state.
- GoTo's default rate limit is 10 requests a second for each API, so the bridge spaces its requests 0.15 seconds apart. It waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from GoTo or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.
- Errors show GoTo's code: the Admin API sends `{"incidentId", "errors": [{"code", "field", "value"}]}`, the token endpoint `{"error", "error_description"}`, and GoTo's gateway `{"int_err_code", "msg"}`.

Each job goes out as the bridge read it, after these fields:

| Field | Value |
| --- | --- |
| `goto_record` | `admin_job` |
| `goto_account_key` | The account key in the request path |

GoTo sends `context`, `request.content` and `response.content` as text that holds JSON. The bridge passes them on as text.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the personal access token, a refresh token, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/goto-admin-jobs -p 'test_*.py' -v
```

The tests start a local mock of GoTo's token endpoint, `/me` and Get Jobs, and HTTP Ingest, built from the documented shapes and the two inferred answer shapes, and check the personal access token and refresh token grants with Basic client authentication, the token's reuse and renewal, a refused token on 401 and on the gateway's 403, saving a replaced refresh token (mode 600, read first on the next start, and kept in a dry run), the account key from `/me`, both answer shapes and the error for any other, splitting a window when an answer holds fewer jobs than its total, windows of `GOTO_WINDOW_MINUTES` with no gap or overlap, record tagging, repeats and state changes, overlaps, the lookback, that a window ends only after HTTP Ingest accepted it and never past now, GoTo error codes and HTTP errors, request spacing, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- GoTo Admin API (Jobs: the job and metadata schemas, Get Jobs and its parameters, the error container, Get Me): https://developer.goto.com/admin
- Personal access tokens: https://developer.goto.com/guides/Authentication/03.1_HOW_accessTokenPAT/
- Authorization code and refresh tokens: https://developer.goto.com/guides/Authentication/03_HOW_accessToken/ and https://developer.goto.com/guides/Authentication/05_HOW_refreshToken/
- Refresh token lifetime and replacement: https://developer.goto.com/Authentication/
- Rate limits: https://developer.goto.com/guides/References/Ref-Rate-Limits/
- Track admin activity in your admin portal (GoTo Connect, system "PBX"): https://support.goto.com/connect/help/how-do-i-track-activity-on-my-account
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
