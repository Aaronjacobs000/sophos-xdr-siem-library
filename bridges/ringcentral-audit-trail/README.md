# RingCentral audit trail bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real RingCentral account or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from RingCentral's OpenAPI spec and developer guides. Run it with `--dry-run` first and check what it would send.

RingCentral (RingEX) keeps an audit trail of account changes, Admin Portal sign-ins, and failed sign-ins and locked accounts from every client, and offers it only through a search API, which is pull only. This script reads it with a private app that uses the JWT grant, and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"ringcentral_record": "audit_trail"` in front of each record, and the library parsers in `parsers/ringcentral/ringex-audit-trail` normalize them. Sophos Fusion has no RingCentral integration.

| Data | Endpoint |
| --- | --- |
| Access token (JWT grant) | `POST /restapi/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and the JWT as `assertion` |
| Audit trail records | `POST /restapi/v1.0/account/~/audit-trail/search` |

Every search carries the access token as `Authorization: Bearer <token>`. Python 3.9 or later, standard library only. One file: `ringcentral_audit_trail_bridge.py`.

RingCentral still calls the Audit Trail API beta. It returns the last 180 days or the last 10,000 records of an account, whichever is less, so a bridge that stops for long can lose records it never read.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/ringcentral/ringex-audit-trail` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**RingCentral.**

1. In the RingCentral Developer Console, register a REST API app for your own account (private), with no user interface and the JWT auth flow.
2. Give it the Read Audit Trail permission only. The guide says you may add that permission yourself while the API is in beta.
3. Sign in as an admin who can see the audit trail in the Admin Portal (a Super Admin), and create a JWT credential under Credentials. Restrict it to the app's client ID.
4. Note the app's Client ID and Client Secret, and the JWT. The JWT acts as that admin until you revoke it, so store it like a password.

## Configuration

Everything comes from environment variables. Keep the client secret, the JWT and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `RINGCENTRAL_URL` | `https://platform.ringcentral.com` | The RingCentral server: scheme and host only. |
| `RINGCENTRAL_CLIENT_ID` | none | The app's Client ID. |
| `RINGCENTRAL_CLIENT_SECRET` | none | The app's Client Secret. |
| `RINGCENTRAL_JWT` | none | The admin's JWT credential. |
| `RINGCENTRAL_PAGE_SIZE` | `1000` | Records per search, 1 to 1000. |
| `BRIDGE_STATE_FILE` | `ringcentral_audit_trail_state.json` | The last window's end and the records sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 4320 (180 days). |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for records RingCentral lists late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 ringcentral_audit_trail_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 ringcentral_audit_trail_bridge.py                   # one pass, for cron or a systemd timer
python3 ringcentral_audit_trail_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means the audit trail was read and sent. On an error the bridge logs it with the HTTP status and RingCentral's error code and message, stops, and leaves the window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration, credential or permission error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/ringcentral-audit-trail.env` (owned by root, mode 600):

```ini
[Unit]
Description=RingCentral audit trail bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/ringcentral-audit-trail/ringcentral_audit_trail_bridge.py --interval 300
EnvironmentFile=/etc/ringcentral-audit-trail.env
DynamicUser=yes
StateDirectory=ringcentral-audit-trail
WorkingDirectory=/var/lib/ringcentral-audit-trail
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- The bridge gets an access token with the JWT grant, sending the Client ID and Client Secret as Basic authentication, and keeps it until a minute before the `expires_in` RingCentral gives. Token requests are in RingCentral's Auth rate group (5 a minute), so with `--interval` one token serves every run until it expires. When a search answers 401, the bridge gets a new token and sends the search once more.
- Each run searches from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now, never further back than 180 days. The body is `{"eventTimeFrom", "eventTimeTo", "page", "perPage", "includeAdmins": true, "includeHidden": true}`, as RingCentral's guide sends it, with times in ISO 8601 UTC to the millisecond.
- Pages start at 1 and run until `paging.total` (the number of pages) or `paging.totalFound` (the number of records) is reached, or, when RingCentral leaves both out, until a page is shorter than `paging.perPage`.
- Records have an `id`, so the bridge drops repeats by `id`. The window's end is saved only after every page of it was sent, and never past the time of the run.
- The search is in RingCentral's Heavy rate group: 10 requests a minute for each user and app, with a penalty (60 seconds by default) that starts again with every request sent during it. So the bridge spaces its searches 6.5 seconds apart, waits `X-Rate-Limit-Window` seconds when `X-Rate-Limit-Remaining` reaches 0, and on a 429 waits the `Retry-After` RingCentral gives (up to 5 minutes), or 60 seconds when it gives none, before it tries again. It retries 408, 429, 500, 502, 503 and 504 up to 6 times. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from RingCentral or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.
- A refused JWT (`invalid_grant`, `invalid_client`), a missing permission or admin role (HTTP 403, such as `CMN-401`, `CMN-402` or `CMN-408`) and other 400 and 404 answers stop the run with RingCentral's error code and message.

Each record goes out as the bridge read it, after this field:

| Field | Value |
| --- | --- |
| `ringcentral_record` | `audit_trail` |

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the client secret, the JWT, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/ringcentral-audit-trail -p 'test_*.py' -v
```

The tests start a local mock of the RingCentral token and audit trail search endpoints and HTTP Ingest, built from the documented shapes, and check the JWT grant and Basic client authentication, the token's reuse and renewal, the search body and its time window, paging with and without totals, record tagging, windows, overlaps and repeats, the lookback and the 180-day limit, that a window ends only after HTTP Ingest accepted it and never past now, RingCentral error codes and HTTP errors, search spacing, the 429 penalty wait and the rate limit headers, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Audit Trail guide (permission, beta, 180-day and 10,000-record limits, the sample search): https://developers.ringcentral.com/guide/account/audit-trail
- Account changes tracked in the Audit Trail (sign-ins, failed sign-ins and locked accounts): https://support.ringcentral.com/article-v2/Audit-Trail-Configuration-Changes-Tracked.html
- RingCentral OpenAPI spec (auditTrailSearch, getToken, error models): https://netstorage.ringcentral.com/dpw/api-reference/specs/rc-platform.yml
- JWT auth flow: https://developers.ringcentral.com/guide/authentication/jwt-flow
- Rate limits: https://developers.ringcentral.com/guide/basics/rate-limits
- Error codes: https://developers.ringcentral.com/guide/basics/errors
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
