# CyberArk Endpoint Privilege Manager events bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real CyberArk EPM tenant or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from CyberArk's EPM web services reference. Run it with `--dry-run` first and check what it would send.

CyberArk Endpoint Privilege Manager (EPM SaaS) offers its endpoint events (threat protection detections, blocked applications, elevation requests, launches and installations) through its REST API only, which is pull only. This script reads every set the service user can view and sends each event as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `cyberark_epm_record`, `setId` and `setName` in front of each event, and the library parsers in `parsers/cyberark/endpoint-privilege-manager` normalize them. Sophos Fusion's CyberArk integrations cover Privileged Threat Analytics and the Vault, not EPM.

| Data | Endpoint | `cyberark_epm_record` |
| --- | --- | --- |
| Detailed raw events (application events, threat protection, admin privilege) | `POST /API/Sets/{setId}/Events/Search` | `raw_event` |
| Policy audit raw events (events from policies with auditing on, with the policy, its action and the computer) | `POST /API/Sets/{setId}/policyaudits/search` | `policy_audit` |
| The sets to read | `GET /API/Sets` | none |

Python 3.9 or later, standard library only. One file: `cyberark_epm_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/cyberark/endpoint-privilege-manager` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**CyberArk.** The EPM tenant must be connected to Idira Identity Security Platform Shared Services (ISPSS). CyberArk says the standalone EPM console works alongside ISPSS only until 31 December 2026, so the bridge signs in through ISPSS, not the EPM logon API. An Identity administrator, with an EPM administrator for the role:

1. In Identity Administration, go to Manage > Inventory > Users, choose Add User, and create a service user with Is OAuth confidential client, Is Service User and Password never expires selected.
2. Add the service user to an EPM role that can only view events in the sets the bridge reads. CyberArk recommends a read-only user for APIs that only retrieve data.
3. Go to Manage > Inventory > Targets > Applications, choose Add Application, add Idira EPM API Client, fill in its Settings and save. Note its application ID.
4. On the app's Tokens tab, pick the token lifetime. On its Permissions tab, add the service user. The app should show Deployed.
5. Find the Identity sub-domain under your profile > About (the ID; the login URL is `<sub-domain>.id.cyberark.cloud`), and the EPM API regional subdomain for your region, such as `api-au.epm.cyberark.cloud` for Australia.

## Configuration

Everything comes from environment variables. Keep the password and key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `CYBERARK_IDENTITY_URL` | none | The Identity tenant, `https://<sub-domain>.id.cyberark.cloud`. |
| `CYBERARK_APP_ID` | none | The EPM API web app's application ID. |
| `CYBERARK_CLIENT_ID` | none | The service user's login name, such as `epm-siem@acme.example.com`. |
| `CYBERARK_CLIENT_SECRET` | none | The service user's password. |
| `CYBERARK_EPM_API_URL` | none | The EPM API regional subdomain, such as `https://api-au.epm.cyberark.cloud`. |
| `CYBERARK_EPM_SET_IDS` | all | Set IDs to read, comma separated. Empty reads every set the service user can view. |
| `CYBERARK_EPM_SOURCES` | `raw_events,policy_audits` | What to read: `raw_events`, `policy_audits` or both. |
| `CYBERARK_EPM_EVENT_TYPES` | all | Event types to read, comma separated, such as `AttackAttempt,AttackBlock,SuspiciousActivityAttempt,SuspiciousActivityBlock,Ransomware,Block,ElevationRequest,ManualRequest`. Empty reads every type. |
| `CYBERARK_EPM_PAGE_SIZE` | `1000` | Events per request, 1 to 1000. |
| `BRIDGE_STATE_FILE` | `cyberark_epm_state.json` | Each set's and source's last window end and the events sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `900` | How far before the last window's end each run reads again, for events that reach EPM late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 cyberark_epm_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 cyberark_epm_bridge.py                   # one pass, for cron or a systemd timer
python3 cyberark_epm_bridge.py --interval 300    # keep polling every 5 minutes
```

Exit code 0 means every set and source was read and sent. On an error the bridge logs it with the HTTP status, stops, and leaves the window where it was, so the next run reads the same events again and drops the ones it already sent. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log.

As a systemd service that polls, with the variables in `/etc/cyberark-epm-events.env` (owned by root, mode 600):

```ini
[Unit]
Description=CyberArk Endpoint Privilege Manager events bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/cyberark-epm-events/cyberark_epm_bridge.py --interval 300
EnvironmentFile=/etc/cyberark-epm-events.env
DynamicUser=yes
StateDirectory=cyberark-epm-events
WorkingDirectory=/var/lib/cyberark-epm-events
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- It gets an access token (a JWT) from `POST <CYBERARK_IDENTITY_URL>/oauth2/token/<CYBERARK_APP_ID>` with the service user in `Authorization: Basic` and the form body `grant_type=client_credentials`, and sends it to EPM as `Authorization: Bearer`. It renews the token a minute before it expires, and once more if EPM refuses it. With `--interval`, one token serves every run until it expires.
- Each run lists the sets with `GET /API/Sets` (`offset` and `limit`), then reads each set and source from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to a minute before now. The body is `{"filter": "arrivalTime GE <start> AND arrivalTime LE <end>"}`, with `AND eventType IN <types>` when `CYBERARK_EPM_EVENT_TYPES` is set. `arrivalTime` is when EPM received the event, so an endpoint that reports late is still read. It pages with `nextCursor`, `start` first and then the cursor EPM returns, as CyberArk advises for reading every result of a time range past 1,000.
- Raw events and policy audits carry no ID, so the bridge drops repeats by a hash of the whole event. An event that stands for several identical ones (`agentEventCount`) comes again when EPM updates it, as a new record. A window's end is saved only after every page of it was sent, and never past the time of the run.
- EPM allows 5 event API calls a second and 1,000 in 5 minutes, so the bridge spaces its calls a quarter of a second apart. It also lets the API extract 100,000 events, and separately 100,000 policy audit events, in 24 hours, and answers 403 past a license limit; a busy tenant may need `CYBERARK_EPM_EVENT_TYPES` or fewer sets. The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Identity, EPM or HTTP Ingest is refused, not followed, so no key or token goes to another URL, and the run stops with an error that says so.

CyberArk doesn't say how long EPM keeps events, so run the bridge at least daily. EPM's admin audit API is deprecated in favor of the platform's SIEM integration API, which this bridge doesn't read.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.

The bridge never logs the service user's name or password, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/cyberark-epm-events -p 'test_*.py' -v
```

The tests start a local mock of the Identity token endpoint, the EPM sets, raw events and policy audits endpoints and HTTP Ingest, built from the documented shapes, and check the token request and its reuse, the sets list and the set filter, the `arrivalTime` filter and `nextCursor` paging, tagging with the set, windows, overlaps and repeats, the lookback, that a window ends only after HTTP Ingest accepted it and never past now, the event type and source settings, refused credentials and permissions, call spacing, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Set up API authentication for EPM REST APIs using ISPSS (service user, Idira EPM API Client web app, token request): https://docs.cyberark.com/epm/latest/en/content/webservices/authenticate-with-tenant-url.htm
- Get detailed raw events: https://docs.cyberark.com/epm/latest/en/content/webservices/getdetailedrawevents.htm
- Get policy audit raw event details: https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicyauditraweventdetails.htm
- Get sets list: https://docs.cyberark.com/epm/latest/en/content/webservices/getsetslist.htm
- Web services overview (API limits, read-only users, timestamps, return codes): https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm
- Service URLs and API regional subdomains: https://docs.cyberark.com/epm/latest/en/content/installation/network-setup.htm
- Onboard EPM to ISPSS (the standalone console works alongside ISPSS until 31 December 2026): https://docs.cyberark.com/epm/latest/en/content/admin/onboard-epm-to-ispss.htm
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
