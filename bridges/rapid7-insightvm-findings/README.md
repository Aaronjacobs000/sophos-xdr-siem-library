# Rapid7 InsightVM findings bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Insight Platform organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Rapid7's InsightVM Cloud Integrations API reference. Run it with `--dry-run` first and check what it would send.

InsightVM keeps each asset's vulnerability findings, but has no push for them. So this script asks the InsightVM Cloud Integrations API (v4) on the Insight Platform, on each run, which findings are new on each asset and which were remediated since the last run, and sends each one as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser in `parsers/rapid7/insightvm` normalizes them.

Each record is one finding:

- `rapid7_record` (`finding`), `rapid7_region` (the region code) and `rapid7_state` first. The state is `new` (on the asset now, not at the last run), `remediated` (on the asset at the last run, not now) or `same` (on the asset at both times).
- `asset`: the asset as Rapid7 returns it (`id`, `ip`, `host_name`, `mac`, the `os_` fields, `tags`, `unique_identifiers`, the scan times, `risk_score` and the counts), without its finding lists.
- `finding`: the finding as Rapid7 returns it (`vulnerability_id`, `check_id`, `first_found`, `last_found`, `port`, `protocol`, `nic`, `proof`, `status`, the `solution_` fields and, for a remediated one, `remediation_date`).
- `vulnerability`: unless `RAPID7_DEFINITIONS=0`, the vulnerability's definition: `id`, `title`, `severity`, `severity_score`, `risk_score`, `cvss_v2_score`, `cvss_v2_vector`, `cvss_v3_score`, `cvss_v3_vector`, `cves`, `categories`, `published`, `modified`, `added`, `denial_of_service`, `exploits` and `malware_kits`. The description, links, references and PCI details are left out, so records stay small.

The first run has no earlier time to compare with, so it sends every current finding of the assets assessed in the last `BRIDGE_LOOKBACK_HOURS`, as `same`. After that, each run sends only the changes, unless `RAPID7_INCLUDE_SAME=1`.

Python 3.9 or later, standard library only. One file: `rapid7_insightvm_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/rapid7/insightvm` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Rapid7.** InsightVM must be connected to the Insight Platform (the Cloud Integrations API reads the platform's copy of your assets). Find your region code: `us`, `us2`, `us3`, `eu`, `ca`, `au`, `ap`, `aps2` or `me1`. Create a user for the bridge on the Insight Platform, linked to an InsightVM user with the User role (or a custom role with only View Site Asset Data and View Group Asset Data) for the sites it should read, then sign in as that user and create a User Key under Administration > API Key Management. The API returns only the assets the key's user can see. Rapid7 doesn't document the least role for this API; if the user key is refused, an Organization Key works, but it can do everything in every Rapid7 product, so keep it to the bridge's host.

## Configuration

Everything comes from environment variables. Keep the API key and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `RAPID7_REGION` | none | Your Insight Platform region's code, such as `au`. |
| `RAPID7_API_KEY` | none | The Insight Platform API key, sent as `X-Api-Key`. |
| `RAPID7_API_URL` | `https://<region>.api.insight.rapid7.com` | The API's address with no path. Set it only to go through a proxy of your own. |
| `RAPID7_PAGE_SIZE` | `50` | Assets per page, 1 to 500. Rapid7 recommends 50 when it works out changes. |
| `RAPID7_INCLUDE_SAME` | `0` | Also send, on every run, each current finding of each asset assessed since the last run. |
| `RAPID7_DEFINITIONS` | `1` | Add each vulnerability's definition as `vulnerability`. |
| `BRIDGE_STATE_FILE` | `rapid7_insightvm_state.json` | Where each region's last run ended. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run reads assets, up to 8,760. |
| `BRIDGE_DELAY_SECONDS` | `900` | How far behind now each run's time is, so the platform has the latest assessments. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `120` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing. Run one bridge, with its own state file, per Insight Platform organization.

## Run it

```bash
python3 rapid7_insightvm_bridge.py --dry-run          # print the NDJSON it would send; sends and saves nothing
python3 rapid7_insightvm_bridge.py                    # one pass, for cron or a systemd timer
python3 rapid7_insightvm_bridge.py --interval 3600    # keep polling every hour
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status and Rapid7's message, stops, and leaves the run's position where it was, so the next run reads the same records again from where the last accepted page ended. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/rapid7-insightvm-findings.env` (owned by root, mode 600):

```ini
[Unit]
Description=Rapid7 InsightVM findings bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/rapid7-insightvm-findings/rapid7_insightvm_bridge.py --interval 3600
EnvironmentFile=/etc/rapid7-insightvm-findings.env
DynamicUser=yes
StateDirectory=rapid7-insightvm-findings
WorkingDirectory=/var/lib/rapid7-insightvm-findings
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run has a time, `BRIDGE_DELAY_SECONDS` before now, and compares the assets at that time with the last run's time. It posts to `/vm/v4/integration/assets` with `currentTime` (this run's time), `comparisonTime` (the last run's), `includeSame=false` (or `true` with `RAPID7_INCLUDE_SAME=1`), `includeUniqueIdentifiers=true`, `size` and the body `{"asset": "last_assessed_for_vulnerabilities > <the last run's time>"}`, so it pages only through the assets assessed since then. Rapid7 works out each asset's `new` and `remediated` findings between the two times. The first run sends `includeSame=true` with no `comparisonTime`, and the lookback as the asset filter.
- Each run's comparison starts at the last one's time, so a finding that appears or goes is sent once, as new or remediated. A finding that is found and fixed between two runs is in neither run's snapshot, so it isn't sent.
- Pages follow `metadata.cursor`, with the same times on every page. The position is saved after HTTP Ingest accepted each page, and a run that stopped partway goes on from the next page with the same times. If Rapid7 refuses a saved cursor, the bridge reads that window again from its first page, so some findings can arrive twice.
- For the vulnerabilities on each page that it hasn't seen yet, the bridge posts `{"vulnerability": "id IN ['...', ...]"}` to `/vm/v4/integration/vulnerabilities`, 100 IDs at a time, and keeps the definitions in memory while it runs. Only IDs of letters, digits and `-`, `.`, `_` and `:` go in a filter; a finding with any other ID, or one Rapid7 doesn't return, gets no `vulnerability`.
- 408, 429, 500, 502, 503 and 504 are retried with backoff, honoring `Retry-After`, up to 6 times. A 401 or 403 stops the run with Rapid7's message: check the key, the region, and that the key's user can view the assets. A 400 stops the run with Rapid7's message. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Rapid7 or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.
- The asset filter's syntax and field name follow Rapid7's own examples; Rapid7 publishes no full list of filter fields. Microsoft Sentinel's InsightVM connector notes that the v4 API may not always return every expected record, which this bridge can't detect.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the API key, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/rapid7-insightvm-findings -p 'test_*.py' -v
```

The tests start a local mock of the assets and vulnerabilities endpoints (working out each asset's new, remediated and same findings from when each was found and remediated, running the bridge's asset filter, and paging by cursor) and HTTP Ingest, built from the documented shapes, and check the records, the first run and the later ones, the times each run sends, include-same, paging and going on from a stopped page, a refused cursor, the definitions and their cache, refused keys and requests, dry-run, retries, batching and gzip, state per region, settings, times, refused redirects, the response size cap, and that no secret reaches the log.

## References

- InsightVM Cloud Integrations API (v4): https://help.rapid7.com/insightvm/en-us/api/integrations.html
- Insight Platform API keys and regions: https://docs.rapid7.com/insight/managing-platform-api-keys/ and https://docs.rapid7.com/insight/product-apis/
- InsightVM user roles: https://docs.rapid7.com/insightvm/managing-users-and-authentication/
- InsightVM query operators: https://docs.rapid7.com/insightvm/query-operators-1/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
