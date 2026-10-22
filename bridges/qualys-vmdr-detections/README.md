# Qualys VMDR detections bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Qualys subscription or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Qualys's VM API documentation and output DTDs. Run it with `--dry-run` first and check what it would send.

Qualys VMDR keeps each host's vulnerability detections and their status (New, Active, Re-Opened, Fixed), but has no push for them. So this script asks the Host List Detection API for the detections whose status changed in each new window and sends each one as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parser in `parsers/qualys/qualys-vmdr` normalizes them.

The Host List Detection API answers in XML. Each record is one detection, as JSON:

- `qualys_record` (`detection`) and `qualys_platform` (the API server's host name) first.
- `HOST`: the host's elements as Qualys names them (`ID`, `ASSET_ID`, `IP`, `TRACKING_METHOD`, `OS`, `DNS`, `DNS_DATA`, `NETBIOS` and the rest), without its `DETECTION_LIST`.
- `DETECTION`: the detection's elements (`UNIQUE_VULN_ID`, `QID`, `TYPE`, `SEVERITY`, `PORT`, `PROTOCOL`, `RESULTS`, `STATUS`, `QDS` and the dates).
- `KB`: unless `QUALYS_KB=0`, the QID's entry from the KnowledgeBase: `TITLE`, `VULN_TYPE`, `SEVERITY_LEVEL`, `CATEGORY`, `PUBLISHED_DATETIME`, `PATCHABLE`, `CVE_LIST` (the CVE IDs), `CVSS` and `CVSS_V3` (`BASE`, `TEMPORAL`, `VECTOR_STRING`) and `THREAT_INTELLIGENCE` (the threat indicator names). A detection has no title of its own, only its QID, so the KnowledgeBase gives it one.

Every value is the XML's text. An element with attributes, such as `<QDS severity="HIGH">72</QDS>`, becomes `{"value": "72", "severity": "HIGH"}`, `QDS_FACTORS` becomes an object of factor name to value, and a `*_LIST` element or `TAGS` becomes an array.

Python 3.9 or later, standard library only. One file: `qualys_vmdr_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parser from `parsers/qualys/qualys-vmdr` under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn it on.

**Qualys.** Find your platform's API server on Qualys's platform identification page, such as `https://qualysapi.qualys.com` (US 1), `https://qualysapi.qualys.eu` (EU 1) or `https://qualysapi.qg1.apps.qualys.com.au` (AU 1). Create a user for the bridge with the Reader role and API access, and give it the asset groups whose hosts it should read: Readers see the hosts in their account, Managers every host in the subscription, and Unit Managers their business unit. With tag-based user scoping, the user's tags decide. The KnowledgeBase API also needs the subscription to allow KnowledgeBase downloads; if it doesn't, set `QUALYS_KB=0`.

The bridge signs in with basic authentication, the user name and password on each request over https, with the `X-Requested-With` header Qualys requires.

## Configuration

Everything comes from environment variables. Keep the password and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `QUALYS_API_URL` | none | Your platform's API server with no path, such as `https://qualysapi.qg1.apps.qualys.com.au`. |
| `QUALYS_USERNAME` | none | The bridge user's login. |
| `QUALYS_PASSWORD` | none | Its password. |
| `QUALYS_PAGE_HOSTS` | `100` | Hosts per page (`truncation_limit`), 1 to 10,000. Lower it if a page is over the 64 MB the bridge reads. |
| `QUALYS_SEVERITIES` | all | Only these severities, such as `3-5` or `4,5`. |
| `QUALYS_SHOW_RESULTS` | `1` | Include each detection's `RESULTS`, the scan's evidence. `0` makes records much smaller. |
| `QUALYS_SHOW_QDS` | `1` | Include the Qualys Detection Score (`QDS`). |
| `QUALYS_SHOW_IGS` | `0` | Include information gathered detections, not only confirmed and potential vulnerabilities. |
| `QUALYS_KB` | `1` | Add each QID's KnowledgeBase entry as `KB`. |
| `BRIDGE_STATE_FILE` | `qualys_vmdr_state.json` | Where each user's window ended. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts, up to 8,760. |
| `BRIDGE_DELAY_SECONDS` | `900` | How far behind now each window ends, so detections from a scan Qualys is still processing are in the next one. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `120` | Seconds per request read. Qualys sends a keep-alive comment every 30 to 40 seconds while it builds a large answer. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 qualys_vmdr_bridge.py --dry-run          # print the NDJSON it would send; sends and saves nothing
python3 qualys_vmdr_bridge.py                    # one pass, for cron or a systemd timer
python3 qualys_vmdr_bridge.py --interval 3600    # keep polling every hour
```

Exit code 0 means every page was read and sent. On an error the bridge logs it with the HTTP status and Qualys's error code, stops, and leaves the window where it was, so the next run reads the same records again from where the last accepted page ended. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a Qualys API limit that outlasts them, a read timeout and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/qualys-vmdr-detections.env` (owned by root, mode 600):

```ini
[Unit]
Description=Qualys VMDR detections bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/qualys-vmdr-detections/qualys_vmdr_bridge.py --interval 3600
EnvironmentFile=/etc/qualys-vmdr-detections.env
DynamicUser=yes
StateDirectory=qualys-vmdr-detections
WorkingDirectory=/var/lib/qualys-vmdr-detections
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads the API

- Each run reads one window: from where the last one ended (or `BRIDGE_LOOKBACK_HOURS` back, the first time) to `BRIDGE_DELAY_SECONDS` before now. It posts `action=list` to `/api/6.0/fo/asset/host/vm/detection/` with `detection_updated_since` and `detection_updated_before` (to the second, in UTC), `status=New,Active,Re-Opened,Fixed`, `truncation_limit`, `show_asset_id=1`, and the `show_` and `severities` settings, in the form body, so no URL carries them.
- Qualys counts a detection as updated when its status changes, so each detection is sent when it is found (New), found again (Active), fixed (Fixed) and reopened (Re-Opened), not on every scan that sees it. A detection whose status never changed counts from when it was last detected.
- A full page ends with a warning (code 1980) and the next page's URL. The bridge reads only `id_min` from that URL and sends the next request itself, so the user name and password go only to `QUALYS_API_URL`. The position, page by page, is saved after HTTP Ingest accepted each page, and a run that stopped partway goes on from the next page of the same window.
- Qualys doesn't say whether both of a window's bounds count. A detection whose status changed at the window's end is remembered, by host, unique vulnerability ID, QID and update time, and skipped if the next window returns it again.
- For the QIDs on each page that it hasn't seen yet, the bridge posts `action=list&details=All&ids=...` to `/api/4.0/fo/knowledge_base/vuln/`, 500 QIDs at a time, and keeps the entries in memory while it runs. A QID the KnowledgeBase doesn't return gets no `KB`.
- 408, 429, 500, 502, 503 and 504 are retried with backoff, honoring `Retry-After`, up to 6 times. A call Qualys's API limits blocked (HTTP 409, or 400, with code 1920, 1960 or 1965) is retried the same way, waiting as long as `X-RateLimit-ToWait-Sec` says, up to five minutes a time. Any other Qualys error stops the run with its HTTP status, code and text, such as 401 code 2000 (a wrong user name or password), 403 code 2012 (no API access) or 409 code 2003 (the subscription's EULA isn't accepted). An MSP user's errors come with HTTP 200, so the bridge reads the code from the body. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Qualys or HTTP Ingest is refused, not followed, so no key or password goes to another URL, and the run stops with an error that says so.
- Qualys's answers declare no XML entities, so an answer that does is refused before it is parsed. The bridge never fetches the DTD an answer names.
- Hosts tracked by the Cloud Agent show only to users whose asset groups hold their IP addresses; Qualys's online help explains how to give a sub-user those hosts.

The detection's time fields come as Qualys gives them, in UTC to the second.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the password, the `Authorization` header, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/qualys-vmdr-detections -p 'test_*.py' -v
```

The tests start a local mock of the Host List Detection API (running the bridge's status, severity and update-time filters, host ID order, `truncation_limit` and `id_min` paging), the KnowledgeBase API and HTTP Ingest, built from the documented shapes, and check the records and their XML to JSON rules, the form body, the window's end and start, paging and going on from a stopped page, a detection at a window's end being sent once, the KnowledgeBase lookups and their cache, API limits and their wait, Qualys's error codes and the MSP case, XML that declares entities, dry-run, retries, batching and gzip, state per user and platform, settings, times, refused redirects, the response size cap, and that no secret reaches the log.

## References

- Host List Detection API (parameters, output, paging, keep-alive, API versions): https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm
- Host List Detection output DTD: https://qualysapi.qualys.com/api/6.0/fo/asset/host/vm/detection/dtd/output.dtd
- KnowledgeBase API: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm
- Authentication, API limits and their headers: https://docs.qualys.com/en/vm/qweb-all-api/get_started/get_started.htm
- Error codes: https://docs.qualys.com/en/vm/qweb-all-api/appendix/appendix_d.htm
- API versions and their end of support: https://docs.qualys.com/en/vm/qweb-all-api/get_started/api_versioning_standards.htm
- Platform API servers: https://www.qualys.com/platform-identification/
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
