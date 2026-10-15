# Webhook relay for Huntress, ScreenConnect, Hudu, Autotask and Juniper Mist

> **Unofficial, and tested against documented request shapes only.** This relay has not received real Huntress, ConnectWise ScreenConnect, Hudu, Autotask or Juniper Mist webhooks, or sent to a real Sophos NG-SIEM HTTP Ingest integration. Its unit tests sign deliveries the way each vendor documents and post to a local mock of HTTP Ingest. Run it with `--dry-run` first and check what it would send.

The first four push webhooks, but none of them can add the `Authorization: Bearer` header that Sophos NG-SIEM HTTP Ingest needs. Juniper Mist can add the header, but sends most topics as a batch of events in one body, which HTTP Ingest would store as one record; with `BRIDGE_SPLIT_BATCHES=1` the relay forwards each event as its own record. Run this relay where the vendors can reach it over HTTPS. It takes each vendor's webhook on its own path, checks that the delivery came from that vendor, and forwards the body to HTTP Ingest with the header.

| Vendor | Path | How the relay checks a delivery | Library entry |
| --- | --- | --- | --- |
| Huntress | `/huntress` | Svix signature: HMAC-SHA256 over the delivery ID, timestamp and body; timestamp within 5 minutes | `parsers/huntress/huntress-webhooks` |
| Autotask PSA | `/autotask` | `X-Hook-Signature`: HMAC-SHA1 over the body with the webhook's `SecretKey` | `parsers/autotask/autotask-webhooks` |
| Hudu | `/hudu/<secret>` | Secret in the path. A Hudu webhook has only a URL and a payload. | `parsers/hudu/hudu-alert-webhooks` |
| ConnectWise ScreenConnect | `/screenconnect/<secret>` | Secret in the path. Perform Web Request has only URL, method, content type and body. | `parsers/connectwise/screenconnect` |
| Juniper Mist | `/mist` | `X-Mist-Signature-v2`: HMAC-SHA256 over the body with the webhook's secret, in hex | `parsers/juniper/juniper-mist` |

Configure only the vendors you use; the other paths answer 404.

Python 3.9 or later, standard library only. One file: `webhook_relay.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from the library entries above under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn them on.

**A public HTTPS name.** The vendors post from the internet, so the relay needs a DNS name with a TLS certificate in front of it (see Put TLS in front, below).

**Secrets.** Generate the Autotask key and each path secret separately. The relay refuses shared secrets shorter than 32 characters.

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

## Set up each vendor

**Huntress.** An account admin opens Integrations from the menu, then Add an Integration > Webhooks > Add Endpoint. Enter `https://<relay name>/huntress`, pick the categories, and save. In the endpoint's three-dot menu, View Signing Secret, and set `HUNTRESS_SIGNING_SECRET` to it (it starts with `whsec_`). Use Send Test, then View Delivery Attempts to check for a 200.

**Autotask.** Webhooks are created through the REST API. For each entity you want (for example `CompanyWebhooks`), create a webhook with `WebhookUrl` set to `https://<relay name>/autotask` and `SecretKey` set to your `AUTOTASK_SECRET_KEY` (Autotask takes up to 64 characters), then add its fields as Autotask's webhook guide describes. Point `DeactivationUrl` at a different server, as Autotask advises.

**Hudu.** In the admin area, go to Alerts > + New Alert and choose the alert type and companies. Under Configure Webhook, enter `https://<relay name>/hudu/<HUDU_PATH_SECRET>` and the payload for that alert type from the [Hudu entry's README](../../parsers/hudu/hudu-alert-webhooks/README.md). Test WebHook sends sample values.

**Juniper Mist.** In the Mist portal, go to Organization > Settings for an organization webhook, or Organization > Site Configuration and a site for a site webhook. Under Webhooks, choose Add Webhook, set Webhook Type to HTTP Post and URL to `https://<relay name>/mist`, and pick the topics, such as Audits, Alarms and NAC Events. Under Advanced Settings, set Secret to your `MIST_WEBHOOK_SECRET`. Add a topic at the organization or the site, not both, or each event arrives twice. Set `BRIDGE_SPLIT_BATCHES=1` so each event becomes its own record. The [Mist entry's README](../../parsers/juniper/juniper-mist/README.md) has the topics the parsers read.

**ScreenConnect.** Under Administration > Automations, create the security and session automations in the [ScreenConnect entry's README](../../parsers/connectwise/screenconnect/README.md). Set each Perform Web Request action to HTTP Method POST, Content Type `text/plain`, and URL `https://<relay name>/screenconnect/<SCREENCONNECT_PATH_SECRET>`.

## Configuration

Everything comes from environment variables. Keep secrets in a secrets manager or an environment file only the relay's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `HUNTRESS_SIGNING_SECRET` | none | The endpoint's signing secret (`whsec_...`). Turns on `/huntress`. |
| `AUTOTASK_SECRET_KEY` | none | The `SecretKey` on your Autotask webhooks, 32 to 64 characters. Turns on `/autotask`. |
| `HUDU_PATH_SECRET` | none | The secret in the Hudu webhook URL. Turns on `/hudu/<secret>`. |
| `SCREENCONNECT_PATH_SECRET` | none | The secret in the ScreenConnect web request URL. Turns on `/screenconnect/<secret>`. |
| `MIST_WEBHOOK_SECRET` | none | The Secret on your Mist webhook, at least 32 characters. Turns on `/mist`. |
| `BRIDGE_SPLIT_BATCHES` | `0` | Forward each event of a Mist batch, `{"topic": ..., "events": [...]}`, as its own record, in the same envelope with one event. Only Mist sends batches. |
| `BRIDGE_LISTEN_HOST` | `127.0.0.1` | Address to listen on. Keep it on loopback behind the TLS proxy. |
| `BRIDGE_LISTEN_PORT` | `8080` | Port to listen on. |
| `BRIDGE_MAX_BODY_BYTES` | `524288` | Larger deliveries get 413. HTTP Ingest recommends records under about 500 KB. |
| `BRIDGE_FORWARD_DEADLINE` | `8` | Seconds to keep retrying HTTP Ingest before answering the vendor 503. Autotask gives up on a delivery after 10 seconds. |
| `BRIDGE_MAX_CONNECTIONS` | `32` | Requests the relay handles at once, 1 to 1000. Past that it answers 503 straight away, and the vendor retries. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |
| `BRIDGE_LOG_LEVEL` | `INFO` | Same as `--log-level`. |

Set at least one vendor secret. Only an https HTTP Ingest URL is accepted, except plain http to this machine for testing.

## Run it

```bash
python3 webhook_relay.py --dry-run   # check deliveries and print each body to stdout; forwards nothing
python3 webhook_relay.py             # check deliveries and forward them
```

As a systemd service, with the variables in `/etc/webhook-relay.env` (owned by root, mode 600):

```ini
[Unit]
Description=Webhook relay to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/webhook-relay/webhook_relay.py
EnvironmentFile=/etc/webhook-relay.env
DynamicUser=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Keep the host's clock in sync: the relay refuses Huntress deliveries stamped more than 5 minutes from its clock.

## Put TLS in front

Vendors need an HTTPS URL. Keep the relay on 127.0.0.1 and put a reverse proxy in front that terminates TLS. Caddy gets the certificate itself:

```
{
	servers {
		timeouts {
			read_header 10s
			read_body 30s
		}
	}
}

relay.example.com {
	request_body {
		max_size 1MB
	}
	reverse_proxy 127.0.0.1:8080
}
```

With nginx and your own certificate:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;
    ssl_certificate     /etc/ssl/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/relay.example.com/privkey.pem;
    client_max_body_size 1m;
    client_header_timeout 10s;
    client_body_timeout 10s;
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Keep the proxy's access log off: it records request URLs, which hold the Hudu and ScreenConnect secrets. Caddy writes none unless you add a `log` directive. nginx's error log also records the request URL when it can't reach the relay, so keep that file readable only by administrators.

The timeouts above make the proxy, not the relay, wait on a slow sender. nginx also reads the whole body before it passes a request on.

## What it sends and answers

- The body goes to HTTP Ingest unchanged, with `Authorization: Bearer` and `Content-Type: application/json` for a JSON object or `text/plain` for anything else. The vendor's headers are not passed on.
- With `BRIDGE_SPLIT_BATCHES=1`, a Mist body with two or more events goes to HTTP Ingest in one request with one line per event, `{"topic": "<topic>", "events": [<event>]}`. A body with one event, and every other vendor's body, goes on as one record.
- HTTP Ingest reads every line as a separate record, so a body with line breaks inside is put on one line first. In JSON they become spaces (JSON only allows them between values, so the data is the same). In text, such as a multi-line ScreenConnect `{Event.Data}`, each becomes the two characters `\n`.
- HTTP Ingest 408, 429, 5xx and connection errors are retried with backoff, honoring `Retry-After`, until `BRIDGE_FORWARD_DEADLINE`. Other answers (400, 401, 403, 413 and redirects) are not retried.

| The relay answers | When |
| --- | --- |
| 200 | HTTP Ingest took the delivery, or `--dry-run` checked it. |
| 401 | The Huntress, Autotask or Mist signature is missing or wrong, or the Huntress timestamp is more than 5 minutes off. |
| 404 | Unknown path, vendor not configured, or wrong path secret. |
| 400, 405, 411, 413 | Empty body or JSON nested too deeply to read, not POST, no `Content-Length` (chunked), or body over `BRIDGE_MAX_BODY_BYTES`. |
| 502 | HTTP Ingest refused the delivery. Check the key and URL. |
| 503 | HTTP Ingest stayed unavailable until the deadline, or `BRIDGE_MAX_CONNECTIONS` requests were already in progress. |

After a non-2xx answer, Huntress (Svix) tries again after 5 seconds, 5 minutes, 30 minutes, then 2, 5, 10 and 10 hours. Autotask tries 5 times in 2 minutes, keeps the payload in its Webhook Error Log for 30 days, and turns the webhook off after 25 consecutive failures over more than 4 hours. Hudu, ScreenConnect and Mist don't document retries, so a delivery the relay can't forward may be lost.

HTTP Ingest delivers at least once and does not remove duplicates, so a vendor retry after a lost 200 sends the record again.

## Security notes

- Huntress, Autotask and Mist sign every delivery. The relay recomputes the HMAC and compares it in constant time. Autotask and Mist sign only the body, with no timestamp, so a captured delivery could be replayed; TLS is what stops capture.
- Hudu and ScreenConnect can't sign, so the path secret is the only check, and it is weaker: anyone who sees the URL (in the vendor's settings, a proxy log or a screenshot) can post records. Rotate a secret that leaks: change the variable, restart the relay, and update the vendor.
- The relay never logs secrets, the HTTP Ingest key, the HTTP Ingest URL path or bodies. It logs the vendor, the outcome, the size, Huntress delivery IDs, and the connecting address on rejections (the proxy's, behind a proxy).
- It verifies the HTTP Ingest certificate and doesn't follow redirects, so the key only goes to the configured host.
- It handles at most `BRIDGE_MAX_CONNECTIONS` requests at once and gives each 30 seconds in all to arrive, so slow or numerous connections can't use up its threads and files. While they last they can still keep it busy, so set the proxy timeouts above.

## Tests

```bash
python3 -m unittest discover -s bridges/webhook-relay -p 'test_*.py' -v
```

The tests sign deliveries the way each vendor documents, post them to the relay, and check forwarding with the header to a local mock of HTTP Ingest; valid, wrong, missing and stale signatures and path secrets for each vendor; splitting a Mist batch into one record per event, and only when turned on; the size limit; line-break handling; retries, the deadline and refusals; the connection limit and the time limit for a slow sender; dry-run; and that no secret or body reaches the log.

## References

- Huntress webhooks (setup, Svix signing): https://support.huntress.io/hc/en-us/articles/51679111552147-How-to-use-Webhooks-Integration
- Huntress webhook payloads: https://api.huntress.io/v1/webhooks_doc.json
- Svix signature verification: https://docs.svix.com/receiving/verifying-payloads/how-manual
- Svix retry schedule: https://docs.svix.com/retries
- Autotask, creating a webhook: https://www.autotask.net/help/developerhelp/Content/APIs/Webhooks/Webhooks_Creating.htm
- Autotask, secret key and payload verification: https://www.autotask.net/help/developerhelp/Content/APIs/Webhooks/SecretKeyPayloadVerification.htm
- Autotask, webhook error handling (retries, deactivation): https://www.autotask.net/help/developerhelp/Content/APIs/Webhooks/Webhooks_Error_Handling.htm
- Hudu webhooks: https://support.hudu.com/hc/en-us/articles/9613883219991-Understanding-WebHooks
- Juniper Mist webhooks (secret, X-Mist-Signature-v2, custom headers): https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/task/webhooks-add-portal.html
- Juniper Mist webhook messages (the batch envelope): https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/topic-map/webhook-messages.html
- ScreenConnect session automations (Perform Web Request): https://docs.connectwise.com/ScreenConnect_Documentation/Get_started/Administration_page/Automations_page/Create_a_new_session_automation
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract (bearer header, one record per line, size limits, status codes), in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
