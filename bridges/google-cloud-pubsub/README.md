# Google Cloud Pub/Sub bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Pub/Sub subscription or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from Google's Pub/Sub REST reference. Run it with `--dry-run` first and check what it would send.

Google Cloud Logging routes logs through a sink to a Pub/Sub topic, where each message's data is one log entry as JSON. Pub/Sub can push messages to an endpoint, but a push subscription authenticates with a token Google signs, not with the `Authorization` header HTTP Ingest needs. This script pulls the messages from a subscription instead and sends each one as one JSON line to a Sophos NG-SIEM HTTP Ingest integration, then acknowledges it.

| Data | Endpoint | Role |
| --- | --- | --- |
| Messages | `POST /v1/projects/{project}/subscriptions/{subscription}:pull` | Pub/Sub Subscriber |
| Acknowledgements | `POST /v1/projects/{project}/subscriptions/{subscription}:acknowledge` | Pub/Sub Subscriber |

A message whose data is a JSON object, such as a Cloud Logging entry, goes out as that object, unchanged, so the library parsers that read Cloud Logging entries, such as `parsers/google/google-cloud-dns-query-logs`, see it as Cloud Logging wrote it. Any other message goes out as `{"pubsub_subscription", "pubsub_message_id", "pubsub_publish_time", "pubsub_attributes", "pubsub_data"}`, with its data as text.

Python 3.9 or later, standard library only. One file: `google_cloud_pubsub_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers for your logs under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn them on.

**Google Cloud.**

1. Create a Pub/Sub topic, and a pull subscription to it for the bridge, with an acknowledgement deadline of 300 seconds, so a batch is sent before Pub/Sub hands its messages out again. Give the bridge a subscription of its own: each subscription gets every message, so one shared with another reader, such as Sophos Fusion's Google Cloud Platform integration, would split the messages between them.
2. In Cloud Logging, go to Log Router and create a sink with the topic as its destination, and an inclusion filter for the logs you want, such as `resource.type="dns_query"` for Cloud DNS query logs. Grant the sink's writer identity the Pub/Sub Publisher role on the topic, if the console doesn't do it for you.
3. Create a service account for the bridge, give it the Pub/Sub Subscriber role on the subscription only, and create a JSON key for it. The bridge asks for the `https://www.googleapis.com/auth/pubsub` scope; the role keeps it to reading and acknowledging that subscription.

Pub/Sub keeps a message it hasn't delivered for the subscription's retention period, 7 days by default.

## Configuration

Everything comes from environment variables. Keep the service account key and the HTTP Ingest key in a secrets manager or files only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `PUBSUB_SERVICE_ACCOUNT_KEY_FILE` | none | Path to the service account's JSON key file. |
| `PUBSUB_SERVICE_ACCOUNT_KEY` | none | The JSON key itself, instead of a file. Set one of the two. |
| `PUBSUB_SUBSCRIPTION` | none | The subscription's full name, such as `projects/example-project/subscriptions/ngsiem-logs`. |
| `PUBSUB_MAX_MESSAGES` | `1000` | Messages per pull, 1 to 1000. |
| `PUBSUB_MAX_PULLS` | `100` | Pulls per run, 1 to 10000. A run ends sooner when a pull comes back empty. |
| `PUBSUB_API_URL` | `https://pubsub.googleapis.com` | The Pub/Sub API host, or a regional or Private Service Connect endpoint. |
| `PUBSUB_TOKEN_URL` | `https://oauth2.googleapis.com/token` | Google's OAuth 2.0 token endpoint. The key file's own `token_uri` is not used. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 google_cloud_pubsub_bridge.py --dry-run        # pull once and print the NDJSON it would send; sends and acknowledges nothing
python3 google_cloud_pubsub_bridge.py                  # one pass, for cron or a systemd timer
python3 google_cloud_pubsub_bridge.py --interval 60    # keep pulling every minute
```

A dry run leaves the messages it pulled unacknowledged, so Pub/Sub hands them out again after the acknowledgement deadline.

Exit code 0 means the subscription was read and every message sent and acknowledged. On an error the bridge logs it with the HTTP status, stops, and acknowledges nothing it hadn't sent, so Pub/Sub delivers those messages again. A response over 64 MB also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or acknowledged. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/google-cloud-pubsub.env` (owned by root, mode 600) and the key file at `/etc/google-cloud-pubsub/key.json`. systemd hands the key to the bridge and sets `PUBSUB_SERVICE_ACCOUNT_KEY_FILE`, so leave that variable out of the file:

```ini
[Unit]
Description=Google Cloud Pub/Sub bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/google-cloud-pubsub/google_cloud_pubsub_bridge.py --interval 60
EnvironmentFile=/etc/google-cloud-pubsub.env
LoadCredential=key.json:/etc/google-cloud-pubsub/key.json
Environment=PUBSUB_SERVICE_ACCOUNT_KEY_FILE=%d/key.json
DynamicUser=yes
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet. The bridge keeps no state file: Pub/Sub keeps its place.

## How it reads Pub/Sub

- The bridge signs a JWT with the service account's key (issuer the service account, only the Pub/Sub scope) and trades it at the token endpoint for an access token, which lasts an hour. It renews the token a minute before it expires, and once more if Google refuses it.
- Each run pulls up to `PUBSUB_MAX_MESSAGES` messages at a time, sends them, and acknowledges them, until a pull comes back empty or it has made `PUBSUB_MAX_PULLS` pulls. A message is acknowledged only after HTTP Ingest accepted the batch it was in.
- Pub/Sub delivers each message at least once, and can deliver one twice. Within a run, a message is sent once by its `messageId`, and every delivery of it is acknowledged.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504 up to 6 times, honoring `Retry-After` up to 5 minutes. A 401 or 403 means the service account lacks the Pub/Sub Subscriber role on the subscription, a 404 that the subscription doesn't exist, and a 400 shows Google's message. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Google or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and acknowledging it, or a batch that takes longer than the acknowledgement deadline, can send those messages again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the service account key, the access token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/google-cloud-pubsub -p 'test_*.py' -v
```

The tests start a local mock of the token endpoint and the Pub/Sub pull and acknowledge methods, built from the documented shapes, and of HTTP Ingest, and check the signed token request and its scope, PKCS #8 and PKCS #1 keys, key files, pulls until the subscription is empty or the pull limit, that a message is acknowledged only after HTTP Ingest accepted it, repeated deliveries, messages that aren't JSON objects, the subscription in the path, refused keys and access, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Pub/Sub pull (request and response): https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/pull
- Pub/Sub acknowledge: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/acknowledge
- Pub/Sub push subscriptions and their authentication: https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions
- Cloud Logging routing to Pub/Sub (each message's data is a LogEntry): https://cloud.google.com/logging/docs/export/pubsub
- Using OAuth 2.0 for server to server applications (the signed JWT): https://developers.google.com/identity/protocols/oauth2/service-account
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
