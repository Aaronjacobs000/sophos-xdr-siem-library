# FortiCNAPP alerts to Sophos NG-SIEM

FortiCNAPP (formerly Lacework) sends alerts to a custom webhook alert channel, which takes only a URL. It can't add the `Authorization` header that Sophos NG-SIEM HTTP Ingest needs, so the alerts go through the [webhook relay](../../../bridges/webhook-relay/), which adds it.

1. In Sophos Fusion, add an HTTP Ingest integration (Security Operations > Integrations > Marketplace > Custom) and copy its URL and integration key.
2. Run the webhook relay where FortiCNAPP can reach it over HTTPS, with `NGSIEM_INGEST_URL`, `NGSIEM_INGEST_KEY` and `FORTICNAPP_PATH_SECRET` set. The relay's README covers the TLS proxy and the service.
3. In the FortiCNAPP console, go to Settings > Notifications > Channels, choose + Add new, then Webhook, then Next. Set Webhook URL to `https://<relay name>/forticnapp/<FORTICNAPP_PATH_SECRET>` and save. Fortinet's docs show a token in the query string; the relay reads it from the path.
4. Under Alert rules, route the alerts you want to the new channel.
5. Add `FORTINET_FORTICNAPP_JSON_STANDALONE_THIRDPARTYALERT` in Sophos Fusion under Security Operations > Integrations > Custom Parsers, and use Run Test with your own alerts before you turn it on.

Each alert becomes a third-party alert: the title, the description as the summary, the event ID, the event type as the category, the source (such as AWSCompliance or Agent) as the sub-provider, and the severity (1 critical to 5 info). The account, the console link and the compliance recommendation ID go to `additional_data`.

The payload has no fixed fields for users, hosts or addresses; they stay in the description. FortiCNAPP doesn't document retries, so an alert the relay can't forward may be lost. Not checked against a live FortiCNAPP account.
