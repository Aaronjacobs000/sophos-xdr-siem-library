# Datto RMM to Sophos NG-SIEM

Two record types, each with its own parser:

| Records | How they get to Sophos NG-SIEM | Parser | Schema |
| --- | --- | --- | --- |
| Monitor alerts, raised and resolved | Datto RMM Global Webhooks push to HTTP Ingest | `DATTO_RMM_WEBHOOK_JSON_STANDALONE_THIRDPARTYALERT` | Third-party alert |
| Activity Log (logins, jobs, remote sessions, file transfers, device and user changes) | Pulled from the API by `collectors/datto-rmm-activity-logs` and posted to HTTP Ingest | `DATTO_RMM_ACTIVITY_JSON_STANDALONE_CLOUDAUDIT` | CloudAudit |

Datto RMM only pushes alerts. The Activity Log, which is where an attacker's remote sessions and script runs show up, is API only, so it needs the collector.

## Alerts: Global Webhooks

In Sophos Fusion, add an HTTP Ingest integration (Security Operations > Integrations > Marketplace > Custom) and copy its URL and key. In Datto RMM, go to Setup > Integrations > Global Webhooks and turn on webhooks for the alert priorities you want:

- URL: the HTTP Ingest URL
- Content Type: application/json
- Custom header: name `Authorization`, value `Bearer <integration key>` (hide the value)
- Alert raised payload:

```json
{"source":"Datto RMM","event":"raised","alert_uid":"[alert_uid]","alert_type":"[alert_type]","alert_category":"[alert_category]","alert_priority":"[alert_priority]","alert_message":"[alert_message]","device_uid":"[device_uid]","device_hostname":"[device_hostname]","device_ip":"[device_ip]","device_os":"[device_os]","last_user":"[last_user]","site_name":"[site_name]","site_uid":"[site_uid]","platform":"[platform]"}
```

- Turn on When alert is resolved and use the same payload with `"event":"resolved"`.

Keep `"source":"Datto RMM"` and `"event"` as the first two keys: the parser's confirm string looks for them. Turning on Global Webhooks turns off webhooks set on single monitors.

## Activity Log: collector

See `collectors/datto-rmm-activity-logs`. It posts each Activity Log record unchanged, one JSON object per line.

## Not checked against a live account

Whether Datto RMM escapes quotes and backslashes in the values it puts into the payload (its own Teams template puts `[alert_message_en]` inside a JSON string, so the parser assumes it does), the full list of activity categories and actions, and the format of the `details` text. Compare a test webhook and a few collected records with `samples.log` before you rely on them.
