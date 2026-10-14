# Kaseya VSA 10 to Sophos NG-SIEM

| Records | How they get to Sophos NG-SIEM | Parser | Schema |
| --- | --- | --- | --- |
| Notifications (alerts) | A notification webhook pushes them to HTTP Ingest | `KASEYA_VSA10_NOTIFICATION_JSON_STANDALONE_THIRDPARTYALERT` | Third-party alert |
| Audit log (script runs, remote control, file transfers, API tokens, account changes) | Pulled from the API by `bridges/kaseya-vsa10-audit-logs` | `KASEYA_VSA10_AUDIT_JSON_STANDALONE_CLOUDAUDIT` | CloudAudit |

VSA 10 only pushes notifications. The audit log, which records who ran what on which device and from where, is API only.

## Notifications

Create an HTTP Ingest integration in Sophos Fusion (Security Operations > Integrations > Marketplace > Custom), then create the webhook with the VSA 10 REST API (`POST https://<server_name>/api/v3/notifications/webhooks`, authenticated with a third-party API token). The API documentation is linked in `meta.json`.

```json
{
  "Name": "Sophos NG-SIEM",
  "Description": "Notifications to HTTP Ingest",
  "Priorities": ["Low", "Normal", "Elevated", "Critical"],
  "OrganizationIds": [],
  "Headers": { "Authorization": "Bearer <integration key>" },
  "Url": "<HTTP Ingest URL>",
  "Language": "en"
}
```

Each delivery carries an `x-hmac-signature` header that HTTP Ingest ignores. The body has the device identifier, not its name.

## Audit log

See `bridges/kaseya-vsa10-audit-logs`. It posts each audit record unchanged, one JSON object per line.

Pulseway documents the same webhook and audit log, so both parsers should read Pulseway records too. That hasn't been tested.
