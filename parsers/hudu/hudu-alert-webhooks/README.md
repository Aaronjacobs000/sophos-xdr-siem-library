# Hudu alert webhooks to Sophos NG-SIEM

Hudu has no syslog export. Its alerts can send a webhook with a JSON payload you write from Hudu webhook variables. A Hudu webhook takes only a URL and a payload, and Sophos NG-SIEM HTTP Ingest needs `Authorization: Bearer <integration key>`, so send the webhooks to the [webhook relay](../../../collectors/webhook-relay/) in this repo, which forwards the body to the HTTP Ingest URL with that header.

In Hudu, go to the admin area > Alerts > + New Alert, pick the alert type and companies, and under Configure Webhook enter the relay URL and the payload for that type. Keep `"source":"Hudu"` and `"alert"` as the first two keys: the parser's confirm string looks for them.

## Record created/updated/deleted

```json
{"source":"Hudu","alert":"record","action":"$ACTION","record_type":"$RECORD_TYPE","record_name":"$RECORD_NAME","record_id":"$RECORD_ID","company_name":"$COMPANY_NAME","company_id":"$COMPANY_ID","user":"$USER","url":"$HUDU_URL","asset_layout_id":"$ASSET_LAYOUT_ID"}
```

## One-time shared password reveal

```json
{"source":"Hudu","alert":"password_reveal","record_type":"$RECORD_TYPE","record_name":"$RECORD_NAME","record_id":"$RECORD_ID","company_name":"$COMPANY_NAME","company_id":"$COMPANY_ID","user":"$USER","url":"$HUDU_URL"}
```

Both go to CloudAudit. The event name is the record type and the action, or `one_time_reveal`. Hudu sends no time, so the event time is when the record arrives. Hudu alerts cover the companies you pick, so add every company you want watched.

Hudu's full activity log is only in its API, and the API reference is only inside each Hudu instance, so this entry doesn't cover it.

Not checked against a live Hudu instance: the exact text of `$USER` (the parser takes the first IPv4 address in it as the source address) and whether Hudu escapes quotes in values. Compare a test alert with `samples.log` before you rely on it.
