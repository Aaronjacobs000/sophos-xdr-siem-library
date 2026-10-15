# FortiDLP webhooks to Sophos NG-SIEM

FortiDLP webhooks can add their own `Authorization` header, so they post straight to a Sophos NG-SIEM HTTP Ingest integration. No bridge or relay is needed.

1. In Sophos Fusion, add an HTTP Ingest integration (Security Operations > Integrations > Marketplace > Custom) and copy its URL and integration key.
2. In the FortiDLP Console, under Event export, choose Webhooks, then Create new webhook. Each webhook carries one event type, and a tenant has five webhooks by default, so create one for each type you want: Detections, Incidents and Audit logs.
   - URL: the HTTP Ingest URL.
   - Payload format: JSON.
   - Event type and filters: as you need. Action events stay generic in Sophos NG-SIEM.
   - Headers: `Authorization:Bearer <integration key>`.
   - Delivery and rate limiting: leave Batching enabled off.
3. Click the webhook's row and choose Test to check FortiDLP can reach the URL.
4. Add the four parsers in Sophos Fusion under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own events before you turn them on.

Leave batching off. A batch arrives as one body with a `detections`, `incidents`, `audit_logs` or `actions` array, which HTTP Ingest stores as one record and these parsers don't read.

## What you get

- Detections: Thirdparty, titled with the policy name, with the description, risk score, a severity from the score (CRITICAL from 90, HIGH from 70, MEDIUM from 40, LOW below), the user and node, and the first address, port, URL and host FortiDLP lists. Files, the application, tags, labels, USB device, process path, MITRE technique and requested actions go to `additional_data`.
- Incidents: Thirdparty, titled with the description, with why FortiDLP sent it as the status, the policy, the score, and the first and last detection times.
- Audit logs: ManagementEvent, with the event type, summary, operator, the operator's address, the audience (webapp or api) and the request.

Not checked against a live FortiDLP tenant. HTTP Ingest reads each line as a record, so check that one event arrives as one record before you rely on the parsers.
