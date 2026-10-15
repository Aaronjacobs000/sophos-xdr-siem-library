# ExtraHop RevealX detections to Sophos NG-SIEM

RevealX sends security detections to a webhook from a detection notification rule. The webhook can add `Authorization: Bearer <token>` itself, so it posts straight to a Sophos NG-SIEM HTTP Ingest integration with no relay. RevealX 360 sends webhooks only to endpoints open to the internet with a publicly trusted certificate, which HTTP Ingest is.

## Set it up

1. In Sophos Fusion, add an HTTP Ingest integration and copy its URL and integration key.
2. In RevealX, go to System Settings > Notification Rules > Create > Security Detection. Set the criteria you want, such as a minimum risk score.
3. Under Target, choose Custom Webhook. Set Payload URL to the HTTP Ingest URL. Under Show Advanced Connection Options, choose Bearer Token and paste the integration key.
4. Under Notification Behavior, choose Send for every detection update. ExtraHop recommends it for SIEM export, and the participant fields (`src`, `dst`) are only filled with it.
5. Under Payload Options, choose Custom payload and replace the suggested payload with the one below. It has the same fields as ExtraHop's suggested payload, on one line.
6. Save, then use Send Test Payload. The test message stays in the generic schema.

HTTP Ingest reads each line of a request body as its own record, and ExtraHop's payload templates span many lines. Sent as they are, a detection could arrive split into many records. The template below is one line, so each detection is one record.

```
{"title": "{{ title }}", "type": "{{ type }}", "src": {"type": "{{ src.type }}", "hostname": {{ src.hostname | safe }}, "ipaddr": "{{ src.ipaddr }}", "role": "{{ src.role }}", "endpoint": "{{ src.endpoint }}", "username": "{{ src.username }}", "device": {"oid": {{ src.device.oid }}, "name": {{ src.device.name | safe }}, "ipaddrs": {{ src.device.ipaddrs | safe }}, "macaddr": {{ src.device.macaddr | safe }}}}, "dst": {"type": "{{ dst.type }}", "hostname": {{ dst.hostname | safe }}, "ipaddr": "{{ dst.ipaddr }}", "role": "{{ dst.role }}", "endpoint": "{{ dst.endpoint }}", "username": "{{ dst.username }}", "device": {"oid": {{ dst.device.oid }}, "name": {{ dst.device.name | safe }}, "ipaddrs": {{ dst.device.ipaddrs | safe }}, "macaddr": {{ dst.device.macaddr | safe }}}}, "additional_participants": {{ additional_participants | safe }}, "properties": {{ properties | safe }}, "description": "{{ description }}", "categories_ids": {{ categories_ids | safe }}, "mitre_techniques": {{ mitre_techniques | safe }}, "recommended": "{{ recommended }}", "recommended_factors": {{ recommended_factors | safe }}, "url": "{{ url }}", "risk_score": {{ risk_score }}, "time": {{ time }}, "id": {{ detection_id or id }}}
```

Keep `url`, `risk_score` and `time`: the parser's confirm string looks for the detection URL and the risk score, and `time` is the event time. You can add fields; the parser ignores ones it doesn't map.

## What the parser maps

Each detection goes to the third-party alert schema:

| Field | From |
| --- | --- |
| `alert_id`, `title`, `summary` | `id`, `title`, `description` |
| `alert_category` | `type`, the detection type |
| `risk_score`, `vendor_severity` | `risk_score` |
| `severity` | `risk_score`: 1 to 30 low, 31 to 79 medium, 80 to 99 high, ExtraHop's own bands |
| `source_address`, `source_host_name`, `source_user_name`, `source_mac` | `src` |
| `destination_address`, `target_host_name`, `target_user_name`, `destination_mac` | `dst` |
| `event_time_usec` | `time`, epoch milliseconds |
| `additional_data` | the detection URL, each participant's role (offender or victim), the most specific category, the first MITRE technique, and whether it is recommended for triage |

`src` is the participant that started the traffic, which isn't always the offender, so the roles go to `additional_data`. A host name is the participant's `hostname`, or its device name when that is empty.

Not checked against a live RevealX system: what ExtraHop renders for a participant with no device (the samples use `null`), and whether `recommended` comes as `"true"` or `"True"`. The parser reads the text in any case, and also takes a JSON boolean and MITRE techniques given as objects with an `id`.
