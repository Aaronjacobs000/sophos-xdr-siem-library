# NinjaOne activity webhooks to Sophos NG-SIEM

NinjaOne sends activities as they happen to one webhook per API application. Point it at a Sophos NG-SIEM HTTP Ingest integration (Security Operations > Integrations > Marketplace > Custom > HTTP Ingest in Sophos Fusion).

Send this body with `PUT /v2/webhook` from the NinjaOne Public API (Administration > Apps > API > API documentation, Try it out), or use the SIEM Exporter app. Use your region's NinjaOne host, and replace the URL and key with the HTTP Ingest values.

```json
{
  "url": "<HTTP Ingest URL>",
  "activities": {
    "SYSTEM": ["*"],
    "ACTIONSET": ["*"],
    "ACTION": ["*"],
    "SCRIPTING": ["*"],
    "REMOTE_TOOLS": ["*"],
    "SPLASHTOP": ["*"],
    "TEAMVIEWER": ["*"],
    "RDP": ["*"],
    "NINJA_REMOTE": ["*"],
    "CONDITION": ["*"],
    "ANTIVIRUS": ["*"]
  },
  "expand": ["device"],
  "headers": [
    { "name": "Authorization", "value": "Bearer <integration key>" }
  ]
}
```

A 204 response means it worked. In NinjaOne, a webhook with no name then appears under Notification Channels: leave it as it is. Turn on the Webhook failure system activity so you hear about delivery problems.

| Activity | Schema |
| --- | --- |
| Logins, logouts, failed logins, MFA set up or removed (SYSTEM) | Auth |
| Scripts and actions, remote access sessions, remote tools, credential access, technician role changes | ManagementEvent |
| Triggered conditions, antivirus threat activities | Third-party alert |
| Everything else | Generic |

NinjaOne documents the Activity fields and codes but not the wording of `subject` and `message`, which is where the user and address appear. Compare one real delivery with `samples.log` before you rely on those two fields.
