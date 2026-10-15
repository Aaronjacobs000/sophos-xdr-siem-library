# Juniper Mist to Sophos NG-SIEM

These parsers read three Mist webhook topics:

| Topic | What it holds | Schema |
| --- | --- | --- |
| `audits` | Every configuration change made in the Mist portal or API: the admin, their address and browser, the message (such as Update Site Settings) and the settings before and after | CloudAudit |
| `alarms` | Security alarms (rogue AP, rogue client, honeypot SSID, spoofing and flooding attacks, repeated authentication failures, gateway malware, IDP and URL blocks), infrastructure alarms (devices offline) and Marvis alarms, with Mist's severity | Thirdparty |
| `nac-events` | Mist Access Assurance: network sign-ins allowed or denied, certificate checks, sessions, and identity provider and MDM lookups | Auth |

Mist sends these topics as a batch, `{"topic": ..., "events": [...]}`, with several events in one body, and doesn't offer one event per message for them. HTTP Ingest stores a body as one record, so send them through the [webhook relay](../../../bridges/webhook-relay/) with `BRIDGE_SPLIT_BATCHES=1`, which forwards each event as its own record in the same envelope. The parsers read the first event of a record, so a batch sent straight to HTTP Ingest would keep only its first event.

## Set it up

1. In Sophos Fusion, set up an HTTP Ingest integration (Security Operations > Integrations > Marketplace > Custom > HTTP Ingest) and add these parsers under Custom Parsers, parent first.
2. Run the webhook relay with `NGSIEM_INGEST_URL` and `NGSIEM_INGEST_KEY` from that integration, `MIST_WEBHOOK_SECRET` set to a random secret of at least 32 characters, and `BRIDGE_SPLIT_BATCHES=1`, behind a TLS proxy the Mist cloud can reach.
3. In the Mist portal, go to Organization > Settings for an organization webhook, or Organization > Site Configuration and a site for a site webhook. Under Webhooks, choose Add Webhook: Webhook Type HTTP Post, URL `https://<relay name>/mist`, Topics Audits, Alarms and NAC Events, and under Advanced Settings, Secret set to the same secret.
4. Add each topic at the organization or the site, not both, or each event arrives twice.

NAC events come from Mist Access Assurance. Mist's APAC 01 cloud is hosted in Australia.

## What each record becomes

- **Audits**: the message is the event name, the email in `admin_name` is the user, `src_ip` and `user_agent` are the source, and the site and device are resources. `before` and `after` go to additional event data as text.
- **Alarms**: the alarm type (such as `rogue_ap`) is the title, the group (`security`, `infrastructure` or `marvis`) is the category, and Mist's severity maps critical to Critical, warn to Medium and info to Info. The first hostname is the target host, gateway alarms give the source and destination addresses, and the APs, BSSIDs, SSIDs, client MACs, files, attacks and CVE IDs Mist lists go to additional data.
- **NAC events**: the event type (such as `NAC_CLIENT_PERMIT`) is the status and Mist's text the sub-status. Permit and session start are a successful sign-in, session end a sign-out, and deny, expired or revoked certificates and other failures a failed sign-in. NAC events carry no client IP address; the client MAC, auth type, SSID, AP or switch port, VLAN, IdP roles and certificate go to event metadata.

The Juniper docs these parsers follow are listed in `meta.json`.
