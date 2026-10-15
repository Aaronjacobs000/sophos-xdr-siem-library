# PingOne to Sophos NG-SIEM

PingOne webhooks send audit activities (sign-ons, MFA checks, lockouts, password resets and admin changes) in Ping Activity Format, the same records the Audit Activities API returns. These parsers read them one event per Sophos NG-SIEM HTTP Ingest record.

## Send the events

PingOne posts up to 500 events in one body, as a JSON array by default, and HTTP Ingest would store that as one record. The [webhook relay](../../../bridges/webhook-relay/) takes PingOne's webhook on `/pingone`, checks its token and forwards each event as its own record.

1. In Sophos Fusion, go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Copy the Integration Key and URL.
2. Run the relay with `NGSIEM_INGEST_URL`, `NGSIEM_INGEST_KEY` and `PINGONE_WEBHOOK_TOKEN` (32 characters or more) behind a TLS proxy, as its README describes.
3. In the PingOne admin console, go to Integrations > Webhooks and add a webhook:
   - Protocol HTTPS, Destination URL `https://<relay name>/pingone`, and Allow TLS connection with untrusted certificates off.
   - Under Headers, Add Custom HTTP Headers: Key `Authorization`, Value `Bearer <PINGONE_WEBHOOK_TOKEN>`.
   - Payload Format JSON array with Pretty Print off (NDJSON works too), Event Schema Ping Activity Format.
   - Payload Limit: Limit by Size, at most 500 KB with the relay's default `BRIDGE_MAX_BODY_BYTES`. PingOne resends a delivery until it gets 200 and holds every later event until then.
   - Turn on Include IP address and Include User Agent, or the events carry neither.
   - Event Types: the sign-on, MFA and password types below, and the admin change types you want, such as users, roles, groups, applications, populations, identity providers and sign-on policies.

PingOne's NDJSON format, with an `Authorization: Bearer <Integration Key>` custom header, could post to HTTP Ingest without the relay, one event per line, the way the OneLogin entry sends. That route hasn't been tried with HTTP Ingest; the relay is the tested one.

## Add the parsers

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers. Add `PINGONE_ACTIVITY_JSON_PARENT` first, then each child with the parent as its parent parser. Use Run Test with your own events before you turn them on.

| Parser | Events |
| --- | --- |
| `PINGONE_ACTIVITY_JSON_PARENT` | Claims Ping Activity Format events and routes them by action type |
| `PINGONE_ACTIVITY_JSON_CHILD_AUTH` | Sign-on, MFA, lockout, password reset and sign-off events to Auth |
| `PINGONE_ACTIVITY_JSON_CHILD_CLOUDAUDIT` | Every other action type to CloudAudit |

## What you get

- Auth, by action type: `PASSWORD.CHECK_SUCCEEDED`, `PASSWORD.CHECK_FAILED` and `PASSWORD.CHECK_FAILED_USER_NOT_FOUND`, `USER.KERBEROS_SUCCEEDED` and `_FAILED`, `CIBA_AUTHENTICATION.SUCCEEDED` and `.FAILED` (sign-on); `OTP.CHECK_SUCCESS`, `.CHECK_FAILED` and `.CHECK_INVALID`, `ASSERTION.CHECK_SUCCESS` and `.CHECK_FAILED`, `PUSH_BIOMETRICS.REJECTED` (MFA); `USER.LOCKED` and `.UNLOCKED`, `PASSWORD.LOCKED` and `.UNLOCKED`; `PASSWORD.RESET`, `.RECOVERY` and `.SET`; `SESSION.DELETED` and `USER.SLO_SUCCESS` (sign-off). Each has the account, the address and user agent, the application, the session, LOGON, LOGOFF, FAILURE or ACCOUNT with the auth category, a failure category for failures, and whether MFA was used. The action type is the status and the result description the sub-status.
- CloudAudit: the action type as the event name and its resource (such as `ROLE_ASSIGNMENT`) as the event type, the acting user or API client, the environment as the account, the address and user agent, the user acted on, the result, the resources with their environment, and a management event flag for changes. The action and result descriptions, client, correlation and session IDs go to `additional_event_data`.
- The event time is `recordedAt`.

## Limits

PingOne's data model says `result.status` is succeeded or failed, but its examples show SUCCESS, so the parsers read FAILED or FAILURE in any case as a failure, and otherwise judge the outcome from the action type.
