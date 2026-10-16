# PingOne to Sophos NG-SIEM

PingOne webhooks send audit activities (sign-ons, MFA checks, lockouts, password resets and admin changes) in Ping Activity Format, the same records the Audit Activities API returns. These parsers read them one event per Sophos NG-SIEM HTTP Ingest record.

## Send the events

PingOne posts its webhook straight to a Sophos NG-SIEM HTTP Ingest integration in NDJSON, one event per line, with the integration key in a custom `Authorization` header, the way the OneLogin entry sends. No bridge is needed.

1. In Sophos Fusion, go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Copy the Integration Key and URL.
2. In the PingOne admin console, go to Integrations > Webhooks and add a webhook:
   - Protocol HTTPS, Destination URL the HTTP Ingest URL, and Allow TLS connection with untrusted certificates off.
   - Under Headers, Add Custom HTTP Headers: Key `Authorization`, Value `Bearer <Integration Key>`.
   - Payload Format NDJSON, Event Schema Ping Activity Format. Not JSON array: HTTP Ingest would store a whole batch of up to 500 events as one record, which the parsers leave unclaimed.
   - Turn on Include IP address and Include User Agent, or the events carry neither.
   - Event Types: the sign-on, MFA and password types below, and the admin change types you want, such as users, roles, groups, applications, populations, identity providers and sign-on policies.

This route hasn't been tested end to end: the parsers passed Run Test on NDJSON lines, but no event was sent through HTTP Ingest. PingOne's webhook page offers NDJSON and also says its requests don't use line-delimited JSON, so after you set it up, search for a few PingOne events and check each event is its own record. If a whole batch arrives as one record, nothing is normalized.

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
