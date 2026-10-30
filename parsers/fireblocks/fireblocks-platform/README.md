# Fireblocks to Sophos NG-SIEM

Fireblocks is a platform that banks, fintechs, exchanges and other digital-asset businesses use to hold, move and settle crypto assets. It has no syslog and no SIEM connector of its own. It offers two feeds, and these parsers read both, sent to Sophos NG-SIEM HTTP Ingest:

- The **audit log**: sign-ins, user and role changes, admin quorum, Transaction Authorization Policy (TAP) changes, address and IP allowlists, signing keys, key backups, vaults, webhooks, transactions, AML screening and Fireblocks Security Posture Management (FSPM) findings. It is pull only, so the example bridge in [bridges/fireblocks-audit-logs](../../../bridges/fireblocks-audit-logs/) reads it from the Fireblocks API, signing each request with an API user's RSA key.
- **Webhooks v2**: each transaction as it is created and changes status, with its source, destination, amount, asset, initiator and signers, plus allowlisted wallets, vault accounts, network connections and stuck-transaction alerts. Fireblocks signs each delivery (RS512, with keys it publishes as a JWKS) but can't add the `Authorization` header HTTP Ingest needs, so the `/fireblocks` route of [bridges/webhook-relay](../../../bridges/webhook-relay/) checks the signature and forwards the delivery.

Start with the audit log: it is the record Fireblocks itself points SIEM tools at. Add the webhooks when you want transaction detail: a transfer's amount, destination address and signers, and the sub-status when a policy blocks it.

## Pull the audit log

1. In Sophos Fusion, go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Copy the Integration Key and URL.
2. In the Fireblocks Console, go to Developer center > API users and add an API user with the Auditor, Security Auditor or Non-Signing Admin role. Keep its private key (`fireblocks_secret.key`) and copy its API key.
3. Run the bridge with those values, as its [README](../../../bridges/fireblocks-audit-logs/README.md) describes. Each event arrives as one record with `"fireblocks_record": "audit_log"` first.

## Send webhooks through the relay

1. Run [bridges/webhook-relay](../../../bridges/webhook-relay/) behind TLS, with `FIREBLOCKS_JWKS_URL` set to the JWKS endpoint for the workspace's environment, from the relay's README.
2. In the Fireblocks Console, go to Developer center > Webhooks > Create webhook, set Endpoint URL to `https://<relay name>/fireblocks`, and pick the events, such as Transactions and Whitelist.
3. Check that a test transaction arrives in Sophos NG-SIEM as one record.

## Add the parsers

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers. Add `FIREBLOCKS_JSON_PARENT` first, then each child with the parent as its parent parser. Use Run Test with your own records before you turn them on.

| Parser | Events |
| --- | --- |
| `FIREBLOCKS_JSON_PARENT` | Claims audit log records and webhook notifications and routes them |
| `FIREBLOCKS_JSON_CHILD_AUTH` | Audit log sign-ins, failed sign-ins, access denied, password changes and 2FA resets to Auth |
| `FIREBLOCKS_JSON_CHILD_THIRDPARTYALERT` | Transactions the TAP blocked, AML rejections and flags, and new or reopened FSPM findings to Thirdparty |
| `FIREBLOCKS_JSON_CHILD_CLOUDAUDIT` | Every other audit log event to CloudAudit |
| `FIREBLOCKS_JSON_CHILD_WEBHOOK` | Every webhook notification to CloudAudit |

## What you get

- Auth: the user as the target user, LOGON, FAILURE or ACCOUNT with the auth category, the event as the status and the subject as the sub-status, and the category, user ID and workspace ID as metadata.
- Thirdparty: a title such as "Fireblocks: transaction blocked by the Transaction Authorization Policy", high severity for an AML rejection and medium otherwise, blocked for a policy block or an AML rejection, and the user who started it.
- CloudAudit, audit log: "<subject>: <event>" as the event name (such as "Whitelisted address: Added" or "Policy states: Published policy"), the category as the event type, the user and user ID, and the workspace as the recipient account. Events outside Transactions, Compliance and Orders are management events.
- CloudAudit, webhooks: the eventType as the event name (such as `transaction.status.updated`), the part before the first dot as the event type, the initiator's user ID, the status, the sub-status as the error code when a transaction is blocked, rejected, failed or cancelled, the transaction, source, destination, wallet or vault as resources, and the operation, asset, amount, USD amount, source, destination, destination address, note and external ID as request parameters. The transaction hash, signers, fee and confirmations go in additional event data.
- The event time is the audit event's `timestamp` (epoch milliseconds or ISO 8601) or the notification's `createdAt`.

## Testing

On 30 October 2026 the parsers passed Run Test in a Sophos Fusion test tenant on the synthetic samples. With the children combined into the parent as one parser, 240 of 240 fields matched the emulator in each of 3 runs. With each child added as a separate parser under its parent, 240 of 240 matched again. In 3 Parse Message runs, no built-in parser claimed any of the records.

## Limits

- Every sample is synthetic and follows Fireblocks' public docs. Fireblocks documents the audit log's fields and its event names but publishes no full audit record, so the samples are built from the field list. Whether `user` holds a name or an email address isn't documented; the samples use names.
- Audit events carry no source address, client or object ID: sign-ins have no address, and alerts don't name the transaction or finding. The webhook feed carries a transaction's detail.
- Webhooks name users by ID only.
- Audit Event notification webhooks (Settings > Audit log > Manage subscriptions) are a third feed, but Fireblocks doesn't document their payload, so these parsers don't read them.
- The bridge and the relay route are tested only against local mocks built from Fireblocks' docs. Neither they nor the parsers have run against a real Fireblocks workspace.

## Where Fireblocks' docs disagree

Fireblocks' docs contradict themselves in three places. Each needs checking against a live workspace.

- An audit event's `timestamp` is epoch milliseconds in the API reference and ISO 8601 in the Audit Logs guide. The parsers and the bridge read both.
- The Python and Go examples on the webhook validation page fetch keys from a JWKS URL that the endpoint table on the same page doesn't list. The relay's README follows the table and names both URLs.
- The authentication page says a request JWT's `exp` must be less than 30 seconds after `iat`, but both official SDKs, Python and JavaScript, set it 55 seconds out. The bridge uses 29 seconds.
