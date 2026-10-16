# Sophos Mobile connector (unofficial)

A custom connector for Sophos Fusion playbooks that calls the [Sophos Mobile API](https://developer.sophos.com/reference/mobile-v1/). It locks devices, sends them a message, reads a device, and reads the actions it started. It has no wipe, locate or unenroll. Sophos doesn't make, maintain or support it.

The playbooks [Sophos Mobile lock](../../../playbooks/sophos/sophos-mobile-lock/) and [Sophos Mobile send message](../../../playbooks/sophos/sophos-mobile-send-message/) use it.

## Functions

| Function | Call | Risk tier |
| --- | --- | --- |
| `validate` | `GET /mobile/v1/devices?pageSize=1` | lookup |
| `getDevice` | `GET /mobile/v1/devices/{id}` | lookup |
| `getActions` | `GET /mobile/v1/actions?ids=...` | lookup |
| `lock` | `POST /mobile/v1/actions/lock` | reversible action |
| `sendMessage` | `POST /mobile/v1/actions/send-message` | notify |

Actions are asynchronous. `lock` and `sendMessage` return one action for each device, in the state `accepted`, and devices Sophos Mobile couldn't act on under `errors`. Read the actions with `getActions` until each is `successful`, `failed` or `skipped`. A Mac needs a six-digit lock code to lock, which this connector doesn't send, so Sophos Mobile lists a Mac under `endpointsWithUnsatisfiedArguments`.

## Before you add a connection

- Region: The Sophos Mobile API serves the eu01, eu02, us01 and us03 data regions. Sophos Mobile isn't available in the Australian, Brazilian, Canadian, Indian or Japanese data regions, so the account that holds Sophos Mobile is in the US or EU.
- Credential: Create an API credential in that account under Global Settings > Access Control > API Credentials. Give it the least role that can act on devices: Service Principal Management. Read-only can't create actions, and Super Admin can do far more than this needs. Use one credential per tenant.
- Expiry: Sophos Fusion doesn't warn you when an API credential expires: it removes it, and the connection stops working. Note the expiry date and set a reminder to replace it.
- Tenant ID and host: Get a token once (below), then call `GET https://api.central.sophos.com/whoami/v1`. It returns the tenant `id` and `apiHosts.dataRegion`, such as `https://api-us01.central.sophos.com`.

## Add it

1. In Sophos Fusion, go to Security Operations > Automations > Connectors > Connector Library and import `connector.yaml`.
2. Add a connection to it with the settings below.
3. Use Test on the connection. It reads one device.

| Setting | Value |
| --- | --- |
| Authentication | OAuth Client Credentials |
| Grant URL | `https://id.sophos.com/api/v2/oauth2/token` |
| Client ID and Client Secret | The API credential's |
| Scopes | `token` |
| Sophos Mobile API host | The host of your data region |
| Tenant ID | From whoami |

## How it signs in

The connection gets an access token from `id.sophos.com` with the client credentials grant and the scope `token`, and sends it as `Authorization: Bearer` with `X-Tenant-ID` on every call. A token lasts an hour (`expires_in` 3600); the connection gets a new one with the same credential (inferred: how Sophos Fusion's OAuth handler renews tokens isn't documented). The API allows 100 calls a minute per credential.

Open question: how the client secret is sent. Sophos's token endpoint takes `client_id` and `client_secret` in the form body. Whether Sophos Fusion's OAuth Client Credentials handler sends them in the body or in an HTTP Basic header, and whether `id.sophos.com` accepts Basic, isn't documented. If Test fails with a sign-in error and the credential is right, this is the likely cause. Nobody has tested this connector against a tenant with Sophos Mobile yet.

## Sources

- Sophos Mobile API: https://developer.sophos.com/mobile/ and https://developer.sophos.com/reference/mobile-v1/
- Getting a token and whoami: https://developer.sophos.com/getting-started-tenant/
- Regions: https://developer.sophos.com/concepts/regions/
- Rate limits: https://developer.sophos.com/concepts/rate-limits/
- API credential roles and expiry: https://docs.sophos.com/fusion/customer/help/en-us/index.html?contextId=API-credential-management
- Regions without Sophos Mobile: https://docs.sophos.com/fusion/customer/help/en-us/index.html?contextId=unsupported-regions
