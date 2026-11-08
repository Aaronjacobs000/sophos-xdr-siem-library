# Sophos Endpoint connector (unofficial)

A custom connector for Sophos Fusion playbooks that calls the [Sophos Endpoint API](https://developer.sophos.com/reference/endpoint-v1/). It regenerates tamper protection passwords, turns tamper protection on, resets device health, and reads devices and their tamper protection state. It can't turn tamper protection off, and it never returns a password. Sophos doesn't make, maintain or support it.

The playbooks [Sophos Endpoint tamper protection passwords](../../../playbooks/sophos/sophos-endpoint-tamper-protection-passwords/) and [Sophos Endpoint reset health on case close](../../../playbooks/sophos/sophos-endpoint-reset-health-on-case-close/) use it. [Sophos Endpoint scan case devices](../../../playbooks/sophos/sophos-endpoint-scan-case-devices/) doesn't: scans go through the Sophos Endpoint connector Sophos manages, which has `initiateScan`.

## Functions

| Function | Call | Risk tier |
| --- | --- | --- |
| `validate` | `GET /endpoint/v1/endpoints?pageSize=1` | lookup |
| `getEndpoints` | `GET /endpoint/v1/endpoints?ids=...` | lookup |
| `listEndpoints` | `GET /endpoint/v1/endpoints?groupIds=...` | lookup |
| `getTamperProtection` | `GET /endpoint/v1/endpoints/{id}/tamper-protection` | lookup |
| `updateTamperProtection` | `POST /endpoint/v1/endpoints/tamper-protection` | reversible action |
| `resetHealth` | `POST /endpoint/v1/endpoints/reset-health` | destructive |

- `getEndpoints` reads up to 100 devices by ID, with their group, platform, health, online state and tamper protection state. An ID Sophos doesn't know is left out of `items`.
- `listEndpoints` lists the devices in up to 50 groups, 500 a page. Pass `pages.nextKey` back as `page_from_key` for the next page.
- `getTamperProtection` returns `enabled` and `password_changed_at`, the time each earlier password was replaced. The API also returns the current and earlier passwords; the connector drops them, so they never reach a playbook's execution log.
- `updateTamperProtection` takes up to 200 devices. `regenerate` gives each one a new password. `turn_on` turns tamper protection on; a device can't go on while tamper protection is off for the whole account. There is no way to turn it off through this connector.
- `resetHealth` takes up to 500 devices. It sets health to green and clears every alert on each device, whatever the alert is about. There is no undo. Windows and Linux only: other devices come back under `errors` as `notSupported`.

Both write functions answer `202` with the devices Sophos accepted under `items`, each `requested`, and the ones it refused under `errors`, each with an `errorCode` (`notFound`, `notSupported`, `conflict`, `permissionDenied`, `internalError`) and an `errorMessage`. Accepted means requested, not done: read the device back.

## Before you add a connection

- Credential: Create an API credential under Global Settings > Access Control > API Credentials. Give it the least role that can change devices, Service Principal Management (inferred from the role descriptions). Super Admin can do far more than this needs. Use one credential per tenant.
- Expiry: Sophos Fusion doesn't warn you when an API credential expires: it removes it, and the connection stops working. Note the expiry date and set a reminder to replace it.
- Tenant ID and host: Get a token once (below), then call `GET https://api.central.sophos.com/whoami/v1`. It returns the tenant `id` and `apiHosts.dataRegion`, such as `https://api-au01.central.sophos.com`.

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
| Sophos Endpoint API host | The host of your data region: us01, us03, eu01, eu02, ca01, au01, jp01, br01 or in01 |
| Tenant ID | From whoami |

## How it signs in

The connection gets an access token from `id.sophos.com` with the client credentials grant and the scope `token`, and sends it as `Authorization: Bearer` with `X-Tenant-ID` on every call. This worked through Sophos Fusion's OAuth Client Credentials handler in a test tenant on 2026-11-08. The API allows 100 calls a minute per credential.

## Sources

- Endpoint API: https://developer.sophos.com/reference/endpoint-v1/
- Bulk tamper protection and reset health: https://developer.sophos.com/whatsnew/oct-14-2026-bulk-action-apis/
- Getting a token and whoami: https://developer.sophos.com/getting-started-tenant/
- Regions: https://developer.sophos.com/concepts/regions/
- Rate limits: https://developer.sophos.com/concepts/rate-limits/
- API credential roles and expiry: https://docs.sophos.com/fusion/customer/help/en-us/index.html?contextId=API-credential-management
