# NinjaOne connector (unofficial)

A custom connector for Sophos Fusion playbooks that calls the NinjaOne public API (v2) to search devices, read a device and read an organization. It only reads: it can't run scripts, reboot devices or change anything in NinjaOne. Sophos and NinjaOne don't make, maintain or support it.

The playbook [NinjaOne device context](../../../playbooks/ninjaone/ninjaone-device-context/) uses it.

## Functions

| Function | Call | Risk tier |
| --- | --- | --- |
| `validate` | `GET /v2/organizations?pageSize=1` | lookup |
| `searchDevices` | `GET /v2/devices/search?q=...` | lookup |
| `getDevice` | `GET /v2/device/{id}` | lookup |
| `getOrganization` | `GET /v2/organization/{id}` | lookup |

`getDevice` also returns a link that opens the device in NinjaOne.

## Before you add a connection

- Client app: in NinjaOne, go to Administration > Apps > API and add a client app of type API Services (machine-to-machine), with the Client Credentials grant and the Monitoring scope only. Monitoring is read only. Management and Control would let the credential change devices and start remote sessions, which this connector never needs.
- Instance: your instance host is the one you sign in to NinjaOne on: `app.ninjarmm.com`, `us2.ninjarmm.com`, `ca.ninjarmm.com`, `eu.ninjarmm.com` or `oc.ninjarmm.com` for Oceania.

## Add it

1. In Sophos Fusion, go to Security Operations > Automations > Connectors > Connector Library and import `connector.yaml`.
2. Add a connection to it with the settings below.
3. Use Test on the connection. It reads one organization.

| Setting | Value |
| --- | --- |
| Authentication | OAuth Client Credentials |
| Grant URL | `https://<instance host>/ws/oauth/token`, such as `https://oc.ninjarmm.com/ws/oauth/token` |
| Client ID and Client Secret | The client app's |
| Scopes | `monitoring` |
| NinjaOne instance host | The same host |

## Not tested

Nobody has run this connector against NinjaOne yet. Three details are untested: whether Sophos Fusion's OAuth Client Credentials handler sends the client secret in the form body, as NinjaOne's token endpoint expects, the device search response, which this connector reads as a `devices` list, and the device link format.

## Sources

- API client apps and scopes: https://www.ninjaone.com/docs/integrations/how-to-set-up-api-oauth-token/
- OAuth token configuration: https://www.ninjaone.com/docs/application-programming-interface-api/oauth-token-configuration/
- API reference, on each instance: https://app.ninjarmm.com/apidocs-beta/
