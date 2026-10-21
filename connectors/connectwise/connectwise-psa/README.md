# ConnectWise PSA connector (unofficial)

A custom connector for Sophos Fusion playbooks that calls the [ConnectWise PSA REST API](https://developer.connectwise.com/Products/ConnectWise_PSA/REST) on a ConnectWise cloud host. It creates, reads and updates service tickets and adds notes to them. It can't delete tickets. Sophos and ConnectWise don't make, maintain or support it.

The playbook [ConnectWise PSA case sync](../../../playbooks/connectwise/connectwise-psa-case-sync/) uses it.

## Functions

| Function | Call | Risk tier |
| --- | --- | --- |
| `validate` | `GET /system/info` | lookup |
| `getTicket` | `GET /service/tickets/{id}` | lookup |
| `createTicket` | `POST /service/tickets` | notify |
| `updateTicket` | `PATCH /service/tickets/{id}` | reversible action |
| `addNote` | `POST /service/tickets/{id}/notes` | notify |

Every call goes to `https://<API host>/v4_6_release/apis/3.0` with the `clientId` header. `updateTicket` takes JSON Patch operations, such as `[{"op": "replace", "path": "status", "value": {"name": "Closed"}}]`. `createTicket` returns the ticket number and a link that opens the ticket in ConnectWise PSA, which the case sync saves on the case.

## Before you add a connection

- API member: in ConnectWise PSA, create an API member under System > Members > API Members, with a security role that can add and edit service tickets and their notes on the boards you sync to. Generate its public and private keys under API Keys.
- clientId: ConnectWise requires a clientId on every API call. Register one on the [ConnectWise developer site](https://developer.connectwise.com/); it identifies the integration, not a user.
- Host: the API host for your region is `api-na.myconnectwise.net`, `api-eu.myconnectwise.net` or `api-au.myconnectwise.net` (ConnectWise also answers on `api-aus.myconnectwise.net`). On-premises ConnectWise PSA servers aren't covered: the connector only calls hosts on the library's allowlist.

## Add it

1. In Sophos Fusion, go to Security Operations > Automations > Connectors > Connector Library and import `connector.yaml`.
2. Add a connection to it with the settings below.
3. Use Test on the connection. It reads the system information.

| Setting | Value |
| --- | --- |
| Authentication | Basic |
| Username | Your company ID, a plus sign and the public key, such as `acme+PublicKey` |
| Password | The private key |
| ConnectWise PSA API host | The host of your region |
| ConnectWise company ID | The company ID you sign in with |
| ConnectWise clientId | Your clientId |

## Not tested

Nobody has run this connector against ConnectWise PSA yet. The request and response shapes follow ConnectWise's published API models. Two details are untested: the JSON Patch form of a status change by name, and the ticket link, which uses the ConnectWise web host for your region.

## Sources

- REST API and versioning: https://developer.connectwise.com/Products/ConnectWise_PSA/REST
- Cloud URL formatting: https://developer.connectwise.com/Best_Practices/Manage_Cloud_URL_Formatting
