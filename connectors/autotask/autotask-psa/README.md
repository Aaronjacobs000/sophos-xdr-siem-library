# Autotask PSA connector (unofficial)

A custom connector for Sophos Fusion playbooks that calls the [Autotask PSA REST API](https://www.autotask.net/help/developerhelp/Content/APIs/REST/Entities/TicketsEntity.htm). It creates, reads and updates tickets and adds notes to them. It can't delete tickets. Sophos and Kaseya don't make, maintain or support it.

The playbook [Autotask PSA case sync](../../../playbooks/autotask/autotask-psa-case-sync/) uses it.

## Functions

| Function | Call | Risk tier |
| --- | --- | --- |
| `validate` | `GET /Tickets/entityInformation` | lookup |
| `getTicket` | `GET /Tickets/{id}` | lookup |
| `createTicket` | `POST /Tickets` | notify |
| `updateTicket` | `PATCH /Tickets` | reversible action |
| `addNote` | `POST /Tickets/{id}/Notes` | notify |

Every call goes to `https://<zone host>/ATServicesRest/V1.0` with three headers: `Secret` from the connection's API key, and `UserName` and `ApiIntegrationCode` from its settings. `createTicket` returns the ticket ID and a link that opens the ticket in Autotask, which the case sync saves on the case.

## Before you add a connection

- API user: in Autotask, add an API user (API only) under Admin > Resources/Users. Its API User (API-only) security level has full administrator access, so give it a copy of that level cut down to adding and editing tickets and ticket notes. Note its user name and secret.
- Integration code: under API Tracking Identifier on the same user, pick Custom (Internal Integration) and note the tracking identifier. The connector sends it as `ApiIntegrationCode`.
- Zone: your zone is the number in your Autotask web address. The API host for zone 6 is `webservices6.autotask.net`, which is Australia and New Zealand. The full list is on Autotask's [API zones](https://www.autotask.net/help/developerhelp/Content/APIs/General/API_Zones.htm) page.

## Add it

1. In Sophos Fusion, go to Security Operations > Automations > Connectors > Connector Library and import `connector.yaml`.
2. Add a connection to it with the settings below.
3. Use Test on the connection. It reads the Tickets entity information.

| Setting | Value |
| --- | --- |
| Authentication | API Key |
| Header | `Secret` |
| Key | The API user's secret |
| Autotask API zone host | The webservices host of your zone |
| API user name | The API user's user name |
| API integration code | The tracking identifier |

## Not tested

Nobody has run this connector against Autotask yet. Three details are untested: whether Sophos Fusion's API Key sign-in sends the `Secret` header alongside the two headers the connector sets, the `Tickets/{id}/Notes` child path for a new note, and the ticket link, which uses the `ww` web host that matches your zone.

## Sources

- Authentication: https://www.autotask.net/help/developerhelp/Content/APIs/REST/General_Topics/REST_Security_Auth.htm
- Zones: https://www.autotask.net/help/developerhelp/Content/APIs/General/API_Zones.htm
- Tickets: https://www.autotask.net/help/developerhelp/Content/APIs/REST/Entities/TicketsEntity.htm
- Ticket notes: https://www.autotask.net/help/developerhelp/Content/APIs/REST/Entities/TicketNotesEntity.htm
