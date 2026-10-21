# IT Glue connector (unofficial)

A custom connector for Sophos Fusion playbooks that calls the [IT Glue API](https://api.itglue.com/developer/) to find configurations by name and read organizations. It only reads, and it never reads passwords. Sophos and Kaseya don't make, maintain or support it.

The playbook [IT Glue configuration context](../../../playbooks/it-glue/it-glue-configuration-context/) uses it.

## Functions

| Function | Call | Risk tier |
| --- | --- | --- |
| `validate` | `GET /organizations?page[size]=1` | lookup |
| `findConfigurations` | `GET /configurations?filter[name]=...` | lookup |
| `getOrganization` | `GET /organizations/{id}` | lookup |

IT Glue's name filter matches the whole configuration name, so `host01` won't find `host01.corp.example.com`. The playbook tries both.

## Before you add a connection

- API key: in IT Glue, go to Account > Settings > API Keys, generate a key and leave Password Access off. Keep it to an account with access only to the organizations you need.
- Data center: the API host is `api.itglue.com` for the US, `api.eu.itglue.com` for the EU and `api.au.itglue.com` for Australia.
- IT Glue disables a key that goes unused for 90 days.

## Add it

1. In Sophos Fusion, go to Security Operations > Automations > Connectors > Connector Library and import `connector.yaml`.
2. Add a connection to it with the settings below.
3. Use Test on the connection. It reads one organization.

| Setting | Value |
| --- | --- |
| Authentication | API Key |
| Header | `x-api-key` |
| Key | The API key |
| IT Glue API host | The host of your data center |

## Not tested

Nobody has run this connector against IT Glue yet. Its calls and the attributes it reads follow IT Glue's published API reference.

## Sources

- API reference, hosts and rate limits: https://api.itglue.com/developer/
