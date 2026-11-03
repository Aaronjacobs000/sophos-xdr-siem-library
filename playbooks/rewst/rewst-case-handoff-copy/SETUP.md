# Set up Rewst case handoff

A template carries no trigger, connections or settings, so you set them up once in your tenant. Leave the playbook off until a test run.

## 1. In Rewst

Create or open the workflow that should handle Sophos Fusion cases, and add a webhook trigger to it. Copy the trigger's URL. If you set a secret key on the trigger, Rewst expects it in the `x-rewst-secret` header and answers 401 without it. Build the workflow on the document described below, and if it writes back to the case, start each comment with `[rewst]`.

## 2. The connection

Add a connection to the Generic Webhook connector Sophos manages (Taegis.Webhook) under Security Operations > Automations > Connectors:

- **Webhook URL:** the Rewst trigger URL.
- **Authentication:** None, or API Key with the header `x-rewst-secret` and the trigger's secret.

You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 3. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 4. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, events Create, Update and Comment Added.
- **When does this playbook run?** Always. Minimum severity and Managed by do the scoping.
- **Connections:** the Rewst webhook connection and the Case connection.
- **Minimum severity** and **Managed by:** which cases go to Rewst.
- **Send comments:** off unless your workflow needs comment text. Comments can hold anything an analyst typed.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 5. Test it

1. Point the connection at a test Rewst trigger, or put the workflow in a test mode, and turn the playbook on.
2. Create a test case at or above the minimum severity.
3. Check the execution under Playbooks > Executions, and the trigger's run in Rewst.

## What Rewst receives

```json
{
  "source": "sophos-fusion",
  "schema": "unofficial-rewst-case-handoff/1",
  "event": "create",
  "case": {
    "id": "<case ID>", "short_id": "CSE00042", "title": "...", "severity": 8, "severity_name": "High",
    "status": "open", "closed": false, "managed_by": "CUSTOMER", "assignee": "...", "tenant_id": "<tenant ID>",
    "link": "<link to the case in Sophos Fusion>"
  },
  "changed": ["status"],
  "comment": {}
}
```

`event` is create, update, comment added or manual. `changed` lists status, severity, assignee or title on an update. `comment` holds `text` and `author` only for a comment, and only with Send comments on.

## Rollback

None for what was sent. Turn the playbook off to stop sending, and undo what your Rewst workflow did in the tools it touched.
