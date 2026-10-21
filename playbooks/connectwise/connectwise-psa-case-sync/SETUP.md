# Set up ConnectWise PSA case sync

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connector and its connection

If your tenant doesn't have it yet, import the [ConnectWise PSA connector](../../../connectors/connectwise/connectwise-psa/) under Security Operations > Automations > Connectors > Connector Library, and add a connection to it as its README says. You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, events Create, Update and Comment Added. Other case events, such as Link Added, would only add notes about the playbook's own link.
- **When does this playbook run?** Always. Minimum severity and Managed by do the scoping.
- **Connections:** the ConnectWise PSA connection and the Case connection.
- **Board** and **Company:** the service board and the company identifier new tickets go to. For a partner-level playbook that serves several customer tenants, set Company by tenant to JSON such as `{"<tenant ID>": "AcmeCorp"}`; a tenant not in it uses Company.
- **Statuses:** New ticket status (empty uses the board's default), Closed status and Reopen status, spelled as they are on the board.
- **Minimum severity** and **Managed by:** which cases get a ticket. Managed by defaults to self, so Sophos MDR cases get none.
- **Internal notes:** on, notes go to internal analysis. Off, they go to the discussion your customer can see.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Create a test case at or above the minimum severity, or wait for one.
3. Read the execution under Playbooks > Executions. Its outcome says what the playbook would do, such as open a ticket. Nothing is written in dry run.
4. Turn off dry run and create another test case. Check that a ticket opens on your board and a ConnectWisePSA link appears on the case.
5. Comment on the case and check that the comment reaches the ticket as a note. Close the case and check that the ticket closes.
6. Only then leave it on for real cases.

## Sophos MDR cases

Managed by defaults to self, which leaves Sophos MDR cases alone. Before you set it to sophos or any, test on one MDR case: check that the link lands on the case (if it can't, every later event opens another ticket) and that the notes it copies, which include every comment on the case, are ones your customer may see.

## Rollback

Turn the playbook off. Close or delete the tickets it opened in ConnectWise PSA, and delete the ConnectWisePSA links on the cases.
