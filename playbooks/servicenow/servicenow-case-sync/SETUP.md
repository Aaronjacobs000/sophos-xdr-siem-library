# Set up ServiceNow case sync

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connector and its connection

Add a connection to the ServiceNow connector Sophos manages (Taegis.ServiceNow) under Security Operations > Automations > Connectors, with your instance URL and a user that can create and update incidents through the Table API (the itil role covers it). You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, events Create, Update and Comment Added. Other case events, such as Link Added, would only add notes about the playbook's own link.
- **When does this playbook run?** Always. Minimum severity and Managed by do the scoping.
- **Connections:** the ServiceNow connection and the Case connection.
- **Incident settings:** Assignment group, Caller and Category for new incidents, each left out when empty. Note field is work_notes, which stays internal, or comments, which the caller sees.
- **Resolved state** and **Close code:** what a closed case sets. Check your instance's incident states and close codes; 6 and Solution provided are a standard instance's.
- **Reopen state:** what a reopened case sets, 2 (In Progress) unless you change it.
- **Minimum severity** and **Managed by:** which cases get an incident. Managed by defaults to self, so Sophos MDR cases get none.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Create a test case at or above the minimum severity, or wait for one.
3. Read the execution under Playbooks > Executions. Its outcome says what the playbook would do, such as open an incident. Nothing is written in dry run.
4. Turn off dry run and create another test case. Check that an incident opens with the case ID as its correlation ID and a ServiceNow link appears on the case.
5. Comment on the case and check that the comment reaches the incident as a note. Close the case and check that the incident closes.
6. Only then leave it on for real cases.

## Sophos MDR cases

Managed by defaults to self, which leaves Sophos MDR cases alone. Before you set it to sophos or any, test on one MDR case: check that the link lands on the case (if it can't, every later event opens another incident) and that the notes it copies, which include every comment on the case, are ones your customer may see.

## Rollback

Turn the playbook off. Close or delete the incidents it opened in ServiceNow, and delete the ServiceNow links on the cases.
