# Set up Sophos Endpoint scan case devices

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connections

The playbook uses three connectors Sophos manages, under Security Operations > Automations > Connectors: Sophos Endpoint (Taegis.SophosEndpoint), Sophos Case (Taegis.Case) and Sophos Asset (Taegis.Asset). They sign in as the platform and need no credential. A tenant with Sophos Endpoint devices usually has the Sophos Endpoint connection already. If one is missing, add it from the Connector Library.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** User Initiated, category Response Action, context Case. Name it something your analysts will recognize, such as Scan case devices. To scan the devices of every new case instead, use Platform Events, source Case, event Create, with When does this playbook run? set to Only When `caseManagedBy(inputs) == 'CUSTOMER'`.
- **When does this playbook run?** Always, for the User Initiated trigger. The device groups and the per-run limit do the scoping.
- **Connections:** the Sophos Endpoint, Case and Asset connections.
- **Device groups:** the IDs of the device groups whose devices the playbook may scan. List the groups and their IDs with the Endpoint API, `GET /endpoint/v1/endpoint-groups`. With none, the playbook scans nothing.
- **All groups:** leave it off, unless any device a case names may be scanned.
- **Most devices per run:** 5 unless you need more. A run that finds more devices in scope scans none.
- **Include Sophos-managed cases:** leave it off unless you've agreed it with the Sophos MDR team.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Open a case whose devices include a test device in an allowed group, and run the action on the case.
3. Read the case comment and the execution under Playbooks > Executions. It names the devices it would scan.
4. Turn off dry run and run it once more. Check that the comment says the scan was requested.
5. Only then use it on real cases.

Sophos answers a scan request with `requested`. The API has no way to read a scan's progress, so the comment can't say whether it ran.

## Rollback

A scan changes nothing on its own. What happens to anything it finds is set by the device's threat protection policy, as with any scan.
