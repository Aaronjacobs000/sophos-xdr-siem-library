# Set up Sophos Endpoint tamper protection passwords

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connector and its connection

If your tenant doesn't have it yet, import the [Sophos Endpoint connector](../../../connectors/sophos/sophos-endpoint/) under Security Operations > Automations > Connectors > Connector Library, and add a connection to it as its README says. You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** User Initiated, category Response Action, context Case. Name it something your analysts will recognize, such as Regenerate tamper protection passwords.
- **When does this playbook run?** Always. The device groups and the per-run limit do the scoping.
- **Connections:** the Sophos Endpoint connection and the Case connection.
- **Device groups:** the IDs of the device groups whose devices get a new password, up to 50. List them with the Endpoint API, `GET /endpoint/v1/endpoint-groups`. An admin can read the password of every device, so list every group you want covered. With none, the playbook changes nothing.
- **Turn tamper protection on:** leave it on, so a device an attacker turned it off on gets it back. It can't go on while tamper protection is off for the whole account.
- **Most devices per run:** set it to the number of devices in those groups, up to 1000. A run that finds more changes none.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Set Device groups to a group that holds only a test device, open a case, and run the action on the case.
3. Read the case comment and the execution under Playbooks > Executions. It names the devices it would change.
4. Turn off dry run and run it once more. Check that the comment says the new password was read back, and read the device's new password in Sophos Fusion.
5. Only then set your real groups.

## When an admin is compromised

1. Lock the admin account out first: an admin who can still sign in can read the new passwords too.
2. Run the playbook from the case about the compromise.
3. Read the comment. Check any device it lists as refused or unchanged by hand.

## Rollback

Nothing brings back an old password. Read each new password in Sophos Fusion on the device page. Tamper protection the playbook turned on can be turned off there.
