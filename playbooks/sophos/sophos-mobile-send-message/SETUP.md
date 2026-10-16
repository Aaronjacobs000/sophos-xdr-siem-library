# Set up Sophos Mobile send message

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connector and its connection

If your tenant doesn't have it yet, import the [Sophos Mobile connector](../../../connectors/sophos/sophos-mobile/) under Security Operations > Automations > Connectors > Connector Library, and add a connection to it as its README says. You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** User Initiated, category Response Action, context Host. Name it something your analysts will recognize, such as Message mobile device.
- **When does this playbook run?** Always. The device groups and the per-run limit do the scoping.
- **Connections:** the Sophos Mobile connection and the Case connection.
- **Device groups:** the IDs of the Sophos Mobile device groups whose devices the playbook may message. List them with `GET /mobile/v1/device-groups` or read them in Sophos Mobile. With none, the playbook sends nothing.
- **Most devices per run:** leave it at 1 unless you need more. A run that finds more devices sends nothing.
- **Message:** what the user sees, up to 500 characters. Say who sent it and how to reach your team, and never ask for a password.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Open a case with a host that is a test device in an allowed group, and run the action on the host.
3. Read the case comment and the execution under Playbooks > Executions. It names the device it would message.
4. Turn off dry run and run it once more against the test device. Check that the message arrives and that the comment says `successful`.
5. Only then use it on real devices.

A message that stays pending after three minutes is reported as UNKNOWN. The device may be offline; Sophos Mobile keeps the action until the device checks in.

## Rollback

None. A message can't be recalled once Sophos Mobile sends it.
