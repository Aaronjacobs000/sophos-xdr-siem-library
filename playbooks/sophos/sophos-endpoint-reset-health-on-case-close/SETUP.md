# Set up Sophos Endpoint reset health on case close

Reset health sets a device's health to green and clears every alert on it, including alerts that have nothing to do with the case, or that another open case is about. There is no undo. Read this through before you turn it on.

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connector and its connections

If your tenant doesn't have it yet, import the [Sophos Endpoint connector](../../../connectors/sophos/sophos-endpoint/) under Security Operations > Automations > Connectors > Connector Library, and add a connection to it as its README says. You also need connections to the Case and Asset connectors Sophos manages (Taegis.Case and Taegis.Asset), which sign in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, event Update.
- **When does this playbook run?** Always. The playbook works out whether the update closed the case, and ends without a comment when it didn't.
- **Connections:** the Sophos Endpoint, Case and Asset connections.
- **Device groups:** the IDs of the device groups whose devices the playbook may reset. List them with the Endpoint API, `GET /endpoint/v1/endpoint-groups`. With none, the playbook resets nothing.
- **Most devices per run:** 3 unless you need more. A run that finds more devices in scope resets none.
- **Only devices that aren't healthy:** leave it on.
- **Minutes after close:** 15. It acts only on the update that closed the case, and only this soon after the close.
- **Include Sophos-managed cases:** leave it off unless you've agreed it with the Sophos MDR team.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Open a test case whose devices include a test device in an allowed group, and close it.
3. Read the case comment and the execution under Playbooks > Executions. It names the devices it would reset and their health.
4. Turn off dry run. Reopen the test case and close it again: the dry run's comment counts as a run for the first close.
5. Check that the comment says Sophos accepted the reset, and read the device's health in Sophos Fusion.
6. Only then let it run on real cases.

To run it by hand from a case, configure a second playbook from the template with a User Initiated trigger, context Case. It still acts only within Minutes after close, and once per close. This trigger is untested.

## Rollback

None. Cleared alerts can't be brought back. Detections and cases in Sophos Fusion are not changed. To stop it, turn the playbook off.
