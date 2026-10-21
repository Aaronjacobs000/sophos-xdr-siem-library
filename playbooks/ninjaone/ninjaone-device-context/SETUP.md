# Set up NinjaOne device context

A template carries no trigger, connections or settings, so you set them up once in your tenant. Leave the playbook off until a test run.

## 1. The connector and its connection

If your tenant doesn't have it yet, import the [NinjaOne connector](../../../connectors/ninjaone/ninjaone/) under Security Operations > Automations > Connectors > Connector Library, and add a connection to it as its README says. You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** User Initiated, category Response Action, context Host. Name it something your analysts will recognize, such as NinjaOne device context.
- **When does this playbook run?** Always.
- **Connections:** the NinjaOne connection and the Case connection.
- **Most hosts per run:** leave it at 3 unless you need more.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on. It only reads NinjaOne and comments on the case.
2. Open a case with a host you know is in NinjaOne, and run the action on the host.
3. Read the case comment. It names the NinjaOne organization, whether the device is online, its last contact, last logged-on user and operating system, and links to the device.
4. Run it on a host that isn't in NinjaOne and check the comment says so.

## Rollback

Delete the comment on the case if you don't want it. Nothing in NinjaOne changes.
