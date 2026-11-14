# Set up Autotask PSA playbook failure tickets

A template carries no trigger, connections or settings, so you set them up once in your tenant. Leave the playbook off until a test run.

## 1. The connector and its connection

If your tenant doesn't have it yet, import the [Autotask PSA connector](../../../connectors/autotask/autotask-psa/) under Security Operations > Automations > Connectors > Connector Library, and add a connection to it as its README says.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Playbook Execution, events failed and completed.
- **When does this playbook run?** Only When, with this CEL. It leaves out runs that a Playbook Execution event started and the playbook failure and notification playbooks, so nothing loops, and keeps only failed runs and runs with the outcome FAIL:

  ```
  inputs.execution.triggerContext != 'execution' && !string(inputs.execution.template.name).startsWith('Unofficial_PlaybookFailure_') && !string(inputs.execution.template.name).startsWith('Taegis.Send_Notification_Message') && (inputs.event == 'failed' || inputs.execution.outcomeStatus == 'FAIL')
  ```
- **Connections:** the Autotask PSA connection.
- **Company ID:** the Autotask company new tickets go to. For a partner-level playbook that serves several customer tenants, set Company by tenant to JSON such as `{"<tenant ID>": 174}`; a tenant not in it uses Company ID.
- **Queue ID, Priority, New ticket status:** picklist numbers from your Autotask account. The defaults are no queue, 2 (Medium) and 1 (New) in Autotask's standard lists.
- **Due in hours:** 24 unless you change it.
- **Alert on a FAIL outcome:** on. Many playbooks catch their own errors and finish with the outcome FAIL instead of failing.
- **Playbooks to watch:** leave it empty to cover every playbook, or list the configured playbooks or template names to cover only those.
- **Playbooks to ignore:** configured playbooks or template names never to report, such as one that fails by design.
- **Error length:** 1000 characters unless you change it.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off. To post to chat as well, set up [Playbook failure alerts](../../sophos/playbook-failure-alerts/) on the same triggers.

For health events, choose Use this Template again and set the trigger to Platform Events, source Health, event create, with Only When:

```
inputs.health.name in ['Collector Down', 'Collector Warning', 'Collector health status Alert', 'Collector Endpoint Certificate Expiration Alert', 'Data Sources Alert']
```

These are the health event names Sophos Fusion's Health Event Case template lists. Remove any you don't want, and leave out Collector scheduled maintenance alert unless you want planned work reported. Use the same settings as the first one.

## 4. Test it

1. Turn the playbook on.
2. Make a run finish with the outcome FAIL, such as a library playbook run on a user or device that doesn't exist, or wait for a real failure.
3. Read this playbook's run under Playbooks > Executions. Its outcome names the ticket it opened, or why it skipped the run.
4. If nothing happens, check the trigger filter in the CEL Explorer against the failed run, and that the failed playbook isn't one this playbook skips.

## Rollback

Close or delete the tickets in Autotask PSA. Turn the playbook off to stop new ones.
