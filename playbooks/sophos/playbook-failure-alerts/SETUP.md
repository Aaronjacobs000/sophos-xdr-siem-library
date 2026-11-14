# Set up Playbook failure alerts

A template carries no trigger, connections or settings, so you set them up once in your tenant. Leave the playbook off until a test run.

## 1. The chat connection

The playbook posts through Sophos Fusion's Send Notification Message interface, so it needs a connection for the chat tool you use, under Security Operations > Automations > Connectors:

- **Microsoft Teams (Taegis.MicrosoftTeams):** in Teams, add the Workflows template Send webhook alerts to a channel, and use its webhook URL as the connection's Workflow Webhook URL. Set Adaptive Card Version to 1.4 or later.
- **Slack (Taegis.SalesforceSlack):** your Slack app's incoming webhook URL.
- **Google Chat (Taegis.GoogleChatWebhook):** the space's webhook URL.

Use Test on the connection.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Playbook Execution, events failed and completed.
- **When does this playbook run?** Only When, with this CEL. It leaves out runs that a Playbook Execution event started and the playbook failure and notification playbooks, so nothing loops, and keeps only failed runs and runs with the outcome FAIL:

  ```
  inputs.execution.triggerContext != 'execution' && !string(inputs.execution.template.name).startsWith('Unofficial_PlaybookFailure_') && !string(inputs.execution.template.name).startsWith('Taegis.Send_Notification_Message') && (inputs.event == 'failed' || inputs.execution.outcomeStatus == 'FAIL')
  ```
- **Send Notification Message Interface:** pick Send Notification Message Microsoft Teams, Send Notification Message Salesforce Slack or Send Notification Message Google Workspace Chat, and the connection from step 1. Add more than one to post to each.
- **Alert on a FAIL outcome:** on. Many playbooks catch their own errors and finish with the outcome FAIL instead of failing.
- **Playbooks to watch:** leave it empty to cover every playbook, or list the configured playbooks or template names to cover only those.
- **Playbooks to ignore:** configured playbooks or template names never to report, such as one that fails by design.
- **Error length:** 1000 characters unless you change it.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

For health events, choose Use this Template again and set the trigger to Platform Events, source Health, event create, with Only When:

```
inputs.health.name in ['Collector Down', 'Collector Warning', 'Collector health status Alert', 'Collector Endpoint Certificate Expiration Alert', 'Data Sources Alert']
```

These are the health event names Sophos Fusion's Health Event Case template lists. Remove any you don't want, and leave out Collector scheduled maintenance alert unless you want planned work reported. Use the same settings as the first one.

## 4. Test it

1. Turn the playbook on.
2. Make a run finish with the outcome FAIL, such as a library playbook run on a user or device that doesn't exist, or wait for a real failure.
3. Read this playbook's run under Playbooks > Executions. Its outcome says what it sent, or why it skipped the run.
4. If nothing happens, check the trigger filter in the CEL Explorer against the failed run, and that the failed playbook isn't one this playbook skips.

## Rollback

None for posted messages. Turn the playbook off to stop posting.
