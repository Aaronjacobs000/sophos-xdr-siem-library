# Set up Slack case chat sync

A template carries no trigger, connections or settings, so you set them up once in your tenant. Leave the playbook off until a test run.

## 1. The Slack app and its connection

Create a Slack app for your workspace at the Slack API site, from scratch:

- Under Incoming Webhooks, turn them on and choose Add New Webhook to Workspace, then pick the channel. Copy the webhook URL.
- For the two-way buttons (step 5), also add the bot scope `chat:write` under OAuth & Permissions so the app gets a bot token, and note the signing secret under Basic Information.

In Sophos Fusion, add a connection to the Slack connector Sophos manages (Taegis.SalesforceSlack) under Security Operations > Automations > Connectors, with the webhook URL. Use Test on the connection: a test message arrives in the channel. You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, events Create, Update and Comment Added.
- **When does this playbook run?** Always, or a CEL filter of your own. Minimum severity and Managed by already scope it.
- **Connections:** the Slack connection and the Case connection.
- **Minimum severity** and **Managed by:** which cases reach the channel.
- **Bridge comment prefix:** leave it at `[chat-sync]`, the prefix the chat bridge writes.
- **Ignore comments by:** optionally, the subject ID of the chat bridge's API credential, as a second guard.
- **Two-way buttons:** off until the chat bridge works (step 5).
- **Status buttons:** the case status names to offer, which the bridge must also allow.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on and create a test case at or above the minimum severity.
2. Check that a message with the case's short ID arrives in the channel, and that Open in Sophos Fusion opens the case.
3. Change the case's status and add a comment, and check that each posts a message.

## 5. Two-way: act on cases from Slack

1. Deploy the [chat bridge](../../../chat-bridge/) as its README says, with the app's signing secret and bot token.
2. In the Slack app, turn on Interactivity and set the request URL to `https://<your bridge>/slack/interactivity`.
3. In the configured playbook, turn on Two-way buttons.
4. On the next message, use Set active, Close case or Add comment. Close case and Add comment open a form. The bridge replies to you in the channel, and the case gets a comment that names who acted.

## Rollback

None for posted messages. Turn the playbook off to stop posting, and turn off the app's interactivity to stop the two-way half.
