# Set up Teams case chat sync

A template carries no trigger, connections or settings, so you set them up once in your tenant. Leave the playbook off until a test run.

## 1. The Teams webhook and its connection

In Teams, open Apps, find the Workflows template Send webhook alerts to a channel, pick the team and channel, and choose Add workflow. Copy the webhook URL it gives you.

In Sophos Fusion, add a connection to the Microsoft Teams connector Sophos manages (Taegis.MicrosoftTeams) under Security Operations > Automations > Connectors:

- **Workflow Webhook URL:** the URL from Teams.
- **Adaptive Card Version:** 1.4 or later.

Use Test on the connection: a test card arrives in the channel. You also need a connection to the Case connector Sophos manages (Taegis.Case), which signs in with the platform.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, events Create, Update and Comment Added.
- **When does this playbook run?** Always, or a CEL filter of your own. Minimum severity and Managed by already scope it.
- **Connections:** the Teams connection and the Case connection.
- **Minimum severity** and **Managed by:** which cases reach the channel.
- **Bridge comment prefix:** leave it at `[chat-sync]`, the prefix the chat bridge writes.
- **Ignore comments by:** optionally, the subject ID of the chat bridge's API credential, as a second guard.
- **Bridge name:** the name of your outgoing webhook (step 5), or empty if you don't run the bridge.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on and create a test case at or above the minimum severity.
2. Check that a card with the case's short ID arrives in the channel, and that Open in Sophos Fusion opens the case.
3. Change the case's status and add a comment, and check that each posts a card.

## 5. Two-way: act on cases from Teams

Teams cards from a Workflows webhook can't send button clicks back, so the two-way half uses a Teams outgoing webhook and the [chat bridge](../../../chat-bridge/) in this repo:

1. Deploy the chat bridge as its README says.
2. In Teams, open the team's Manage team > Apps and choose Create an outgoing webhook. Name it as Bridge name, such as Fusion, and set the callback URL to `https://<your bridge>/teams/outgoing`.
3. Copy the security token Teams shows into the bridge's `TEAMS_HMAC_SECRET`.
4. In the channel, reply with `@Fusion active CSE00042`, `@Fusion close CSE00042 false_positive test box` or `@Fusion comment CSE00042 called the user`. The bridge answers in the thread, and the case gets a comment that names who acted.

Outgoing webhooks work in standard channels only, and only when someone @mentions them.

## Rollback

None for posted cards. Turn the playbook off to stop posting, and remove the outgoing webhook to stop the two-way half.
