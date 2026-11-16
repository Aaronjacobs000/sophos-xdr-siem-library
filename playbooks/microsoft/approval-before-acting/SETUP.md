# Set up Approval before acting

This one needs the [chat bridge](../../../chat-bridge/). Teams and Slack case chat sync give you full cards with no bridge, but an approval only reaches the case through it.

Four pieces work together, and you set up each once:

1. The chat bridge, which carries the answer from Teams or Slack to the case.
2. Teams case chat sync 1.3.0 or Slack case chat sync 1.1.0, which posts the request to the channel.
3. Microsoft 365 account takeover cleanup 1.2.0 or Phishing triage and purge 1.1.0, with Ask for approval first on, which writes the request in place of acting.
4. This playbook, which runs the request once someone approves it.

## 1. The chat bridge

Deploy it as its README says, with a Sophos Fusion API credential in this tenant. For Teams, create the outgoing webhook; for Slack, set the Slack app's interactivity URL to the bridge.

Write down the API credential's client ID, from Global Settings > API Credentials. Sophos Fusion records it as the author of every comment the bridge writes, and this playbook trusts only decisions with that author.

## 2. Post requests to the channel

Use Teams case chat sync 1.3.0 or Slack case chat sync 1.1.0, set up as its SETUP.md says, with Comment Added in its trigger. Either one posts an approval request as Approval needed even when the case is below its Minimum severity or outside Managed by, and even with Post comments off.

- Teams: set Bridge name to your outgoing webhook's name. The request itself carries the reply lines.
- Slack: turn on Two-way buttons. The message gets Approve and Deny buttons, and Approve asks to confirm.

## 3. Ask for approval in the playbooks that act

In each configured Microsoft 365 account takeover cleanup or Phishing triage and purge playbook you want held:

- **Ask for approval first:** on.
- **Approval window (hours):** how long a request stays open, 4 by default, 1 to 72.
- **Bridge name:** your outgoing webhook's name, for the reply line, Fusion by default.
- **Dry run:** off. With dry run on, the playbook only records what it would do and asks nothing.

A request needs a case. A takeover cleanup run from a Sophos ITDR finding has none, so with Ask for approval first on it does nothing and ends FAIL with a message that says why. Detection and case runs work.

## 4. Import this template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 5. Configure this playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, event Comment Added, with When does this playbook run? set to Only When:

  ```
  caseComment(inputs).contains('Approval decision: ')
  ```

  Without the filter it runs on every comment and skips all but decisions.
- **Connections:** the Microsoft Graph API connection the requesting playbooks use, and the Case connection.
- **Chat bridge author ID:** the client ID from step 1. With none set, nothing is trusted.
- **Bridge comment prefix:** the bridge's BRIDGE_COMMENT_PREFIX, `[chat-sync]` by default.
- **Allowed actions:** all seven by default. Take off any you never want run from chat.
- **Max actions per request:** 50. A request with more runs none.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 6. Test it

1. Turn this playbook on with dry run still on.
2. Run account takeover cleanup, with Ask for approval first on, on a test case whose detection names a test user. The case gets an approval request, and the channel gets an Approval needed card.
3. In Teams, reply `@Fusion approve CSE00042 AP-7K2M9QX4` with your case and request ID. The bridge answers in the thread.
4. The case gets a comment that names you and lists what would run.
5. Turn dry run off, run the cleanup again for a new request, and approve that one.

## What the comments look like

- The request, written by the requesting playbook: what it would do, the request ID, when it expires, the reply lines, and a block of `approval-` lines that this playbook reads. Don't edit it: an edited request is refused.
- The decision, written by the bridge: `[chat-sync] Approval decision: approve AP-7K2M9QX4 by Jane Analyst via Teams.`
- A short note from this playbook that it has the decision, starting with the bridge prefix so the chat sync playbooks don't post it.
- The outcome: approved with each action's result, denied, expired, already decided, or refused. The chat sync playbooks post it to the channel.

## Limits

- It reads the case's latest 100 comments, so a request with more than 100 comments after it is not found.
- To run a request once, it records the decision on the case, waits five seconds and reads the case again; an earlier decision wins. Two decisions written in the same second ran once in testing, but a read that lags more than five seconds could let both run. The bridge also refuses a second decision on a request it has already answered.
- A Teams reply can take more than four seconds when the bridge has to sign in first. The bridge then answers that it is still working and records the decision anyway.
- The chat sync playbooks post any comment that holds a request line, including one a person typed. This playbook refuses those, and its comment says so.

## Rollback

Enable the account if it was disabled, turn the inbox rules back on, dismiss the user's risk in Entra ID, and restore moved email from Recoverable Items. A password reset and revoked sessions can't be undone. To stop approvals, turn this playbook off: requests then stay unanswered and expire.
