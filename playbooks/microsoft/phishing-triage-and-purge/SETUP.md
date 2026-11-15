# Set up Phishing triage and purge

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connections

You need a connection to each of three connectors Sophos manages, under Security Operations > Automations > Connectors:

- **Microsoft Graph API (Taegis.MicrosoftGraphAPI).** Add it from the Microsoft Graph API actions card in the Marketplace, as [Enable Microsoft 365 response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Products/Microsoft365/ResponseActions/) says. That connection did every step in testing. With your own app instead, give it these application permissions: User.Read.All, Mail.ReadWrite, and ThreatHunting.Read.All if you keep Search with Defender advanced hunting on.
- **Sophos Case (Taegis.Case) and Sophos Detection (Taegis.Alert).** If you don't have a connection to one, add it from the Connector Library. They sign in as the platform and need no credential.

Use Test on the Microsoft Graph API connection.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template. Pick one trigger per configured playbook; to use two, configure the template twice.

- **Trigger, from a case:** User Initiated, a Response Action on Case. An analyst runs it from a case whose detections name the email, such as a Microsoft Defender for Office 365 alert or a Sophos Email detection. It takes the Internet message ID, the sender and the recipients from them.
- **Trigger, by hand on an email:** Generic Trigger. Run it from the configured playbook with More Actions > Manually Trigger, and fill in Internet message ID (the email's Message-ID header), and optionally Case and Mailboxes to search.
- **Trigger, from an automatic case rule:** Platform Events, source Case, event Create, with Only When set to the title your case template gives phishing cases:

  ```
  caseManagedBy(inputs) == 'CUSTOMER' && caseTitle(inputs).startsWith('Phishing')
  ```

  This one runs with no analyst, so pick the rule's detections with care, and leave dry run on until its comments look right.
- **Connections:** the three connections above.
- **Domains:** the mailbox domains in scope, such as `example.com`. With none, the playbook does nothing.
- **Excluded mailboxes:** mailboxes it must never search or change, such as a report mailbox you keep as evidence.
- **Move copies to:** `recoverableitemsdeletions` (Recoverable Items, the default), `deleteditems` or `junkemail`. Recoverable Items takes the email out of the user's folders and leaves it recoverable; the other two leave it where the user still sees it.
- **Search every mailbox in Domains:** on. It finds copies sent by Bcc or to a group. Microsoft Graph returns the first 100 mailboxes per domain, and the comment says when a domain has more.
- **Search with Defender advanced hunting:** on. It finds every recipient where the tenant has Microsoft Defender for Office 365 Plan 2 or Microsoft 365 E5. Without it the playbook says so in the comment and searches the other mailboxes.
- **Max mailboxes per run:** 20. A run with copies in more mailboxes moves none and lists them.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Run it by hand on a harmless email in a test mailbox, with Case set to a test case, or run it from a test case.
3. Read the comment on the case, or the run under Playbooks > Executions. It lists the triage, each mailbox with a copy and what it would move.
4. Turn off dry run when the comments say what you expect.

## What it doesn't do

- Block the sender. The comment names them: use Block Email Address on the case, or the Tenant Allow/Block List in Microsoft Defender.
- Detonate links or attachments, or look up their reputation. The comment lists the link domains to check.
- Delete anything. Recoverable Items keeps every copy until your retention settings remove it.

## Rollback

A user gets a copy back from Recoverable Items with Recover Deleted Items in Outlook, or an admin moves it back. Copies moved to Deleted Items or Junk Email can be moved back by hand. The comment names each mailbox. To stop the automation, turn off the playbook.
