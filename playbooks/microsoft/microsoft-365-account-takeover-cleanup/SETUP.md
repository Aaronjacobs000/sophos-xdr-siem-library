# Set up Microsoft 365 account takeover cleanup

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connections

You need a connection to each of three connectors Sophos manages, under Security Operations > Automations > Connectors:

- **Microsoft Graph API (Taegis.MicrosoftGraphAPI).** Add it from the Microsoft Graph API actions card in the Marketplace, as [Enable Microsoft 365 response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Products/Microsoft365/ResponseActions/) says. That connection did every step in testing. With your own app instead, give it these application permissions: User.Read.All, User.RevokeSessions.All, User-PasswordProfile.ReadWrite.All, MailboxSettings.ReadWrite, IdentityRiskyUser.ReadWrite.All, and User.EnableDisableAccount.All if you turn on Disable account.
- **Sophos Case (Taegis.Case) and Sophos Detection (Taegis.Alert).** If you don't have a connection to one, add it from the Connector Library. They sign in as the platform and need no credential.

Use Test on the Microsoft Graph API connection. Microsoft Graph refuses a password change on an admin unless the app holds an admin role of its own, so admins get a failed step in the comment.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template. Pick one trigger per configured playbook; to use two, configure the template twice.

- **Trigger, from Sophos ITDR:** Platform Events, source Identity Findings, event Created only, with When does this playbook run? set to Only When:

  ```
  inputs.identityFindings.new.check.category.toLower() == 'credential_leak' && inputs.identityFindings.new.primaryReference.derivedType == 'USER'
  ```

  Don't add Updated: posture checks update findings often, and each update would run the cleanup again.
- **Trigger, from a detection:** Platform Events, source Alert2, event create, with Only When:

  ```
  detectionTitle(inputs) in ['Suspicious email forwarding activity', 'User restricted from sending email', 'Suspicious inbox forwarding', 'Suspicious inbox manipulation rule', 'Suspicious inbox manipulation rules', 'Leaked credentials']
  ```

  Check the titles on your Detections page and change both this list and Detection titles to match. Detection triggers only run for high and critical detections.
- **Trigger, by hand:** User Initiated, a Response Action on Case. An analyst runs it from the case, and it acts on the users in all of the case's detections.
- **Connections:** the three connections above.
- **Domains:** the user principal name domains in scope, such as `example.com`. With none, the playbook acts on no one.
- **Excluded users:** break-glass accounts, service accounts and anyone else it must never touch.
- **Steps:** Revoke sign-in sessions, Require a password change, Turn off inbox rules and Confirm compromised are on; Disable account is off. Turn off Confirm compromised if you don't have Microsoft Entra ID P2.
- **Max users per run:** 1. A run with more users in scope acts on none and says so.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Run it by hand from a test case whose detection names a test user, or wait for a finding or detection.
3. Read the comment on the case, or the run under Playbooks > Executions for a finding. It lists the inbox rules and what the playbook would do.
4. Turn off dry run when the comments say what you expect.

## Hybrid identity

If Microsoft Entra Connect Sync syncs the user from on-premises Active Directory, the next sync can undo changes made in Entra ID. The comment flags synced users: disable them and reset their password in Active Directory too, by hand or with an on-premises LDAP response action, as [Identity response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/ITDR/ITDRResponseActions/) explains.

## What it doesn't clean up

MFA methods the attacker registered, OAuth apps the user consented to, and mailbox forwarding set in Exchange Online (forwardingSmtpAddress) are outside the Microsoft Graph API connector. Check them by hand, as [Respond to a compromised email account](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account) lists.

## Rollback

Turn the inbox rules back on in Outlook or Exchange; the comment names each one. Enable the account if Disable account was on, and dismiss the user's risk in Entra ID. Revoked sessions stay revoked, so the user signs in again. To stop the automation, turn off the playbook.
