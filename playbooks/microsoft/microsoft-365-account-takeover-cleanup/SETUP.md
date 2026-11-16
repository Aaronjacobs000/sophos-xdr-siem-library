# Set up Microsoft 365 account takeover cleanup

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connections

You need a connection to each of three connectors Sophos manages, under Security Operations > Automations > Connectors:

- **Microsoft Graph API (Taegis.MicrosoftGraphAPI).** Add it from the Microsoft Graph API actions card in the Marketplace, as [Enable Microsoft 365 response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Products/Microsoft365/ResponseActions/) says. That connection did every step in testing. With your own app instead, give it these application permissions: User.Read.All, User.RevokeSessions.All, User-PasswordProfile.ReadWrite.All, MailboxSettings.ReadWrite, IdentityRiskyUser.ReadWrite.All, and User.EnableDisableAccount.All if you turn on Disable account.
- **Sophos Case (Taegis.Case) and Sophos Detection (Taegis.Alert).** If you don't have a connection to one, add it from the Connector Library. They sign in as the platform and need no credential.

Leave the connection's **Password to use in response actions** setting at its default. It makes a new random password for each reset; a fixed value there would give every reset user that same password.

Use Test on the Microsoft Graph API connection. Microsoft Graph refuses a password reset or change on an admin unless the app holds an admin role of its own, so admins get a failed step in the comment.

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
- **Steps:** Reset the password, Revoke sign-in sessions, Require a password change, Turn off inbox rules and Confirm compromised are on; Disable account is off. Confirm compromised needs Microsoft Entra ID P2 in the tenant. Microsoft checks the tenant's license, not the user's, so with P2 anywhere in the tenant every user is confirmed, even one with only P1. Only in a tenant with no P2 at all does the playbook skip that step and say so on the case, so you can leave it on either way. Turn off Reset the password to only require a change at the next sign-in; with it on, the reset itself requires the change.
- **Max users per run:** 1. A run with more users in scope acts on none and says so.
- **Ask for approval first:** off. On, with dry run off, the run writes an approval request on the case in place of acting; see [Approval before acting](../approval-before-acting/SETUP.md). A finding run has no case, so it then does nothing. **Approval window (hours)** is 4 and **Bridge name** is your outgoing webhook's name.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Run it by hand from a test case whose detection names a test user, or wait for a finding or detection.
3. Read the comment on the case, or the run under Playbooks > Executions for a finding. It lists the inbox rules and what the playbook would do, including whether it would skip Confirm compromised for want of Entra ID P2.
4. Turn off dry run when the comments say what you expect.

## The new password

The reset sets a random password that nobody sees: the connector makes it, and the playbook keeps that request out of the execution log, so it isn't in the run, its log or the case. The user can't sign in until your helpdesk gives them a new password or they use self-service password reset. Check their MFA methods first, because an attacker who registered one can use self-service password reset too.

## Hybrid identity

If Microsoft Entra Connect Sync syncs the user from on-premises Active Directory, the next sync can undo changes made in Entra ID, and resetting a synced user's password in Entra ID needs password writeback. The comment flags synced users: disable them and reset their password in Active Directory too, by hand or with an on-premises LDAP response action, as [Identity response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/ITDR/ITDRResponseActions/) explains.

## What it doesn't clean up

MFA methods the attacker registered, OAuth apps the user consented to, and mailbox forwarding set in Exchange Online (forwardingSmtpAddress) are outside the Microsoft Graph API connector. Check them by hand, as [Respond to a compromised email account](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account) lists.

## Rollback

Turn the inbox rules back on in Outlook or Exchange; the comment names each one. Enable the account if Disable account was on, and dismiss the user's risk in Entra ID. Revoked sessions stay revoked and the old password can't be restored, so the user signs in with a new one. To stop the automation, turn off the playbook.
