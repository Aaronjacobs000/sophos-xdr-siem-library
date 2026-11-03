# Set up Disable dormant users

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connection

You need one connection, to the **Microsoft Graph API (Taegis.MicrosoftGraphAPI)** connector Sophos manages, under Security Operations > Automations > Connectors. Its app needs the User.Read.All and User.EnableDisableAccount.All application permissions. Use Test on the connection.

This playbook disables cloud-only accounts. For accounts in on-premises Active Directory, synced or not, also set up [Disable dormant users in Active Directory](../../../playbooks/microsoft/disable-dormant-users-in-active-directory/), which needs only the LDAP connection.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Identity Findings, event Created only. Posture checks update their findings several times a day, so Updated would run the playbook over and over.
- **When does this playbook run?** Only When, with this CEL:

  ```
  inputs.identityFindings.new.check.category.toLower() == 'dormant_resource' && inputs.identityFindings.new.primaryReference.derivedType == 'USER'
  ```

- **Connections:** the Microsoft Graph API connection.
- **Domains:** the user principal name domains in scope, such as `example.com`. With none, the playbook disables nothing.
- **Excluded users:** break-glass and emergency access accounts, service accounts, and anyone else who must stay enabled. Give a user principal name, sAMAccountName or email address. Matches ignore case.
- **ITDR checks:** leave the default, Dormant Accounts (90 days). To add a check such as Dormant Guests, copy its title from Identity Settings > Posture Check Preferences. The Active Directory check's findings are for Disable dormant users in Active Directory.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Leave it for a day. ITDR runs its dormant checks every 2 hours, and each new dormant finding starts one run.
3. Read each run under Playbooks > Executions. The outcome names the user it would disable, or says why it skipped them. A user synced from Active Directory is skipped.
4. Add anyone who must stay enabled to Excluded users.
5. Only then turn off dry run.

Findings that already exist when you turn the playbook on don't start a run. To act on those, filter the Directory on Is Dormant and use the response actions by hand.

## Rollback

Enable the account again in Entra ID, with the Microsoft Entra ID Enable User template or the Entra admin center. Then add the user to Excluded users so a later finding doesn't disable them again.
