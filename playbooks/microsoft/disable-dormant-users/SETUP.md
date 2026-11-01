# Set up Disable dormant users

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. The connections

You need a connection to each of two connectors Sophos manages, under Security Operations > Automations > Connectors:

- **LDAP (Taegis.LDAP), the Microsoft Active Directory/LDAP connector,** for on-premises and synced accounts. Deploy a Sophos data collector on your network, add the On-Premise Automation Connector application to it, and add the connection for on-premises use, as [Identity response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/ITDR/ITDRResponseActions/) says. It signs in over LDAPS with an account that can disable users. Set BaseDN to the domain root, such as `DC=corp,DC=example,DC=com`, because the connector doesn't find users outside it.
- **Microsoft Graph API (Taegis.MicrosoftGraphAPI)** for cloud-only accounts. Its app needs the User.Read.All and User.EnableDisableAccount.All application permissions.

Use Test on each connection.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Identity Findings, event Created only. Posture checks update their findings several times a day, so Updated would run the playbook over and over.
- **When does this playbook run?** Only When, with this CEL:

  ```
  inputs.identityFindings.new.check.category.toLower() == 'dormant_resource' && inputs.identityFindings.new.primaryReference.derivedType == 'USER'
  ```

- **Connections:** the LDAP connection and the Microsoft Graph API connection.
- **Domains:** the user principal name domains in scope, such as `example.com`. With none, the playbook disables nothing.
- **Excluded users:** break-glass and emergency access accounts, service accounts, and anyone else who must stay enabled. Give a user principal name, sAMAccountName or email address. Matches ignore case.
- **ITDR checks:** leave the defaults, Dormant Accounts (90 days) and AD enabled user accounts shall not be dormant without hybrid activity (180 days, Active Directory). To add a check such as Dormant Guests, copy its title from Identity Settings > Posture Check Preferences.
- **Disable in Active Directory** and **Disable in Entra ID:** turn off a directory you don't have. With Active Directory off, synced users are reported, not disabled, because Entra Connect Sync would undo an Entra ID disable.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Leave it for a day. ITDR runs its dormant checks every 2 hours, and each new dormant finding starts one run.
3. Read each run under Playbooks > Executions. The outcome names the user and the directory it would disable them in, or says why it skipped them.
4. Add anyone who must stay enabled to Excluded users.
5. Only then turn off dry run.

Findings that already exist when you turn the playbook on don't start a run. To act on those, filter the Directory on Is Dormant and use the response actions by hand.

## Rollback

Enable the account again where the playbook disabled it: in Active Directory with `Enable-ADAccount` or the Enable User Microsoft LDAP template, or in Entra ID with the Microsoft Entra ID Enable User template or the Entra admin center. Then add the user to Excluded users so a later finding doesn't disable them again.
