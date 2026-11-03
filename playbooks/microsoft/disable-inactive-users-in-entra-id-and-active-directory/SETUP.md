# Set up Disable inactive users in Entra ID and Active Directory

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on.

## 1. The connections

This playbook is for tenants with Entra ID and on-premises Active Directory. You need a connection to each of two connectors Sophos manages, under Security Operations > Automations > Connectors:

- **Microsoft Graph API (Taegis.MicrosoftGraphAPI)** to find inactive users and disable cloud-only accounts. Its app needs the User.Read.All, AuditLog.Read.All, Directory.Read.All and User.EnableDisableAccount.All application permissions, with admin consent. Sign-in activity needs Microsoft Entra ID P1 or P2.
- **LDAP (Taegis.LDAP), the Microsoft Active Directory/LDAP connector,** for synced accounts. Deploy a Sophos data collector on your network, add the On-Premise Automation Connector application to it, and add the connection for on-premises use, as [Identity response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/ITDR/ITDRResponseActions/) says. It signs in over LDAPS with an account that can disable users. Set BaseDN to the domain root, such as `DC=corp,DC=example,DC=com`, because the connector doesn't find users outside it.

Use Test on each connection.

Sophos Fusion asks for a connection to each connector a template lists, so you can't save this playbook without both. For a tenant without on-premises Active Directory, use [Disable inactive users](../../../playbooks/microsoft/disable-inactive-users/) instead, which needs only the Microsoft Graph API connection. Don't run both, because they find the same users.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Generic Trigger, Playbook Usage Playbook Schedule.
- **Connections:** the Microsoft Graph API connection and the LDAP connection. Both are required.
- **Domains:** the user principal name domains in scope, as Entra ID shows them, such as `example.com`. With none, the playbook disables nothing.
- **Excluded users:** break-glass and emergency access accounts, service accounts, accounts that only run on-premises services, and anyone on long leave. Give a user principal name, sAMAccountName or email address. Matches ignore case.
- **Days without a sign-in:** 30 by default, and 14 or more.
- **Look-back days:** 7 by default. Set it to at least the days between runs.
- **Include users with no sign-in on record:** off by default. Turn it on to also disable accounts that have never signed in, or not since December 2023, when they're older than Days without a sign-in.
- **Max users per run:** 10 by default.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it, then turn it on with dry run still on. A playbook has to be on before you can schedule it.

## 4. Schedule it

1. Open the playbook and choose More Actions > Schedule Executions.
2. Name the schedule, and check the settings under Playbook Inputs.
3. Under Schedule Recurrence, set a daily run, such as `0 2 * * *` for 02:00, in your time zone.
4. Save it. The Schedules tab shows the next run.

## 5. Test it

1. Leave dry run on for a week of runs.
2. Read each run under Playbooks > Executions. The outcome names each user it would disable and where, each user it skipped and why, and how many more matched.
3. Add anyone who must stay enabled to Excluded users.
4. Only then turn off dry run.

## Rollback

Enable the account again where the playbook disabled it: in Active Directory with `Enable-ADAccount` or the Enable User Microsoft LDAP template, or in Entra ID with the Microsoft Entra ID Enable User template or the Entra admin center. Then add the user to Excluded users so a later run doesn't disable them again.

To stop the playbook, pause or delete its schedule on the Schedules tab, or turn the playbook off.
