# Set up Malicious URL click response

The response has two parts. An automatic case rule makes a self-managed case from the detection, and this playbook disables the user and comments on that case. A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

## 1. Check the detection reaches Sophos Fusion

Microsoft raises the alert "A potentially malicious URL click was detected" when a user protected by Safe Links clicks a link that Microsoft judges malicious, including clicks in the 48 hours before the verdict. It needs Microsoft Defender for Office 365 Plan 2 or Microsoft 365 E5. See [Alert policies in the Microsoft Defender portal](https://learn.microsoft.com/en-us/defender-xdr/alert-policies).

The alert reaches Sophos Fusion through the [Microsoft Graph security API alerts v2](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Products/Microsoft365/GraphSecurityAPI/Setup/) integration. Find one on Security Operations > Detections and check three things:

- The title, exactly as shown. Use it in the rule and in Detection titles.
- The severity. [Automatic case rules](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Cases/AutomaticCases/) only act on medium and higher detections.
- The entities. The playbook reads the user principal name from `userName`, or from `targetUserName` when there's no `userName` with an @.

## 2. Make the case

Under Security Operations > Cases > Templates, create a [case template](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Cases/Templates/):

- Case type: Investigation on a Sophos MDR tenant, where only Investigation and Other cases can be self-managed. On a Sophos XDR tenant, the type you use for security cases.
- Case title: `Malicious URL click`
- Severity: High. Status: New. Assignee: your tenant or the user who works these cases.

Under Security Operations > Cases > Automatic Cases, choose New Rule:

- State: Test, until the rule logs show it matching what you expect. Then Enabled.
- Case template: the one above.
- Filter:

  ```
  from detection where title in ('A potentially malicious URL click was detected', 'A user clicked through to a potentially malicious URL')
  ```

- Detection grouping, with Criteria Count 1. It puts later clicks by the same user into the open case, and the suffix stops them being added to cases from other rules:

  ```
  ${alertUsernames(alert).map(u, u + ' malicious URL click')}
  ```

On a Sophos MDR tenant a case from your own rule is self-managed: your team works it, not Sophos MDR. Your tenant's rules run before rules set above it, evaluation stops at the first match, and the docs advise caution for MDR customers, so talk to the Sophos MDR team before you enable the rule. See [Cases in Sophos MDR](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/MDR/MDRInvestigations/MDRCases/).

Case email alerts go to every admin when a case is created. To send them to a team mailbox instead, add a custom rule under [Configure email alerts](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Cases/CaseEmailAlerts/). Your first custom rule stops the default emails to all admins.

## 3. The connections

You need a connection to each of three connectors Sophos manages, under Security Operations > Automations > Connectors:

- **Microsoft Graph API (Taegis.MicrosoftGraphAPI).** Add it from the Microsoft Graph API actions card in the Marketplace, as [Enable Microsoft 365 response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Products/Microsoft365/ResponseActions/) says. With your own app instead, it needs the User.Read.All, User.EnableDisableAccount.All and User.RevokeSessions.All application permissions.
- **Sophos Case (Taegis.Case) and Sophos Detection (Taegis.Alert).** If you don't have a connection to one, add it from the Connector Library. They sign in as the platform and need no credential.

Use Test on the Microsoft Graph API connection.

## 4. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 5. Configure the playbook

On the template, choose Use this Template, then set:

- **Trigger:** Platform Events, source Case, event Create.
- **When does this playbook run?** Only When, with this CEL. Match the title your case template sets:

  ```
  caseManagedBy(inputs) == 'CUSTOMER' && caseTitle(inputs).startsWith('Malicious URL click')
  ```

- **Connections:** the three connections above.
- **Domains:** the user principal name domains in scope, such as `example.com`. With none, the playbook disables nothing.
- **Excluded users:** break-glass accounts, service accounts and anyone else who must stay enabled.
- **Detection titles:** leave the defaults unless your detection's title differs.
- **Revoke sign-in sessions:** leave it on. Disabling a user stops new sign-ins, but an access token already issued works until it expires, by default an hour. See [Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access).
- **Max users per run:** 3. A case with more users in scope gets a comment and no disables.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

To act faster than the case, use source Alert2 (detections), event create, with `detectionTitle(inputs) in ['A potentially malicious URL click was detected', 'A user clicked through to a potentially malicious URL']`. The playbook then disables the user at once and comments on the detection's case if one exists within Seconds to wait for the case. Detection triggers only run for high and critical detections.

## 6. Test it

1. Turn on the playbook with dry run still on, and set the rule to Enabled.
2. When the next detection makes a case, read the playbook's comment on it and the run under Playbooks > Executions.
3. Turn off dry run when the comments say what you expect.

## Hybrid identity

If Microsoft Entra Connect Sync syncs the user from on-premises Active Directory, the next sync can enable the account again. The comment flags synced users. Disable them in Active Directory too, by hand or with an on-premises LDAP response action, as [Identity response actions](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/ITDR/ITDRResponseActions/) explains.

## Rollback

Enable the user again in the Entra admin center or with the Microsoft Entra ID Enable User template, and in Active Directory for a synced user. Revoked sessions stay revoked, so the user signs in again. To stop the automation, turn off the playbook and set the rule to Disabled.
