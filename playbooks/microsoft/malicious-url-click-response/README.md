# Malicious URL click response

Contains a user who clicked a link that Microsoft Defender for Office 365 judged malicious, and records what was done on the case.

## What it covers

| Step | How |
| --- | --- |
| Make a high-severity case from the detection, assigned to your team | An automatic case rule and a case template, set up in Sophos Fusion. SETUP.md has the settings. |
| Notify your team | Case email alerts, under Global Settings > Platform > Notification Settings |
| Disable the user and revoke their sign-in sessions | This playbook, through the Microsoft Graph API connector |
| Record the outcome on the case | This playbook adds a comment to the case |

## What it doesn't cover

- Creating the case. Sophos Fusion documents automatic case rules for that, not playbooks. On a Sophos MDR tenant, a case from your own rule is self-managed.
- Disabling a synced user in on-premises Active Directory. The comment flags synced users so you can disable them there.
- Checking what the user did after the click, talking to them, deleting the message, blocking the domain, enabling the account again and closing the case. Your team does these.
