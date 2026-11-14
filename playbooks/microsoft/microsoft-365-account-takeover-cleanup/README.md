# Microsoft 365 account takeover cleanup

Cleans up a taken-over Microsoft 365 account in one run, and records the inbox rules before and after on the case.

## What it covers

| Step | How |
| --- | --- |
| End the attacker's sessions | Revoke sign-in sessions |
| Make the user set a new password | Require a password change at the next sign-in. It doesn't change the password itself, so whoever signs in next with it sets the new one; MFA is what stops an attacker there |
| Remove the usual persistence | Turn off inbox rules that forward, redirect or delete mail |
| Raise the user's risk in Entra ID Protection | Confirm compromised, which needs Entra ID P2 |
| Lock the account, if you want that | Disable account, off by default |
| Show what changed | A case comment with the inbox rules before and after |

## What it doesn't cover

- MFA methods, OAuth app consents and mailbox forwarding set in Exchange Online. The Microsoft Graph API connector can't reach them.
- Disabling a synced user in on-premises Active Directory. The comment flags synced users.
- Finding out what the attacker read or sent, talking to the user and closing the case. Your team does these.
