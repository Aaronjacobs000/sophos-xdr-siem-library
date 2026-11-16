# Microsoft 365 account takeover cleanup

Cleans up a taken-over Microsoft 365 account in one run, and records the inbox rules before and after on the case.

## What it covers

| Step | How |
| --- | --- |
| Take the password away from the attacker | Reset it to a random one that nobody sees. The user gets a new one from your helpdesk or self-service password reset |
| End the attacker's sessions | Revoke sign-in sessions |
| Make the user set a new password | Require a password change at the next sign-in |
| Remove the usual persistence | Turn off inbox rules that forward, redirect or delete mail |
| Raise the user's risk in Entra ID Protection | Confirm compromised. It needs Entra ID P2 in the tenant, not on the user: with P2 anywhere in the tenant every user is confirmed, even one with only P1. Only in a tenant with no P2 does the playbook skip this step and say so on the case |
| Lock the account, if you want that | Disable account, off by default |
| Show what changed | A case comment with the inbox rules before and after |
| Ask a person first, if you want that | Ask for approval first, off by default: a request on the case that someone approves in Teams or Slack, through the chat bridge and [Approval before acting](../approval-before-acting/) |

## What it doesn't cover

- MFA methods, OAuth app consents and mailbox forwarding set in Exchange Online. The Microsoft Graph API connector can't reach them.
- Disabling a synced user in on-premises Active Directory. The comment flags synced users.
- Finding out what the attacker read or sent, talking to the user and closing the case. Your team does these.
