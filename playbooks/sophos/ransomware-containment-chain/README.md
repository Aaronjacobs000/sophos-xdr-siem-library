# Ransomware containment chain

Contains a Critical ransomware or hands-on-keyboard detection in one run, and comments a timeline of what it did on the case.

## What it covers

| Step | How | Needs |
| --- | --- | --- |
| Cut the host off | Isolate each Sophos endpoint the detections name. Servers only if you turn that on | Sophos Endpoint |
| Harden the host and its neighbors | Adaptive Attack Protection for 24 hours, on the host and the rest of its device group | Sophos Endpoint |
| Lock the user out | Revoke the user's sign-in sessions and require a password change at the next sign-in | Microsoft 365 and a Microsoft Graph API connection |
| Stop the file running elsewhere | Block the SHA-256 hashes, for the whole tenant | Sophos Endpoint |
| Keep the evidence | Ask each device for its forensic logs | A forensic snapshot S3 bucket, Windows, XDR or MDR |
| Wake someone up | Page on-call in Teams, Slack or Google Chat | A chat connection |
| Show what happened | A timeline on the case: each step, its time and outcome | |
| Ask a person first, if you want that | Ask for approval first holds the isolation and the user steps for [Approval before acting](../../microsoft/approval-before-acting/) | The chat bridge |

Without Microsoft 365, use [Ransomware containment chain without Microsoft 365](../ransomware-containment-chain-without-microsoft-365/).

## What it doesn't cover

- A PSA ticket. The library's Autotask PSA and ConnectWise PSA case syncs copy the timeline comment to the case's ticket.
- Resetting the user's password to a random one, inbox rules and Entra ID risk. Run [Microsoft 365 account takeover cleanup](../../microsoft/microsoft-365-account-takeover-cleanup/) for those.
- Users only in on-premises Active Directory.
