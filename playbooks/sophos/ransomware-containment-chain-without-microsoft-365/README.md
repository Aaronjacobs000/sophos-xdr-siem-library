# Ransomware containment chain without Microsoft 365

The [Ransomware containment chain](../ransomware-containment-chain/) for tenants without Microsoft 365: everything but the user step, with no Microsoft Graph API connection.

## What it covers

| Step | How | Needs |
| --- | --- | --- |
| Cut the host off | Isolate each Sophos endpoint the detections name. Servers only if you turn that on | Sophos Endpoint |
| Harden the host and its neighbors | Adaptive Attack Protection for 24 hours, on the host and the rest of its device group | Sophos Endpoint |
| Stop the file running elsewhere | Block the SHA-256 hashes, for the whole tenant | Sophos Endpoint |
| Keep the evidence | Ask each device for its forensic logs | A forensic snapshot S3 bucket, Windows, XDR or MDR |
| Wake someone up | Page on-call in Teams, Slack or Google Chat | A chat connection |
| Show what happened | A timeline on the case: each step, its time and outcome | |

## What it doesn't cover

- A PSA ticket. The library's Autotask PSA and ConnectWise PSA case syncs copy the timeline comment to the case's ticket.
- Locking the user out. The Microsoft 365 version does that.
- Asking for approval first, since Approval before acting needs a Microsoft Graph API connection.
