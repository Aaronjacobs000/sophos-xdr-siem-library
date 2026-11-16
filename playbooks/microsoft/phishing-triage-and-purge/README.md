# Phishing triage and purge

Finds every copy of a phishing email in your Microsoft 365 mailboxes, checks it, moves the copies out of the users' folders and records it all on the case.

## What it covers

| Step | How |
| --- | --- |
| Find the email | From the case's email detections, or the Internet message ID you give it |
| Find every copy | The recipients on the email and in the detections, every mailbox in your domains, and Defender advanced hunting where the tenant has it |
| Triage it | Sender, Reply-To, SPF, DKIM, DMARC, Microsoft's spam verdict, attachments and link domains, from one copy |
| Pull it from the mailboxes | Move each copy to Recoverable Items (or Deleted Items or Junk Email), then check again |
| Show what happened | A case comment with the triage, each mailbox and what is left |
| Ask a person first, if you want that | Ask for approval first, off by default: a request on the case that someone approves in Teams or Slack, through the chat bridge and [Approval before acting](../approval-before-acting/) |

## What it doesn't cover

- Blocking the sender. The comment names them for Block Email Address or the Tenant Allow/Block List.
- Detonating links or attachments, and reputation lookups.
- Deleting mail, finding who clicked, talking to the users and closing the case. Your team does these.
