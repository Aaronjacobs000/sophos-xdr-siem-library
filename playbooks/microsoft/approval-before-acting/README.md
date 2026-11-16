# Approval before acting

Holds the Microsoft 365 actions of account takeover cleanup and phishing triage and purge until someone approves them in Teams or Slack, then runs them once and records who approved them on the case.

It needs the library's [chat bridge](../../../chat-bridge/), which carries the approval back to the case. Teams and Slack case chat sync work without the bridge; this playbook doesn't.

## How a request gets approved

| Step | Who | What happens |
| --- | --- | --- |
| Ask | Account takeover cleanup 1.2.0 or Phishing triage and purge 1.1.0, with Ask for approval first on | Writes an approval request on the case: each action, its target, a request ID such as AP-7K2M9QX4, and when it expires. Changes nothing |
| Post | Teams case chat sync 1.3.0 or Slack case chat sync 1.1.0 | Posts the request to the channel as Approval needed, whatever its severity and managed-by filters say |
| Answer | Someone in the channel | Teams: `@Fusion approve CSE00042 AP-7K2M9QX4` or `deny`. Slack: Approve or Deny on the message |
| Record | The chat bridge | Checks the Teams or Slack signature and writes the decision on the case as its own API credential |
| Act | This playbook | Checks the decision and the request, then runs the actions once and comments the outcome and the approver |

## What it checks before it acts

| Check | Why |
| --- | --- |
| Sophos Fusion recorded the decision as written by the chat bridge's API credential | A decision typed in the console, or by any other credential, does nothing |
| A playbook wrote the request, on the same case, and nobody edited it | A request typed by a person is refused |
| The decision came before the request expired | An expired request runs nothing; the case gets a comment saying so |
| No earlier decision on the same request | A second approval, or an approval after a deny, runs nothing again |
| The case is open | A closed case runs nothing |

## What it doesn't cover

- Isolating a host. No library playbook isolates yet, and adding it here would make every user of this playbook add a Sophos Endpoint connection.
- Approving from the Sophos Fusion console. A person there can run the action directly.
- Reminders, escalation to a second approver, or more than one approval per request.
