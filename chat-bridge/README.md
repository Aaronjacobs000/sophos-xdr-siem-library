# Chat bridge for Sophos Fusion cases (unofficial)

> **Unofficial. Run with a real Teams outgoing webhook, not yet with a real Slack workspace.** On 2026-11-16 a comment sent from a real Teams channel's outgoing webhook landed on a test case in a Sophos Fusion tenant. Signed requests shaped like a Teams outgoing webhook's have set statuses, closed a case with a verdict, and approved and denied requests for the Approval before acting playbook, each read back on the case, and a bad signature got 401. The Slack path has run only in the unit tests, which sign requests the way Slack documents, including Slack's own published example. Run it with dry run on first.

Sophos Fusion playbooks can post a case to Teams or Slack, but nothing in a playbook can receive a reply. This bridge takes a Slack button or form, or a Teams outgoing webhook command, checks that the request came from Slack or Teams, and sets the case status, adds a case comment or records an approval decision through the Sophos Fusion Cases API. Every write adds a case comment that names the person who acted.

It's an optional add-on for two playbooks in this library, which post the cases it acts on and work fine without it:

- [Teams case chat sync](../playbooks/microsoft/teams-case-chat-sync/): a card for each new or changed case, with the commands to reply with.
- [Slack case chat sync](../playbooks/slack/slack-case-chat-sync/): a message for each new or changed case, with Set status, Close case and Add comment buttons.

[Approval before acting](../playbooks/microsoft/approval-before-acting/) needs it: approvals reach the case only through the bridge.

## How it works

```
Sophos Fusion case event
  -> playbook posts the case to Teams (Workflows webhook) or Slack (incoming webhook)
     -> someone replies in Teams (@Fusion close CSE00042 false_positive test box)
        or clicks a Slack button and fills in the form
        -> Teams or Slack calls the bridge, signed
           -> the bridge checks the signature, the user and the command,
              finds the case, sets its status or adds a comment, and answers in chat
              -> the case comment starts with [chat-sync], so the playbook doesn't post it back
```

| Route | Called by | What it checks |
| --- | --- | --- |
| `POST /slack/interactivity` | Your Slack app's interactivity request URL | `X-Slack-Signature`: HMAC-SHA256 with the app's signing secret over `v0:<timestamp>:<body>`, and a timestamp within five minutes |
| `POST /teams/outgoing` | A Teams outgoing webhook | `Authorization: HMAC ...`: HMAC-SHA256 of the body with the webhook's base64 security token |
| `GET /healthz` | Monitoring | Nothing; answers `ok` |

A request that fails its check gets 401 and reaches neither Sophos Fusion nor Slack.

### What it can do to a case

| Action | Teams | Slack | Sophos Fusion call |
| --- | --- | --- | --- |
| Set a status | `@Fusion in_progress CSE00042 [note]` | Set in progress, Set customer action required | `updateCase` with the status, then `addCaseComment` |
| Close | `@Fusion close CSE00042 <verdict> [note]` | Close case, then a form with the verdict and why | `updateCase` with the closed status, verdict and close reason, then `addCaseComment` |
| Comment | `@Fusion comment CSE00042 <text>` | Add comment, then a form | `addCaseComment` |
| Approve or deny a request | `@Fusion approve CSE00042 AP-7K2M9QX4`, `@Fusion deny CSE00042 AP-7K2M9QX4` | Approve or Deny on an Approval needed message | `caseComments`, then `addCaseComment` |

A case is its short ID, such as CSE00042 or E-01167, or its ID. The bridge only sets the statuses in `BRIDGE_ALLOWED_STATUSES` and the verdicts in `BRIDGE_ALLOWED_VERDICTS`. By default those are the statuses a Sophos MDR tenant's cases use: in_progress, customer_action_required and closed. A tenant without Sophos MDR uses active, awaiting_action and closed, so set `BRIDGE_ALLOWED_STATUSES` to `active,awaiting_action,closed` there. Where active and awaiting_action aren't allowed, active from an older Teams card and the Set active and Set awaiting action buttons on older Slack messages set in_progress and customer_action_required. It refuses to change the status of a case Sophos MDR manages, since a customer can't do that in Sophos Fusion either, and it refuses any change to a closed case. A comment it writes reads like `[chat-sync] Jane Analyst via Teams set the status to In Progress: looking now`.

### Approvals

An approval answers a request that a library playbook left on the case, such as account takeover cleanup with Ask for approval first on. The bridge looks for the request ID in the case's latest 100 comments and checks that it hasn't already written a decision for it. Then it writes one comment, `[chat-sync] Approval decision: approve AP-7K2M9QX4 by Jane Analyst via Teams.`, and answers in chat. It doesn't check expiry or who wrote the request, and it runs nothing: the [Approval before acting](../playbooks/microsoft/approval-before-acting/) playbook does those checks and runs the actions. That playbook trusts the decision because Sophos Fusion records it as written by the bridge's API credential, which nobody can do from the console. So keep that credential to the bridge alone.

### Why a Cloudflare Worker

Slack wants an answer within three seconds and Teams within five, the bridge holds one credential, and it has nothing to store. A Worker gives it an HTTPS address and a secret store with no server to patch, and the free plan covers a SOC channel's traffic. An Azure Function would work as well, but needs a subscription, a plan and a storage account before it answers its first request. The bridge is one file with no dependencies, so it moves to any JavaScript runtime that has `fetch` and Web Crypto.

## Before you start

- A Sophos Fusion API credential in the tenant whose cases you sync: Global Settings > Access Control > API Credentials. Writes need a role above Read-only; which role is the least that can update cases is untested, so try Service Principal Management first. One bridge serves one tenant. The credential's expiry is yours to track: Sophos Fusion removes an expired credential without warning.
- A Cloudflare account and `wrangler` (`npm install -g wrangler`).
- Slack: the Slack app from the Slack playbook's setup, with its signing secret and a bot token (the bot scope `chat:write` is enough; the token opens the forms).
- Teams: a team where you can create an outgoing webhook.

## Deploy

```bash
cd chat-bridge
wrangler deploy
wrangler secret put FUSION_CLIENT_ID
wrangler secret put FUSION_CLIENT_SECRET
wrangler secret put SLACK_SIGNING_SECRET     # Slack only
wrangler secret put SLACK_BOT_TOKEN          # Slack only
wrangler secret put TEAMS_HMAC_SECRET        # Teams only
```

`wrangler deploy` prints the bridge's address, such as `https://fusion-chat-bridge.<your subdomain>.workers.dev`. To serve it on your own domain instead, add a custom domain to the Worker in Cloudflare and set `workers_dev = false`.

Then point Slack and Teams at it:

- Slack: in the app's Interactivity & Shortcuts, turn on Interactivity and set the request URL to `https://<bridge>/slack/interactivity`.
- Teams: in the team, open Manage team > Apps > Create an outgoing webhook. Give it the name people will @mention, such as Fusion, and the callback URL `https://<bridge>/teams/outgoing`. Teams shows a security token once: run `wrangler secret put TEAMS_HMAC_SECRET` and paste it.

Test with dry run on, which is how `wrangler.toml` ships: the bridge finds the case and answers with what it would do, and writes nothing. Then set `BRIDGE_DRY_RUN = "0"` in `wrangler.toml` and run `wrangler deploy` again.

## Settings

Secrets go in with `wrangler secret put`; the rest are `[vars]` in `wrangler.toml`.

| Name | Kind | Meaning |
| --- | --- | --- |
| `FUSION_CLIENT_ID`, `FUSION_CLIENT_SECRET` | secret | The Sophos Fusion API credential. Required. |
| `SLACK_SIGNING_SECRET` | secret | The Slack app's signing secret. Required for Slack. |
| `SLACK_BOT_TOKEN` | secret | The Slack app's bot token, which opens the Close case and Add comment forms. |
| `TEAMS_HMAC_SECRET` | secret | The outgoing webhook's security token. Required for Teams. |
| `FUSION_TENANT_ID` | var | The tenant ID. Without it the bridge asks `whoami` once and keeps the answer. |
| `FUSION_API` | var | The Sophos Fusion GraphQL URL. Defaults to `https://api.taegis.sophos.com/graphql`; only hosts on `taegis.sophos.com` are accepted. |
| `BRIDGE_ALLOWED_STATUSES` | var | Status names the bridge may set. Defaults to `in_progress,customer_action_required,closed`, the statuses a Sophos MDR tenant's cases use; a tenant without Sophos MDR needs `active,awaiting_action,closed`. |
| `BRIDGE_ALLOWED_VERDICTS` | var | Verdict names a close may use. Defaults to a tenant without Sophos MDR's verdicts plus true_positive_benign and true_positive_malicious, which a Sophos MDR tenant uses. |
| `BRIDGE_COMMENT_PREFIX` | var | The start of every comment the bridge writes. Defaults to `[chat-sync]`; keep it the same as the playbooks' Bridge comment prefix. |
| `BRIDGE_DRY_RUN` | var | `1` to check and answer without writing. |
| `SLACK_ALLOWED_USERS` | var | Comma-separated Slack user IDs who may act. Empty lets everyone who can click. |
| `SLACK_TEAM_ID` | var | Refuse requests from any other Slack workspace. |
| `TEAMS_ALLOWED_USERS` | var | Comma-separated Microsoft Entra object IDs who may act. Empty lets everyone in the team. |
| `TEAMS_TENANT_ID` | var | Refuse requests from any other Microsoft 365 tenant. |

## Logs

Each action logs one JSON line with the time, platform, user ID and name, action, case and result. With `[observability]` on they are in Workers Logs; `wrangler tail` shows them live. Rejected requests log why. Secrets and tokens never reach the log.

## Limits

- Teams waits five seconds. A first request after the Worker starts takes about three, to sign in to Sophos; if the bridge runs past four seconds it answers that it is still working and finishes the change. The case comment, and the playbook's next card, show the result. A close makes five Sophos Fusion calls, so it can pass four seconds: in the 2026-10-22 test one took 4.2 seconds, got the still-working answer, and the case closed.
- Teams outgoing webhooks only work in standard channels, and only when someone @mentions them.
- Slack forms must open within three seconds of the click, so the bridge opens them before it answers Slack.
- The bridge keeps nothing between requests except the Sophos sign-in token in memory.

## Tests

```bash
node --test test/chat-bridge.test.mjs
```

The tests run the Worker in Node against a mocked Sophos Fusion and Slack: signatures (with Slack's published example), commands, the status, close, comment and approval writes and their comment text, allowlists, Sophos MDR and closed cases, dry run, the Teams time budget, and the response URL check.
