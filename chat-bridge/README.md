# Chat bridge for Sophos Fusion cases (unofficial)

> **Unofficial, and not yet run against a real Slack workspace or Teams team.** It has run in the Cloudflare Workers runtime against a real Sophos Fusion tenant in dry run, where it found cases, checked statuses and verdicts and reported the exact change and comment it would write. Its unit tests sign requests the way Slack and Microsoft document, including Slack's own published example. A live write to a case through the bridge is untested: on the test day the Sophos Fusion Cases API refused to create a test case to write to. Run it with dry run on first.

Sophos Fusion playbooks can post a case to Teams or Slack, but nothing in a playbook can receive a reply. This bridge takes a Slack button or form, or a Teams outgoing webhook command, checks that the request came from Slack or Teams, and sets the case status or adds a case comment through the Sophos Fusion Cases API. Every write adds a case comment that names the person who acted.

It pairs with two playbooks in this library, which post the cases it acts on:

- [Teams case chat sync](../playbooks/microsoft/teams-case-chat-sync/): a card for each new or changed case, with the commands to reply with.
- [Slack case chat sync](../playbooks/slack/slack-case-chat-sync/): a message for each new or changed case, with Set status, Close case and Add comment buttons.

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
| Set a status | `@Fusion active CSE00042 [note]` | Set active, Set awaiting action | `updateCase` with the status, then `addCaseComment` |
| Close | `@Fusion close CSE00042 <verdict> [note]` | Close case, then a form with the verdict and why | `updateCase` with the closed status, verdict and close reason, then `addCaseComment` |
| Comment | `@Fusion comment CSE00042 <text>` | Add comment, then a form | `addCaseComment` |

A case is its short ID, such as CSE00042, or its ID. The bridge only sets the statuses in `BRIDGE_ALLOWED_STATUSES` and the verdicts in `BRIDGE_ALLOWED_VERDICTS`. It refuses to change the status of a case Sophos MDR manages, since a customer can't do that in Sophos Fusion either, and it refuses any change to a closed case. A comment it writes reads like `[chat-sync] Jane Analyst via Teams set the status to Active: looking now`.

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
| `BRIDGE_ALLOWED_STATUSES` | var | Status names the bridge may set. Defaults to `active,awaiting_action,closed`. |
| `BRIDGE_ALLOWED_VERDICTS` | var | Verdict names a close may use. |
| `BRIDGE_COMMENT_PREFIX` | var | The start of every comment the bridge writes. Defaults to `[chat-sync]`; keep it the same as the playbooks' Bridge comment prefix. |
| `BRIDGE_DRY_RUN` | var | `1` to check and answer without writing. |
| `SLACK_ALLOWED_USERS` | var | Comma-separated Slack user IDs who may act. Empty lets everyone who can click. |
| `SLACK_TEAM_ID` | var | Refuse requests from any other Slack workspace. |
| `TEAMS_ALLOWED_USERS` | var | Comma-separated Microsoft Entra object IDs who may act. Empty lets everyone in the team. |
| `TEAMS_TENANT_ID` | var | Refuse requests from any other Microsoft 365 tenant. |

## Logs

Each action logs one JSON line with the time, platform, user ID and name, action, case and result. With `[observability]` on they are in Workers Logs; `wrangler tail` shows them live. Rejected requests log why. Secrets and tokens never reach the log.

## Limits

- Teams waits five seconds. A first request after the Worker starts takes about three, to sign in to Sophos; if the bridge runs past four seconds it answers that it is still working and finishes the change. The case comment, and the playbook's next card, show the result.
- Teams outgoing webhooks only work in standard channels, and only when someone @mentions them.
- Slack forms must open within three seconds of the click, so the bridge opens them before it answers Slack.
- The bridge keeps nothing between requests except the Sophos sign-in token in memory.

## Tests

```bash
node --test test/chat-bridge.test.mjs
```

The tests run the Worker in Node against a mocked Sophos Fusion and Slack: signatures (with Slack's published example), commands, the status, close and comment writes and their comment text, allowlists, Sophos MDR and closed cases, dry run, the Teams time budget, and the response URL check.
