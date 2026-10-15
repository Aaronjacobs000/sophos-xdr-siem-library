# AI compliance log bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real ChatGPT Enterprise workspace, OpenAI API Platform organization, Claude Enterprise organization or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the vendors' published response shapes. Run it with `--dry-run` first and check what it would send.

OpenAI and Anthropic only offer their enterprise compliance logs through pull APIs. There is no syslog or push option, so a parser alone can't get them into Sophos NG-SIEM. This script polls the APIs, keeps a cursor for each one, and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. The library parsers then normalize them.

| Source (`BRIDGE_SOURCES`) | API | Library entry |
| --- | --- | --- |
| `openai_clp` | ChatGPT Enterprise Compliance Logs Platform: lists and downloads JSONL log files per event type | `parsers/openai/chatgpt-enterprise-compliance-logs` |
| `openai_audit` | OpenAI API Platform audit logs (`GET /v1/organization/audit_logs`) | `parsers/openai/api-platform-audit-logs` |
| `anthropic` | Claude Compliance API Activity Feed (`GET /v1/compliance/activities`) | `parsers/anthropic/claude-compliance-api-activity-feed` |

Python 3.9 or later, standard library only. One file: `ai_compliance_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the library parsers for your sources under Security Operations > Integrations > Custom Parsers, and use Run Test with your own records before you turn them on.

**ChatGPT Enterprise or Edu (`openai_clp`).** A workspace owner or admin creates an Admin key in the OpenAI Admin Console (Credentials > Admin keys) with Custom permissions. Grant only the log types you collect, for example Auth log and Audit log read. Only a workspace owner can grant Conversation messages. You need the workspace ID (or the API Platform organization ID, which starts with `org-`).

**OpenAI API Platform (`openai_audit`).** An organization owner turns on audit logging (organization settings > Data controls > Data retention > Audit logging; it can't be turned off again without OpenAI support) and creates an Admin key.

**Claude Enterprise or Claude Console (`anthropic`).** Claude Enterprise: the primary owner turns on the Compliance API in claude.ai (Organization settings > API) and creates a Compliance Access Key with only the `read:compliance_activities` scope. Standalone Claude Console organization: an admin turns on the Compliance API (Settings > Security), then creates a new Admin API key. Admin keys made before the Compliance API was turned on can't read the Activity Feed.

## Configuration

Everything comes from environment variables. Keep keys in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `BRIDGE_SOURCES` | every source with a key | Comma-separated: `openai_clp`, `openai_audit`, `anthropic`. |
| `BRIDGE_STATE_FILE` | `ai_compliance_state.json` | Cursors and recently seen IDs. |
| `BRIDGE_REDACT` | `1` | Content redaction. `0` turns it off (see Privacy). |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_OVERLAP_SECONDS` | `300` | How much of the previous window each run re-reads, to catch late events. Repeats are dropped by ID. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |
| `OPENAI_COMPLIANCE_API_KEY` | none | ChatGPT workspace Admin key with Compliance Logs Platform read scopes. |
| `OPENAI_CLP_PRINCIPAL_ID` | none | Workspace ID, or API Platform organization ID (`org-...`). |
| `OPENAI_CLP_EVENT_TYPES` | `AUTH_LOG,AUDIT_LOG` | Log types to download. Add `CONVERSATION_MESSAGE` only if you need it. |
| `OPENAI_ADMIN_KEY` | none | API Platform Admin key for audit logs. |
| `ANTHROPIC_COMPLIANCE_KEY` | none | Compliance Access Key or Admin API key, sent as `x-api-key`. |
| `ANTHROPIC_ACTIVITY_TYPES` | all | Optional comma-separated activity types to collect. |
| `ANTHROPIC_ORGANIZATION_IDS` | all | Optional comma-separated organization IDs. |
| `ANTHROPIC_SETTLE_SECONDS` | `60` | Each window stops this far before now; Anthropic indexes activity within a minute. |

Base URLs (`OPENAI_CLP_BASE_URL`, `OPENAI_API_BASE_URL`, `ANTHROPIC_BASE_URL`) can be changed for testing. Only https is accepted, except plain http to this machine.

## Run it

```bash
python3 ai_compliance_bridge.py --dry-run        # print the NDJSON it would send; sends and saves nothing
python3 ai_compliance_bridge.py                  # one pass, for cron or a systemd timer
python3 ai_compliance_bridge.py --interval 300   # keep polling every 5 minutes
```

Exit code 0 means every source was read and sent. On an error the bridge logs the source and the HTTP status, stops, and leaves the cursor where the last accepted batch left it, so the next run picks up from there. An API response over 64 MB, or a log file over 512 MB, also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password in a URL setting shows as `[redacted]` in the log. A signed download URL whose host name doesn't resolve says it came from the API's redirect, not the URL setting.

As a systemd service that polls, with the variables in `/etc/ai-compliance-logs.env` (owned by root, mode 600):

```ini
[Unit]
Description=AI compliance log bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/ai-compliance-logs/ai_compliance_bridge.py --interval 300
EnvironmentFile=/etc/ai-compliance-logs.env
DynamicUser=yes
StateDirectory=ai-compliance-logs
WorkingDirectory=/var/lib/ai-compliance-logs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads each API

- **openai_clp:** lists files per event type with `after` set to the cursor, follows `has_more` and `last_end_time`, and downloads each file. The download answers with a redirect to a short-lived signed URL; the bridge fetches it without the Admin key, only over https (redirects included), and never logs it. The cursor moves after each file is sent. Files expire after 30 days, so run the bridge at least daily.
- **openai_audit:** reads `effective_at[gte]` from the cursor minus the overlap, pages with `after` and `last_id`, and sends the events oldest first. The cursor never moves past the time of the run.
- **anthropic:** reads a window from the cursor minus the overlap to now minus `ANTHROPIC_SETTLE_SECONDS`, with `order=asc`, paging with `after_id` and `last_id`.

All three APIs, and HTTP Ingest, deliver at least once. The bridge drops repeats it has seen recently, but a crash between sending a batch and saving the cursor can send that batch again. HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

Rate limits: OpenAI allows 100 requests a minute per route per workspace, and Anthropic 600 a minute per parent organization across all compliance endpoints. On 408, 429, 500, 502, 503 or 504 the bridge waits (honoring `Retry-After` up to 5 minutes) and retries up to 6 times. HTTP Ingest 400, 401, 403 and 413 are not retried. Apart from the log file download's signed URL, which is fetched without the key and only over https, a redirect from an API or HTTP Ingest is refused, not followed, so no key goes to another URL, and the run stops with an error that says so.

## Privacy

ChatGPT `CONVERSATION_MESSAGE` records carry prompts and responses. With redaction on (the default), the bridge replaces these with `[redacted]` before anything leaves the machine:

- `CONVERSATION_MESSAGE`: message content (text, quotes, cited URLs), attached file names, applied custom instructions, and the conversation title. IDs, model, client and timestamps stay.
- `AUDIT_LOG`: `instructions`, `system_instruction` and `workspace_policy` in `action_data` (agent and workspace system prompts).
- Other ChatGPT log types you add (Codex, apps, plugins, agents): every string except the envelope, IDs, types, actions, statuses, models and timestamps.
- Claude Activity Feed: `request_body` on `compliance_api_accessed`, and any `title`, `description` or `filename`. The feed has no chat text.
- OpenAI API Platform audit logs: nothing; they carry no content.

The library parsers never put content in normalized fields, but `original_data` keeps whatever the bridge sends. Turn redaction off only if your Sophos NG-SIEM retention and access controls are approved for that content.

The bridge never logs keys, the HTTP Ingest URL path, or signed download URLs.

## Tests

```bash
python3 -m unittest discover -s bridges/ai-compliance-logs -p 'test_*.py' -v
```

The tests start a local mock of the three APIs and of HTTP Ingest, built from the documented response shapes, and check paging, the signed-URL redirect, cursors, de-duplication, redaction, dry-run, retries, batching, gzip and that no secret reaches the log.

## References

- ChatGPT Admin and Compliance API reference: https://chatgpt.com/admin/api-reference
- OpenAI Compliance Platform for Enterprise and Edu: https://help.openai.com/en/articles/9261474-compliance-api-for-chatgpt-enterprise-edu-and-chatgpt-for-teachers
- OpenAI audit logs API: https://developers.openai.com/api/reference/resources/organization/subresources/audit_logs/methods/list
- Claude Compliance API Activity Feed: https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract (URL, bearer header, NDJSON and gzip rules), in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
