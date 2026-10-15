# FortiSandbox to Sophos NG-SIEM

FortiSandbox sends its own logs (sandbox verdicts, network alerts and system events) to remote log servers. These parsers read them once they reach the Sophos NG-SIEM data collector over syslog.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. In FortiSandbox, go to Log & Report > Log Servers and choose Create New.
3. Set Type to syslog, not CEF. Enter the data collector's address and port.
4. Under Log Level, turn on Enable Alert Logs for the verdicts. FortiSandbox sends only jobs rated other than Clean unless you also select Include job with Clean Rating. Turn on Enable Information Logs (and the levels above it) for the system events that record what administrators do.
5. Choose OK.

## Add the parsers

Each parser extends a built-in Sophos parser, so it carries a `!PARENT` line:

| Parser | Parent | Events |
| --- | --- | --- |
| `FORTINET_FORTISANDBOX_KV_CHILD_THIRDPARTYALERT` | `Fortinet_Master_non-cef` | Alert logs: malware, netattack, netbotnet and neturl, to Thirdparty |
| `FORTINET_FORTISANDBOX_KV_CHILD_MGMT` | `Fortinet_Event` | System events an administrator caused, to ManagementEvent |

For each one, in Sophos Fusion go to Security Operations > Integrations > Custom Parsers:

1. Choose Add Custom Parser.
2. Tick Set Global Parent in Parser Script and keep Parent parser (default). The parent picker lists only your own parsers, never built-in ones.
3. Paste the whole file, `!PARENT` line included. Its `!SCHEMA` line sets the schema, whatever the dialog shows.
4. Save. Without the option the save fails with "code contains restricted syntax: !PARENT"; turn it on in the editor and save again.
5. Use Run Test with your own lines before you turn the parser on.

`Fortinet_Master_non-cef` claims every FortiSandbox line and stores nothing from the alert logs. `Fortinet_Event`, its built-in child for `type=event subtype=system` lines from FortiGate and FortiSandbox, stores only the sensor type FORTIGATE_FW. So the alert parser sits under the first and the management parser under the second.

## What you get

- Thirdparty: the malware name, attack, botnet or host as the title; the file name and rating as the summary; the job ID as the alert ID; the source and destination addresses and ports; the URL and the user. The rating sets the severity (Malicious critical, High Risk high, Medium Risk medium, Low Risk low, Clean info), and the log level sets it when there is no rating. The file hashes, the malware name and category, the device and VDOM that submitted the file, the protocol, the VM, the job status, and the host, attack and botnet names go to `additional_data`.
- ManagementEvent: the administrator, the interface (`ui`), the action, the message as the command, the status and reason as the result, and `cip` as the client.
- The event time comes from `date` and `time`, which FortiSandbox sends to a syslog server in UTC. Each parser checks for a FortiSandbox serial (`FSA...`) in `devid`.

FortiSandbox's own system events (user `system`), such as VM and job status, stay with the built-in parsers in the generic schema.

## Limits

Fortinet's FortiSandbox log reference gives field tables but no message catalog and no example alert line. The alert line layout here follows those tables and the header of Fortinet's example event line. The reference names the alert type both `alert` and `malware` or `netalert`, so the parser takes any of them. The log IDs and messages in `samples.log` are made up.
