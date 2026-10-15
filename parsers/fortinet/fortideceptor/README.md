# FortiDeceptor to Sophos NG-SIEM

FortiDeceptor sends its event log (decoy hits, administrator sign-ins and configuration changes) to remote log servers. These parsers read it once it reaches the Sophos NG-SIEM data collector over syslog.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. In FortiDeceptor, go to Log > Log Servers (Log & Reports > Log Servers on older releases) and choose Create New.
3. Set Type to Syslog Protocol, not Common Event Format or FortiAnalyzer. Enter the data collector's address and port.
4. Under Log Level, pick the levels to send. Fortinet's examples put decoy hits at Alert and sign-ins and configuration changes at Information.
5. Choose OK.

## Add the parsers

Every FortiDeceptor line is `type=event subtype=system`, which the built-in `Fortinet_Event` claims. It stores only the sensor type FORTIGATE_FW, so each parser here is a child of `Fortinet_Event` and carries a `!PARENT` line:

| Parser | Events |
| --- | --- |
| `FORTINET_FORTIDECEPTOR_KV_CHILD_THIRDPARTYALERT` | Decoy hits (regular, IPS, web filtering and port scan events) to Thirdparty |
| `FORTINET_FORTIDECEPTOR_KV_CHILD_AUTH` | Administrator logins, logouts and session timeouts in the web console and CLI, and failed logins, to Auth |
| `FORTINET_FORTIDECEPTOR_KV_CHILD_MGMT` | Other events an administrator caused, such as decoy deployments and network, mail, fabric and token changes, to ManagementEvent |

For each one, in Sophos Fusion go to Security Operations > Integrations > Custom Parsers:

1. Choose Add Custom Parser.
2. Tick Set Global Parent in Parser Script and keep Parent parser (default). The parent picker lists only your own parsers, never built-in ones.
3. Paste the whole file, `!PARENT` line included. Its `!SCHEMA` line sets the schema, whatever the dialog shows.
4. Save. Without the option the save fails with "code contains restricted syntax: !PARENT"; turn it on in the editor and save again.
5. Use Run Test with your own lines before you turn the parser on.

## What you get

- Thirdparty: the attacker's address and port as the source, the decoy's as the destination, the service, the account the attacker tried, the operation as the category, the event ID as the alert ID, the attack or operation as the title, and the description as the summary. The log level sets the severity. The incident ID, decoy group and type, tag key, attack, web filter category and description go to `additional_data`. The password the attacker tried is not copied out of the line.
- Auth: the administrator, the address and interface (such as `ssh(192.0.2.11)`), and LOGON, LOGOFF or FAILURE.
- ManagementEvent: the administrator, the interface (`ui`), the action, the message as the command and the status.
- The event time comes from `date` and `time`, read as UTC. Each parser checks for a FortiDeceptor serial (`FDC...`) in `devid`.

FortiDeceptor's own events (user `system`), such as FortiGuard updates, and its "SNMP TRAP sent out" copies of decoy hits stay with the built-in parsers in the generic schema.

## Limits

- Fortinet shows decoy events two ways. Releases before 4.3 put the fields inside `msg` (`msg="Service=SSH AttackerIp=... Operation=Authentication Failure ..."`). The log message reference since 5.0 lists them as fields (`EventID=... AttackerIP=... Operation=Authentication_Failure ...`) but shows no full syslog line, so where they sit on the line is inferred. The parser reads them from either place.
- Fortinet documents the login and logout messages but not the text of a failed login, so the Auth parser counts an `action=Login` line whose status isn't `success` as a failure. That rule, and the failed login line in `samples.log`, are inferred.
- FortiDeceptor doesn't say whether `date` and `time` are UTC or local. FortiSandbox, which sends the same header, documents UTC, so the parsers read UTC.
