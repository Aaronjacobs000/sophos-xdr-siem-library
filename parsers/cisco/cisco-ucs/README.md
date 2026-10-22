# Cisco UCS to Sophos NG-SIEM

Cisco UCS Manager sends its faults, events and audit log from the fabric interconnects to up to three syslog servers, and each Cisco Integrated Management Controller (CIMC) sends its own audit records. These parsers read the administrator sign-ins and changes once they reach the Sophos NG-SIEM data collector.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. UCS Manager: go to Admin > Faults, Events and Audit Log > Syslog, add the data collector as a remote destination at the Information level, and turn on the Audits source. In the CLI:

```
scope monitoring
enable syslog remote-destination server-1
set syslog remote-destination server-1 level information
set syslog remote-destination server-1 hostname <data collector address>
set syslog remote-destination server-1 facility local7
enable syslog source audits
enable syslog source events
enable syslog source faults
commit-buffer
```

3. Servers managed by Intersight: add the data collector to the Syslog policy of the domain profile and of the server profiles. Standalone C-Series: in the CIMC, go to Chassis > Faults and Logs > Logging Controls, add the data collector as a remote syslog server and set the remote severity to Notice or lower, since the audit records are sent at Notice. In the CLI: `scope cimc`, `scope log`, `scope server 1`, `set server-ip <data collector address>`, `set enabled yes`, `commit`.

The UCS Manager time carries the zone name the fabric interconnects use. UTC and the common names in the parsers' comments are read with their offset; set the fabric interconnects to one of them.

## Add the parsers

The two UCS Manager parsers extend a built-in Sophos parser, so they carry a `!PARENT` line:

| Parser | Parent | Events |
| --- | --- | --- |
| `CISCO_UCS_SYSLOG_CHILD_AUTH` | `Cisco_IOS_Master` | Web and SSH sign-ins to UCS Manager (AUDIT `[session]` creation records) to Auth |
| `CISCO_UCS_SYSLOG_CHILD_MGMT` | `Cisco_IOS_Master` | Changes in the audit log (AUDIT `[admin]`, `[oper]`, `[special]` and `[authorization]` records) to Management Event |
| `CISCO_IMC_SYSLOG_STANDALONE_MGMT` | none | CIMC `AUDIT[<pid>]:` records to Management Event |

For each child, in Sophos Fusion go to Security Operations > Integrations > Custom Parsers:

1. Choose Add Custom Parser.
2. Tick Set Global Parent in Parser Script and keep Parent parser (default). The parent picker lists only your own parsers, never built-in ones.
3. Paste the whole file, `!PARENT` line included. Its `!SCHEMA` line sets the schema, whatever the dialog shows.
4. Save. Without the option the save fails with "code contains restricted syntax: !PARENT"; turn it on in the editor and save again.
5. Use Run Test with your own lines before you turn the parser on.

Add the CIMC parser as an ordinary custom parser.

Failed sign-ins to a fabric interconnect are `%AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed` lines, which the built-in Cisco IOS parsers already read to Auth. Faults, FSM events and the other NX-OS lines stay with the built-in parsers.
