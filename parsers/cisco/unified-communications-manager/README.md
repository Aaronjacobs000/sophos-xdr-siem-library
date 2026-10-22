# Cisco Unified Communications Manager to Sophos NG-SIEM

Cisco Unified Communications Manager (CUCM) sends its alarms and audit events by remote syslog. These parsers read the sign-ins, account lockouts, refused device registrations and audit events once they reach the Sophos NG-SIEM data collector.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. Alarms (`%UC_LOGIN` sign-ins and lockouts, `%UC_CALLMANAGER` device registrations): in Cisco Unified CM Administration, go to System > Enterprise Parameters. Under Cisco Syslog Agent, set Remote Syslog Server Name 1 to the data collector's address and Syslog Severity For Remote Syslog messages to Informational. Choose Save, then Apply Config.
3. Audit events (`%UC_AUDITLOG`): in Cisco Unified Serviceability, go to Tools > Audit Log Configuration, select a server and choose Go. Tick Apply to All Nodes, enter the data collector's address in Server Name, and choose Save. Detailed Audit Logging adds the values that changed, and is off by default.

Cisco's 14 and 15 guides describe the Audit Log Configuration fields as IM and Presence Service settings, though the procedure for Unified CM uses the same Server Name. Check that audit events arrive before you rely on them.

## Add the parsers

Each parser extends a built-in Sophos parser, so it carries a `!PARENT` line:

| Parser | Parent | Events |
| --- | --- | --- |
| `CISCO_CUCM_SYSLOG_CHILD_AUTH` | `Cisco_IOS_Master` | `%UC_LOGIN` AuthenticationFailed, AuthenticationSucceeded and PlatformAdminAccountLocked, `%UC_AUDITLOG` events of the UserLogging type, and `%UC_CALLMANAGER` DeviceTransientConnection with reason 2, 3, 4, 10, 11, 17, 28 or 35, to Auth |
| `CISCO_CUCM_SYSLOG_CHILD_MGMT` | `Cisco_IOS_Master` | Every other `%UC_AUDITLOG` audit event, and the `CCM_TOMCAT-GENERIC AuditEventGenerated` form the Administration Guide shows, to ManagementEvent |

For each one, in Sophos Fusion go to Security Operations > Integrations > Custom Parsers:

1. Choose Add Custom Parser.
2. Tick Set Global Parent in Parser Script and keep Parent parser (default). The parent picker lists only your own parsers, never built-in ones.
3. Paste the whole file, `!PARENT` line included. Its `!SCHEMA` line sets the schema, whatever the dialog shows.
4. Save. Without the option the save fails with "code contains restricted syntax: !PARENT"; turn it on in the editor and save again.
5. Use Run Test with your own lines before you turn the parser on.

`Cisco_IOS_Master` is the built-in parser that claims Cisco IOS syslog. It claims CUCM's lines too and leaves them without a schema, and none of its built-in children takes them.

## What you get

- Auth: the account, the address it came from, the interface (such as Cisco CallManager Administration, or Apache-Axis2 for the AXL API), LOGON, LOGOFF or FAILURE, and lockouts as ACCOUNT_LOCK. A refused device registration names the SIP digest user (or the device), the device's address, the protocol, the port it connected to and the reason, such as AuthenticationError for a failed digest or DatabaseConfigurationError for a device CUCM doesn't know. The node, cluster, audit details and device name go to `event_metadata`.
- ManagementEvent: the user, the address, the event type (such as GeneralConfigurationUpdate, UserAccess or CLICommand) as the operation name, the audit details as the operation, the CLI command, the status, the component as the channel, the cluster as the namespace and the node.
- The event time, read as UTC from either time form (`02:10:19 PM.484 UTC` or `14:12:02.118 UTC`), with or without the year. A line in another zone keeps the ingest time.

Other alarms, such as other DeviceTransientConnection reasons, RTMT alerts and service alarms, stay with the built-in parser. Call detail records ship as CSV files over SFTP, not syslog, and aren't covered.
