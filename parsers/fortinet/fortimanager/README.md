# FortiManager to Sophos NG-SIEM

FortiManager sends its own event log (administrator logins, object changes, policy package installs, device changes) to a syslog server. These parsers read that log once it reaches the Sophos NG-SIEM data collector.

## Send the event log

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. In FortiManager, go to System Settings > Advanced > Syslog Server, choose Create New, and enter the data collector's address and port. Turn on Reliable Connection to send over TCP.
3. Turn on sending in the CLI, which is the only place it can be turned on:

```
config system locallog syslogd setting
    set severity information
    set status enable
    set syslog-name <the syslog server's name>
end
```

Leave `csv` at its default, disable. With `csv enable` the lines are comma separated and these parsers don't read them.

## Add the parsers

Each parser extends a built-in Sophos parser, so it carries a `!PARENT` line:

| Parser | Parent | Events |
| --- | --- | --- |
| `FORTINET_FORTIMANAGER_KV_CHILD_AUTH` | `Fortinet_Event` | Logins, logouts and login failures (system messages 10018, 10019, 10014) to Auth |
| `FORTINET_FORTIMANAGER_SYSTEM_KV_CHILD_MGMT` | `Fortinet_Event` | System messages for an administrator's action (CLI command, setting changed, reboot, settings backup and restore, ADOM and policy package locks, firmware upgrade, reset) to ManagementEvent |
| `FORTINET_FORTIMANAGER_KV_CHILD_MGMT` | `Fortinet_Master_non-cef` | Configuration events (devcfg, glbcfg, scrmgr, scply, dm, fmwmgr, objcfg, dvm) to ManagementEvent |

For each one, in Sophos Fusion go to Security Operations > Integrations > Custom Parsers:

1. Choose Add Custom Parser.
2. Tick Set Global Parent in Parser Script and keep Parent parser (default). The parent picker lists only your own parsers, never built-in ones.
3. Paste the whole file, `!PARENT` line included. Its `!SCHEMA` line sets the schema, whatever the dialog shows.
4. Save. Without the option the save fails with "code contains restricted syntax: !PARENT"; turn it on in the editor and save again.
5. Use Run Test with your own lines before you turn the parser on.

`Fortinet_Event` is the built-in child of `Fortinet_Master_non-cef` that claims `type=event subtype=system` lines, FortiGate's and FortiManager's, and stores only the sensor type FORTIGATE_FW. A FortiManager parser placed next to it, under `Fortinet_Master_non-cef`, lost those lines to it in Run Test whenever a FortiGate system event came before them, so the parsers for system messages sit under `Fortinet_Event`.

## What you get

- Auth: the administrator, the address and interface from `userfrom` (such as `GUI(192.0.2.10)`), the session, and LOGON, LOGOFF or FAILURE. The log ID, description, message and admin profile go to `event_metadata`.
- ManagementEvent: the administrator (not FortiManager's own `system` or `fgfm` user), the address and interface, the description as the operation name, `operation`, the change (`changes`, else `msg`) as the command, the managed device (`device`, `inst_dev` or `dev=` in `performed_on`) as the target host, the ADOM as the namespace, and the result.
- The event time comes from `date`, `time` and `tz`. Each parser checks for a FortiManager serial (`FMG...`) in `device_id`.

Other events, such as fgfm tunnel status, HA, FortiGuard updates and logging, stay with the built-in parsers in the generic schema.
