# AudioCodes Mediant SBC to Sophos NG-SIEM

The SBC sends management user activity (logins, failed logins, logouts, parameter and table changes, CLI commands) and its alarms (IDS alarms included) to syslog. This entry reads those lines; signaling CDRs and debug lines reach Sophos NG-SIEM in the generic schema.

## On the SBC

1. Open Troubleshoot > Logging > Logging Settings. Turn on syslog, set the syslog server to your data collector, port 514, UDP or TCP, and leave the syslog level at Notice.
2. Set VoIP Debug Level to Basic: AudioCodes sends no syslog at all while it is off. Basic adds SIP debug lines, which land in the generic schema; use Logging Filters if you want fewer of them.
3. Leave Syslog Optimization off, so each message goes in its own packet.
4. Under Activity Types to Report, choose Select All, so logins and logouts, non-authorized access, parameter value changes, saves, resets and file loads are reported.
5. CLI commands are only logged once you turn them on from the CLI (`configure troubleshoot`, then `activity-log`) or the ini file (`ActivityListToLog`).
6. To get IDS alarms, turn on IDS and add an IDS policy under the SBC's Intrusion Detection settings.

The device sends the priority and then its own fields, with no time or host name in front:

```
<133>[S=3] [BID=5b1035:7]  Activity Log: WEB: Successful login at 192.0.2.10:443. User: Admin. Session: WEB (198.51.100.23) [Time:21-10@16:39:22.736]
<132>[S=592] [BID=5b1035:7]  RAISE-ALARM:acProxyConnectionLost; Textual Description: ...; Severity:minor; Source:System#0; Unique ID:41;  [Time:21-10@17:10:40.512]
```

A syslog relay that adds a time and host name in front works too.

## What lands where

| Line | Schema |
| --- | --- |
| `Activity Log:` logins (`WEB: Successful login at`, `Successful user login at`, `User login succeeded`), failed logins (`Unauthorized access attempt to Login Page. Reason: ...`) and logouts (`WEB: User logout`, `User logged out`) | Auth |
| Every other `Activity Log:` line: parameter and table changes (`... was changed from '...' to '...'`), CLI commands (`CLI: '...'`), saves, resets and other actions | ManagementEvent |
| `RAISE-ALARM:` lines, IDS alarms with the attacking address | Thirdparty |
| `CLEAR-ALARM:` lines, the `acKeepAlive` heartbeat, signaling CDRs (the CALL_START, CALL_CONNECT and CALL_END lines) and debug lines | Generic |

CDR lines are left generic: their columns follow the SBC CDR Format table, which you can change, and the device sends the title line only now and then, so the parser can't name a column with confidence.

The device's own time, `[Time:dd-mm@hh:mm:ss.mmm]`, has no year or zone, so the parser takes this year and reads the time as UTC: set the SBC to UTC, or expect the times to be off by its offset. A line with no `[Time:]` gets the time Sophos NG-SIEM received it.

Not checked against a live SBC: the lines here follow AudioCodes' manuals (versions 7.2 to 7.6), its Syslog Viewer guide and its alarm reference. Log in once, change a setting, and compare what arrives with `samples.log` before you rely on it.
