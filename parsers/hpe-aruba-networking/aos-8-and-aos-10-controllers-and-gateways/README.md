# HPE Aruba Networking AOS 8 and AOS 10 to Sophos NG-SIEM

AOS 8 Mobility Controllers and Mobility Conductors, and AOS 10 gateways, send syslog lines that carry a six-digit message ID and a severity, such as `authmgr[2435]: <522008> <2435> <NOTI> <mc01 192.0.2.5>  User Authentication Successful: ...`, and audit trail lines for configuration commands. These parsers read user and management authentication, configuration commands, management users, and rogue and interfering access points once they reach the Sophos NG-SIEM data collector. Sophos Fusion's Aruba integration covers ClearPass only.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. On the Mobility Conductor (or each standalone controller), add the data collector as a syslog server. The default logging level for every category is Warning, so lower it for the user and security categories, or user authentication successes and management sign-ins (notices) aren't sent:

```
logging <data collector address>
logging level notifications user
logging level notifications security
```

User authentication successes (522008) and de-authentications (522010) are user notices, failures (522275 and 522274) user errors, management sign-ins (125023, 125024, 125032 and 124025) security notices, and rogue AP events (126000 and 126002) security errors. Management users added or removed (125063 and 125064) are security informational messages, sent only at `informational`. The audit trail logs every command that changes the configuration; `audit-trail all` adds show commands. On AOS 10 gateways, set the syslog server and levels in HPE Aruba Networking Central.

The syslog time has no zone and is read as UTC, so keep the controllers on UTC.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Events |
| --- | --- |
| `ARUBA_AOS_SYSLOG_PARENT` | Claims every line with a message ID, and audit trail lines; other messages stay generic |
| `ARUBA_AOS_SYSLOG_CHILD_AUTH` | 522008 and 522275 (user authentication), 522010 (user de-authenticated), 522274 (management authentication failed), and 125023, 125024, 125032 and 124025 (management sign-ins) to Auth |
| `ARUBA_AOS_SYSLOG_CHILD_MGMT` | Audit trail commands, and 125063 and 125064 (management users added and removed) to Management Event |
| `ARUBA_AOS_SYSLOG_CHILD_THIRDPARTYALERT` | 126000 and 126002 (rogue AP) and 127004 (interfering AP) to Thirdparty |

Use Run Test with your own lines before you turn the parsers on.
