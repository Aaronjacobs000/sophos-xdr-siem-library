# Huawei VRP switches and routers to Sophos NG-SIEM

Huawei devices that run VRP (S series and CloudEngine switches, AR and NetEngine routers) send their information center logs to a syslog server as `%%01<MODULE>/<severity>/<brief>(<type>)` lines. USG and HiSecEngine firewalls log CLI and SSH sign-ins and commands with the same messages. These parsers read sign-ins, command records, local account changes and switch attack defense messages once they reach the Sophos NG-SIEM data collector.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. Send the information center logs to the data collector at the informational level:

```
info-center enable
info-center loghost <data collector address> facility local7
info-center source default channel loghost log level informational
```

The default `date` timestamp carries the zone (`Oct 15 2026 09:12:44+10:00`), and so do `format-date`, `rfc-3339` and `short-date`. With `without-timezone` the time is read as UTC, so keep the zone or keep the device clock on UTC.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Events |
| --- | --- |
| `HUAWEI_VRP_SYSLOG_PARENT` | Claims the SHELL, CLI, SSH, AAA and SECE modules; other messages of these modules stay generic |
| `HUAWEI_VRP_SYSLOG_CHILD_AUTH` | `SHELL/5/LOGIN`, `LOGOUT`, `SHELL/4/LOGINFAILED`, `LOGIN_FAIL_FOR_INPUT_TIMEOUT`, `CLI/5/LOGIN`, `LOGOUT`, `LOGINFAILED`, `SSH/5/SSH_USER_LOGIN`, `SSH_USER_LOGIN_FAIL`, `SSH_USER_LOGOUT`, `SSH/4/SSH_FAIL` and `AAA/6/LOCALACCOUNT_LOCK` and `UNLOCK` to Auth |
| `HUAWEI_VRP_SYSLOG_CHILD_MGMT` | `SHELL/5/CMDRECORD`, `CLI/5/CMDRECORD` (and the `CMDRECORDFAILED` messages) and `AAA/6/LOCALACCOUNT_CREATE_SUCCESS`, `DELETE` and `MODIFY` to Management Event |
| `HUAWEI_VRP_SYSLOG_CHILD_NIDS` | `SECE/4/ARPMISS`, `GWCONFLICT`, `STRACK_DENY`, `PORT_ATTACK`, `USER_ATTACK` and `SPECIFY_SIP_ATTACK` to NIDS |

The firewall messages of USG and HiSecEngine firewalls (policy, session, IPS, antivirus, URL filtering and SSL VPN) are in the Huawei USG and HiSecEngine firewalls entry.

Use Run Test with your own lines before you turn the parsers on.
