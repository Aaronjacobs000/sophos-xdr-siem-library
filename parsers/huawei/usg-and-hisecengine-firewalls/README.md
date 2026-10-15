# Huawei USG and HiSecEngine firewalls to Sophos NG-SIEM

Huawei USG and HiSecEngine firewalls (USG6000E, USG6000F and the models that run the same software) send their information center logs to a syslog server as `%%01<MODULE>/<severity>/<brief>(<type>):` lines, and their session logs in the same syslog format by default. These parsers read the security policy, session, intrusion prevention, antivirus, URL filtering, SSL VPN and web sign-in messages once they reach the Sophos NG-SIEM data collector.

## Send the firewall logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. Send the information center logs (policy, threat, URL, SSL VPN and web sign-in messages) to the data collector at the informational level, in the default syslog format for service logs:

```
info-center enable
info-center loghost <data collector address> facility local7
info-center source default channel loghost log level informational
firewall log service log-type syslog
```

3. Turn on logging in the security policy rules you want logged. Policy matching logs (`POLICY/6/POLICYPERMIT` and `POLICYDENY`) are off by default; turn on policy logging in the rule. Session logs come from rules with `session logging`:

```
security-policy
 rule name <rule>
  session logging
```

4. Send the session logs in the default syslog format, not MTN, NetFlow or a custom template:

```
firewall log host 1 <data collector address> 514
firewall log session log-type syslog
```

5. For drop records (`SECLOG/4/SESSION_DROP_RECORD`), turn on packet loss logs as Huawei's packet loss example describes.

The default `date` timestamp carries the zone (`Oct 15 2026 09:21:40+10:00`), and so do `format-date`, `rfc-3339` and `short-date`. With `without-timezone` the time is read as UTC, so keep the zone or keep the device clock on UTC.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Events |
| --- | --- |
| `HUAWEI_USG_SYSLOG_PARENT` | Claims the POLICY, SECLOG, IPS, AV, URL, WAF, SSLVPN and WEBM modules; other messages of these modules stay generic |
| `HUAWEI_USG_SYSLOG_CHILD_NETFLOW` | `POLICY/6/POLICYPERMIT`, `POLICYDENY`, `SECLOG/6/SESSION_BUILT`, `SESSION_TEARDOWN` and `SECLOG/4/SESSION_DROP_RECORD` to Netflow |
| `HUAWEI_USG_SYSLOG_CHILD_NIDS` | `IPS/4/DETECT`, `BOTNET`, `TROJAN`, `WORM`, `DOMAIN` and `WAF/4/CONSTRAINT` to NIDS |
| `HUAWEI_USG_SYSLOG_CHILD_ANTIVIRUS` | `AV/4/VIRUS` and `AV/4/REPUTATION` to Antivirus |
| `HUAWEI_USG_SYSLOG_CHILD_HTTP` | `URL/4/FILTER` to HTTP |
| `HUAWEI_USG_SYSLOG_CHILD_AUTH` | SSL VPN sign-ins, failures and sign-outs, and web UI sign-ins and failures, to Auth |
| `HUAWEI_USG_SYSLOG_CHILD_MGMT` | `POLICY/6/POLICYMODIFY` (security policy rule changes) to Management Event |

CLI and SSH sign-ins and command records (`CLI/5/LOGIN`, `CLI/5/CMDRECORD`, `SSH/5/SSH_USER_LOGIN` and others) are the same messages on every Huawei VRP device. Add the Huawei VRP switches and routers entry for those.

Use Run Test with your own lines before you turn the parsers on.
