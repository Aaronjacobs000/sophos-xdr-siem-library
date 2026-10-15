# H3C and HPE Comware to Sophos NG-SIEM

Comware 7 runs H3C switches, routers and SecPath firewalls, and HPE's FlexNetwork and FlexFabric switches. It sends system logs to a log host as `%%10<MODULE>/<severity>/<MNEMONIC>:` lines. These parsers read sign-ins, commands, configuration changes, 802.1X and MAC authentication, and the firewall's session, packet filter, IPS, attack defense, URL filtering and antivirus logs once they reach the Sophos NG-SIEM data collector.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. Send the system logs to the data collector in the default (non-customized) format, at the informational level:

```
info-center enable
info-center loghost <data collector address> facility local7
info-center source default loghost level informational
info-center timestamp loghost date
```

Don't set `info-center format cmcc`, `sgcc` or `unicom`: those formats change the line and aren't read. The `date` and `iso` log host timestamps carry no zone unless you add `with-timezone` to `iso`, and are read as UTC, so keep the device clock on UTC or use `iso with-timezone`.

3. On a SecPath firewall, turn on the logs you want: session logs (`session log flow-begin`, `session log flow-end` and `session log enable ipv4 inbound` on an interface), logging in security policy rules, and the IPS, antivirus and URL filtering profiles' logging. They go through the information center unless fast log output is set up for them.

With fast log output (`customlog host <data collector address> export <log type>`), the parsers read the standard fast log header. Fast log output uses GB18030 by default, so set `customlog character-encoding utf-8`. Its times are GMT unless you set `customlog timestamp localtime`.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Events |
| --- | --- |
| `H3C_COMWARE_SYSLOG_PARENT` | Claims the SHELL, LOGIN, SSHS, AAA, CFGMAN, WEB, DOT1X, MACA, SESSION, FILTER, IPS, ATK, UFLT and ANTI-VIR modules; other messages of these modules stay generic |
| `H3C_COMWARE_SYSLOG_CHILD_AUTH` | CLI, SSH and web sign-ins, failures and sign-outs, AAA authentication results, and 802.1X and MAC authentication, to Auth |
| `H3C_COMWARE_SYSLOG_CHILD_MGMT` | `SHELL_CMD` command records and `CFGMAN_CFGCHANGED` configuration changes to Management Event |
| `H3C_COMWARE_SYSLOG_CHILD_NETFLOW` | `SESSION_IPV4_FLOW`, `SESSION_IPV6_FLOW` and the `FILTER` execution messages to Netflow |
| `H3C_COMWARE_SYSLOG_CHILD_NIDS` | `IPS_IPV4_INTERZONE`, `IPS_IPV6_INTERZONE` and `ATK` attack defense messages to NIDS |
| `H3C_COMWARE_SYSLOG_CHILD_HTTP` | `UFLT_MATCH_IPV4_LOG` and `UFLT_MATCH_IPV6_LOG` to HTTP |
| `H3C_COMWARE_SYSLOG_CHILD_ANTIVIRUS` | `ANTIVIRUS_IPV4_INTERZONE` and `ANTIVIRUS_IPV6_INTERZONE` to Antivirus |

Use Run Test with your own lines before you turn the parsers on.
