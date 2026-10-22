# Stormshield Network Security (SNS) to Sophos NG-SIEM

Stormshield Network Security firewalls write their audit logs as WELF lines, one `key=value` line per event, and send the log families you choose to up to four syslog servers. These parsers read the connection, filter, application plugin, alarm, HTTP proxy, authentication, SSL VPN and administration logs once they reach the Sophos NG-SIEM data collector.

## Send the firewall logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. On the firewall, go to Configuration > Notifications > Logs - Syslog - IPFIX, Syslog tab, and edit a syslog profile:
   - Syslog server: a host object for the data collector. Protocol: UDP or TCP, and the port the data collector listens on.
   - Format: RFC5424. The parsers also read LEGACY-LONG; LEGACY cuts each message at 1024 characters.
   - Logs enabled: turn on the alarm, connection, filter, plugin, web, authentication, server (administration) and SSL VPN logs, plus any others you want kept as generic events. In the CLI these are `LogAlarm`, `LogConnection`, `LogFilter`, `LogPlugin`, `LogWeb`, `LogAuth`, `LogServer` and `LogXvpn` in `CONFIG COMMUNICATION SYSLOG PROFILE UPDATE`.
3. Filter and NAT rule logs (l_filter) are off by default. Stormshield advises turning on a rule's verbose log level only while you check that rule.

The firewall writes `time` in its local time with its offset in `tz`, so event times are right in any time zone.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Events |
| --- | --- |
| `STORMSHIELD_SNS_KV_PARENT` | Claims every SNS audit log line; system, IPsec, SSL proxy, sandboxing, mail and FTP proxy, statistics and other logs stay generic |
| `STORMSHIELD_SNS_KV_CHILD_NETFLOW` | Connection, filter and plugin logs to Netflow, with NAT, bytes, rule and interfaces |
| `STORMSHIELD_SNS_KV_CHILD_NIDS` | Intrusion prevention alarms with addresses to NIDS, with the alarm ID as the signature |
| `STORMSHIELD_SNS_KV_CHILD_HTTP` | HTTP proxy logs to HTTP, with the method, host, path, response code, URL category and block |
| `STORMSHIELD_SNS_KV_CHILD_AUTH` | Authentication and SSL VPN sign-in results to Auth |
| `STORMSHIELD_SNS_KV_CHILD_MGMT` | Administration commands (l_server) to Management Event, with the user, client address and command |

Use Run Test with your own lines before you turn the parsers on.
