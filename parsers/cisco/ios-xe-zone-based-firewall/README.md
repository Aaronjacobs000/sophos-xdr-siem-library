# Cisco IOS XE zone-based firewall to Sophos NG-SIEM

The zone-based policy firewall on IOS XE routers (ISR, ASR 1000, Catalyst 8000) and Catalyst SD-WAN edges logs dropped and passed packets, drop and pass summaries, and the start and end of inspected sessions as `%FW-6` syslog messages. This parser reads them once they reach the Sophos NG-SIEM data collector.

## Send the firewall logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. On a router, send syslog to the data collector at the informational level, with dates in the timestamps, and keep the clock on UTC:

```
logging host <data collector address>
logging trap informational
service timestamps log datetime msec
```

3. Turn on the firewall messages:

```
parameter-map type inspect-global
 log dropped-packets
parameter-map type inspect <parameter map>
 audit-trail on
 log summary flows 15 time-interval 30
policy-map type inspect <policy map>
 class type inspect <class map>
  inspect <parameter map>
 class class-default
  drop log
```

`audit-trail on` logs the start and end of each inspected session, `drop log` and `pass log` log a class's dropped and passed packets, and `log summary` logs summaries.

On a Catalyst SD-WAN edge, send its syslog to the data collector in SD-WAN Manager (the Logging feature template or Logging profile), turn on Audit Trail in the security policy for Inspect rules, and turn on logging for the rules that drop.

With high-speed logging (`log flow-export v9`, or High Speed Logging in SD-WAN Manager) the firewall exports NetFlow v9 records instead of syslog, which this parser doesn't read.

## Add the parser

The parser extends a built-in Sophos parser, so it carries a `!PARENT` line:

| Parser | Parent | Events |
| --- | --- | --- |
| `CISCO_IOSXE_ZBFW_SYSLOG_CHILD_NETFLOW` | `Cisco_IOS_Master` | `%FW-6-DROP_PKT`, `%FW-6-PASS_PKT`, `%FW-6-LOG_SUMMARY`, `%FW-6-SESS_AUDIT_TRAIL_START` and `%FW-6-SESS_AUDIT_TRAIL` to Netflow |

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers:

1. Choose Add Custom Parser.
2. Tick Set Global Parent in Parser Script and keep Parent parser (default). The parent picker lists only your own parsers, never built-in ones.
3. Paste the whole file, `!PARENT` line included. Its `!SCHEMA` line sets the schema, whatever the dialog shows.
4. Save. Without the option the save fails with "code contains restricted syntax: !PARENT"; turn it on in the editor and save again.
5. Use Run Test with your own lines before you turn the parser on.

`Cisco_IOS_Master` is the built-in parser that claims Cisco IOS syslog. It leaves the firewall messages without a schema, and none of its built-in children takes them.

## What you get

- Drops and drop summaries as blocked flows; passes, pass summaries and inspected sessions as allowed flows.
- The addresses and ports, the protocol (tcp, udp and icmp as numbers, a layer 7 name such as `dns` as the application name), a summary's packet count, and the bytes each side sent in a session that ended.
- The interface, zone pair, class, reason, TCP flags and, on SD-WAN edges, the VPN or VRF pair in `event_metadata`.
- The event time from the IOS XE timestamp, read as UTC. Lines are read with or without the `%IOSXE-6-PLATFORM: ... cpp_cp:` wrapper.

Threshold and host alerts, such as `%FW-4-ALERT_ON`, `%FW-4-HOST_TCP_ALERT_ON` and `%FW-2-BLOCK_HOST`, carry no flow and stay with the built-in parser.
