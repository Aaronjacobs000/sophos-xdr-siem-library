# FortiNDR to Sophos NG-SIEM

FortiNDR (on-premises, formerly FortiAI) sends NDR detections, malware and attack chain logs, NetFlow detections and its event log to syslog servers. These parsers read them once they reach the Sophos NG-SIEM data collector. FortiNDR Cloud is a separate, API-only product and isn't covered.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. In FortiNDR, go to Log & Report > Log Settings, turn on Send logs to Syslog Server 1, keep Type at Syslog Protocol, and enter the data collector's address and port (UDP 514 by default).
3. Pick the log types and NDR severities in the CLI, and keep the default format, not CEF:

```
config system syslog1 settings
    set status enable
    set type event malware ndr netflow
    set ndr-severity low medium high critical
    set format default
end
```

Sensors send their own detection logs, so set this up on each sensor too (System > Sensor Settings on a Center). FortiNDR leaves muted detections out.

## Add the parsers

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers. Add `FORTINET_FORTINDR_KV_PARENT` first, then each child with the parent as its parent parser. Use Run Test with your own lines before you turn them on.

| Parser | Events |
| --- | --- |
| `FORTINET_FORTINDR_KV_PARENT` | Claims FortiNDR lines, reads the pairs and the time, and hands each line to a child. Other events stay generic. |
| `FORTINET_FORTINDR_KV_CHILD_NIDS` | NDR detections (Botnet, Encrypted, IOC, IPS attack, Weak cipher, ML) and NetFlow detections to NIDS |
| `FORTINET_FORTINDR_KV_CHILD_THIRDPARTYALERT` | Attack logs (Malware and Attack Chain) to Thirdparty |
| `FORTINET_FORTINDR_KV_CHILD_AUTH` | Administrator logins, failed and blocked logins, logouts and timeouts to Auth |
| `FORTINET_FORTINDR_KV_CHILD_MGMT` | Other user events, such as settings changes, to ManagementEvent |

## What you get

- NIDS: the addresses, ports, protocol, application and VLAN; the botnet, campaign, signature, malware family or NetFlow tag in the message; the subtype (or vulnerability type) as the classification; and the severity as the priority (critical and high 1, medium 2, low 3). The session, behavior, host name, URL, MD5, JA3, JA3S, cipher, TLS version, MACs and ML reasons go to `event_metadata`.
- Thirdparty: the malware name or attack chain scenario as the title, the attacker and victim addresses and ports, the URL, the event ID as the alert ID, and the risk level as the severity. The file hashes, type, size and ID, confidence, detection types, scenario and malware family go to `additional_data`.
- Auth: the administrator, the address and interface from the message (such as `ssh(203.0.113.45)`), and LOGON, LOGOFF or FAILURE. A blocked login is a lockout, with its reason in `event_metadata`.
- ManagementEvent: the administrator, the interface and address from `ui`, the message as the command, and for a settings change the configuration path as the namespace.

## Event time

`date` and `time` are FortiNDR's local time, and `tz` gives only a zone name such as AEST. The parent knows the offsets of numeric zones (such as `+10` or `+0530`) and of AEST, AEDT, ACST, ACDT, AWST, NZST, NZDT, JST, KST, HKT, SGT, WIB, UTC, GMT and the common North American and European names. For any other zone, including names that mean more than one zone (CST, IST, PST), the event keeps the time the line arrived.

## Limits

Fortinet's samples show the pairs but not the syslog header in front of them, so the parent finds `date="` wherever the line starts. The CEF format and FortiNDR's FortiAnalyzer and OFTPS outputs aren't covered.
