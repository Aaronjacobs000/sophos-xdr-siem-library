# OpenCanary to Sophos NG-SIEM

OpenCanary is the open source honeypot from Thinkst. It runs fake services (SSH, FTP, HTTP, SMB, MSSQL, RDP and more) and logs every touch as one JSON object. These parsers read those objects once they reach the Sophos NG-SIEM data collector over syslog.

Sophos Fusion's Thinkst Canary integration polls the commercial Canary console. It doesn't read OpenCanary's syslog, which is what this entry is for.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. On the honeypot, open the OpenCanary config (`/etc/opencanaryd/opencanary.conf`) and add a handler under `logger` > `kwargs` > `handlers`, with the data collector's address in place of 192.0.2.50:

   ```json
   "syslog-ngsiem": {
       "class": "logging.handlers.SysLogHandler",
       "formatter": "syslog_rfc",
       "address": ["192.0.2.50", 514],
       "socktype": "ext://socket.SOCK_DGRAM"
   }
   ```

3. Restart OpenCanary: `opencanaryd --restart`.

This is the syslog handler from OpenCanary's configuration docs, pointed at the data collector's UDP syslog port. The `plain` formatter works too. So does a relay such as rsyslog that forwards the lines for you, as long as each event stays on one line with its JSON intact: the parsers find the JSON object wherever it sits on the line.

## Add the parsers

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers. Add `OPENCANARY_JSON_PARENT` first, then `OPENCANARY_JSON_CHILD_THIRDPARTYALERT` with the parent as its parent parser. Paste a few of your own lines as sample messages and use Run Test before you turn them on, parent first.

| Parser | Events |
| --- | --- |
| `OPENCANARY_JSON_PARENT` | Claims every OpenCanary line, sets the time and the honeypot's `node_id`, and keeps OpenCanary's own messages (logtype under 2000) generic |
| `OPENCANARY_JSON_CHILD_THIRDPARTYALERT` | Every honeypot event (logtype 2000 and up) to Thirdparty |

## What you get

Each honeypot event is a Thirdparty record:

- `log_type`: the logtype number as text, such as `4002`.
- `source_address` and `source_port`: the attacker. `destination_address` and `destination_port`: the honeypot. `target_host_name` and `host_id`: the honeypot's `node_id`.
- `title`, such as "OpenCanary: SSH login attempt", and a one-line `summary`.
- `alert_category`: Login attempt, Connection, Request, File access, Port scan, LLMNR response or User-defined.
- `destination_service_name`: the OpenCanary module, such as `ssh`, `http`, `smb` or `mssql`.
- `target_user_name`: the account an attacker tried. For an SMB file open, `source_user_name` and `source_host_name` are the user and the client machine.
- `severity`: HIGH for a login with one of the honeypot's planted credentials (`honeycred` true), MEDIUM for logins, requests, commands, file opens and Nmap scans, LOW for bare connections, single SYN packets, user-defined events and unknown logtypes. OpenCanary sets no severity, so this is the parser's own scale.
- `additional_data`: the rest of `logdata`, such as the share and file name, the HTTP skin, the SSH versions or the Redis command.
- The event time is `utc_time`.

Passwords, the SNMP community string, the VNC challenge and response, a Redis AUTH argument and the TCP banner keep-alive secret are not copied into fields. They stay in `original_data`.

## Logtypes

| Logtype | Event |
| --- | --- |
| 2000, 2001 | FTP login attempt, FTP login started |
| 3000 to 3003 | HTTP page request, login attempt, unsupported method, redirect |
| 4000 to 4002 | SSH connection, client version, login attempt |
| 5000 | SMB file opened |
| 5001 to 5005 | TCP SYN packet, Nmap OS, NULL, Xmas and FIN scans |
| 6001, 6002 | Telnet login attempt, connection |
| 7001 | HTTP proxy login attempt |
| 8001, 9003 | MySQL login attempt, connection |
| 9001, 9002 | MSSQL login attempt with SQL or Windows authentication |
| 10001, 11001 | TFTP request, NTP monlist request |
| 12001, 14001 | VNC login attempt, RDP login attempt |
| 13001, 15001 | SNMP request, SIP request |
| 16001, 17001 | Git clone request, Redis command |
| 18001 to 18005 | TCP banner connections and data |
| 19001 | LLMNR query answered |
| 20001 | MongoDB connection, login attempt, command or error |
| 99000 to 99009 | User-defined modules |

## Write a detection rule on it

A custom detection rule runs a Data Lake Search query against one schema. For example, to raise a detection on HTTP, SMB and MSSQL activity:

```
FROM thirdparty WHERE sensor_type = 'OpenCanary' AND log_type IN ('3000', '3001', '3002', '3003', '5000', '9001', '9002')
```

Data Lake Search accepts this query in a lab tenant. It hasn't run as a rule or against real OpenCanary events.

Logtype 5001 is logged for every TCP SYN the honeypot sees, up to `portscan.synrate` a second (5 by default). A custom rule that creates more than 5,000 detections in an hour is turned off, so leave 5001 out of a rule or expect bursts during a scan.

## Limits

- The samples are built from OpenCanary's source. No line was captured from a running OpenCanary.
- The https module logs with the http logtypes, so only the destination port tells the two apart.
- A UDP service that listens on every address logs 0.0.0.0 as its own, which the parser leaves out of `destination_address`.
- A user-defined module's `logdata` is copied only where it uses a key that one of OpenCanary's own modules uses, such as `USERNAME`. Fork the child parser to map your own keys.
