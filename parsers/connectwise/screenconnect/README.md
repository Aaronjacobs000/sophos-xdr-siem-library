# ConnectWise ScreenConnect to Sophos NG-SIEM

ScreenConnect has no syslog export. Its automations (Administration > Automations) can send a web request when an event happens. The web request has no header field, and Sophos NG-SIEM HTTP Ingest needs `Authorization: Bearer <integration key>`, so point the automations at a small relay (for example a cloud function) that forwards the body unchanged to the HTTP Ingest URL with that header.

ScreenConnect puts values into the body as they are, without escaping, so these templates are pipe-delimited text rather than JSON. Keep the keys and their order: the parsers read them by name, and Data must stay last.

## Security automation

- Event Filter: `Event.EventType = 'LoginAttempt' OR Event.EventType = 'ChangePasswordAttempt'`
- Action: Perform Web Request, HTTP Method POST, Content Type `text/plain`, URL: the relay
- Body:

```
ScreenConnect|category=Security|event={Event.EventType}|result={Event.OperationResult}|time={Event.Time}|user={Event.UserName}|source={Event.UserSource}|address={Event.NetworkAddress}
```

## Session automation

- Event Filter: the session events you want, for example `Event.EventType = 'Connected' OR Event.EventType = 'Disconnected' OR Event.EventType = 'QueuedCommand' OR Event.EventType = 'RanCommand' OR Event.EventType = 'QueuedTool' OR Event.EventType = 'QueuedElevatedTool' OR Event.EventType = 'RanFiles' OR Event.EventType = 'SentFiles' OR Event.EventType = 'CreatedSession' OR Event.EventType = 'DeletedSession'`
- Action: Perform Web Request, HTTP Method POST, Content Type `text/plain`, URL: the relay
- Body:

```
ScreenConnect|category=Session|event={Event.EventType}|time={Event.Time}|session_type={Session.SessionType}|session_guid={Session.SessionID}|company={Session.CustomProperty1}|guest_machine={Session.GuestMachineName}|guest_domain={Session.GuestMachineDomain}|guest_user={Session.GuestLoggedOnUserName}|guest_os={Session.GuestOperatingSystemName}|host={Event.Host}|participant={Connection.ParticipantName}|process_type={Connection.ProcessType}|address={Connection.NetworkAddress}|data={Event.Data}
```

## What each record becomes

| Record | Schema |
| --- | --- |
| LoginAttempt, ChangePasswordAttempt | Auth |
| Connected or Disconnected by a technician (process_type Host) | Auth, as a remote logon or logoff of the guest machine |
| Connected or Disconnected by the guest (an agent coming online) | Generic |
| Other session events | ManagementEvent, with the command in `command` and output or file names in `result` |

Not checked against a live server: the format of `{Event.Time}` (the parser reads ISO 8601 and US month/day/year times as UTC), the UserSource values, and Data that spans several lines, which HTTP Ingest splits into extra records. Send a test event and compare it with `samples.log` before you rely on it.

ConnectWise Labs also publishes a Splunk Integration extension that sends session and security events to a Splunk HTTP Event Collector. HTTP Ingest accepts the Splunk token scheme, so it may work without a relay, but ConnectWise doesn't publish the extension's record format and it hasn't been tested here, so this entry doesn't parse it.
