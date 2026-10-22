# Cybereason to Sophos NG-SIEM

Cybereason (LevelBlue) sends MalOp notifications from the Detection Server and user audit records from the WebApp server as CEF over syslog. These parsers read them once they reach the Sophos NG-SIEM data collector.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog over TCP, if you don't have one.
2. Syslog forwarding isn't a setting in the Cybereason console. Ask Cybereason Technical Support through the support portal to send the MalOp syslog and the User Audit syslog to the data collector's address and port. Cybereason sends unencrypted TCP, from the Detection Server, so allow that connection through your firewalls.

The CEF Forwarder, a Docker tool Cybereason Technical Support provides that reads the API and sends CEF, writes a different CEF layout that these parsers don't read.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Events |
| --- | --- |
| `CYBEREASON_CEF_PARENT` | Claims Cybereason Malop, Malware and UserAction lines; Malware lines stay generic |
| `CYBEREASON_CEF_CHILD_THIRDPARTYALERT` | MalOp Created, Updated and Closed lines, and Machine Information lines, to Thirdparty |
| `CYBEREASON_CEF_CHILD_AUTH` | Console sign-ins (UserAction General/Login) to Auth |
| `CYBEREASON_CEF_CHILD_MGMT` | Other console user actions, such as queries, machine isolation and remediation, to Management Event |

Use Run Test with your own lines before you turn the parsers on.

## What you get

- Thirdparty: the MalOp ID as the alert ID, the key suspicion as the title, the detection type and suspect in the summary, the activity type as the category, the creation and update times, CRITICAL for Cybereason's CEF severity 10, and the affected machine on Machine Information lines. The detection type, suspect, counts and console link go to `additional_data`.
- Auth: the user, the address and machine signed in from, and the result from `actionSuccess`.
- Management Event: the user, the action (`Investigation/Query` as the operation name, `Query` as the operation), the query or MalOp acted on, the machine, and the result.
