# Symantec DLP to Sophos NG-SIEM

Symantec Data Loss Prevention sends an incident to syslog only through a response rule, and the rule's message is free text that you write. This entry reads the CEF message Broadcom publishes in knowledge base article 256282 (linked from this entry's docs), plus a few more incident variables in the same KEY=$VARIABLE$ form.

1. In the Enforce Server console, go to Manage > Policies > Response Rules and add an automated response rule with the action **All: Log to a Syslog Server**.
2. Set Host to your data collector, Port to 514, and Protocol to UDP or TCP. From 25.1 you also pick the syslog format: RFC 3164 or RFC 5424 both work.
3. Paste one of the messages below into Message, on one line, and set Level to 6 - Informational.
4. Add the response rule to each policy whose incidents you want in Sophos NG-SIEM.

Broadcom's message, as in KB 256282:

```
CEF:0|Broadcom|DLP|16.0|ruleID|$POLICY$|5|INCIDENT_ID=$INCIDENT_ID$ APPLICATION_USER=$APPLICATION_USER$ ENDPOINT_MACHINE=$ENDPOINT_MACHINE$ ENDPOINT_USERNAME=$ENDPOINT_USERNAME$ MACHINE_IP=$MACHINE_IP$ SEVERITY=$SEVERITY$ BLOCKED=$BLOCKED$
```

The same message with the rules, channel, sender, recipients and file, which the parser also reads:

```
CEF:0|Broadcom|DLP|16.0|ruleID|$POLICY$|5|INCIDENT_ID=$INCIDENT_ID$ APPLICATION_USER=$APPLICATION_USER$ ENDPOINT_MACHINE=$ENDPOINT_MACHINE$ ENDPOINT_USERNAME=$ENDPOINT_USERNAME$ MACHINE_IP=$MACHINE_IP$ SEVERITY=$SEVERITY$ BLOCKED=$BLOCKED$ RULES=$RULES$ PROTOCOL=$PROTOCOL$ SENDER=$SENDER$ RECIPIENTS=$RECIPIENTS$ MATCH_COUNT=$MATCH_COUNT$ STATUS=$STATUS$ MONITOR_NAME=$MONITOR_NAME$ DESTINATION_IP=$DESTINATION_IP$ ATTACHMENT_FILENAME=$ATTACHMENT_FILENAME$ URL=$URL$ INCIDENT_SNAPSHOT=$INCIDENT_SNAPSHOT$
```

Keep `CEF:0|Broadcom|DLP|` at the start and the `INCIDENT_ID=` key: the parser's confirm string looks for them. You can change the version field, and you can leave out or reorder the other keys.

Each incident becomes a third-party alert: the policy is the title, $SEVERITY$ the severity, $BLOCKED$ (yes or no) the action, the endpoint user, machine and IP or the sender the source, and the rest goes to additional_data.

DLP doesn't escape the values it fills in. A `|` in a policy name breaks the CEF header, a value that contains a space followed by a word and `=` is cut there, and `\\` reads as one backslash. Broadcom KB 159680 caps a syslog message at 1,024 characters, so drop keys you don't need if long recipient lists get cut.

Not checked against a live Enforce Server: the values DLP puts in each variable and the syslog header it adds. Send one test incident and compare it with `samples.log` before you rely on it.
