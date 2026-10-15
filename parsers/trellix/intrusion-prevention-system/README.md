# Trellix Intrusion Prevention System to Sophos NG-SIEM

The Trellix IPS Manager (formerly McAfee Network Security Platform) builds each syslog message from a template of `$IV_` variables, and Trellix recommends a custom template because the default one may change between releases. Use the two templates below, one for IPS alerts and one for user activity. Each is a list of KEY=value pairs joined by `|`, and each key is the variable's name without `IV_`.

The parser also reads the Manager's default alert message, with fewer fields: no category, attack ID, protocol or MITRE details.

## IPS alerts

1. In the Manager, go to Manager > (admin domain) > Setup > Notification > IPS Events > Syslog.
2. Add a target server profile for your data collector: UDP, or TCP on port 514.
3. Add a syslog notification profile that uses that server, set Message to the template below on one line, and save.

```
TRELLIX_IPS=alert|ALERT_ID=$IV_ALERT_ID$|ATTACK_TIME=$IV_ATTACK_TIME$|SENSOR_NAME=$IV_SENSOR_NAME$|INTERFACE=$IV_INTERFACE$|ADMIN_DOMAIN=$IV_ADMIN_DOMAIN$|ATTACK_ID=$IV_ATTACK_ID$|ATTACK_NAME=$IV_ATTACK_NAME$|ATTACK_SEVERITY=$IV_ATTACK_SEVERITY$|ATTACK_CONFIDENCE=$IV_ATTACK_CONFIDENCE$|CATEGORY=$IV_CATEGORY$|SUB_CATEGORY=$IV_SUB_CATEGORY$|DETECTION_MECHANISM=$IV_DETECTION_MECHANISM$|DIRECTION=$IV_DIRECTION$|RESULT_STATUS=$IV_RESULT_STATUS$|SOURCE_IP=$IV_SOURCE_IP$|SOURCE_PORT=$IV_SOURCE_PORT$|DESTINATION_IP=$IV_DESTINATION_IP$|DESTINATION_PORT=$IV_DESTINATION_PORT$|NETWORK_PROTOCOL=$IV_NETWORK_PROTOCOL$|APPLICATION_PROTOCOL=$IV_APPLICATION_PROTOCOL$|VLAN_ID=$IV_VLAN_ID$|ATTACK_COUNT=$IV_ATTACK_COUNT$|ATTACK_SIGNATURE=$IV_ATTACK_SIGNATURE$|TTPID=$IV_TTPID$|TACTIC=$IV_TACTIC$|TECHNIQUE=$IV_TECHNIQUE$|MALWARE_FILE_NAME=$IV_MALWARE_FILE_NAME$|MALWARE_FILE_SHA256_HASH=$IV_MALWARE_FILE_SHA256_HASH$|CC_DOMAIN=$IV_CC_DOMAIN$
```

Each alert goes to NIDS: the attack name, category, attack ID, result (as the action, with blocked set when it says Blocked), direction, addresses, ports, protocol and VLAN, and the rest to event_metadata.

## User activity

1. Go to Manager > (admin domain) > Setup > Notification > User Activity > Syslog, turn on syslog notification, and set the server, protocol and port.
2. Set Message Preference to Customized, set the message to the template below on one line, and save.

```
TRELLIX_IPS=audit|AUDIT_TIME=$IV_AUDIT_TIME$|AUDIT_USER=$IV_AUDIT_USER$|AUDIT_DOMAIN=$IV_AUDIT_DOMAIN$|AUDIT_CATEGORY=$IV_AUDIT_CATEGORY$|AUDIT_ACTION=$IV_AUDIT_ACTION$|AUDIT_RESULT=$IV_AUDIT_RESULT$|AUDIT_MESSAGE=$IV_AUDIT_MESSAGE$
```

Each record goes to ManagementEvent with the user, action, category, result and message.

Keep `TRELLIX_IPS=alert|` and `TRELLIX_IPS=audit|` at the start: the parser's confirm string looks for them. You can leave out or reorder the other pairs. Don't use `%`, `/` or `$` in the template text; Trellix reserves them.

From 11.1 Update 5 the Manager adds a `[Mmm dd, yyyy hh:mm:ss]` time to every message. The parser takes it off either end and uses it as the event time; before that release it uses the syslog header time. Both are read as UTC.

Faults and firewall access events aren't covered. Not checked against a live Manager: the values the Manager puts in each variable, such as the result and direction text, and whether anything sits between the syslog time and the message. The parser looks for the template or the default message anywhere after the time. Send one test alert and compare it with `samples.log` before you rely on it.
