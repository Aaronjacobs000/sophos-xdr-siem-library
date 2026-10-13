# ThreatLocker Detect to Sophos NG-SIEM

ThreatLocker has no syslog export. A ThreatLocker Detect policy can post each event it matches straight from the agent to a Sophos NG-SIEM HTTP Ingest integration.

1. In Sophos Fusion, add an HTTP Ingest integration (Security Operations > Integrations > Marketplace > Custom) and copy its URL and integration key.
2. In the ThreatLocker portal, open Modules > ThreatLocker Detect and add a policy. Set the conditions to the events you want, for example Policy Action matches Deny (Option to Request).
3. Add the action Call Rest API (Client):
   - Method: POST
   - URL: the HTTP Ingest URL
   - Content Type: application/json
   - Headers: `Authorization: Bearer <integration key>`
   - Body: the template below, on one line
4. Deploy the policies.

```json
{"source":"ThreatLocker Detect","DetectPolicyName":"%DetectPolicyName%","DateTime":"%DateTime%","Organization":"%Organization%","Hostname":"%Hostname%","ComputerId":"%ComputerId%","DeviceType":"%DeviceType%","Username":"%Username%","ActionType":"%ActionType%","PolicyAction":"%PolicyAction%","EffectiveAction":"%EffectiveAction%","PolicyName":"%PolicyName%","PolicyId":"%PolicyId%","ApplicationName":"%ApplicationName%","FullPath":"%FullPath%","ProcessPath":"%ProcessPath%","ProcessId":"%ProcessId%","CmdLineParameters":"%CmdLineParameters%","CreatedByProcess":"%CreatedByProcess%","SHA256":"%SHA256%","TLHash":"%TLHash%","Certificates":"%Certificates%","FileSize":"%FileSize%","SourceIpAddress":"%SourceIpAddress%","DestinationIpAddress":"%DestinationIpAddress%","DestinationPort":"%DestinationPort%","DestinationDomain":"%DestinationDomain%","NetworkDirection":"%NetworkDirection%","TransportLayer":"%TransportLayer%","Occurrences":"%Occurrences%","MonitorOnly":"%MonitorOnly%","Ringfenced":"%Ringfenced%"}
```

Keep `"source":"ThreatLocker Detect"` as the first key: the parser's confirm string looks for it. Don't put `[]` in the body; ThreatLocker sends `[Object, object]` for it.

Each record becomes a third-party alert: the Detect policy name is the title, deny and block decisions are BLOCKED, and the file, process, hash and network fields go to their alert fields or to additional_data.

Not checked against a live ThreatLocker agent: the values ThreatLocker puts in each variable, the %DateTime% format, and whether it escapes backslashes in paths. Send one test event and compare it with `samples.log` before you rely on it.
