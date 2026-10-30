// Rules-only field mapping: an alias dictionary from common source key names to parser
// fields, value-shape fallbacks, enum value guesses, and a schema guess per event type.
// Nothing here calls out of the browser.

import { fieldsByParser, typeKind, enumMembers, messageType, schemaInfo, hasEventMetadata, SCHEMA_IDS, GENERIC } from './schemas.js';

const n = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');

// Source key (normalized: lowercase, letters and digits only) -> parser fields, best first.
// The first field that exists in the target schema wins.
const ALIASES = {};
function alias(fields, keys) {
  for (const k of keys) ALIASES[n(k)] = [...(ALIASES[n(k)] || []), ...fields];
}
// IDS conventions (Snort and Suricata): the rule text is the message, its category the classification.
alias(['message$', 'threatName$', 'title$'], ['signature', 'signature_name', 'sig_name', 'msg']);
alias(['classification$', 'threatCategory$', 'alertCategory$', 'vendorAlertType$'], ['category', 'classification', 'alert_category', 'classtype']);
alias(['sourceAddress$', 'senderIp$', 'clientAddress$'], ['src', 'srcip', 'src_ip', 'source_ip', 'sourceip', 'source_address', 'sourceaddress', 'src_addr', 'srcaddr', 'saddr', 'ip_src', 'client_ip', 'clientip', 'c-ip', 'remote_ip', 'remoteip', 'remote_addr', 'ipaddress', 'ip_address', 'callerip', 'callerIpAddress', 'sourceIPAddress', 'src_ipaddr', 'sip']);
alias(['destinationAddress$', 'targetAddress$', 'serverAddress$'], ['dst', 'dstip', 'dst_ip', 'dest', 'dest_ip', 'destip', 'destination_ip', 'destinationip', 'destination_address', 'destinationaddress', 'dst_addr', 'dstaddr', 'daddr', 'ip_dst', 'server_ip', 'serverip', 's-ip', 'target_address', 'target_ip', 'targetip', 'dip']);
alias(['sourcePort$', 'sourcePortNumber$'], ['spt', 'sport', 'srcport', 'src_port', 'source_port', 'sourceport', 'client_port', 'clientport']);
alias(['destinationPort$', 'targetPortNumber$'], ['dpt', 'dport', 'dstport', 'dst_port', 'dest_port', 'destination_port', 'destinationport', 'target_port', 'targetport', 'server_port', 'serverport']);
alias(['protocol$'], ['proto', 'protocol', 'ip_protocol', 'protocol_id', 'transport']);
alias(['sourceMac$', 'clientMac$'], ['smac', 'src_mac', 'srcmac', 'source_mac', 'sourcemac', 'client_mac', 'mac']);
alias(['destinationMac$', 'serverMac$'], ['dmac', 'dst_mac', 'dstmac', 'destination_mac', 'destinationmac']);
alias(['sourceNatAddress$'], ['src_nat', 'srcnat', 'transip', 'nat_src_ip', 'source_nat_address', 'src_translated_ip']);
alias(['destinationNatAddress$'], ['dst_nat', 'dstnat', 'nat_dst_ip', 'destination_nat_address', 'dst_translated_ip']);
alias(['sourceNatPort$'], ['transport_port', 'nat_src_port', 'src_translated_port', 'source_nat_port']);
alias(['destinationNatPort$'], ['nat_dst_port', 'dst_translated_port', 'destination_nat_port']);
alias(['txByteCount$'], ['sentbyte', 'bytes_out', 'bytesout', 'out', 'sent_bytes', 'bytes_sent', 'tx_bytes', 'txbytes', 'orig_bytes', 'sc-bytes', 'bytes_toserver']);
alias(['rxByteCount$'], ['rcvdbyte', 'bytes_in', 'bytesin', 'in', 'received_bytes', 'bytes_received', 'rx_bytes', 'rxbytes', 'resp_bytes', 'cs-bytes', 'bytes_toclient']);
alias(['txPacketCount$'], ['sentpkt', 'packets_out', 'pkts_out', 'tx_packets', 'orig_pkts', 'pkts_toserver']);
alias(['rxPacketCount$'], ['rcvdpkt', 'packets_in', 'pkts_in', 'rx_packets', 'resp_pkts', 'pkts_toclient']);
alias(['flowAction$', 'actionTaken$', 'action$', 'sensorTypeActions$', 'status$'], ['act', 'action', 'fw_action', 'disposition', 'action_taken', 'actiontaken', 'verdict', 'result_action']);
alias(['actionResult$', 'action$', 'status$'], ['result', 'outcome', 'status_result', 'auth_result', 'login_result', 'eventoutcome']);
alias(['direction$', 'requestDirection$'], ['direction', 'dir', 'deviceDirection', 'traffic_direction', 'flow_direction', 'inbound']);
alias(['applicationName$', 'processName$', 'process$'], ['app', 'application', 'app_name', 'appname', 'application_name', 'service', 'svc']);
alias(['processName$', 'imagePath$', 'applicationName$', 'processFilename$'], ['process', 'processname', 'process_name', 'proc', 'image', 'image_path', 'exe', 'executable', 'process_path', 'sproc']);
alias(['commandline$'], ['cmd', 'cmdline', 'command_line', 'commandline', 'command', 'process_command_line']);
alias(['processId$'], ['pid', 'process_id', 'processid', 'spid']);
alias(['parentProcessId$'], ['ppid', 'parent_pid', 'parent_process_id', 'parentprocessid']);
alias(['parentImagePath$'], ['parent_image', 'parent_process', 'parent_process_name', 'parentimage', 'parent_image_path']);
alias(['targetUserName$', 'userName$', 'username$', 'sourceUsername$', 'sourceUserName$', 'userPrincipalName$'], ['user', 'username', 'user_name', 'usr', 'duser', 'suser', 'login', 'account', 'account_name', 'accountname', 'logonname', 'uid', 'userid', 'user_id', 'principal', 'userprincipalname', 'upn', 'targetusername', 'target_user', 'cs-username', 'srcuser']);
alias(['sourceUserName$', 'sourceUsername$'], ['source_user', 'source_username', 'sourceuser', 'subject_user', 'subjectusername', 'actor', 'actor_user', 'initiator']);
alias(['targetDomainName$', 'domainName$'], ['domain', 'user_domain', 'targetdomainname', 'domain_name', 'realm']);
alias(['targetHostName$', 'computerName$', 'hostId$', 'clientHostname$'], ['hostname', 'host', 'host_name', 'devname', 'device_name', 'devicename', 'dvchost', 'computer', 'computername', 'computer_name', 'workstation', 'machine', 'endpoint', 'shost', 'dhost', 'client_hostname']);
alias(['hostId$'], ['dvc', 'device_ip', 'deviceaddress', 'host_ip', 'agent_ip', 'devid', 'device_id', 'serial', 'sn']);
alias(['sensorVersion$', 'agentVersion$'], ['version', 'device_version', 'sw_version', 'agent_version', 'agentversion', 'product_version']);
alias(['sensorEventId$', 'eventId$', 'alertId$'], ['event_id', 'eventid', 'logid', 'log_id', 'record_id', 'recordid', 'msgid', 'message_id', 'uuid', 'eventuid', 'alert_id', 'alertid', 'id']);
alias(['startTimestampUsec$', 'eventTimeUsec$'], ['start', 'starttime', 'start_time', 'flow_start', 'session_start']);
alias(['endTimestampUsec$'], ['end', 'endtime', 'end_time', 'flow_end', 'session_end']);
alias(['eventTimeUsec$'], ['time', 'timestamp', 'ts', 'datetime', 'date_time', 'eventtime', 'event_time', 'occured', 'occurred', 'rt', 'devtime', 'event_ts', 'created', 'created_at', 'createdtime', 'logtime', 'generated', 'timegenerated', 'eventdatetime', '@timestamp', 'time_generated', 'detect_time', 'detectiontime']);
alias(['message$', 'summary$', 'title$', 'winSummary$'], ['msg', 'message', 'description', 'desc', 'event', 'event_description', 'summary', 'title', 'reason', 'details']);
alias(['classification$', 'threatName$', 'title$'], ['signature', 'sig', 'rule', 'rule_name', 'rulename', 'attack', 'attackname', 'alert', 'alert_name', 'threat', 'threat_name', 'threatname', 'virus', 'virusname', 'malware', 'malware_name', 'detection', 'detection_name', 'name']);
alias(['signatureId$', 'vendorSignatureId$'], ['sid', 'signature_id', 'signatureid', 'rule_id', 'ruleid', 'attackid', 'attack_id', 'sigid', 'vendor_signature_id']);
alias(['priority$', 'agentPriority$', 'vendorSeverity$', 'severity$'], ['severity', 'sev', 'level', 'priority', 'pri', 'risk', 'risk_level', 'crlevel', 'alert_severity', 'threat_level', 'threatlevel']);
alias(['policyName$', 'policyId$'], ['policy', 'policy_name', 'policyname', 'policyid', 'policy_id', 'rule_policy', 'acl', 'rule_set']);
alias(['vendorAlertType$', 'threatCategory$', 'alertCategory$', 'logType$'], ['threat_type', 'threattype', 'alert_type', 'alerttype', 'category', 'cat', 'subtype', 'threat_category', 'classification_type']);
alias(['threatType$'], ['object_type', 'objecttype', 'detection_type', 'scan_type']);
alias(['filePath$', 'imagePath$', 'targetFilename$'], ['file', 'filepath', 'file_path', 'path', 'filename', 'file_name', 'object', 'object_uri', 'objecturi', 'target_file', 'fname']);
alias(['fileHash$.md5$', 'programHash$.md5$', 'processFileHash$.md5$'], ['md5', 'filehash_md5', 'file_md5', 'hash_md5', 'md5hash']);
alias(['fileHash$.sha1$', 'programHash$.sha1$', 'processFileHash$.sha1$'], ['sha1', 'hash', 'filehash', 'file_hash', 'sha1hash', 'hash_sha1', 'file_sha1']);
alias(['fileHash$.sha256$', 'programHash$.sha256$', 'processFileHash$.sha256$'], ['sha256', 'sha256hash', 'hash_sha256', 'file_sha256', 'filehash256']);
alias(['agentDeviceId$'], ['source_uuid', 'device_uuid', 'deviceuuid', 'agent_id', 'agentid', 'device_guid', 'computer_id', 'endpoint_id', 'machine_id', 'host_uuid']);
alias(['urlString$', 'destinationUrl$', 'uriPathRaw$'], ['url', 'uri', 'request', 'request_url', 'requesturl', 'full_url', 'cs-uri', 'cs-uri-stem', 'dest_url', 'target_url']);
alias(['uriHostRaw$', 'queryName$', 'uriHost$'], ['hostheader', 'http_host', 'url_host', 'domain_name', 'fqdn', 'cs-host', 'dhost', 'site', 'website']);
alias(['httpMethod$'], ['method', 'http_method', 'request_method', 'requestmethod', 'cs-method', 'httpmethod', 'verb']);
alias(['userAgent$'], ['useragent', 'user_agent', 'http_user_agent', 'agent', 'ua', 'requestclientapplication', 'cs(user-agent)', 'browser']);
alias(['referer$'], ['referer', 'referrer', 'http_referer', 'http_referrer', 'cs(referer)']);
alias(['responseCode$'], ['status', 'status_code', 'statuscode', 'http_status', 'response_code', 'responsecode', 'sc-status', 'rcode', 'return_code']);
alias(['uriPathRaw$'], ['url_path', 'uri_path', 'request_path', 'path_info', 'cs-uri-stem']);
alias(['uriQueryRaw$'], ['url_query', 'uri_query', 'query_string', 'querystring', 'cs-uri-query']);
alias(['queryName$'], ['query', 'qname', 'query_name', 'queryname', 'dns_query', 'dnsquery', 'question', 'rrname', 'domain_requested', 'domain']);
alias(['queryType$'], ['qtype', 'query_type', 'querytype', 'rrtype', 'record_type']);
alias(['responseCode$'], ['rcode_name', 'dns_rcode', 'response_code']);
alias(['mfaUsed$'], ['mfa', 'mfa_used', 'mfaused', 'is_mfa', 'two_factor', '2fa']);
alias(['logonType$'], ['logon_type', 'logontype']);
alias(['authSystem$'], ['auth_system', 'authsystem', 'auth_method', 'authmethod', 'authentication_method']);
alias(['sessionId$'], ['session', 'session_id', 'sessionid', 'sid_session']);
alias(['subject$'], ['subject', 'email_subject', 'mail_subject']);
alias(['fromEmailAddress$'], ['from', 'sender', 'from_address', 'mail_from', 'fromaddress', 'sender_address']);
alias(['toEmailAddress$'], ['to', 'recipient', 'recipients', 'rcpt', 'to_address', 'toaddresses', 'rcpt_to']);
alias(['eventName$', 'logType$'], ['event_name', 'eventname', 'operation', 'api', 'api_call', 'activity']);
alias(['eventSource$'], ['event_source', 'eventsource', 'service_name', 'provider']);
alias(['region$'], ['region', 'aws_region', 'awsregion', 'location']);
alias(['vendor$', 'provider$'], ['vendor', 'device_vendor']);

const SHAPE_FIELDS = {
  ip: (key) => (/(^|[^a-z])(src|source|client|orig|from|remote|caller|attacker|s)([^a-z]|ip|addr|$)/i.test(key) ? ['sourceAddress$'] : /(dst|dest|destination|target|server|resp|to|victim|d)([^a-z]|ip|addr|$)/i.test(key) ? ['destinationAddress$', 'targetAddress$'] : []),
  port: (key) => (/(src|source|client|s)port|sport|spt/i.test(key) ? ['sourcePort$', 'sourcePortNumber$'] : ['destinationPort$', 'targetPortNumber$']),
  md5: () => ['fileHash$.md5$', 'programHash$.md5$'],
  sha1: () => ['fileHash$.sha1$', 'programHash$.sha1$'],
  sha256: () => ['fileHash$.sha256$', 'programHash$.sha256$'],
  time: () => ['eventTimeUsec$'],
  'epoch-s': () => ['eventTimeUsec$'],
  'epoch-ms': () => ['eventTimeUsec$'],
  url: () => ['urlString$', 'destinationUrl$'],
  'file-uri': () => ['filePath$'],
  'win-path': () => ['filePath$', 'imagePath$', 'processName$'],
  'unix-path': () => ['filePath$', 'imagePath$'],
  email: () => ['userPrincipalName$', 'targetUserName$', 'userName$'],
  'domain-user': () => ['targetUserName$', 'userName$', 'username$', 'sourceUsername$'],
  mac: () => ['sourceMac$', 'clientMac$'],
  uuid: () => ['agentDeviceId$', 'sensorEventId$'],
};

// Words in an event type's value or keys that point at a schema.
const SCHEMA_HINTS = [
  ['scwx.antivirus', /threat|virus|malware|quarantin|antivirus|\bav\b|infect|detection/i],
  ['scwx.auth', /auth|login|logon|logoff|sign.?in|signin|password|mfa|sso|vpn.?(login|auth)/i],
  ['scwx.nids', /ids|ips|intrusion|exploit|attack|signature|firewall.?aggregat|hips|alert/i],
  ['scwx.netflow', /traffic|flow|conn|session|firewall|forward|deny|allow|packet|netflow/i],
  ['scwx.dnsquery', /\bdns\b|query|resolve|dnsmasq|named/i],
  ['scwx.http', /http|web|url|proxy|request|access.?log/i],
  ['scwx.process', /process|exec|spawn|command/i],
  ['scwx.email', /mail|smtp|message.?trace|phish|spam/i],
  ['scwx.cloudaudit', /cloudtrail|audit|api.?call|activity.?log/i],
  ['scwx.dhcp', /dhcp|lease/i],
  ['scwx.thirdpartyalert', /alert|incident|finding|case/i],
];

// Value words -> enum member words. Members match when their words appear in the value.
const ENUM_SYNONYMS = [
  [/^(allow|allowed|accept|accepted|permit|permitted|pass|passed|ok)$/i, ['FW_ALLOWED', 'HTTP_ALLOWED', 'SUCCEEDED', 'SUCCESS']],
  [/^(deny|denied|drop|dropped|block|blocked|reject|rejected|reset|discard|prevent|prevented)$/i, ['FW_BLOCKED', 'HTTP_BLOCKED', 'BLOCKED', 'FAILED']],
  [/success|succeed|ok$|accepted/i, ['SUCCESS', 'SUCCEEDED', 'LOGON']],
  [/fail|error|invalid|bad/i, ['FAILED', 'FAILURE']],
  [/delet|remov|clean/i, ['DELETED']],
  [/quarantin/i, ['QUARANTINED']],
  [/block|deny|prevent/i, ['BLOCKED', 'FW_BLOCKED', 'HTTP_BLOCKED']],
  [/kill|terminat/i, ['TERMINATED']],
  [/alert|detect|log only|monitor/i, ['ALERT']],
  [/restor/i, ['RESTORED']],
  [/^(none|no action|ignored?)$/i, ['NONE']],
  [/^(in|inbound|ingress|incoming|true)$/i, ['INBOUND']],
  [/^(out|outbound|egress|outgoing|false)$/i, ['OUTBOUND']],
  [/critical/i, ['CRITICAL']], [/high/i, ['HIGH']], [/medium|moderate|warn/i, ['MEDIUM']], [/^low|minor/i, ['LOW']], [/info|notice|debug/i, ['INFO']],
  [/^file$/i, ['FILE']], [/process/i, ['PROCESS']], [/memory/i, ['MEMORY']], [/scan/i, ['SCAN']],
  [/trojan/i, ['TROJAN']], [/ransom/i, ['RANSOMWARE']], [/virus|worm/i, ['VIRUS']], [/backdoor/i, ['BACKDOOR']], [/miner|coin/i, ['MINER']], [/exploit/i, ['EXPLOIT']], [/pua|pup|potentially|adware|application/i, ['APPLICATION']], [/malware/i, ['MALWARE']],
  [/logon|login|sign.?in/i, ['LOGON', 'ACCOUNT_LOGON']], [/logoff|logout|sign.?out/i, ['LOGOFF', 'ACCOUNT_LOGOFF']],
];

export function enumDefault(members) {
  return members.find((m) => /^UNKNOWN|_UNKNOWN$|^UNCLASSIFIED$|^UNSET$|^UNDEFINED$/.test(m)) || members[0];
}

// Guess a member for one source value.
export function guessEnum(type, value) {
  const members = enumMembers(type) || [];
  const v = String(value ?? '').trim();
  if (!v) return null;
  const exact = members.find((m) => m.toLowerCase() === v.toLowerCase().replace(/[\s-]+/g, '_'));
  if (exact) return exact;
  for (const [re, wants] of ENUM_SYNONYMS) {
    if (!re.test(v)) continue;
    const hit = wants.find((w) => members.includes(w));
    if (hit) return hit;
  }
  const loose = members.find((m) => m.length > 3 && v.toLowerCase().replace(/[^a-z]/g, '').includes(m.toLowerCase().replace(/[^a-z]/g, '')));
  return loose || null;
}

// A stem of the source value to match with CONTAINS, as in the docs-style IF chains.
export function enumStem(value) {
  const v = String(value).toLowerCase().trim();
  if (v.length <= 5) return v;
  return v.replace(/(ed|ing|es|s)$/, '').slice(0, 9);
}

// Mapping suggestions for one event type. keys: analyseSample().keys restricted to its lines.
const AMBIGUOUS = new Set(['version', 'id', 'type', 'name', 'state', 'flags', 'txid', 'rev', 'length', 'size', 'count', 'age', 'reason', 'status', 'result', 'value', 'key', 'code', 'host', 'hostname']);

const NUMERIC_SHAPES = new Set(['int', 'int-string', 'port', 'epoch-s', 'epoch-ms', 'float', 'empty']);

// Whether a number fits a 32-bit field of this type. One that doesn't wraps there, as Cisco
// Secure Endpoint's 19-digit id does in event_id; text that isn't a number is left to the shape.
function fits32(v, type) {
  const n = typeof v === 'number' ? v : typeof v === 'string' && /^\s*-?\d+\s*$/.test(v) ? Number(v) : null;
  if (n === null) return true;
  return type === 'uint32' ? n >= 0 && n <= 4294967295 : n >= -2147483648 && n <= 2147483647;
}

// Whether a key's values can go in a field of this type at all.
function compatible(k, type, field) {
  if (!type) return false;
  if (/^(u|s)?int32$/.test(type) && !k.values.every((v) => fits32(v, type))) return false;
  if (/^(u|s)?int(32|64)$/.test(type)) return NUMERIC_SHAPES.has(k.shape) || (/Usec\$$/.test(field) && k.shape === 'time') || field === 'protocol$' || field === 'queryType$' || (field === 'responseCode$' && type === 'int32');
  if (type === 'float' || type === 'double') return NUMERIC_SHAPES.has(k.shape);
  if (type === 'bool') return k.shape === 'bool' || k.shape === 'bool-string';
  return true;
}

function typeOf(fields, f) {
  const [head, sub] = f.split('.');
  const top = fields.get(head);
  if (!top) return null;
  if (!sub) return top.type;
  const st = (messageType(top.type) || []).find((x) => x.parser === sub);
  return st ? st.type : null;
}

export function suggestMappings(keys, schemaId) {
  const fields = fieldsByParser(schemaId);
  const used = new Set();
  const out = [];
  let k = null;
  const available = (f, key = k) => {
    const head = f.split('.')[0];
    return fields.has(head) && !fields.get(head).derived && !used.has(f) && compatible(key, typeOf(fields, f), f);
  };
  const aliasesOf = (key) => {
    const short = n(key.key.split('.').pop());
    const full = n(key.key);
    // A nested key with a generic last part (dns.version, flow.state) doesn't get the
    // top-level meaning of that name.
    const nested = key.key.includes('.') || key.key.includes('[');
    return [...(ALIASES[full] || []), ...(nested && AMBIGUOUS.has(short) ? [] : ALIASES[short] || [])];
  };
  // A key with only a time's shape leaves a time field to a later key named for it that has a
  // value on as many lines: Tailscale's deferredAt is a time, but eventTime is the event's.
  const filled = (key) => key.values.filter((v) => v !== null && v !== '').length;
  const named = (c) => /Usec\$$/.test(c) && keys.slice(keys.indexOf(k) + 1).some((x) => filled(x) >= filled(k) && aliasesOf(x).find((a) => available(a, x)) === c);
  for (k of keys) {
    let pick = null;
    let origin = 'alias';
    for (const c of aliasesOf(k)) if (available(c)) { pick = c; break; }
    if (!pick && SHAPE_FIELDS[k.shape]) {
      for (const c of SHAPE_FIELDS[k.shape](k.key)) if (available(c) && !named(c)) { pick = c; origin = 'shape'; break; }
    }
    if (!pick) continue;
    // A hash alias only fits when the value has that hash's length.
    if (/fileHash\$|programHash\$|processFileHash\$/.test(pick) && ['md5', 'sha1', 'sha256'].includes(k.shape)) {
      const want = pick.replace(/^(\w+\$)\.\w+\$$/, `$1.${k.shape}$`);
      if (available(want)) pick = want;
    }
    used.add(pick);
    out.push(makeMapping(k, pick, schemaId, origin));
    // A hostname also identifies the host for Data Lake Search, as hostId$.
    if (/^(computerName\$|targetHostName\$)$/.test(pick) && available('hostId$') && /host|computer|device|machine/i.test(k.key)) {
      used.add('hostId$');
      out.push(makeMapping(k, 'hostId$', schemaId, 'alias'));
    }
  }
  return out;
}

export function makeMapping(k, field, schemaId, origin = 'you') {
  const fields = fieldsByParser(schemaId);
  const head = field.split('.')[0];
  const f = fields.get(head);
  const m = { key: k.key, path: k.path, index: k.index, field, origin, transform: { kind: 'none' } };
  if (!f) return m;
  const kind = typeKind(f.type);
  if (kind === 'enum') {
    const values = [...new Set(k.values.map((v) => String(v)))];
    const map = [];
    for (const v of values) {
      const g = guessEnum(f.type, v);
      if (g) map.push({ match: enumStem(v), kind: 'contains', member: g, seen: v });
    }
    m.transform = { kind: 'enum', type: f.type, map, default: enumDefault(enumMembers(f.type)) };
    m.origin = 'enum';
  } else if (/Usec\$$/.test(field)) {
    if (k.shape === 'epoch-s') m.transform = { kind: 'epoch-s' };
    else if (k.shape === 'epoch-ms') m.transform = { kind: 'epoch-ms' };
    else m.transform = { kind: 'datetime', layout: k.layout || '2006-01-02T15:04:05Z07:00' };
    m.origin = origin === 'alias' ? 'shape' : origin;
  } else if (field === 'protocol$') {
    m.transform = { kind: 'protocol' };
  } else if (field === 'queryType$' && !NUMERIC_SHAPES.has(k.shape)) {
    m.transform = { kind: 'dns-type' };
  } else if (field === 'responseCode$' && f.type === 'int32' && !NUMERIC_SHAPES.has(k.shape)) {
    m.transform = { kind: 'dns-rcode' };
  } else if (/^(uint|int|sint)/.test(f.type) && k.values.some((v) => typeof v === 'string')) {
    m.transform = { kind: 'int' };
  } else if (f.type === 'bool') {
    m.transform = { kind: 'bool' };
  } else if (k.shape === 'file-uri' && field === 'filePath$') {
    m.transform = { kind: 'replace', from: 'file:///', to: '' };
    m.origin = 'shape';
  }
  return m;
}

// A schema only fits when at least one of its defining fields maps.
const DEFINING = {
  'scwx.http': ['urlString$', 'uriPathRaw$', 'uriHostRaw$', 'uriHost$', 'httpMethod$', 'userAgent$', 'responseCode$', 'referer$'],
  'scwx.dnsquery': ['queryName$'],
  'scwx.antivirus': ['threatName$', 'threatType$', 'threatCategory$', 'actionTaken$', 'fileHash$.md5$', 'fileHash$.sha1$', 'fileHash$.sha256$'],
  'scwx.process': ['commandline$', 'imagePath$', 'processId$', 'parentImagePath$'],
  'scwx.email': ['fromEmailAddress$', 'toEmailAddress$', 'subject$'],
  'scwx.auth': ['targetUserName$', 'sourceUserName$', 'action$', 'actionResult$', 'mfaUsed$', 'logonType$', 'authSystem$'],
  'scwx.cloudaudit': ['eventName$', 'eventSource$', 'region$', 'userName$'],
  'scwx.dhcp': ['clientMac$', 'clientAddress$', 'clientHostname$'],
  'scwx.nids': ['signatureId$', 'classification$', 'message$', 'generatorId$'],
  'scwx.netflow': ['sourceAddress$', 'destinationAddress$', 'flowAction$', 'txByteCount$', 'rxByteCount$'],
};

// Fields nearly every schema has; they say nothing about which schema fits.
const GENERAL_FIELDS = new Set(['hostId$', 'sensorEventId$', 'eventTimeUsec$', 'computerName$', 'targetHostName$', 'agentDeviceId$', 'agentPriority$', 'priority$', 'vendorSeverity$', 'sensorVersion$', 'agentVersion$']);

// The schema to start from. A child with too little to map starts as generic, so its lines
// stay in the generic schema until someone picks a schema on purpose.
export function pickSchema(keys, typeValue = '', { child = false, extraText = '' } = {}) {
  const best = suggestSchema(keys, typeValue, extraText)[0];
  if (!best) return child ? GENERIC : 'scwx.thirdpartyalert';
  return child && best.score < 3 ? GENERIC : best.id;
}

// Score each schema for an event type and return them best first.
export function suggestSchema(keys, typeValue = '', extraText = '') {
  const scores = [];
  // An address in a column with no name (colN, or fN from a capture pattern) could be a user, a
  // sender or a recipient, so a user-name field guessed from its shape says nothing about the schema.
  const unnamedAddress = new Set(keys.filter((k) => k.shape === 'email' && /^(col|f)\d+$/.test(k.key)).map((k) => k.key));
  for (const id of SCHEMA_IDS) {
    if (id === GENERIC) continue;
    const mapped = suggestMappings(keys, id).filter((m) => !GENERAL_FIELDS.has(m.field) && !(m.transform.kind === 'enum' && !m.transform.map.length) && !(m.origin === 'shape' && unnamedAddress.has(m.key)));
    let score = mapped.length;
    if (mapped.length && DEFINING[id] && !mapped.some((m) => DEFINING[id].includes(m.field))) score -= 4;
    const hint = SCHEMA_HINTS.find(([sid]) => sid === id);
    const text = `${keys.map((k) => k.key).join(' ')} ${extraText}`;
    if (hint && typeValue && hint[1].test(String(typeValue))) score += 5;
    else if (hint && hint[1].test(text)) score += 2;
    // Third-party alerts fit almost anything, so only pick them on a clear hint.
    else if (id === 'scwx.thirdpartyalert') score -= 3;
    scores.push({ id, score });
  }
  return scores.sort((a, b) => b.score - a.score);
}

export function metadataAvailable(schemaId) {
  return hasEventMetadata(schemaId);
}

export function schemaName(id) {
  const s = schemaInfo(id);
  return s ? s.name : id;
}
