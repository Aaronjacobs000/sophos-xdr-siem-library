// Parent and child routing, normalization into schema fields, and Go regex handling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runParsers, expectedShape } from '../studio/core/engine.js';
import { compileGo, checkRe2, groupCount } from '../studio/core/goregex.js';
import { parseScript } from '../studio/core/language.js';
import { splitSyslog } from '../studio/core/formats.js';

const PARENT = `!CONFIRMWITH=PATTERN
!CONFIRMSTRING=acmegw\\[\\d+\\]:\\s*\\{"type"
!SCHEMA=scwx.generic
!TRIMALLOFF
m = originalData$|(\\{.*})$
json = JSON(m[1])
eventType$ = json["$.type"]
sensorType$ = "Acme Gateway"`;

const AUTH = `!CONFIRMWITH=EXPRESSION
!CONFIRMSTRING=eventType$=="login"
!SCHEMA=scwx.auth
targetUserName$ = json["$.user"]
sourceAddress$ = json["$.src"]
sourcePortNumber$ = json["$.sport"]
eventTimeUsec$ = DATETIME(json["$.ts"], "2006-01-02T15:04:05Z07:00")
ok = json["$.result"] == "ok"
action$ = IF ok THEN "LOGON" ELSE "FAILURE"
actionResult$ = IF ok THEN "SUCCESS" ELSE "FAILED"
mfaUsed$ = json["$.mfa"]
notAField$ = "dropped"`;

const NETFLOW = `!CONFIRMWITH=EXPRESSION
!CONFIRMSTRING=eventType$=="flow"
!SCHEMA=scwx.netflow
sourceAddress$ = json["$.src"]
destinationAddress$ = json["$.dst"]
destinationPort$ = json["$.dport"]
txByteCount$ = json["$.bytes"]
flowAction$ = IF json["$.act"] == "deny" THEN "FW_BLOCKED" ELSE "FW_ALLOWED"
rule.key$ = "rule"
rule.value$ = json["$.rule"]
eventMetadata$.record$ = eventMetadata$.record$ + [rule]`;

const parsers = [
  { name: 'ACME_GW_JSON_PARENT', text: PARENT },
  { name: 'ACME_GW_JSON_CHILD_AUTH', text: AUTH, parent: 'ACME_GW_JSON_PARENT' },
  { name: 'ACME_GW_JSON_CHILD_NETFLOW', text: NETFLOW, parent: 'ACME_GW_JSON_PARENT' },
];
const lines = [
  'Oct  7 22:00:01 gw01 acmegw[42]: {"type":"login","user":"jdoe","src":"192.0.2.10","sport":51000,"ts":"2026-10-07T22:00:01Z","result":"ok","mfa":true}',
  'Oct  7 22:00:02 gw01 acmegw[42]: {"type":"flow","src":"192.0.2.10","dst":"198.51.100.5","dport":"443","bytes":1200,"act":"deny","rule":"N/A"}',
  'Oct  7 22:00:03 gw01 acmegw[42]: {"type":"heartbeat"}',
  'Oct  7 22:00:04 gw01 otherapp[7]: hello',
];

test('routes each line through the parent to the matching child', () => {
  const r = runParsers(parsers, lines);
  assert.equal(r[0].extractor_path, 'ACME_GW_JSON_PARENT > ACME_GW_JSON_CHILD_AUTH');
  assert.equal(r[0].schema, 'scwx.auth');
  assert.equal(r[1].extractor_path, 'ACME_GW_JSON_PARENT > ACME_GW_JSON_CHILD_NETFLOW');
  assert.equal(r[2].extractor_path, 'ACME_GW_JSON_PARENT');
  assert.equal(r[2].schema, 'scwx.generic');
  assert.equal(r[2].normalized, null);
  assert.equal(r[3].extractor_path, null);
});

test('normalizes into schema field names and types', () => {
  const [auth, flow] = runParsers(parsers, lines);
  // The root parser's defaults (sensor_id from the syslog host, event_time_fidelity) come first.
  assert.deepEqual(auth.normalized, {
    sensor_type: 'Acme Gateway', sensor_id: 'gw01', event_time_usec: Date.UTC(2026, 9, 7, 22, 0, 1) * 1000, event_time_fidelity: 'MICRO',
    target_user_name: 'jdoe', source_address: '192.0.2.10', source_port_number: 51000, action: 'LOGON', action_result: 'SUCCESS', mfa_used: true,
  });
  assert.ok(auth.notes.some((n) => n.code === 'not-a-field' && n.field === 'notAField$'));
  assert.equal(flow.normalized.destination_port, 443);
  assert.equal(flow.normalized.flow_action, 'FW_BLOCKED');
  // SANITIZE_ALL only touches top-level fields, so "N/A" stays inside event_metadata.
  assert.deepEqual(flow.normalized.event_metadata, { record: [{ key: 'rule', value: 'N/A' }] });
  assert.equal(expectedShape(flow).extractor_path, 'ACME_GW_JSON_PARENT > ACME_GW_JSON_CHILD_NETFLOW');
});

test('enums take names in any case or numbers; anything else fails the event', () => {
  const base = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=av\n!SCHEMA=scwx.antivirus\nfileHash$.sha1$ = "abc"\nfileHash$.crc$ = "x"\n';
  const [r] = runParsers([{ name: 'X_AV', text: `${base}actionTaken$ = " Deleted "\nthreatType$ = 2\nthreatCategory$ = "3"` }], ['av event']);
  assert.equal(r.normalized.action_taken, 'DELETED');
  assert.equal(r.normalized.threat_type, 'FILE');
  assert.equal(r.normalized.threat_category, 'VIRUS');
  assert.ok(r.notes.some((n) => n.code === 'sub-field'));
  assert.deepEqual(r.normalized.file_hash, { sha1: 'abc' });
  const [bad] = runParsers([{ name: 'X_AV', text: `${base}actionTaken$ = "Removed"` }], ['av event']);
  assert.match(bad.error, /not a Antivirus.ActionTaken name or number/);
  assert.equal(bad.normalized, null);
});

test('integers, booleans and time follow the engine', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.netflow\nsourcePort$ = " 88 "\ndestinationPort$ = "1.5"\ntxByteCount$ = "abc"\nrxByteCount$ = "-5"\nprotocol$ = 99999999999\nstartTimestampUsec$ = DATETIME("2026-10-07 22:00:00", "2006-01-02 15:04:05") + 1000000';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.equal(r.normalized.source_port, 88);
  assert.equal(r.normalized.destination_port, 1);
  assert.equal(r.normalized.tx_byte_count, undefined);
  assert.equal(r.normalized.rx_byte_count, 18446744073709551616 - 5);
  assert.equal(r.normalized.protocol, 1215752191);
  assert.equal(r.normalized.start_timestamp_usec, Date.UTC(2026, 9, 7, 22, 0, 1) * 1000);
  const b = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\nmfaUsed$ = "no"';
  assert.equal(runParsers([{ name: 'A_B', text: b }], ['x'])[0].normalized.mfa_used, true);
  assert.equal(runParsers([{ name: 'A_B', text: b.replace('"no"', '" FALSE "') }], ['x'])[0].normalized.mfa_used, false);
});

test('captures keep every match, and an unset variable fails the event', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\nm = originalData$|n=(\\d)\ntargetUserName$ = m[1]\nmiss = originalData$|zzz(\\d)\nsourceUserName$ = IF miss[1] != "" THEN "hit" ELSE "miss"';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x n=1 n=2 n=3']);
  assert.equal(r.normalized.target_user_name, '1,2,3');
  assert.equal(r.normalized.source_user_name, 'miss');
  const [cmp] = runParsers([{ name: 'A_B', text: t + '\nauthSystem$ = IF miss != NULL THEN "a" ELSE "b"' }], ['x n=1']);
  assert.match(cmp.error, /cannot convert regex to string/);
  const [unset] = runParsers([{ name: 'A_B', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\ntargetUserName$ = nothing' }], ['x']);
  assert.match(unset.error, /variable nothing is not set/);
});

test('TRIM_ALL removes one enclosing pair; TRIM removes them all', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\ntargetUserName$ = " {jdoe} "\nsourceUserName$ = "((a))"\nauthSystem$ = TRIM("[\\"a\\"]")\nuserAgent$ = "a}"';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.equal(r.normalized.target_user_name, 'jdoe');
  assert.equal(r.normalized.source_user_name, '(a)');
  assert.equal(r.normalized.auth_system, 'a');
  assert.equal(r.normalized.user_agent, 'a}');
});

test('!SCHEMA can list several schemas', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth,scwx.cloudaudit\ntargetUserName$ = "u"\nuserName$ = "v"';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.equal(r.normalized.target_user_name, 'u');
  assert.equal(r.also[0].schema, 'scwx.cloudaudit');
  assert.equal(r.also[0].normalized.user_name, 'v');
});

test('TRIM_ALL strips braces unless !TRIMALLOFF', () => {
  const base = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\ntargetUserName$ = "  {jdoe}  "';
  const [on] = runParsers([{ name: 'A_B', text: base }], ['x']);
  assert.equal(on.normalized.target_user_name, '  jdoe  '.trim());
  assert.ok(on.notes.some((n) => n.code === 'trim-braces'));
  const [off] = runParsers([{ name: 'A_B', text: base.replace('!SCHEMA', '!TRIMALLOFF\n!SCHEMA') }], ['x']);
  assert.equal(off.normalized.target_user_name, '  {jdoe}  ');
});

test('SANITIZE_ALL can be turned off', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\ntargetUserName$ = "N/A"';
  assert.equal(runParsers([{ name: 'A_B', text: t }], ['x'])[0].normalized.target_user_name, undefined);
  assert.equal(runParsers([{ name: 'A_B', text: t.replace('!SCHEMA', '!SANITIZEALLOFF\n!SCHEMA') }], ['x'])[0].normalized.target_user_name, 'N/A');
});

test('reports runtime errors with the parser and line, and keeps the line generic', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\n\nn = INT("abc", 10)';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.match(r.error, /^A_B line 5: INT could not read/);
  assert.equal(r.schema, 'scwx.generic');
});

test('warns when two top-level parsers match the same line', () => {
  const a = { name: 'A_ONE', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=hello\n!SCHEMA=scwx.auth\nauthSystem$ = "a"' };
  const b = { name: 'B_TWO', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=hel+o\n!SCHEMA=scwx.auth\nauthSystem$ = "b"' };
  const [r] = runParsers([a, b], ['hello world']);
  assert.ok(r.notes.some((n) => n.code === 'overlap'));
});

test('!IMPORT runs a shared parser inline and !IMPORTONLY parsers never match', () => {
  const lib = { name: 'SHARED_FIELDS', text: '!IMPORTONLY\nauthSystem$ = "shared"' };
  const main = { name: 'MAIN_AUTH', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\n!IMPORT=SHARED_FIELDS\ntargetUserName$ = "u"' };
  const [r] = runParsers([lib, main], ['x']);
  assert.equal(r.extractor_path, 'MAIN_AUTH');
  assert.equal(r.normalized.auth_system, 'shared');
});

test('the syslog header comes off for `message`', () => {
  assert.equal(splitSyslog('<134>Oct  8 09:14:22 vpn01 acmevpn[2211]: hello').body, 'acmevpn[2211]: hello');
  assert.equal(splitSyslog('<34>1 2026-10-07T22:14:15.003Z host01 su - ID47 - msg').body, 'su - ID47 - msg');
  assert.equal(splitSyslog('Aug 21 12:12:20 192.0.2.254 1 1566000000.000000000 IDOFDEVICE flows').body, '1 1566000000.000000000 IDOFDEVICE flows');
  assert.equal(splitSyslog('{"a":1}'), null);
});

test('Go regex translation and RE2 checks', () => {
  assert.equal(compileGo('(?P<user>\\w+)@').exec('jdoe@example.com').groups.user, 'jdoe');
  assert.ok(compileGo('(?i)error').test('ERROR'));
  assert.ok(compileGo('\\Aabc\\z').test('abc'));
  assert.ok(compileGo('[[:digit:]]+').test('42'));
  assert.ok(compileGo('\\%ASA').test('%ASA'));
  assert.ok(!compileGo('a.c').test('a\nc'));
  assert.ok(compileGo('(?s)a.c').test('a\nc'));
  assert.ok(compileGo('\\{.*}$').test('x {"a":1}'));
  assert.equal(groupCount('(a)(?P<b>b)(?:c)'), 2);
  const bad = (p) => checkRe2(p).filter((x) => x.level === 'error').map((x) => x.message).join(' ');
  assert.match(bad('foo(?=bar)'), /lookahead/);
  assert.match(bad('(a)\\1'), /backreference/);
  assert.match(bad('a{1001}'), /1000/);
  assert.match(bad('a++'), /possessive/);
  assert.equal(bad('\\\\1'), '');
  assert.ok(checkRe2('(a+)+$').some((x) => x.level === 'warning'));
});

test('statement parsing reports problems with line numbers', () => {
  const s = parseScript('!CONFIRMWITH=PATTERN\n!NOPE=1\nx = IF a THEN b\n# comment\ny = 1');
  assert.deepEqual(s.problems.map((p) => [p.line, p.code]), [[2, 'unknown-directive'], [3, 'syntax']]);
  assert.equal(s.statements.length, 1);
});
