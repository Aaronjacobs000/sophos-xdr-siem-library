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
eventMetadata$.record$ = [rule]`;

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
  // The generic event keeps the common fields the parent set.
  assert.deepEqual(r[2].normalized, { sensor_type: 'Acme Gateway', sensor_id: 'gw01', event_time_usec: Date.UTC(2026, 9, 7, 22, 0, 3) * 1000 });
  assert.equal(r[3].extractor_path, null);
  assert.equal(r[3].normalized, null);
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

test('TRIM_ALL takes the brackets off STRING() of a list in a top-level field', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\ntargetUserName$ = STRING(["a", "b"])\nuserDisplayName$ = STRING(["a"])\nr.key$ = "k"\nr.value$ = STRING(["a", "b"])\neventMetadata$.record$ = [r]';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.equal(r.normalized.target_user_name, '"a","b"');
  assert.equal(r.normalized.user_display_name, '"a"');
  assert.equal(r.normalized.event_metadata.record[0].value, '["a","b"]');
  assert.ok(r.notes.some((n) => n.code === 'trim-braces' && n.field === 'target_user_name'));
  assert.equal(runParsers([{ name: 'A_B', text: t.replace('!SCHEMA=scwx.auth', '!SCHEMA=scwx.auth\n!TRIMALLOFF') }], ['x'])[0].normalized.target_user_name, '["a","b"]');
});

test('the Auth schema stores Auth0 log type codes in event_metadata as their descriptions', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\nstatus$ = "f"\na.key$ = "type"\na.value$ = "f"\nb.key$ = "other"\nb.value$ = "FS"\nc.key$ = "k"\nc.value$ = " f"\nd.key$ = "f"\nd.value$ = "x"\ne.key$ = "k"\ne.value$ = "acls_summary"\neventMetadata$.record$ = [a, b, c, d, e]\nafter = a.value$';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.deepEqual(r.normalized.event_metadata.record.map((x) => x.value), ['Failed Login', 'Failed Signup', ' f', 'x', 'acls_summary']);
  assert.equal(r.normalized.status, 'f');
  assert.deepEqual(r.notes.filter((n) => n.code === 'auth0-code').map((n) => n.field), ['event_metadata.record[0].value', 'event_metadata.record[1].value']);
  // Only the Auth schema does it.
  for (const schema of ['scwx.netflow', 'scwx.nids', 'scwx.http']) {
    const [o] = runParsers([{ name: 'A_B', text: t.replace('scwx.auth', schema).replace('status$ = "f"\n', '') }], ['x']);
    assert.deepEqual(o.normalized.event_metadata.record.map((x) => x.value), ['f', 'FS', ' f', 'x', 'acls_summary'], schema);
  }
});

// Every other code in Auth0's tenant log catalog; the engine stored each one as it was.
test('the Auth schema leaves the Auth0 codes its list doesn\'t have as they are', () => {
  const kept = `acls_summary actions_execution_failed acul_sdk_notice api_limit_warning appi ciba_exchange_failed ciba_exchange_succeeded ciba_start_failed
ciba_start_succeeded connected_accounts_connection_failed connected_accounts_connection_succeeded connected_accounts_delete_failed connected_accounts_delete_succeeded
custom_domain_verification_failed directory_sync_completed directory_sync_failed directory_sync_started failed_on_behalf_of_token_exchange fdeleacft fdelsa fecte
federated_logout_failed feta flows_execution_completed flows_execution_failed forms_submission_failed forms_submission_succeeded fpar fpurh fscim
gd_auth_email_verification gd_email_settings_update gd_phone_settings_update gd_send_email gd_send_email_verification gd_send_pn_failure gd_start_enroll_failed
gd_webauthn_challenge_failed gd_webauthn_enrollment_failed idjag_exchange_failed idjag_exchange_succeeded jwt_bearer_exchange_failed kms_key_management_failure
kms_key_management_success kms_key_state_changed limit_phone my_account_authentication_method_failed my_account_authentication_method_succeeded
oidc_backchannel_logout_failed oidc_backchannel_logout_succeeded organization_member_added passkey_challenge_failed passkey_challenge_started reset_pwd_leak
resource_cleanup rich_consents_access_error scv sdel sdeleacft sdelsa secte sepkoobft sepkotpft sepkrcft seta signup_pwd_leak ss_sso_failure ss_sso_info
ss_sso_success sscim success_on_behalf_of_token_exchange universal_logout_failed universal_logout_succeeded wn wum`.split(/\s+/);
  assert.equal(kept.length, 75);
  const recs = kept.map((c, i) => `r${i}.key$ = "k${i}"\nr${i}.value$ = "${c}"`).join('\n');
  const t = `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\n${recs}\neventMetadata$.record$ = [${kept.map((_, i) => `r${i}`).join(', ')}]`;
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.deepEqual(r.normalized.event_metadata.record.map((x) => x.value), kept);
  assert.ok(!r.notes.some((n) => n.code === 'auth0-code'));
});

test('the docs\' append pattern fails until the list exists', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.nids\nr.key$ = "k"\nr.value$ = "v"\neventMetadata$.record$ = eventMetadata$.record$ + [r]';
  const [bad] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.match(bad.error, /variable eventMetadata\$\.record\$ is not set/);
  const [good] = runParsers([{ name: 'A_B', text: t.replace('eventMetadata$.record$ = eventMetadata$.record$ + [r]', 'eventMetadata$.record$ = [r]\neventMetadata$.record$ = eventMetadata$.record$ + [r]') }], ['x']);
  assert.equal(good.normalized.event_metadata.record.length, 2);
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
  const [indexed] = runParsers([{ name: 'A_B', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\nacct = originalData$|user=(\\S+)\nname = acct[1]|^(\\w+)\ntargetUserName$ = name[1]' }], ['x user=alice$']);
  assert.equal(indexed.normalized.target_user_name, 'alice');
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

// What Run Test gave for each line in a lab tenant.
test('in Run Test the root parser only takes a plain BSD header off the line', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=zzprobe\n!SCHEMA=scwx.nids\nr1.key$ = "message"\nr1.value$ = message\nr2.key$ = "sensorId"\nr2.value$ = sensorId$\neventMetadata$.record$ = [r1, r2]';
  const lines = [
    '<134>Oct 14 01:02:03 probe.example.com zzprobe hello',
    'Oct 14 01:02:03 probe.example.com zzprobe hello',
    '<134>1 2026-10-14T01:02:03Z probe.example.com app - - - zzprobe hello',
    'Oct 14 01:02:03 relay.example.com Oct 14 01:02:03 probe.example.com zzprobe hello',
    '2026-10-14T01:02:03Z probe.example.com zzprobe hello',
  ];
  const now = '2026-10-14T03:00:00Z';
  const syslog = Date.UTC(2026, 9, 14, 1, 2, 3) * 1000;
  const got = runParsers([{ name: 'A_B', text: t }], lines, { now }).map((r) => [r.normalized.event_metadata.record.map((x) => x.value), r.normalized.sensor_id, r.normalized.event_time_usec]);
  assert.deepEqual(got, [
    [[lines[0], undefined], undefined, Date.parse(now) * 1000],
    [['zzprobe hello', 'probe.example.com'], 'probe.example.com', syslog],
    [[lines[2], undefined], undefined, Date.parse(now) * 1000],
    [['zzprobe hello', 'probe.example.com'], 'probe.example.com', syslog],
    [[lines[4], undefined], undefined, Date.parse(now) * 1000],
  ]);
});

// What Run Test gave for each line in a lab tenant, with its ingest time as now. The stored
// event time is the same as before; only what the parser can read changed.
test('with no plain BSD header, eventTimeUsec$ starts as the ingest time in microseconds', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=psr3e\n!SCHEMA=scwx.nids\nr1.key$ = "s"\nr1.value$ = STRING(eventTimeUsec$)\nr2.key$ = "l"\nr2.value$ = STRING([eventTimeUsec$])\nr3.key$ = "p"\nr3.value$ = STRING([eventTimeUsec$ + 0])\neventMetadata$.record$ = [r1, r2, r3]';
  const lines = [
    'psr3e {"a":1}',
    '<134>Oct 14 01:02:03 probe.example.com psr3e hello',
    'Oct 14 01:02:03 probe.example.com psr3e hello',
    '<134>1 2026-10-14T01:02:03Z probe.example.com app - - - psr3e hello',
    '2026-10-14T01:02:03Z probe.example.com psr3e hello',
    'Oct 14 01:02:03 relay.example.com Oct 14 01:02:03 probe.example.com psr3e hello',
  ];
  const now = '2026-10-13T23:31:23Z';
  const ingest = Date.parse(now) * 1000;
  const syslog = Date.UTC(2026, 9, 14, 1, 2, 3) * 1000;
  const r = runParsers([{ name: 'A_B', text: t }], lines, { now });
  const got = r.map((x) => [x.normalized.event_metadata.record.map((y) => y.value), x.normalized.event_time_usec]);
  const fromIngest = [[String(ingest), `[${ingest}]`, `[${ingest}]`], ingest];
  // The header time is 1.5 hours ahead of ingest, so the engine moves it back 2 hours.
  const fromHeader = [['2026-10-14 01:02:03 +0000 UTC', '[{}]', `[${syslog}]`], syslog - 2 * 3600e6];
  assert.deepEqual(got, [fromIngest, fromIngest, fromHeader, fromIngest, fromIngest, fromHeader]);
  // The parser never set a time, so the note about the ingest time stays.
  assert.ok(r[0].notes.some((n) => n.code === 'ingest-time'));
  assert.ok(!r[2].notes.some((n) => n.code === 'ingest-time'));
});

// What the engine stored for each record value in a lab tenant.
test('a number joined to text or stored in a string field is written like Go\'s FormatFloat with -1 precision', () => {
  const big = `(1000000000000000000 / 1)${' * 1000000000000000000'.repeat(16)}`;
  const tiny = `(1 / 1000000000000000000)${' / 1000000000000000000'.repeat(16)}`;
  const rows = [
  ['9223372036854775807', '9223372036854776000'],
  ['9007199254740993', '9007199254740992'],
  ['9223372036854775807 + 0', '9223372036854776000'],
  ['9223372036854775807 + 1', '9223372036854776000'],
  ['9223372036854775807 - 1', '9223372036854776000'],
  ['-9223372036854775807 - 2', '-9223372036854776000'],
  ['-9223372036854775808', '-9223372036854776000'],
  ['9007199254740993 * 1', '9007199254740992'],
  ['3037000500 * 3037000500', '9223372037000250000'],
  ['4611686018427387904 * 2', '9223372036854776000'],
  ['1000000000000 * 1000000000', '1000000000000000000000'],
  ['4611686018427387903 * 2', '9223372036854776000'],
  ['3037000499 * 3037000499', '9223372030926249000'],
  ['9007199254740993 + 2', '9007199254740994'],
  ['(6 / 2) * 3074457345618258603', '9223372036854776000'],
  ['(1000000000000 / 1) * 1000000000', '1000000000000000000000'],
  ['LENGTH("abc") * 3074457345618258603', '9223372036854776000'],
  ['9223372036854775807 % 10', '-8'],
  ['9007199254740993 % 10', '2'],
  ['-9223372036854775807 - 1 - 1', '-9223372036854776000'],
  ['INT("9223372036854775807", 10)', '9223372036854776000'],
  ['INT("9007199254740993", 10) + 0', '9007199254740992'],
  ['9007199254740993 / 1', '9007199254740992'],
  ['9223372036854775807 * 1', '9223372036854776000'],
  ['-9223372036854775807 * 2', '-18446744073709552000'],
  ['2147483647 * 2147483647', '4611686014132420600'],
  ['9007199254740993 - 0', '9007199254740992'],
  ['123456789012345678 + 0', '123456789012345680'],
  ['123456789012345678 * 1', '123456789012345680'],
  ['123456789012345678 - 1', '123456789012345680'],
  ['123456789012345678 * 2', '246913578024691360'],
  ['123456789012345678', '123456789012345680'],
  ['-123456789012345678', '-123456789012345680'],
  ['-9223372036854775807 - 1', '-9223372036854776000'],
  ['INT("-9223372036854775808", 10)', '-9223372036854776000'],
  ['123456789012345678 % 1000', '680'],
  ['-1 * 9223372036854775807 * 2', '-18446744073709552000'],
  ['9223372036854775807 * -1', '-9223372036854776000'],
  ['4611686018427387904 * -2', '-9223372036854776000'],
  ['1000000000000 * -1000000000', '-1000000000000000000000'],
  ['9223372036854775807 + 9223372036854775807', '18446744073709552000'],
  ['1 / 3', '0.3333333333333333'],
  ['2 / 3', '0.6666666666666666'],
  ['1 / 10000000', '0.0000001'],
  ['0 / -1', '-0'],
  ['1 / 1000000000000000000', '0.000000000000000001'],
  ['(1 / 1000000000000000000) / 1000000000000000000', '0.0000000000000000000000000000000000010000000000000001'],
  ['(1000000000000000000 / 1) * 1000000000000000000', '1000000000000000000000000000000000000'],
  ['(1 / 10) + (2 / 10)', '0.30000000000000004'],
  ['-1 / 3', '-0.3333333333333333'],
  ['-1 / 10000000', '-0.0000001'],
  ['4 / 2', '2'],
  ['(3 / 2) * 1000000000000', '1500000000000'],
  ['123456789 / 1000', '123456.789'],
  ['1 / 1024', '0.0009765625'],
  ['(100000000000 / 1) * 1000000000', '100000000000000000000'],
  ['9007199254740992 / 1', '9007199254740992'],
  ['9223372036854775807 / 1', '9223372036854776000'],
  ['JSON("{\\"a\\":1e-7}")["$.a"]', '0.0000001'],
  ['JSON("{\\"a\\":1e21}")["$.a"]', '1000000000000000000000'],
  ['JSON("{\\"a\\":12345678901234567890}")["$.a"]', '12345678901234567000'],
  ['JSON("{\\"a\\":5}")["$.a"]', '5'],
  ['JSON("{\\"a\\":-0.0}")["$.a"]', '-0'],
  ['1 / 7', '0.14285714285714285'],
  ['(1 / 1000000) * 1', '0.000001'],
  ['1 / 100000', '0.00001'],
  ['(-3 / 2) * 1000000000000000000000', '-1500000000000000000000'],
  ['"a" + (1 / 10000000)', 'a0.0000001'],
  ['"a" + 9223372036854775807', 'a9223372036854776000'],
  ['"a" + ((1000000000000 / 1) * 1000000000)', 'a1000000000000000000000'],
  ['"a" + (0 / -1)', 'a-0'],
  ['"a" + (3 / 2)', 'a1.5'],
  ['"a" + 9007199254740993', 'a9007199254740992'],
  ['"a" + 123456789012345678', 'a123456789012345680'],
  ['REPLACE(1 / 10000000, "x", "y")', '0.0000001'],
  ['[9223372036854775807] + "a"', '9223372036854776000,a'],
  ['"a" + 1000000', 'a1000000'],
  ['"a" + (100000000000000000000 / 1)', 'a100000000000000000000'],
  ['"a" + (1 / 1000000)', 'a0.000001'],
  ['"a" + (1 / 3)', 'a0.3333333333333333'],
  ['CONTAINS(9007199254740993, "992")', 'true'],
  ['REPLACE(0 / -1, "x", "y")', '-0'],
  ['"a" + ((1000000000000 / 1) * -1000000000000000000000)', 'a-1000000000000000000000000000000000'],
  ['"a" + 0', 'a0'],
  ['"a" + -5', 'a-5'],
  ['"a" + (1 / 100000000000000000000)', 'a0.00000000000000000001'],
    [big, `1${'0'.repeat(306)}`],
    [tiny, `0.${'0'.repeat(305)}10000000000000003`],
  ];
  const recs = rows.map(([expr], i) => `r${i}.key$ = "k${i}"\nr${i}.value$ = ${expr}`).join('\n');
  const t = `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.nids\n${recs}\neventMetadata$.record$ = [${rows.map((_, i) => `r${i}`).join(', ')}]`;
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x']);
  assert.equal(r.error, undefined);
  const got = new Map(r.normalized.event_metadata.record.map((x) => [x.key, x.value]));
  rows.forEach(([expr, want], i) => assert.equal(got.get(`k${i}`), want, expr));
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

// Engine behaviors checked with Run Test in a lab tenant.
const NOW = '2026-10-14T00:00:00Z';

test('enum fields set to their zero value are left out, except Auth logon_type', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\naction$ = "UNCLASSIFIED"\nactionResult$ = 0\nlogonType$ = "SYSTEMONLY"\ntargetUserName$ = "u"';
  const [r] = runParsers([{ name: 'A_B', text: t }], ['x'], { now: NOW });
  assert.equal(r.normalized.action, undefined);
  assert.equal(r.normalized.action_result, undefined);
  assert.equal(r.normalized.logon_type, 'SYSTEMONLY');
  assert.ok(r.notes.some((n) => n.code === 'enum-zero' && n.field === 'action'));
  const [av] = runParsers([{ name: 'A_B', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.antivirus\nthreatType$ = "UNKNOWN_THREATTYPE"\nactionTaken$ = "DELETED"' }], ['x'], { now: NOW });
  assert.equal(av.normalized.threat_type, undefined);
  assert.equal(av.normalized.action_taken, 'DELETED');
});

test('the engine stores a few fields the docs\' tables leave out, only in their schemas', () => {
  const head = (schema) => `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=${schema}\n`;
  const [av] = runParsers([{ name: 'A_B', text: `${head('scwx.antivirus')}eventType$ = "Threat_Event"\nsensorVersion$ = "9.9"\nsourceAddress$ = "192.0.2.1"\nfooBar$ = "fb"\nthreatName$ = "t"` }], ['x'], { now: NOW });
  assert.deepEqual([av.normalized.event_type, av.normalized.sensor_version, av.normalized.source_address], ['Threat_Event', '9.9', '192.0.2.1']);
  assert.ok(av.notes.some((n) => n.code === 'not-a-field' && n.field === 'fooBar$'));
  const [mgmt] = runParsers([{ name: 'A_B', text: `${head('scwx.managementevent')}sourceAddress$ = "192.0.2.1"\neventType$ = "et"\noperation$ = "op"` }], ['x'], { now: NOW });
  assert.equal(mgmt.normalized.source_address, '192.0.2.1');
  assert.equal(mgmt.normalized.event_type, undefined);
  // A variable isn't mapped just because it is named like a field: Auth has no event_type.
  const [auth] = runParsers([{ name: 'A_B', text: `${head('scwx.auth')}eventType$ = "et"\nhostId$ = "h"` }], ['x'], { now: NOW });
  assert.equal(auth.normalized.event_type, undefined);
});

test('the event time settles like the engine: the ingest time when missing, a future time moved back or replaced', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=pss\n!SCHEMA=scwx.auth\njson = JSON(originalData$)\neventTimeUsec$ = DATETIME(json["$.ts"], "2006-01-02T15:04:05Z07:00")\ntargetUserName$ = "u"';
  const N = Date.parse(NOW) * 1000;
  const at = (s) => `{"pss":1,"ts":"${new Date(Date.parse(NOW) + s * 1000).toISOString().replace('.000', '')}"}`;
  // Seconds ahead of ingest, and where the engine put each one in a lab tenant.
  const cases = [[-600, -600], [282, 0], [602, -2998], [882, -2718], [4182, 0], [7182, -18], [86382, -18], [88182, 0]];
  const r = runParsers([{ name: 'A_B', text: t }], ['{"pss":1}', '{"pss":1,"ts":"garbage"}', ...cases.map(([s]) => at(s))], { now: NOW });
  assert.deepEqual(r.map((x) => (x.normalized.event_time_usec - N) / 1e6), [0, 0, ...cases.map(([, want]) => want)]);
  assert.ok(r[0].notes.some((n) => n.code === 'ingest-time'));
  assert.ok(r[5].notes.some((n) => n.code === 'future-time' && /moves it back 1 hour/.test(n.message)));
  assert.ok(r[6].notes.some((n) => n.code === 'future-time' && /ingest time instead/.test(n.message)));
  // The same applies to the time the root parser reads from a BSD header.
  const [hdr] = runParsers([{ name: 'A_B', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=pss\n!SCHEMA=scwx.auth\ntargetUserName$ = "u"' }], ['Oct 14 23:30:00 h01 app: pss'], { now: NOW });
  assert.equal(hdr.normalized.event_time_usec, Date.UTC(2026, 9, 13, 23, 30) * 1000);
});
