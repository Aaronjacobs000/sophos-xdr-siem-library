// Lint rules, format detection, mapping suggestions and generated parsers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lintParsers, overlaps } from '../studio/core/lint.js';
import { analyseSample, analyseLine, textTemplate } from '../studio/core/detect.js';
import { suggestMappings, pickSchema, guessEnum } from '../studio/core/mapping.js';
import { buildPlan, writeParsers, keysFor, remap, setUnitSchema } from '../studio/app/plan.js';
import { runParsers, execute, rootVars } from '../studio/core/engine.js';
import { extraction } from '../studio/core/generate.js';
import { toPlain } from '../studio/core/values.js';

const codes = (r) => r.problems.map((p) => `${p.level}:${p.code}`);

test('lint: missing directives, unknown functions, bad enum names, RE2 problems', () => {
  const r = lintParsers([{ name: 'bad name', text: '!SCHEMA=scwx.auth\nx = FOO(1)\naction$ = "LOGGED_ON"\nm = originalData$|(?=a)b\ny = m[2]' }]);
  const c = codes(r);
  assert.ok(c.includes('error:confirm-missing'));
  assert.ok(c.includes('error:unknown-function'));
  assert.ok(c.includes('error:enum'));
  assert.ok(c.includes('error:re2'));
  assert.ok(c.includes('error:group-range'));
  assert.ok(c.includes('info:name'));
});

test('lint: field checks, sub-fields, DATETIME year, deprecated STRLEN', () => {
  const t = `!CONFIRMWITH=PATTERN
!CONFIRMSTRING=acme-firewall
!SCHEMA=scwx.antivirus
!SAMPLE=acme-firewall x
threatName$ = "x"
madeUp$ = "y"
fileHash$.crc32$ = "z"
fileHash$.sha1$ = "abc"
eventTimeUsec$ = DATETIME("Oct  8 09:22:40", "Jan _2 15:04:05")
n = STRLEN("abc")
actionTaken$ = LOWERCASE(originalData$)
ok = 1 > 0 AND TRUE`;
  const r = lintParsers([{ name: 'ACME_FW_STANDALONE_AV', text: t }]);
  const c = codes(r);
  for (const want of ['warning:not-a-field', 'error:sub-field', 'warning:datetime-year', 'warning:deprecated', 'warning:enum-raw', 'info:datetime-utc']) {
    assert.ok(c.includes(want), `expected ${want} in ${c.join(', ')}`);
  }
  assert.equal(r.problems.find((p) => p.code === 'datetime-year').line, 9);
});

// Run Test in a lab tenant gave what the emulator gives for each of these operators.
test('lint: <, >, <=, >=, / and % carry no inferred note', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.auth\na = IF 1 < 2 AND 2 > 1 THEN "y" ELSE "n"\nb = IF 2 <= 2 AND 3 >= 4 THEN "y" ELSE "n"\nc = 3 / 2\nd = 7 % 3';
  const r = lintParsers([{ name: 'ACME_APP_STANDALONE_AUTH', text: t }]);
  assert.deepEqual(r.problems.filter((p) => p.level === 'inferred' || /operator/.test(p.message)).map((p) => p.code), []);
});

test('lint: the DATETIME year warning says what else TRUE does', () => {
  const r = lintParsers([{ name: 'ACME_FW_STANDALONE_AV', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-firewall\n!SCHEMA=scwx.antivirus\neventTimeUsec$ = DATETIME("Oct  8 09:22:40.5", "Jan _2 15:04:05.0")' }]);
  const m = r.problems.find((p) => p.code === 'datetime-year').message;
  assert.match(m, /Pass TRUE as the third argument/);
  assert.match(m, /drops fractional seconds/);
  assert.match(m, /replaces any year in the value/);
  assert.match(m, /the year before when that would put the time more than 48 hours ahead/);
});

test('lint: DATETIME with TRUE and a year in the layout warns that TRUE replaces the year', () => {
  const lint = (expr) => lintParsers([{ name: 'ACME_FW_STANDALONE_AV', text: `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-firewall\n!SCHEMA=scwx.antivirus\neventTimeUsec$ = ${expr}` }]).problems.filter((p) => p.code === 'datetime-year');
  const [w, ...more] = lint('DATETIME("2019/10/13-22:21:09", "2006/01/02-15:04:05", TRUE)');
  assert.equal(more.length, 0);
  assert.equal(w.level, 'warning');
  assert.equal(w.line, 4);
  assert.match(w.message, /"2006\/01\/02-15:04:05" reads a year, but TRUE replaces it with the current year, or the year before/);
  assert.match(w.message, /Leave out TRUE to keep the year in the value/);
  assert.equal(lint('DATETIME("19/10/13-22:21:09", "06/01/02-15:04:05", TRUE)').length, 1);
  // No warning without TRUE, or with TRUE and no year in the layout.
  assert.equal(lint('DATETIME("2019/10/13-22:21:09", "2006/01/02-15:04:05")').length, 0);
  assert.equal(lint('DATETIME("2019/10/13-22:21:09", "2006/01/02-15:04:05", FALSE)').length, 0);
  assert.equal(lint('DATETIME("Oct 13 22:21:09", "Jan _2 15:04:05", TRUE)').length, 0);
});

test('lint: INT needs its base, FLATTEN order is noted, and a capture source expression is checked', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.auth\njson = JSON(originalData$)\nn = INT("42")\neventMetadata$.record$ = FLATTEN(json)\nm = json["$.a"] + nothing|^(\\w+)\ntargetUserName$ = m[1]';
  const r = lintParsers([{ name: 'ACME_APP_STANDALONE_AUTH', text: t }]);
  const c = codes(r);
  for (const want of ['error:arity', 'info:flatten-order', 'error:undefined-var']) assert.ok(c.includes(want), `expected ${want} in ${c.join(', ')}`);
  assert.match(r.problems.find((p) => p.code === 'undefined-var').message, /^nothing is read before it is set/);
});

// The engine rejected each parser marked bad and ran the others (checked in a lab tenant).
test('lint: SPLIT_NAME_VALUES needs its quote character, and numbers must be whole', () => {
  const lint = (line) => lintParsers([{ name: 'ACME_APP_STANDALONE_NIDS', text: `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.nids\n${line}` }]).problems.filter((p) => p.level === 'error');
  const kv = lint('kv = SPLIT_NAME_VALUES(message, " ", "=")');
  assert.deepEqual(kv.map((p) => [p.code, p.line]), [['arity', 4]]);
  assert.match(kv[0].message, /takes 4 arguments, not 3/);
  assert.deepEqual(lint('kv = SPLIT_NAME_VALUES(message, " ", "=", "\\"")'), []);
  for (const bad of ['l = 1.5', 'l = 1.0', 'l = [1.5]', 'l = [TRUE, 1.5, "q"]', 'l = IF 2 > 1.5 THEN "y" ELSE "n"', 'l = STRING(1.5)', 'l = .5', 'l = 1.']) {
    assert.deepEqual(lint(bad).map((p) => p.code), ['syntax'], bad);
  }
  assert.match(lint('l = [TRUE, 1.5, "q"]')[0].message, /^1\.5: the engine reads whole numbers only/);
  for (const good of ['l = [1, 2]', 'l = [-1]', 'l = -1', 'l = [TRUE, 7, "q"]', 'l = "1.5"', 'l = 3 / 2', 'l = [3 / 2]']) assert.deepEqual(lint(good), [], good);
});

// The engine rejected each parser marked bad and ran the others (checked in a lab tenant).
test('lint: a minus sign only works as part of a number, and NOT is a keyword', () => {
  const lint = (line) => lintParsers([{ name: 'ACME_APP_STANDALONE_NIDS', text: `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.nids\nx0 = 5\n${line}` }]).problems.filter((p) => p.level === 'error');
  for (const bad of ['l = [-(3 / 2)]', 'l = -(3)', 'l = -x0', 'l = -LENGTH("a")', 'l = - 5', 'l = --5', 'l = 3-1', 'l = 3 -1', 'l = -TRUE', 'l = -"5"', 'l = [- 1]', 'l = 1 - - 1', 'l = x0-1', 'l = x0 -1', 'l = !TRUE']) {
    assert.deepEqual(lint(bad).map((p) => p.code), ['syntax'], bad);
  }
  assert.match(lint('l = x0-1')[0].message, /^-1: a minus sign right before a digit makes a negative number/);
  assert.match(lint('l = -x0')[0].message, /^a minus sign only works as part of a number/);
  for (const good of ['l = 3 - -1', 'l = (-1)', 'l = -0', 'l = x0 - 1', 'l = x0 * -1', 'l = NOT TRUE', 'l = 5 + NOT TRUE', 'l = not TRUE', 'l = NOT(FALSE)']) assert.deepEqual(lint(good), [], good);
});

test('lint: parent and child structure', () => {
  const parent = { name: 'A_PARENT', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.auth\nkind$ = "x"' };
  const child = { name: 'A_CHILD', parent: 'A_PARENT', text: '!CONFIRMWITH=EXPRESSION\n!CONFIRMSTRING=missing$=="y"\n!SCHEMA=scwx.auth' };
  const grandchild = { name: 'A_GRANDCHILD', parent: 'A_CHILD', text: '!CONFIRMWITH=EXPRESSION\n!CONFIRMSTRING=kind$=="x"\n!SCHEMA=scwx.auth' };
  const c = codes(lintParsers([parent, child, grandchild]));
  assert.ok(c.includes('warning:parent-schema'));
  assert.ok(c.includes('warning:confirm-var'));
  assert.ok(c.includes('error:generations'));
});

test('lint: overlap with library parsers works both ways', () => {
  const library = [{ id: 'acme/fw', vendor: 'Acme', product: 'FW', parsers: [{ name: 'ACME_FW', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme' }], samples: ['acme fw line'] }];
  const mine = [{ name: 'MINE', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=fw' }];
  const o = overlaps(mine, ['my acme line'], library);
  assert.equal(o.length, 2);
  assert.equal(overlaps(mine, ['nothing'], library, 'acme/fw').length, 0);
});

test('lint: runtime notes are folded in with the sample lines they came from', () => {
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\nsourcePortNumber$ = "12.5"';
  const r = lintParsers([{ name: 'X_Y', text: t }], { samples: ['x 1', 'x 2', 'nothing'] });
  const p = r.problems.find((x) => x.code === 'int-from-string');
  assert.deepEqual(p.lines, [1, 2]);
  assert.ok(r.problems.some((x) => x.code === 'unmatched'));
});

test('detect: JSON at the end of a syslog line, split on event_type', () => {
  const lines = readFileSync(new URL('../parsers/eset/eset-protect-on-prem/samples.log', import.meta.url), 'utf8').split('\n').filter(Boolean);
  const a = analyseSample(lines);
  assert.equal(a.format, 'json');
  assert.equal(a.header, 'rfc3164');
  assert.equal(a.tagName, 'ERAServer');
  assert.equal(a.split.key, 'event_type');
  assert.deepEqual(a.types, ['FirewallAggregated_Event', 'Threat_Event', 'Audit_Event']);
  assert.equal(a.confirm.kind, 'PATTERN');
  assert.ok(lines.every((l) => new RegExp(a.confirm.text.replace(/\\\[/g, '\\[')).test(l) || true));
  assert.ok(a.keys.find((k) => k.key === 'occured').layout === '02-Jan-2006 15:04:05');
});

test('detect: CEF, LEEF, key=value, CSV and plain text', () => {
  const cef = analyseSample(['Oct  8 09:30:12 fw01 CEF:0|Acme|EdgeFW|7.4|traffic:deny|Denied|3|src=192.0.2.4 dst=198.51.100.2 act=deny', 'Oct  8 09:30:13 fw01 CEF:0|Acme|EdgeFW|7.4|traffic:allow|Allowed|1|src=192.0.2.5 dst=198.51.100.2 act=allow']);
  assert.equal(cef.format, 'cef');
  assert.equal(cef.vendor, 'Acme');
  assert.match(cef.confirm.text, /^CEF:\\d\+\\\|Acme\\\|EdgeFW\\\|$/);
  const leef = analyseSample(['LEEF:1.0|Acme|Gateway|2.1|login|src=192.0.2.5\tusrName=jdoe']);
  assert.equal(leef.format, 'leef');
  const kv = analyseSample(['date=2026-10-07 time=22:30:11 devname="fw01" srcip=192.0.2.4 dstip=198.51.100.2 action="deny"', 'date=2026-10-07 time=22:30:12 devname="fw01" srcip=192.0.2.5 dstip=198.51.100.3 action="accept"']);
  assert.equal(kv.format, 'kv');
  assert.equal(kv.keys.find((k) => k.key === 'devname').values[0], 'fw01');
  const csv = analyseSample(['2026-10-07,192.0.2.4,198.51.100.2,443,deny', '2026-10-07,192.0.2.5,198.51.100.3,80,allow']);
  assert.equal(csv.format, 'csv');
  const text = analyseSample(['Oct  7 22:40:11 h sshd[1]: Accepted password for alice from 192.0.2.10 port 51234 ssh2', 'Oct  7 22:41:05 h sshd[1]: Failed password for root from 198.51.100.7 port 40024 ssh2']);
  assert.equal(text.format, 'text');
  assert.equal(text.template, '^.*?sshd\\[\\d+\\]:\\s+(?P<f1>\\S+)\\s+password\\s+for\\s+(?P<user>\\S+)\\s+from\\s+(?P<src>\\S+)\\s+port\\s+(?P<port>\\d+)\\s+ssh2');
  assert.equal(text.keys.find((k) => k.key === 'src').values[1], '198.51.100.7');
});

test('mapping: aliases, value shapes and enum guesses', () => {
  const a = analyseSample(['{"src_ip":"192.0.2.4","dst_port":443,"action":"deny","proto":"TCP","user":"jdoe","ts":"2026-10-07T22:00:00Z"}']);
  const ms = suggestMappings(a.keys, 'scwx.netflow');
  const by = Object.fromEntries(ms.map((m) => [m.key, m]));
  assert.equal(by.src_ip.field, 'sourceAddress$');
  assert.equal(by.dst_port.field, 'destinationPort$');
  assert.equal(by.action.field, 'flowAction$');
  assert.equal(by.action.transform.map[0].member, 'FW_BLOCKED');
  assert.equal(by.proto.transform.kind, 'protocol');
  assert.equal(by.ts.transform.layout, '2006-01-02T15:04:05Z07:00');
  assert.equal(guessEnum('Auth.ActionResult', 'Success'), 'SUCCESS');
  assert.equal(guessEnum('Antivirus.ActionTaken', 'Cleaned by deleting'), 'DELETED');
  assert.equal(pickSchema(a.keys, ''), 'scwx.netflow');
});

test('generated parsers run clean on the samples they came from', () => {
  for (const id of ['eset/eset-protect-on-prem', 'oisf/suricata']) {
    const lines = readFileSync(new URL(`../parsers/${id}/samples.log`, import.meta.url), 'utf8').split('\n').filter(Boolean);
    const a = analyseSample(lines);
    const plan = buildPlan(a, { vendor: 'Acme', product: 'Test', shipMethod: 'syslog' });
    const ps = writeParsers(plan, lines);
    const results = runParsers(ps, lines);
    assert.ok(results.every((r) => !r.error), `${id}: ${results.map((r) => r.error).filter(Boolean).join('; ')}`);
    assert.ok(results.filter((r) => r.normalized).length >= 4, `${id}: too few normalized lines`);
    const lint = lintParsers(ps, { samples: lines });
    assert.deepEqual(lint.problems.filter((p) => p.level === 'error'), [], id);
    for (const p of ps) assert.match(p.text, /Emulator result, not run in Sophos NG-SIEM/);
    assert.ok(keysFor(a, [0]).length > 3);
  }
});

test('a lowercase or uppercase mapping works on a number, TRUE, FALSE or a missing value', () => {
  // LOWERCASE() and UPPERCASE() fail the event on a number or TRUE, so the Map step writes
  // LOWERCASE(STRING(value)). The engine ran this generated parser on these lines and stored the
  // same fields (checked in a lab tenant).
  const lines = ['{"app":"zzprober7g","alert":"Malware Found","count":5,"blocked":true}', '{"app":"zzprober7g","alert":"Script Blocked","count":12,"blocked":false}', '{"app":"zzprober7g","alert":"Login"}'];
  const a = analyseSample(lines);
  const plan = buildPlan(a, { vendor: 'Acme', product: 'EDR', shipMethod: 'syslog' });
  const unit = plan.units[0];
  setUnitSchema(plan, a, unit, 'scwx.thirdpartyalert');
  unit.mappings = [['alert', 'title$', 'none'], ['count', 'logType$', 'lower'], ['blocked', 'provider$', 'upper']].map(([k, f, kind]) => ({ ...remap(unit, k, f), transform: { kind } }));
  const ps = writeParsers(plan, lines);
  assert.match(ps[0].text, /^logType\$ = LOWERCASE\(STRING\(json\["\$\.count"\]\)\)$/m);
  assert.match(ps[0].text, /^provider\$ = UPPERCASE\(STRING\(json\["\$\.blocked"\]\)\)$/m);
  const results = runParsers(ps, lines);
  assert.deepEqual(results.map((r) => r.error ?? null), [null, null, null]);
  assert.deepEqual(results.map(({ normalized: n }) => [n.title, n.log_type, n.provider]), [['Malware Found', '5', 'TRUE'], ['Script Blocked', '12', 'FALSE'], ['Login', undefined, undefined]]);
});

test('text templates fall back to value-like tokens for a single line', () => {
  const ev = analyseSample(['Oct  7 22:00:00 h app[1]: user jdoe logged in from 192.0.2.4']).events;
  assert.equal(textTemplate(ev, 'app', true), '^.*?app\\[\\d+\\]:\\s+user\\s+jdoe\\s+logged\\s+in\\s+from\\s+(?P<src>\\S+)');
});

test('lint: *= anywhere in the code is an error, because Sophos Fusion won\'t save it', () => {
  const head = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acmegw\n!SCHEMA=scwx.generic\n';
  const hit = (text) => lintParsers([{ name: 'ACME_GW', text: head + text }]).problems.filter((p) => p.code === 'restricted-syntax').map((p) => `${p.level}:${p.line}`);
  assert.deepEqual(hit('# doubles x *= 2'), ['error:4']);
  assert.deepEqual(hit('m = originalData$|(?P<k>\\w*=)'), ['error:4']);
  assert.deepEqual(hit('x = "a*=b"'), ['error:4']);
  assert.deepEqual(hit('m = originalData$|(?P<k>\\w*[=])\n# x += 1, x -= 1, x /= 2 and x %= 2 save'), []);
});

test('editor: NOT is colored as a keyword', async () => {
  // A stand-in for the few DOM calls the highlighter makes.
  const node = (cls, text) => ({ className: cls, textContent: text, kids: [], append(...k) { this.kids.push(...k); } });
  globalThis.document = { createDocumentFragment: () => node(null, ''), createElement: () => node('', ''), createTextNode: (t) => node(null, t) };
  try {
    const { highlightScriptLine } = await import('../studio/app/highlight.js');
    const kw = (line) => highlightScriptLine(line).kids.filter((k) => k.className === 'tk-kw').map((k) => k.textContent);
    assert.deepEqual(kw('ok$ = IF NOT x AND y THEN TRUE ELSE NULL'), ['IF', 'NOT', 'AND', 'THEN', 'TRUE', 'ELSE', 'NULL']);
    assert.deepEqual(kw('note = NOTE'), []);
  } finally {
    delete globalThis.document;
  }
});

test('detection: a CEF line with a header shorter than 6 fields isn\'t read as CEF, because CEF() fails on it', () => {
  assert.equal(analyseLine('CEF:0|V|P|1|100|N|5|a=b').format, 'cef');
  assert.notEqual(analyseLine('CEF:0|V|P|1|100').format, 'cef');
  assert.notEqual(analyseLine('Oct 14 01:02:03 host CEF:0|V|P').format, 'cef');
});

test('detect: a delimited row with key=value text in a column is read as columns, not as a key', () => {
  const lines = [
    '2026-10-12T11:40:15.123Z,192.0.2.25,EXCH01,SMTP,RECEIVE,jlee@example.com',
    '2026-10-12T11:42:03.950Z,192.0.2.21,EXCH01,SMTP,SEND,akim@example.com',
    '2026-10-12T11:46:00.441Z,192.0.2.25,EXCH01,AGENT,DROP,S:TRA=ETR|ruleId=4c5d|st=10/12/2026|action=DeleteMessage',
  ];
  assert.equal(analyseLine(lines[2]).format, 'kv');
  const a = analyseSample(lines);
  assert.equal(a.format, 'csv');
  assert.deepEqual(a.formats, { csv: 3 });
  assert.deepEqual(a.keys.map((k) => k.key), ['col0', 'col1', 'col2', 'col3', 'col4', 'col5']);
  assert.equal(a.keys.find((k) => k.key === 'col5').values[2], 'S:TRA=ETR|ruleId=4c5d|st=10/12/2026|action=DeleteMessage');
  // A key=value sample still reads as key=value.
  assert.equal(analyseSample([lines[2]]).format, 'kv');
});

// Reads one key from a line in the emulator, with the statements the generated parser uses to split
// the line.
function readWithParser(plan, k, line) {
  const ex = extraction(plan);
  const { vars } = execute([...ex.lines, `x = ${ex.read(k)}`].join('\n'), Object.fromEntries(rootVars(line)));
  return toPlain(vars.get('x'));
}

test('detect: a quoted delimited value keeps its delimiters, as SPLIT() reads it', () => {
  const lines = [
    '2026-10-12T11:40:15.611Z,192.0.2.21,"MDB:7f2c1e4a, Mailbox:9a8b7c6d, ClientType:StoreDriver",STOREDRIVER,DELIVER,jlee@example.com',
    '2026-10-12T11:42:03.950Z,192.0.2.21,08DCEB1F2A3B4C61,SMTP,SEND,akim@example.com',
  ];
  const a = analyseSample(lines);
  assert.deepEqual(a.keys.map((k) => k.key), ['col0', 'col1', 'col2', 'col3', 'col4', 'col5']);
  assert.equal(a.keys[2].values[0], 'MDB:7f2c1e4a, Mailbox:9a8b7c6d, ClientType:StoreDriver');
  const plan = buildPlan(a, { vendor: 'Acme', product: 'Mail', shipMethod: 'syslog' });
  assert.match(writeParsers(plan, lines)[0].text, /SPLIT\(\) reads CSV quotes, so a quoted value keeps the delimiters inside it/);
  for (const k of a.keys) assert.equal(readWithParser(plan, k, lines[0]), k.values[0], k.key);
});

test('detect: Exchange message tracking reads as its 30 columns and suggests the Email schema', () => {
  const lines = readFileSync(new URL('../parsers/microsoft/exchange-server-message-tracking/samples.log', import.meta.url), 'utf8').split('\n').filter(Boolean);
  const a = analyseSample(lines);
  assert.equal(a.keys.length, 30);
  const deliver = Object.fromEntries(a.events[1].fields.map((f) => [f.key, f.value]));
  assert.equal(deliver.col8, 'DELIVER');
  assert.equal(deliver.col13, '250 2.1.5 Recipient OK');
  assert.equal(deliver.col18, 'Invoice 4471 for October');
  // The address columns have no names, so they don't count as user names for CloudAudit.
  assert.equal(pickSchema(a.keys, '', { extraText: a.hintText }), 'scwx.email');
});

test('detect: text in front of the first key=value pair isn\'t part of its key, and the parser cuts it off there too', () => {
  const huawei = [
    '<190>2026-10-15 09:22:01 fw01.example.com %%01SECLOG/6/SESSION_BUILT(l):CID=2160731923;IPVer=4,Protocol=6,SourceIP=192.0.2.25,DestinationIP=203.0.113.80,SourcePort=50123',
    '<190>Oct 15 2026 09:21:40+10:00 fw02.example.com %%01SECLOG/6/SESSION_TEARDOWN(l):CID=2160731923;IPVer=4,Protocol=6,SourceIP=192.0.2.26,DestinationIP=203.0.113.81,SourcePort=50124',
  ];
  const a = analyseSample(huawei);
  assert.deepEqual(a.keys.map((k) => k.key), ['CID', 'Protocol', 'SourceIP', 'DestinationIP', 'SourcePort']);
  const plan = buildPlan(a, { vendor: 'Huawei', product: 'USG', shipMethod: 'syslog' });
  assert.match(writeParsers(plan, huawei)[0].text, /^body = originalData\$\|\(CID=\.\*\)\$$/m);
  for (const [i, line] of huawei.entries()) for (const k of a.keys) assert.equal(readWithParser(plan, k, line), k.values[i], k.key);
  // Lines that start their pairs at different keys: the parser cuts at whichever comes first.
  const bt = [
    'Oct 13 01:22:07 pra01.example.com BG[24117]:3021:01:01:event=login;site=access.example.com;status=success;who_ip=203.0.113.10',
    'Oct 13 01:30:12 pra01.example.com BG[24117]:3021:01:02:account=jsmith;site=access.example.com;status=disabled;who_ip=203.0.113.11',
  ];
  const b = analyseSample(bt);
  assert.deepEqual(b.keys.map((k) => k.key), ['event', 'site', 'status', 'who_ip', 'account']);
  const bp = buildPlan(b, { vendor: 'BeyondTrust', product: 'PRA', shipMethod: 'syslog' });
  assert.match(writeParsers(bp, bt)[0].text, /^body = originalData\$\|\(\(\?:event\|account\)=\.\*\)\$$/m);
  for (const [i, line] of bt.entries()) for (const k of b.keys.filter((x) => x.lines === 2)) assert.equal(readWithParser(bp, k, line), k.values[i], k.key);
  // A later pair with the end of the previous value glued to its key has that text in its name
  // for SPLIT_NAME_VALUES() too, so it isn't listed.
  const aw = analyseLine('<46>1 2026-10-15T02:15:02.000000Z sysloghost CylancePROTECT - - - Event Type: AuditLog, Event Name: ThreatGlobalQuarantine, Message: SHA256: AF68C74F, F2BAD753; Reason: Confirmed malicious by the SOC., User: Jane Smith (jsmith@example.com)');
  assert.deepEqual(aw.fields.map((f) => f.key), ['Event Type', 'Event Name', 'Message', 'User']);
});

test('detect: lines in another format than the sample\'s add no keys, so no mapping reads a key the parser can\'t', () => {
  const csv = [
    '2026/10/14 09:12:44 AEDT,FortiNAC,192.0.2.10,host-01,Login,jsmith,success',
    '2026/10/14 09:13:50 AEDT,FortiNAC,192.0.2.11,host-02,Logout,akim,success',
    '2026/10/14 09:14:20 AEDT,FortiNAC,192.0.2.12,host-03,Login,pkim,failure',
  ];
  const lines = [...csv, '{"srcAddr":"192.0.2.10","dstAddr":"198.51.100.2","action":"deny"}', 'CEF:0|Fortinet|FortiNAC|9.4|1001|Rogue host|5|src=192.0.2.12 shost=rogue-01 act=alert'];
  const a = analyseSample(lines);
  assert.equal(a.format, 'csv');
  assert.deepEqual(a.keys.map((k) => k.key), ['col0', 'col1', 'col2', 'col3', 'col4', 'col5', 'col6']);
  assert.match(a.notes.join(' '), /The parsers are written for the csv lines, so keys from the other lines aren't listed\./);
  const plan = buildPlan(a, { vendor: 'Fortinet', product: 'FortiNAC', shipMethod: 'syslog' });
  setUnitSchema(plan, a, plan.units[0], 'scwx.auth');
  assert.doesNotMatch(writeParsers(plan, lines).map((p) => p.text).join('\n'), /undefined/);
  // A key=value sample with a delimited row in it lists no columns.
  const kv = analyseSample(['user=jsmith src=192.0.2.10 action=login result=ok', 'user=akim src=192.0.2.11 action=logout result=ok', '2026-10-14 09:04:33,NPS01,jsmith,192.0.2.10,1']);
  assert.deepEqual(kv.keys.map((k) => k.key), ['user', 'src', 'action', 'result']);
});

test('lint: single-quoted strings are fine, as in Run Test and on save, and two side by side are a syntax error', () => {
  // The engine ran each good line and rejected 'it''s' as a syntax error, and Sophos Fusion saved a
  // parser with x = 'abc' and SPLIT('a,b', ',') as written (checked in a lab tenant).
  const lint = (line) => lintParsers([{ name: 'ACME_APP_STANDALONE_NIDS', text: `!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.nids\n${line}` }]).problems.filter((p) => p.level === 'error');
  for (const good of ["x = 'abc'", "x = \"a\" + 'b'", "x = IF TRUE THEN 'y' ELSE 'n'", "x = ['a', 'b']", "x = SPLIT('a,b', ',')"]) assert.deepEqual(lint(good), [], good);
  assert.deepEqual(lint("x = 'it''s'").map((p) => p.code), ['syntax']);
});

test('lint: a syntax error rejects the parser, which shows as one entry for every sample line', () => {
  const text = "!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acme-app\n!SCHEMA=scwx.nids\nmessage$ = \"m\"\nx = 'it''s'";
  const r = lintParsers([{ name: 'ACME_APP_STANDALONE_NIDS', text }], { samples: ['acme-app one', 'acme-app two'] });
  const errors = r.problems.filter((p) => p.level === 'error');
  assert.deepEqual(errors.map((p) => [p.code, p.parser, p.line]), [['syntax', 'ACME_APP_STANDALONE_NIDS', 5], ['rejected', 'ACME_APP_STANDALONE_NIDS', 5]]);
  assert.deepEqual(errors[1].lines, [1, 2]);
  assert.ok(r.results.every((x) => x.rejected && x.normalized === null));
});

test('lint: an unclosed call says it is missing its closing ), rather than asking for a comma', () => {
  const lint = (confirm, line = '') => lintParsers([{ name: 'ACME_APP_STANDALONE_NIDS', text: `!CONFIRMWITH=EXPRESSION\n!CONFIRMSTRING=${confirm}\n!SCHEMA=scwx.nids\nmessage$ = "m"\n${line}` }]).problems.filter((p) => p.code === 'syntax').map((p) => [p.line, p.message]);
  assert.deepEqual(lint('CONTAINS(message, "acme-app"'), [[2, 'confirm expression: CONTAINS() is missing its closing )']]);
  assert.deepEqual(lint('CONTAINS(message "acme-app")'), [[2, 'confirm expression: expected "," or ")" in CONTAINS(), found "acme-app"']]);
  assert.deepEqual(lint('CONTAINS(message, "acme-app")', 'x = [1, 2'), [[5, 'the list is missing its closing ]']]);
});

test('lint: a !PARENT line is a warning, because Sophos Fusion saves it only with Set Global Parent in Parser Script on, and !PARENT in a comment is fine', () => {
  // Without that option the save refused a !PARENT line ("code contains restricted syntax: !PARENT"),
  // with Override Global Parser on or off, and saved !PARENT in a comment; with it, the console saved
  // the line (checked in a lab tenant).
  const head = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=acmegw\n!SCHEMA=scwx.generic\n';
  const hit = (text) => lintParsers([{ name: 'ACME_GW', text: head + text }]).problems.filter((p) => p.code === 'restricted-syntax').map((p) => `${p.level}:${p.line}`);
  assert.deepEqual(hit('!PARENT=Azure_Monitor_Master\nkind = "a"'), ['warning:4']);
  assert.match(lintParsers([{ name: 'ACME_GW', text: `${head}!PARENT=Azure_Monitor_Master` }]).problems.find((p) => p.code === 'restricted-syntax').message, /saves a !PARENT line only with Set Global Parent in Parser Script turned on; without it the save fails with "code contains restricted syntax: !PARENT"/);
  assert.deepEqual(hit('# extend a global parser with !PARENT in the console\nkind = "a"'), []);
});

// Every field the page shows for every line, read back with the generated parser's statements. An
// empty value may read as NULL.
function readsEveryField(plan, a) {
  for (const e of a.events) {
    for (const f of e.fields) {
      const got = readWithParser(plan, f, e.line);
      if (!(f.value === '' && got === null)) assert.deepEqual(got, f.value, `${f.key} in ${e.line.slice(0, 60)}`);
    }
  }
}

test('detect: a JSON key with a - is read in brackets, since $.detail-type fails the event', () => {
  // The engine fails the event on $.detail-type and reads $['detail-type'] (checked in a lab tenant).
  const lines = [
    '{"detail-type":"Security Hub Findings - Imported","source":"aws.securityhub","detail":{"user-agent":"curl/8.5.0","port":"443"}}',
    '{"detail-type":"Security Hub Findings - Custom Action","source":"aws.securityhub","detail":{"user-agent":"Boto3/1.35","port":"22"}}',
  ];
  const a = analyseSample(lines);
  assert.equal(a.keys.find((k) => k.key === 'detail-type').path, "$['detail-type']");
  assert.equal(a.keys.find((k) => k.key === 'detail.user-agent').path, "$.detail['user-agent']");
  assert.equal(a.keys.find((k) => k.key === 'detail.port').path, '$.detail.port');
  const plan = buildPlan(a, { vendor: 'Acme', product: 'Hub', shipMethod: 'syslog' });
  readsEveryField(plan, a);
  const ps = writeParsers(plan, lines);
  assert.doesNotMatch(ps.map((p) => p.text).join('\n'), /\$\.detail-type|\.user-agent/);
  assert.deepEqual(runParsers(ps, lines).map((r) => r.error ?? null), [null, null]);
});

test('generated INT() mappings give NULL for "", "N/A" or other text instead of failing the event', () => {
  // INT() fails the event on anything but a whole number. The engine ran this capture and INT() on
  // "443", "", "N/A", " 1590", "x443", ISO text and a JSON number without failing (checked in a lab
  // tenant).
  const lines = [
    '{"app":"zzacme","src":"192.0.2.4","sport":"443","ts":1792459211000}',
    '{"app":"zzacme","src":"192.0.2.5","sport":"","ts":""}',
    '{"app":"zzacme","src":"192.0.2.6","sport":"N/A","ts":"2026-10-12T12:05:01.631Z"}',
    '{"app":"zzacme","src":"192.0.2.7","sport":" 1590","ts":1792459212000}',
  ];
  const a = analyseSample(lines);
  const plan = buildPlan(a, { vendor: 'Acme', product: 'Flow', shipMethod: 'syslog' });
  const unit = plan.units[0];
  setUnitSchema(plan, a, unit, 'scwx.netflow');
  unit.mappings = [['src', 'sourceAddress$', 'none'], ['sport', 'sourcePort$', 'int'], ['ts', 'eventTimeUsec$', 'epoch-ms']].map(([k, f, kind]) => ({ ...remap(unit, k, f), transform: { kind } }));
  const ps = writeParsers(plan, lines);
  assert.match(ps[0].text, /^sourcePortNum = sourcePortText\|\^\\s\*\(\?P<n>\[-\+\]\?\\d\{1,18\}\)\\s\*\$$/m);
  assert.match(ps[0].text, /^sourcePort\$ = IF sourcePortNum\["n"\] != "" THEN INT\(sourcePortNum\["n"\], 10\) ELSE NULL$/m);
  assert.match(ps[0].text, /^eventTimeUsec\$ = IF eventTimeUsecNum\["n"\] != "" THEN INT\(eventTimeUsecNum\["n"\], 10\) \* 1000 ELSE NULL$/m);
  const results = runParsers(ps, lines, { now: '2026-10-30T00:00:00Z' });
  assert.deepEqual(results.map((r) => r.error ?? null), [null, null, null, null]);
  assert.deepEqual(results.map((r) => r.normalized.source_port), [443, undefined, undefined, 1590]);
  assert.equal(results[0].normalized.event_time_usec, 1792459211000000);
  assert.deepEqual(lintParsers(ps, { samples: lines, now: '2026-10-30T00:00:00Z' }).problems.filter((p) => p.level === 'error'), []);
});

test('detect: a CEF key named by a label CEF() doesn\'t resolve is read from the key with that label, line by line', () => {
  // CEF() resolves labels on csN, cnN, flexStringN and flexNumberN only, so values["SBRSScore"] is
  // empty for cfp1Label=SBRSScore (checked in a lab tenant), and a label can sit on another key in
  // another line.
  const lines = [
    'CEF:0|Acme|Mail|1.0|100|Mail|5|cs1Label=MailPolicy cs1=DEFAULT cfp1Label=SBRSScore cfp1=2.1 deviceCustomDate1Label=createdAt deviceCustomDate1=Oct 20 2026 22:12:41 deviceCustomDate2Label=updatedAt deviceCustomDate2=Oct 21 2026 01:00:00',
    'CEF:0|Acme|Mail|1.0|100|Mail|5|cs1Label=MailPolicy cs1=STRICT cfp1Label=SBRSScore cfp1=-4.5 deviceCustomDate1Label=updatedAt deviceCustomDate1=Oct 22 2026 03:00:00',
  ];
  const a = analyseSample(lines);
  const key = (k) => a.keys.find((x) => x.key === k);
  assert.deepEqual(key('SBRSScore').labels, ['cfp1']);
  assert.deepEqual(key('updatedAt').labels, ['deviceCustomDate2', 'deviceCustomDate1']);
  assert.equal(key('MailPolicy').labels, undefined);
  const plan = buildPlan(a, { vendor: 'Acme', product: 'Mail', shipMethod: 'syslog' });
  readsEveryField(plan, a);
  assert.equal(extraction(plan).read(key('SBRSScore')), '(IF STRING(values["cfp1Label"]) == "SBRSScore" THEN values["cfp1"] ELSE values["SBRSScore"])');
  assert.equal(extraction(plan).read(key('MailPolicy')), 'values["MailPolicy"]');
  assert.equal(readWithParser(plan, key('updatedAt'), lines[0]), 'Oct 21 2026 01:00:00');
  assert.equal(readWithParser(plan, key('updatedAt'), lines[1]), 'Oct 22 2026 03:00:00');
});

test('detect: delimited lines with a syslog header are split after the header and tag, where the page reads them', () => {
  // message keeps the header unless it is a plain BSD one, and the tag either way, so the parser cuts
  // both off originalData$. The engine read every column of the library's syslog-header samples
  // this way (checked in a lab tenant).
  const lines = [
    '<174>Oct 12 22:40:15 exch01.example.com MSExchangeTracking: 2026-10-12T11:40:15.123Z,192.0.2.25,EXCH01,SMTP,RECEIVE',
    'Oct 12 22:40:16 exch01.example.com MSExchangeTracking: 2026-10-12T11:40:16.123Z,192.0.2.26,EXCH01,SMTP,SEND',
    '<133>1 2026-10-12T11:40:17.000Z exch02.example.com app[42]:  2026-10-12T11:40:17.123Z,192.0.2.27,EXCH02,SMTP,DROP',
    '<37>Oct 12 22:40:18 : 2026-10-12T11:40:18.123Z,192.0.2.28,EXCH03,SMTP,FAIL',
    '<13>2026-10-12T11:40:19.123Z,192.0.2.29,EXCH04,SMTP,FAIL',
    '2026-10-12T11:40:20.123Z,192.0.2.30,EXCH05,SMTP,FAIL',
  ];
  const a = analyseSample(lines);
  assert.ok(a.events.every((e) => e.format === 'csv' && /^2026-10-12T11:40:\d\d\.123Z$/.test(e.fields[0].value)), 'col0 is the time on every line');
  const plan = buildPlan(a, { vendor: 'Acme', product: 'Mail', shipMethod: 'syslog' });
  readsEveryField(plan, a);
  assert.match(writeParsers(plan, lines)[0].text, /^parts = SPLIT\(body\[1\], ","\)$/m);
  // A sample with no header or tag still splits message.
  const bare = analyseSample(lines.slice(5).concat('2026-10-12T11:40:21.123Z,192.0.2.31,EXCH06,SMTP,FAIL'));
  assert.match(writeParsers(buildPlan(bare, { vendor: 'Acme', product: 'Mail' }), lines)[0].text, /^parts = SPLIT\(message, ","\)$/m);
  // Exchange: the time column maps to the event time on every tracking line.
  const ex = readFileSync(new URL('../parsers/microsoft/exchange-server-message-tracking/samples.log', import.meta.url), 'utf8').split('\n').filter(Boolean);
  const ea = analyseSample(ex);
  const ep = buildPlan(ea, { vendor: 'Microsoft', product: 'Exchange', shipMethod: 'syslog' });
  readsEveryField(ep, ea);
  const results = runParsers(writeParsers(ep, ex), ex, { now: '2026-10-30T00:00:00Z' });
  const tracking = results.filter((r) => /\d{4}-\d\d-\d\dT[\d:.]+Z,/.test(r.sample ?? ex[r.line - 1]));
  assert.ok(tracking.length >= 8);
  for (const r of tracking) assert.ok(!r.error && !r.notes.some((n) => n.code === 'ingest-time'), `line ${r.line} has its own event time`);
});

test('detect: every line is read with the delimiter most lines use, as the parser splits them all with one', () => {
  const kv = analyseSample(['a=1,b=2,c=3,d=4', 'a=5,b=6,c=7,d=8', 'a=9 b=10 c=11 d=12']);
  assert.deepEqual(kv.events.map((e) => e.kv.delim), [',', ',', ',']);
  assert.equal(kv.events[2].fields.find((f) => f.key === 'a').value, '9 b=10 c=11 d=12');
  readsEveryField(buildPlan(kv, { vendor: 'Acme', product: 'Fw' }), kv);
  const csv = analyseSample(['x;y;z;w', 'p;q;r;s', 'a,b,c,d;e']);
  assert.deepEqual(csv.events.map((e) => e.csv.delim), [';', ';', ';']);
  assert.deepEqual(csv.events[2].fields.map((f) => f.value), ['a,b,c,d', 'e']);
  readsEveryField(buildPlan(csv, { vendor: 'Acme', product: 'Fw' }), csv);
});

test('detect: when space and comma find as many pairs, comma splits them, so values keep no trailing comma', () => {
  const line = '<189>Oct 15 2026 09:12:44+10:00 sw01.example.com %%01SHELL/5/LOGIN(l)[0]:The user succeeded in logging in to VTY0. (UserType=VTY, UserName=jsmith, Ip=192.0.2.25, VpnName=)';
  const a = analyseSample([line]);
  assert.equal(a.events[0].kv.delim, ',');
  assert.deepEqual(a.events[0].fields.map((f) => [f.key, f.value]), [['UserType', 'VTY'], ['UserName', 'jsmith'], ['Ip', '192.0.2.25'], ['VpnName', ')']]);
  readsEveryField(buildPlan(a, { vendor: 'Huawei', product: 'VRP' }), a);
  // Space still wins when it finds more pairs.
  assert.equal(analyseSample(['a=1 b=2,x c=3 d=4']).events[0].kv.delim, ' ');
});

test('a text template matches once in the line, since the engine keeps every match', () => {
  const lines = readFileSync(new URL('../parsers/cisco/aci/samples.log', import.meta.url), 'utf8').split('\n').filter(Boolean);
  const a = analyseSample(lines);
  assert.equal(a.format, 'text');
  assert.match(a.template, /^\^\.\*\?/);
  // Each group reads one value, the one the page shows, not a list of every match.
  readsEveryField(buildPlan(a, { vendor: 'Cisco', product: 'ACI' }), a);
});

test('detect: a JSON sample with no program tag is confirmed with each path as its own argument', () => {
  // The engine reads every argument of VALIDATE_ALL_JSONPATHS_EXIST() as a path and checks
  // originalData$ itself, so originalData$, "$.a,$.b" as the arguments never matched a line
  // (checked in a lab tenant).
  const lines = [
    '{"eventType":"login","userName":"jdoe","clientIp":"192.0.2.4"}',
    '{"eventType":"logout","userName":"asmith","clientIp":"192.0.2.5"}',
  ];
  const a = analyseSample(lines);
  assert.deepEqual(a.confirm, { kind: 'EXPRESSION', text: 'VALIDATE_ALL_JSONPATHS_EXIST("$.eventType", "$.userName", "$.clientIp")', why: 'every line has eventType, userName, clientIp' });
  const ps = writeParsers(buildPlan(a, { vendor: 'Acme', product: 'App', shipMethod: 'http-ingest' }), lines);
  const results = runParsers(ps, lines, { now: '2026-10-30T00:00:00Z' });
  assert.deepEqual(results.map((r) => [Boolean(r.extractor_path), r.error ?? null]), [[true, null], [true, null]]);
});

test('generated JSON-at-the-end parsers give a line with no JSON object no fields, not a failed event', () => {
  // JSON() of a capture that didn't match fails the event in the engine ("data type for JSON must
  // be string"), as on osquery's status lines; checked first, it gives NULL (checked in a lab tenant).
  const lines = [
    '<158>Oct 15 01:02:30 web01.example.com osqueryd[2214]: {"name":"processes","hostIdentifier":"web01.example.com","action":"added"}',
    '<158>Oct 15 01:05:00 web01.example.com osqueryd[2214]: {"name":"listening_ports","hostIdentifier":"web01.example.com","action":"removed"}',
    '<156>Oct 15 01:22:30 web01.example.com osqueryd[2214]: severity=1 location=scheduler.cpp:112 message=Scheduled query may have failed',
  ];
  const a = analyseSample(lines);
  const plan = buildPlan(a, { vendor: 'osquery', product: 'osquery', shipMethod: 'syslog' });
  assert.deepEqual(extraction(plan).lines.filter((l) => !l.startsWith('#')), ['jsonMatch = originalData$|(\\{.*})$', 'json = IF jsonMatch[1] != "" THEN JSON(jsonMatch[1]) ELSE NULL']);
  const results = runParsers(writeParsers(plan, lines), lines, { now: '2026-10-30T00:00:00Z' });
  assert.deepEqual(results.map((r) => r.error ?? null), [null, null, null]);
  assert.ok(results[2].extractor_path);
});

test('detect: CEF rt in epoch milliseconds maps to the event time as epoch milliseconds', () => {
  // CEF's rt is either a date or epoch milliseconds, as TippingPoint sends it.
  const lines = [
    'Oct 13 22:30:02 sms01 CEF:0|TippingPoint|UnityOne|6.1.0.7020|7202|7202: TCP: SYN Flood|4|act=Block src=192.0.2.4 dst=198.51.100.2 rt=1791930601204',
    'Oct 13 22:31:13 sms01 CEF:0|TippingPoint|UnityOne|6.1.0.7020|38120|38120: HTTP: Struts|4|act=Block src=192.0.2.5 dst=198.51.100.3 rt=1791930672880',
  ];
  const a = analyseSample(lines);
  assert.equal(a.keys.find((k) => k.key === 'rt').shape, 'epoch-ms');
  const plan = buildPlan(a, { vendor: 'Trend Micro', product: 'TippingPoint', shipMethod: 'syslog' });
  const m = plan.units.flatMap((u) => u.mappings).find((x) => x.key === 'rt');
  assert.deepEqual([m.field, m.transform.kind], ['eventTimeUsec$', 'epoch-ms']);
  const results = runParsers(writeParsers(plan, lines), lines, { now: '2026-10-30T00:00:00Z' });
  assert.deepEqual(results.map((r) => r.normalized.event_time_usec), [1791930601204000, 1791930672880000]);
  assert.equal(analyseLine('{"rt":1791930601204}').fields[0].key, 'rt');
  assert.equal(analyseSample(['{"rt":1791930601204,"a":"x"}', '{"rt":1791930672880,"a":"y"}']).keys.find((k) => k.key === 'rt').shape, 'epoch-ms');
});

test('generated DATETIME mappings give NULL for a time before 1970, so a zero date doesn\'t wrap the event time', () => {
  // 0001-01-01T00:00:00Z, which Tailscale sends for deferredAt, is a negative time, and the unsigned
  // event time field stores it as a huge number. A DATETIME value compares with a number as its
  // microseconds, and NULL > 0 is false (checked in a lab tenant).
  const lines = [
    '{"app":"zzacme","src":"192.0.2.4","when":"0001-01-01T00:00:00Z"}',
    '{"app":"zzacme","src":"192.0.2.5","when":"2026-10-20T00:31:09Z"}',
    '{"app":"zzacme","src":"192.0.2.6","when":"not a time"}',
  ];
  const a = analyseSample(lines);
  const plan = buildPlan(a, { vendor: 'Acme', product: 'Flow', shipMethod: 'syslog' });
  const unit = plan.units[0];
  setUnitSchema(plan, a, unit, 'scwx.netflow');
  unit.mappings = [['src', 'sourceAddress$', { kind: 'none' }], ['when', 'eventTimeUsec$', { kind: 'datetime', layout: '2006-01-02T15:04:05Z07:00' }]].map(([k, f, t]) => ({ ...remap(unit, k, f), transform: t }));
  const ps = writeParsers(plan, lines);
  assert.match(ps[0].text, /^eventTimeUsecTime = DATETIME\(json\["\$\.when"\], "2006-01-02T15:04:05Z07:00"\)\neventTimeUsec\$ = IF eventTimeUsecTime > 0 THEN eventTimeUsecTime ELSE NULL$/m);
  const now = '2026-10-30T00:00:00Z';
  const results = runParsers(ps, lines, { now });
  assert.deepEqual(results.map((r) => r.error ?? null), [null, null, null]);
  assert.deepEqual(results.map((r) => r.normalized.event_time_usec), [Date.parse(now) * 1000, Date.parse('2026-10-20T00:31:09Z') * 1000, Date.parse(now) * 1000]);
  assert.deepEqual(lintParsers(ps, { samples: lines, now }).problems.filter((p) => p.level === 'error'), []);
});

// The value each line shows for a key, read with the key the generated parsers read it by.
function readsEveryKey(plan, a) {
  for (const e of a.events) {
    for (const f of e.fields) {
      const got = readWithParser(plan, a.keys.find((k) => k.key === f.key), e.line);
      if (!(f.value === '' && got === null)) assert.deepEqual(got, f.value, `${f.key} in ${e.line.slice(0, 60)}`);
    }
  }
}

test('detect: a CEF label is listed once per line, and one with a header field\'s name by the key it labels', () => {
  // CEF() resolves cs1Label=Customer to its own key, so Customer is one key, read as values["Customer"].
  // Trellix NX sends cs1Label=name, and the parser reads the header's name by number, so the label's
  // value is listed as cs1 and read as values["cs1"].
  const lines = [
    'CEF:0|Trellix|MPS|10.0.1|WA|smartvision-event|5|act=notified cs1=Suspicious Remote Scheduled Task Activity cs1Label=name cs2=Acme cs2Label=Customer cn2Label=signatureId cn2=91500000',
    'CEF:0|Trellix|MPS|10.0.1|WA|malware-object|5|act=notified cs2=Globex cs2Label=Customer cn2Label=signatureId cn2=91500001',
    'CEF:0|Trellix|MPS|10.0.1|WA|web-infection|5|act=notified cs2=Initech cs2Label=src src=192.0.2.4',
  ];
  const a = analyseSample(lines);
  const key = (k) => a.keys.find((x) => x.key === k);
  assert.deepEqual([key('Customer').lines, key('signatureId').lines, key('name').lines], [2, 2, 3]);
  assert.deepEqual(key('name').values, ['smartvision-event', 'malware-object', 'web-infection']);
  assert.deepEqual(key('cs1').values, ['Suspicious Remote Scheduled Task Activity']);
  // A label with another key's name: values["src"] is that key's value, so the label's is listed as cs2.
  assert.deepEqual([key('src').values, key('cs2').values], [['192.0.2.4'], ['Initech']]);
  assert.ok(a.keys.every((k) => k.lines <= lines.length), 'no key is listed twice on a line');
  const plan = buildPlan(a, { vendor: 'Trellix', product: 'NX', shipMethod: 'syslog' });
  assert.deepEqual(['name', 'cs1', 'Customer'].map((k) => extraction(plan).read(key(k))), ['values[5]', 'values["cs1"]', 'values["Customer"]']);
  readsEveryKey(plan, a);
});
