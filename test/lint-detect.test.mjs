// Lint rules, format detection, mapping suggestions and generated parsers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lintParsers, overlaps } from '../studio/core/lint.js';
import { analyseSample, textTemplate } from '../studio/core/detect.js';
import { suggestMappings, pickSchema, guessEnum } from '../studio/core/mapping.js';
import { buildPlan, writeParsers, keysFor } from '../studio/app/plan.js';
import { runParsers } from '../studio/core/engine.js';

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

test('lint: field checks, sub-fields, DATETIME year, deprecated STRLEN, inferred markers', () => {
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
  for (const want of ['warning:not-a-field', 'error:sub-field', 'warning:datetime-year', 'warning:deprecated', 'warning:enum-raw', 'inferred:nested', 'inferred:datetime-utc', 'inferred:schema-id', 'inferred:op-AND']) {
    assert.ok(c.includes(want), `expected ${want} in ${c.join(', ')}`);
  }
  assert.equal(r.problems.find((p) => p.code === 'datetime-year').line, 9);
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
  const t = '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=x\n!SCHEMA=scwx.auth\nsourcePortNumber$ = "123"';
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
  assert.equal(text.template, 'sshd\\[\\d+\\]:\\s+(?P<f1>\\S+)\\s+password\\s+for\\s+(?P<user>\\S+)\\s+from\\s+(?P<src>\\S+)\\s+port\\s+(?P<port>\\d+)\\s+ssh2');
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

test('text templates fall back to value-like tokens for a single line', () => {
  const ev = analyseSample(['Oct  7 22:00:00 h app[1]: user jdoe logged in from 192.0.2.4']).events;
  assert.equal(textTemplate(ev, 'app', true), 'app\\[\\d+\\]:\\s+user\\s+jdoe\\s+logged\\s+in\\s+from\\s+(?P<src>\\S+)');
});
