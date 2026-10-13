// Library entries: metadata rules, the sample scan, the issue-form bundle, and the CI script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, writeFile, readFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateMeta, validateEntry, packBundle, unpackBundle, compareExpected, entryId, slug } from '../studio/core/library.js';
import { scanText } from '../studio/core/scan.js';
import { loadLibrary, loadEntryFromDir, listCollectors } from '../tools/lib/fs-library.mjs';
import { runParsers } from '../studio/core/engine.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const kinds = (text) => scanText(text).filter((f) => f.level === 'error').map((f) => f.code);

test('every seed entry in the library passes validation', async () => {
  const lib = await loadLibrary(ROOT);
  const collectors = await listCollectors(ROOT);
  assert.ok(lib.length >= 5);
  for (const e of lib) {
    const v = validateEntry(e, { library: lib.filter((x) => x.id !== e.id), collectors });
    assert.deepEqual(v.problems.filter((p) => p.level === 'error'), [], e.id);
    assert.equal(e.id, entryId(e.meta), `${e.id} folder matches vendor/product`);
  }
});

test('metadata rules', () => {
  const good = { vendor: 'Acme', product: 'Gateway', versions: [], format: 'json', ship_method: 'syslog', author: 'octocat', license: 'MIT', sample_source: 'synthetic', reference_time: '2026-10-13T00:00:00Z', tested: { emulator: '0.1.0', tenant: null }, parsers: [{ name: 'ACME_GW_JSON_PARENT', file: 'ACME_GW_JSON_PARENT.parser.txt', role: 'parent' }] };
  assert.deepEqual(validateMeta(good, ['meta.json', 'ACME_GW_JSON_PARENT.parser.txt', 'samples.log', 'expected.json']), []);
  const bad = validateMeta({ ...good, author: '@octo cat', license: 'GPL', sample_source: 'customer', format: 'yaml' }, ['meta.json', 'evil.exe']);
  const msgs = bad.map((p) => p.message).join('\n');
  for (const s of ['GitHub handle', 'license must be', 'sample_source', 'format must be', 'evil.exe is not allowed', 'samples.log is missing']) assert.match(msgs, new RegExp(s));
  assert.equal(slug('ESET PROTECT On-Prem'), 'eset-protect-on-prem');
});

test('the scan blocks secrets, private and real IPs, real emails, hostnames and company names', () => {
  assert.deepEqual(kinds('src=192.0.2.4 dst=198.51.100.2 host=www.example.com user=jdoe@example.com v6=2001:db8::1'), []);
  assert.deepEqual(kinds('src=10.1.2.3'), ['ip']);
  assert.deepEqual(kinds('src=8.8.4.4'), ['ip']);
  assert.deepEqual(kinds('ip6=fd00::1'), ['ip']);
  assert.deepEqual(kinds('from bob@realcorp.com.au'), ['email']);
  assert.deepEqual(kinds('User root@192.0.2.10 logged in'), []);
  assert.deepEqual(kinds('User root@8.8.4.4 logged in'), ['ip']);
  assert.deepEqual(kinds('see portal.realcorp.com.au'), ['hostname']);
  assert.deepEqual(kinds('host=dc01.corp.local'), ['hostname']);
  assert.deepEqual(kinds('Customer: Initrode Pty Ltd'), ['company']);
  assert.deepEqual(kinds('Customer: Acme Corp'), []);
  assert.deepEqual(kinds('key=AKIAIOSFODNN7EXAMPLE'), ['secret']);
  assert.deepEqual(kinds('"password":"Sup3rS3cret!"'), ['secret']);
  assert.deepEqual(kinds('"password":"REDACTED"'), []);
  assert.deepEqual(kinds('token ghp_abcdefghijklmnopqrstuvwxyz0123456789'), ['secret']);
  assert.deepEqual(kinds('C:\\Windows\\System32\\svchost.exe 5B97884A45C6C05F93B22C4059F3D9189E88E8B7 1361a9f6-1d45-4561-b33a-b5d6c62c71e0'), []);
  assert.deepEqual(kinds('ver 7.4.2 CVE-2017-5638.Struts2 time.ms local4.info'), []);
});

test('the scan lets version numbers through, but not as a way past the IP check', () => {
  assert.deepEqual(kinds('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'), []);
  assert.deepEqual(kinds('"browserVersion":"Chrome 141.0.0.0"'), []);
  assert.deepEqual(kinds('"agent_version":"4.6.0.112"'), []);
  assert.deepEqual(kinds('version 4.6.0.112'), []);
  // The same values without a version context are addresses.
  assert.deepEqual(kinds('src=4.6.0.112'), ['ip']);
  assert.deepEqual(kinds('client 141.0.0.0 server 8.8.8.8'), ['ip', 'ip']);
  // A private, carrier-grade NAT or link-local value is blocked even as a "version".
  assert.deepEqual(kinds('Chrome/192.168.1.1'), ['ip']);
  assert.deepEqual(kinds('"agent_version":"10.1.2.3"'), ['ip']);
  assert.deepEqual(kinds('"osVersion":"100.64.1.2"'), ['ip']);
});

test('the scan reads parser variables and .name properties as names, not hostnames', () => {
  assert.deepEqual(kinds('x.name$ = json["$.name"]\nrec.info$ = "a"\neventMetadata$.record$ = [x, rec]'), []);
  assert.deepEqual(kinds('"job.name":"Backup","Session.Name":"s1","parameters.name":"x"'), []);
  assert.deepEqual(kinds('see files.realcorp.com'), ['hostname']);
  assert.deepEqual(kinds('host=dc01.corp.local'), ['hostname']);
});

test('the scan lets the EICAR test file name through, and only that name', () => {
  assert.deepEqual(kinds('"file_path":"C:\\\\Users\\\\jdoe\\\\Downloads\\\\eicar.com","threat":"EICAR-Test-File"'), []);
  assert.deepEqual(kinds('fetched from eicar.com.au'), ['hostname']);
  assert.deepEqual(kinds('fetched from deicar.com'), ['hostname']);
});

test('the scan reads session IDs and GUIDs as identifiers unless they look like a random token', () => {
  assert.deepEqual(kinds('session_id="q6GJMuPu003642-q6GJMuPv003642" client_ip="192.0.2.4"'), []);
  assert.deepEqual(kinds('{"SessionId":"3fa85f64-5717-4562-b3fc-2c963f66afa6"}'), []);
  assert.deepEqual(kinds('sessionId=1a2b3c4d5e6f'), []);
  // A session token, a GUID under a key name, and a high-entropy session ID are still secrets.
  assert.deepEqual(kinds('session_token=abc123def456'), ['secret']);
  assert.deepEqual(kinds('api_key=3fa85f64-5717-4562-b3fc-2c963f66afa6'), ['secret']);
  assert.deepEqual(kinds('session_id=Q5bXrT9kLm2Vn8Pz4Wc7Yd1Hf6Jg3Ks0Ab'), ['secret']);
});

test('the issue-form bundle round-trips through an issue body', async () => {
  const e = await loadEntryFromDir(path.join(ROOT, 'parsers/eset/eset-protect-on-prem'), ROOT);
  const body = `### Submission\n\n\`\`\`text\n${packBundle(e)}\n\`\`\`\n\n### Notes\n\nnone`;
  const back = unpackBundle(body);
  assert.equal(back.id, 'eset/eset-protect-on-prem');
  assert.deepEqual(back.samples, e.samples);
  assert.equal(back.texts.ESET_PROTECT_JSON_PARENT, e.texts.ESET_PROTECT_JSON_PARENT);
  assert.throws(() => unpackBundle('nothing here'), /no Parser Studio bundle/);
});

test('expected.json comparison catches a changed parser', async () => {
  const e = await loadEntryFromDir(path.join(ROOT, 'parsers/squid/squid'), ROOT);
  const changed = e.parsers.map((p) => ({ ...p, text: p.text.replace('sensorType$ = "Squid"', 'sensorType$ = "Squid Proxy"') }));
  const diffs = compareExpected(runParsers(changed, e.samples, { now: e.meta.reference_time }), e.expected);
  assert.ok(diffs.length >= 4);
  assert.match(diffs[0], /sensor_type: emulator gives "Squid Proxy", expected.json has "Squid"/);
});

// Copies the repo to a temp folder, makes a change, and runs the CI script on it.
async function ciRun(change, author) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-ci-'));
  const base = path.join(dir, 'base');
  const pr = path.join(dir, 'pr');
  for (const d of [base, pr]) {
    await mkdir(d, { recursive: true });
    await cp(path.join(ROOT, 'parsers'), path.join(d, 'parsers'), { recursive: true });
    await cp(path.join(ROOT, 'collectors'), path.join(d, 'collectors'), { recursive: true });
  }
  const changed = await change(pr);
  await writeFile(path.join(dir, 'changed.txt'), changed.join('\n'));
  let code = 0;
  try {
    execFileSync(process.execPath, [path.join(ROOT, 'tools/validate-library.mjs'), '--root', pr, '--base', base, '--changed-files', path.join(dir, 'changed.txt'), '--author', author, '--report', path.join(dir, 'report.json')], { stdio: 'pipe' });
  } catch (e) { code = e.status; }
  const report = JSON.parse(await readFile(path.join(dir, 'report.json'), 'utf8'));
  await rm(dir, { recursive: true, force: true });
  return { code, report };
}

test('CI: a new entry from its author passes and can merge without review', async () => {
  const { code, report } = await ciRun(async (pr) => {
    const from = path.join(pr, 'parsers/squid/squid');
    const to = path.join(pr, 'parsers/ci-fixture/acme-web-proxy');
    await cp(from, to, { recursive: true });
    const meta = JSON.parse(await readFile(path.join(to, 'meta.json'), 'utf8'));
    Object.assign(meta, { vendor: 'CI Fixture', product: 'Acme Web Proxy', author: 'octocat' });
    meta.parsers[0].name = 'ACME_WEB_PROXY_STANDALONE_HTTP';
    meta.parsers[0].file = 'ACME_WEB_PROXY_STANDALONE_HTTP.parser.txt';
    await writeFile(path.join(to, 'meta.json'), JSON.stringify(meta, null, 2));
    const text = (await readFile(path.join(to, 'SQUID_ACCESS_SYSLOG_STANDALONE_HTTP.parser.txt'), 'utf8')).replace(/squid\(/g, 'acmeproxy(').replace(/squid\(\?:/g, 'acmeproxy(?:');
    await rm(path.join(to, 'SQUID_ACCESS_SYSLOG_STANDALONE_HTTP.parser.txt'));
    await writeFile(path.join(to, 'ACME_WEB_PROXY_STANDALONE_HTTP.parser.txt'), text.replace('squid(?:\\[\\d+\\])?:', 'acmeproxy(?:\\[\\d+\\])?:'));
    const samples = (await readFile(path.join(to, 'samples.log'), 'utf8')).replace(/squid\[/g, 'acmeproxy[');
    await writeFile(path.join(to, 'samples.log'), samples);
    const e = await loadEntryFromDir(to, pr);
    const res = runParsers(e.parsers, e.samples, { now: e.meta.reference_time });
    const { expectedFrom } = await import('../studio/core/library.js');
    await writeFile(path.join(to, 'expected.json'), JSON.stringify(expectedFrom(res), null, 2));
    return ['parsers/ci-fixture/acme-web-proxy/meta.json', 'parsers/ci-fixture/acme-web-proxy/samples.log'];
  }, 'octocat');
  assert.equal(code, 0, JSON.stringify(report.entries.map((e) => e.problems), null, 1));
  assert.equal(report.passed, true);
  assert.equal(report.eligible, true);
});

test('CI: a real IP in a sample fails, and changing someone else\'s entry needs review', async () => {
  const leak = await ciRun(async (pr) => {
    const f = path.join(pr, 'parsers/dnsmasq/dnsmasq/samples.log');
    await writeFile(f, (await readFile(f, 'utf8')).replace('192.0.2.50', '10.20.30.40'));
    return ['parsers/dnsmasq/dnsmasq/samples.log'];
  }, 'Aaronjacobs000');
  assert.equal(leak.code, 1);
  assert.ok(leak.report.entries[0].problems.some((p) => p.code === 'ip'));
  const other = await ciRun(async (pr) => {
    const f = path.join(pr, 'parsers/dnsmasq/dnsmasq/meta.json');
    const m = JSON.parse(await readFile(f, 'utf8'));
    m.notes += ' Updated.';
    await writeFile(f, JSON.stringify(m, null, 2));
    return ['parsers/dnsmasq/dnsmasq/meta.json'];
  }, 'someone-else');
  assert.equal(other.report.passed, true);
  assert.equal(other.report.eligible, false);
  assert.match(other.report.reasons.join(' '), /belongs to @Aaronjacobs000/);
  const outside = await ciRun(async () => ['tools/validate-library.mjs'], 'octocat');
  assert.equal(outside.report.eligible, false);
});

// The OpenAI audit log entry belongs to Aaronjacobs000, so a change from that login can merge
// without review when it passes.
const AUDIT = 'parsers/openai/api-platform-audit-logs/meta.json';
async function setCollector(pr, value) {
  const f = path.join(pr, AUDIT);
  const m = JSON.parse(await readFile(f, 'utf8'));
  if (value === undefined) delete m.collector; else m.collector = value;
  await writeFile(f, JSON.stringify(m, null, 2));
}
const collectorErrors = (r) => r.entries.flatMap((e) => e.problems).filter((p) => p.level === 'error' && p.code === 'collector').map((p) => p.message).join('\n');

test('CI: an entry can point at a collector on the base branch and still merge on its own', async () => {
  const { code, report } = await ciRun(async (pr) => { await setCollector(pr, 'collectors/ai-compliance-logs'); return [AUDIT]; }, 'Aaronjacobs000');
  assert.equal(code, 0, JSON.stringify(report.entries.map((e) => e.problems)));
  assert.equal(report.eligible, true, report.reasons.join('; '));
});

test('CI: a collector that is missing, outside collectors/, or only in the pull request fails', async () => {
  const missing = await ciRun(async (pr) => { await setCollector(pr, 'collectors/no-such-collector'); return [AUDIT]; }, 'Aaronjacobs000');
  assert.equal(missing.code, 1);
  assert.match(collectorErrors(missing.report), /collectors\/no-such-collector is not on the main branch/);
  for (const bad of ['parsers/openai/api-platform-audit-logs', '../collectors/ai-compliance-logs', 'collectors/ai-compliance-logs/ai_compliance_collector.py', '/collectors/ai-compliance-logs', 'https://example.com/collector.py']) {
    const r = await ciRun(async (pr) => { await setCollector(pr, bad); return [AUDIT]; }, 'Aaronjacobs000');
    assert.equal(r.code, 1, bad);
    assert.match(collectorErrors(r.report), /must be the path of a folder under collectors\//, bad);
  }
  // Added in the same pull request: the base branch doesn't have it yet, so it fails.
  const sameRequest = await ciRun(async (pr) => {
    await mkdir(path.join(pr, 'collectors/acme-pull'), { recursive: true });
    await writeFile(path.join(pr, 'collectors/acme-pull/README.md'), '# Acme\n');
    await writeFile(path.join(pr, 'collectors/acme-pull/acme_pull.py'), 'print("hi")\n');
    await setCollector(pr, 'collectors/acme-pull');
    return [AUDIT, 'collectors/acme-pull/README.md', 'collectors/acme-pull/acme_pull.py'];
  }, 'Aaronjacobs000');
  assert.equal(sameRequest.code, 1);
  assert.match(collectorErrors(sameRequest.report), /collectors\/acme-pull is not on the main branch/);
  assert.equal(sameRequest.report.eligible, false);
});

test('CI: a pull request that adds a file under collectors/ never merges on its own', async () => {
  const { code, report } = await ciRun(async (pr) => {
    await mkdir(path.join(pr, 'collectors/acme-pull'), { recursive: true });
    await writeFile(path.join(pr, 'collectors/acme-pull/acme_pull.py'), 'import os\nos.system("echo hi")\n');
    await setCollector(pr, 'collectors/ai-compliance-logs');
    return [AUDIT, 'collectors/acme-pull/acme_pull.py'];
  }, 'Aaronjacobs000');
  assert.equal(code, 0);
  assert.equal(report.passed, true);
  assert.equal(report.eligible, false);
  assert.match(report.reasons.join('; '), /changes collector code, which a maintainer always reviews: collectors\/acme-pull\/acme_pull.py/);
  const only = await ciRun(async () => ['collectors/ai-compliance-logs/ai_compliance_collector.py'], 'Aaronjacobs000');
  assert.equal(only.report.eligible, false);
  assert.match(only.report.reasons.join('; '), /collector code/);
});
