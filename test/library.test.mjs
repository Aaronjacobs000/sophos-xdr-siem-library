// Library entries: metadata rules, the sample scan, the issue-form bundle, and the CI script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, writeFile, readFile, rm, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateMeta, validateEntry, packBundle, unpackBundle, compareExpected, entryId, slug, searchText, hasBridge } from '../studio/core/library.js';
import { scanText } from '../studio/core/scan.js';
import { loadLibrary, loadEntryFromDir, listBridges } from '../tools/lib/fs-library.mjs';
import { runParsers } from '../studio/core/engine.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const kinds = (text) => scanText(text).filter((f) => f.level === 'error').map((f) => f.code);

test('every seed entry in the library passes validation', async () => {
  const lib = await loadLibrary(ROOT);
  const bridges = await listBridges(ROOT);
  assert.ok(lib.length >= 5);
  for (const e of lib) {
    const v = validateEntry(e, { library: lib.filter((x) => x.id !== e.id), bridges });
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

test('the scan lets Tenable.ad and Trellix ::~~ line breaks through', () => {
  assert.deepEqual(kinds('Tenable.ad raised an alert'), []);
  assert.deepEqual(kinds('cs6=GET /x.php HTTP/1.1::~~Host: www.example.com::~~Accept: */*::~~User-Agent: Mozilla/5.0::~~::~~'), []);
  // Other .ad names are still internal, and :: without the ~~ is still read as an address.
  assert.deepEqual(kinds('host=dc01.corp.ad'), ['hostname']);
  assert.deepEqual(kinds('next hop beef:: via eth0'), ['ip']);
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

test('the scan lets service domains, .id properties and versions in URL-encoded user agents through', () => {
  assert.deepEqual(kinds('"apiGroup":"rbac.authorization.k8s.io","apiVersion":"audit.k8s.io/v1"'), []);
  assert.deepEqual(kinds('"requestUri":"https://kv-example-prod.vault.azure.net/secrets/db/?api-version=7.4"'), []);
  assert.deepEqual(kinds('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'), []);
  assert.deepEqual(kinds('host=d111111abcdef8.cloudfront.net'), []);
  assert.deepEqual(kinds('# Block.ID names the block\n# event_metadata gets properties.id'), []);
  assert.deepEqual(kinds('ua=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/125.0.0.0%20Safari/537.36'), []);
  // A name under an Indonesian second-level domain is still a hostname, and an address that isn't
  // public is still blocked after an encoded browser token.
  assert.deepEqual(kinds('see mail.realcorp.co.id'), ['hostname']);
  assert.deepEqual(kinds('ua=x%20Chrome/192.168.1.1'), ['ip']);
  assert.deepEqual(kinds('ua=x%20Client/125.0.0.0'), ['ip']);
});

test('an entry file that is a symlink is reported, not followed', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-link-'));
  const entry = path.join(dir, 'parsers/dnsmasq/dnsmasq');
  await cp(path.join(ROOT, 'parsers/dnsmasq/dnsmasq'), entry, { recursive: true });
  await writeFile(path.join(dir, 'elsewhere.txt'), 'TEXT FROM OUTSIDE THE ENTRY\n');
  await rm(path.join(entry, 'samples.log'));
  await symlink(path.join(dir, 'elsewhere.txt'), path.join(entry, 'samples.log'));
  const e = await loadEntryFromDir(entry, dir);
  await rm(dir, { recursive: true, force: true });
  assert.ok(e.loadProblems.some((p) => p.level === 'error' && p.file === 'samples.log' && /not a regular file/.test(p.message)), JSON.stringify(e.loadProblems));
  assert.ok(!e.files.some((f) => f.content.includes('TEXT FROM OUTSIDE')));
  assert.deepEqual(e.samples, []);
});

test('CI: an entry whose folder doesn\'t match its vendor and product fails', async () => {
  const lib = await loadLibrary(ROOT);
  const e = lib.find((x) => x.id === 'dnsmasq/dnsmasq');
  const v = validateEntry({ ...e, id: 'dnsmasq/dns-masq' }, { library: lib.filter((x) => x.id !== e.id) });
  assert.deepEqual(v.problems.filter((p) => p.code === 'folder').map((p) => [p.level, p.message]), [['error', 'the folder is parsers/dnsmasq/dns-masq, but vendor and product make it parsers/dnsmasq/dnsmasq. Move the files there or change vendor and product.']]);
  const { code, report } = await ciRun(async (pr) => {
    await cp(path.join(pr, 'parsers/dnsmasq/dnsmasq'), path.join(pr, 'parsers/dnsmasq/dns-masq'), { recursive: true });
    await rm(path.join(pr, 'parsers/dnsmasq/dnsmasq'), { recursive: true });
    return ['parsers/dnsmasq/dnsmasq/meta.json', 'parsers/dnsmasq/dns-masq/meta.json'];
  }, 'Aaronjacobs000');
  assert.equal(code, 1);
  assert.ok(report.entries.find((x) => x.id === 'dnsmasq/dns-masq').problems.some((p) => p.level === 'error' && p.code === 'folder'));
});

test('library search finds the entries that need a bridge when you search for "bridge"', async () => {
  const meta = { vendor: 'OpenAI', product: 'API Platform audit logs', author: 'octocat', format: 'json', parsers: [{ name: 'OPENAI_AUDIT_JSON_STANDALONE', schema: 'scwx.cloudaudit' }] };
  assert.ok(searchText({ ...meta, bridge: 'bridges/ai-compliance-logs' }).includes('bridge'));
  assert.ok(searchText({ ...meta, bridge: 'bridges/ai-compliance-logs' }).includes('ai-compliance'));
  assert.ok(searchText({ ...meta, collector: 'collectors/ai-compliance-logs' }).includes('needs a bridge'));
  assert.equal(searchText(meta).includes('bridge'), false);
  assert.ok(searchText(meta).includes('scwx.cloudaudit') && searchText(meta).includes('octocat'));
  const lib = await loadLibrary(ROOT);
  const found = lib.filter((e) => searchText(e.meta).includes('bridge')).map((e) => e.id);
  assert.ok(found.length >= 10);
  assert.deepEqual(found, lib.filter((e) => hasBridge(e.meta)).map((e) => e.id));
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

test('expected.json must hold exactly what the emulator writes, with nothing extra', async () => {
  const e = await loadEntryFromDir(path.join(ROOT, 'parsers/squid/squid'), ROOT);
  const results = runParsers(e.parsers, e.samples, { now: e.meta.reference_time });
  assert.deepEqual(compareExpected(results, e.expected), []);
  const extra = structuredClone(e.expected);
  extra[0].notes = 'anything at all';
  assert.match(compareExpected(results, extra).join('\n'), /line 1: expected.json has fields the emulator doesn't write: notes/);
  const renumbered = structuredClone(e.expected);
  renumbered[1].line = 7;
  assert.match(compareExpected(results, renumbered).join('\n'), /line 2: expected.json doesn't match the emulator's output/);
  const empty = structuredClone(e.expected);
  empty[2] = null;
  assert.match(compareExpected(results, empty).join('\n'), /line 3: expected.json has no result for this line/);
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
    await cp(path.join(ROOT, 'bridges'), path.join(d, 'bridges'), { recursive: true });
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

// Adds a valid new entry, parsers/ci-fixture/acme-web-proxy, by octocat, and returns the files it changed.
async function addFixtureEntry(pr) {
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
}

test('CI: a new entry from its author passes and can merge without review', async () => {
  const { code, report } = await ciRun(addFixtureEntry, 'octocat');
  assert.equal(code, 0, JSON.stringify(report.entries.map((e) => e.problems), null, 1));
  assert.equal(report.passed, true);
  assert.equal(report.eligible, true);
});

test('CI: a file in a top-level folder that only looks like parsers/ needs review', async () => {
  for (const folder of [' parsers', '\u00a0parsers']) {
    const hidden = `${folder}/ci-fixture/acme-web-proxy/notes.txt`;
    const { report } = await ciRun(async (pr) => {
      const changed = await addFixtureEntry(pr);
      await mkdir(path.join(pr, path.dirname(hidden)), { recursive: true });
      await writeFile(path.join(pr, hidden), 'not a library file\n');
      return [...changed, hidden];
    }, 'octocat');
    assert.equal(report.eligible, false, JSON.stringify(folder));
    assert.deepEqual(report.outside, [hidden]);
    assert.match(report.reasons.join(' '), /changes files outside parsers\//);
  }
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
async function setBridge(pr, value) {
  const f = path.join(pr, AUDIT);
  const m = JSON.parse(await readFile(f, 'utf8'));
  if (value === undefined) delete m.bridge; else m.bridge = value;
  await writeFile(f, JSON.stringify(m, null, 2));
}
const bridgeErrors = (r) => r.entries.flatMap((e) => e.problems).filter((p) => p.level === 'error' && p.code === 'bridge').map((p) => p.message).join('\n');

test('CI: an entry can point at a bridge on the base branch and still merge on its own', async () => {
  const { code, report } = await ciRun(async (pr) => { await setBridge(pr, 'bridges/ai-compliance-logs'); return [AUDIT]; }, 'Aaronjacobs000');
  assert.equal(code, 0, JSON.stringify(report.entries.map((e) => e.problems)));
  assert.equal(report.eligible, true, report.reasons.join('; '));
});

test('CI: an entry with the old "collector" key passes with a warning and can still merge on its own', async () => {
  // A pull request opened before the rename names the bridge by its old key and path.
  const { code, report } = await ciRun(async (pr) => {
    const f = path.join(pr, AUDIT);
    const m = JSON.parse(await readFile(f, 'utf8'));
    delete m.bridge;
    m.collector = 'collectors/ai-compliance-logs';
    await writeFile(f, JSON.stringify(m, null, 2));
    return [AUDIT];
  }, 'Aaronjacobs000');
  assert.equal(code, 0, JSON.stringify(report.entries.map((e) => e.problems)));
  assert.equal(report.eligible, true, report.reasons.join('; '));
  assert.ok(report.entries[0].problems.some((p) => p.level === 'warning' && p.code === 'bridge' && /"collector" is the old name for "bridge"/.test(p.message)));
  const gone = await ciRun(async (pr) => { await setBridge(pr, undefined); const f = path.join(pr, AUDIT); const m = JSON.parse(await readFile(f, 'utf8')); m.collector = 'collectors/no-such-bridge'; await writeFile(f, JSON.stringify(m, null, 2)); return [AUDIT]; }, 'Aaronjacobs000');
  assert.equal(gone.code, 1);
  assert.match(bridgeErrors(gone.report), /bridges\/no-such-bridge is not on the main branch/);
});

test('CI: a bridge that is missing, outside bridges/, or only in the pull request fails', async () => {
  const missing = await ciRun(async (pr) => { await setBridge(pr, 'bridges/no-such-bridge'); return [AUDIT]; }, 'Aaronjacobs000');
  assert.equal(missing.code, 1);
  assert.match(bridgeErrors(missing.report), /bridges\/no-such-bridge is not on the main branch/);
  for (const bad of ['parsers/openai/api-platform-audit-logs', '../bridges/ai-compliance-logs', 'bridges/ai-compliance-logs/ai_compliance_bridge.py', '/bridges/ai-compliance-logs', 'https://example.com/bridge.py']) {
    const r = await ciRun(async (pr) => { await setBridge(pr, bad); return [AUDIT]; }, 'Aaronjacobs000');
    assert.equal(r.code, 1, bad);
    assert.match(bridgeErrors(r.report), /must be the path of a folder under bridges\//, bad);
  }
  // Added in the same pull request: the base branch doesn't have it yet, so it fails.
  const sameRequest = await ciRun(async (pr) => {
    await mkdir(path.join(pr, 'bridges/acme-pull'), { recursive: true });
    await writeFile(path.join(pr, 'bridges/acme-pull/README.md'), '# Acme\n');
    await writeFile(path.join(pr, 'bridges/acme-pull/acme_pull.py'), 'print("hi")\n');
    await setBridge(pr, 'bridges/acme-pull');
    return [AUDIT, 'bridges/acme-pull/README.md', 'bridges/acme-pull/acme_pull.py'];
  }, 'Aaronjacobs000');
  assert.equal(sameRequest.code, 1);
  assert.match(bridgeErrors(sameRequest.report), /bridges\/acme-pull is not on the main branch/);
  assert.equal(sameRequest.report.eligible, false);
});

test('CI: a pull request that adds a file under bridges/ never merges on its own', async () => {
  const { code, report } = await ciRun(async (pr) => {
    await mkdir(path.join(pr, 'bridges/acme-pull'), { recursive: true });
    await writeFile(path.join(pr, 'bridges/acme-pull/acme_pull.py'), 'import os\nos.system("echo hi")\n');
    await setBridge(pr, 'bridges/ai-compliance-logs');
    return [AUDIT, 'bridges/acme-pull/acme_pull.py'];
  }, 'Aaronjacobs000');
  assert.equal(code, 0);
  assert.equal(report.passed, true);
  assert.equal(report.eligible, false);
  assert.match(report.reasons.join('; '), /changes bridge code, which a maintainer always reviews: bridges\/acme-pull\/acme_pull.py/);
  const only = await ciRun(async () => ['bridges/ai-compliance-logs/ai_compliance_bridge.py'], 'Aaronjacobs000');
  assert.equal(only.report.eligible, false);
  assert.match(only.report.reasons.join('; '), /bridge code/);
});

test('the scan lets a library vendor\'s own company name through, and only that exact name', () => {
  const companies = (text, allowNames) => scanText(text, { allowNames }).filter((f) => f.code === 'company').map((f) => f.text);
  assert.deepEqual(companies('Company: Microsoft Corporation O=Microsoft Corp. signer=Palo Alto Networks Inc', ['Microsoft', 'Palo Alto Networks']), []);
  assert.deepEqual(companies('Company: Microsoft Corporation', []), ['Microsoft Corporation']);
  assert.deepEqual(companies('Customer: Initrode Pty Ltd', ['Microsoft']), ['Initrode Pty Ltd']);
  // Part of a name isn't enough: "isc" is inside Discovery and "rsa" inside Universal, and a
  // customer's name can hold a vendor's name.
  for (const name of ['Discovery Holdings Ltd', 'Universal Pty Ltd', 'Microsoft Australia Pty Ltd', 'Bluewave Microsoft Pty Ltd']) {
    assert.deepEqual(companies(`Customer: ${name}`, ['ISC', 'RSA', 'Microsoft']), [name]);
  }
});

test('validateEntry passes the allowed names to the sample scan', async () => {
  const e = await loadEntryFromDir(path.join(ROOT, 'parsers/microsoft/sysmon'), ROOT);
  e.samples = e.samples.map((l) => l.replace('Company: -', 'Company: Microsoft Corporation'));
  e.files = e.files.map((f) => (f.path === 'samples.log' ? { ...f, content: f.content.replace(/Company: -/g, 'Company: Microsoft Corporation') } : f));
  const companies = (v) => v.problems.filter((p) => p.code === 'company').map((p) => p.message);
  assert.equal(companies(validateEntry(e, {})).length, 1);
  assert.deepEqual(companies(validateEntry(e, { allowNames: ['Microsoft'] })), []);
});

// Puts a company name in the Company field of the Sysmon entry's samples, which belongs to
// Aaronjacobs000, and writes the expected.json the emulator gives for them.
async function setSysmonCompany(pr, company) {
  const dir = path.join(pr, 'parsers/microsoft/sysmon');
  const f = path.join(dir, 'samples.log');
  await writeFile(f, (await readFile(f, 'utf8')).replace(/Company: -/g, `Company: ${company}`));
  const e = await loadEntryFromDir(dir, pr);
  const { expectedFrom } = await import('../studio/core/library.js');
  await writeFile(path.join(dir, 'expected.json'), JSON.stringify(expectedFrom(runParsers(e.parsers, e.samples, { now: e.meta.reference_time })), null, 2) + '\n');
  return ['parsers/microsoft/sysmon/samples.log', 'parsers/microsoft/sysmon/expected.json'];
}

test('CI: a sample may name a vendor on the base branch, such as Microsoft Corporation, but not a customer', async () => {
  const vendor = await ciRun((pr) => setSysmonCompany(pr, 'Microsoft Corporation'), 'Aaronjacobs000');
  assert.equal(vendor.code, 0, JSON.stringify(vendor.report.entries.map((e) => e.problems)));
  assert.equal(vendor.report.eligible, true, vendor.report.reasons.join('; '));
  const customer = await ciRun((pr) => setSysmonCompany(pr, 'Initrode Pty Ltd'), 'Aaronjacobs000');
  assert.equal(customer.code, 1);
  assert.ok(customer.report.entries[0].problems.some((p) => p.code === 'company'));
});

test('CI: a pull request can\'t add to the allowed names with a vendor of its own', async () => {
  // The names come from the base branch, so a vendor that only the pull request adds doesn't count.
  const { code, report } = await ciRun(async (pr) => [...await addFixtureEntry(pr), ...await setSysmonCompany(pr, 'CI Fixture Pty Ltd')], 'Aaronjacobs000');
  assert.equal(code, 1);
  const sysmon = report.entries.find((e) => e.id === 'microsoft/sysmon');
  assert.ok(sysmon.problems.some((p) => p.code === 'company' && /CI Fixture Pty Ltd/.test(p.message)), JSON.stringify(sysmon.problems));
  assert.equal(report.eligible, false);
});
