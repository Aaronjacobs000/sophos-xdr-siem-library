// Rule entries: the query language subset, the checks CI runs on detection rule sets and case rules,
// the report and merge rules, the search test that ql-check runs, and the case rule install tool.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, mkdir, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseQuery, matches, ruleQueryProblems, regexLimits, pinnedSensorTypes, schemaFromQlName, valuesAt, QlError } from '../studio/core/ql.js';
import { compileRules, ruleHits, compareTests, testedState, parserLabel } from '../studio/core/rules.js';
import { validateRuleEntry, crossLibraryProblems, coveragePatterns, sharedTechniques, readCaseRuleYaml, caseRuleTitles } from '../tools/lib/rules.mjs';
import { loadRules, loadRuleEntry, loadCoverage } from '../tools/lib/fs-rules.mjs';
import { loadLibrary } from '../tools/lib/fs-library.mjs';
import { parseYamlDocuments, toJS, YamlError } from '../tools/lib/yaml.mjs';
import { reviewReasons } from '../tools/lib/merge-rules.mjs';
import { ruleQueries, compareRuleSearches, formatRuleReport } from '../tools/lib/ql-rules.mjs';
import { parseArgs as installArgs, templateText, install, readEntry } from '../tools/case-rule-install.mjs';
import { createInput, resaveInput, CASE_DOCUMENTS } from '../tools/lib/fusion-cases.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DET = 'thinkst/opencanary-honeypot-activity';
const CASE = 'thinkst/opencanary-one-case-per-source-ip';
const library = await loadLibrary(ROOT);
const rules = await loadRules(ROOT);
const { coverage } = await loadCoverage(ROOT);
const PLAYBOOKS = ['playbooks/microsoft/teams-case-chat-sync', 'playbooks/slack/slack-case-chat-sync'];
const opts = (over = {}) => ({ library, rules, coverage, playbooks: PLAYBOOKS, ...over });

// A copy of a rule entry with one file changed: edit(text) returns the new text.
function variant(id, file, edit) {
  const e = rules.find((x) => x.id === id);
  const files = e.files.map((f) => (f.path === file ? { ...f, content: edit(f.content) } : f));
  const meta = file === 'meta.json' ? JSON.parse(files.find((f) => f.path === 'meta.json').content) : e.meta;
  return { ...e, files, meta };
}
const errors = (v) => v.problems.filter((p) => p.level === 'error').map((p) => p.message).join('\n');
const metaEdit = (fn) => (text) => { const m = JSON.parse(text); fn(m); return JSON.stringify(m, null, 2); };

// ---------------------------------------------------------------- the query language

test('QL: parses a rule query with AND, OR, NOT, parentheses, lists and both kinds of string', () => {
  const p = parseQuery("FROM thirdparty WHERE sensor_type = 'OpenCanary' AND (log_type IN ('5002', '5003') OR NOT title CONTAINS e'it\\'s') AND port >= 22");
  assert.deepEqual(p.schemas, ['thirdparty']);
  assert.equal(p.where.type, 'and');
  assert.equal(p.whereText, "sensor_type = 'OpenCanary' AND (log_type IN ('5002', '5003') OR NOT title CONTAINS e'it\\'s') AND port >= 22");
  assert.equal(p.pipeline, null);
  // A plain string keeps its backslashes, as a regex needs.
  assert.equal(parseQuery("from nids where x matches_regex 'a\\d+'").where.value.value, 'a\\d+');
  assert.deepEqual(parseQuery("from nids where a = 1 earliest=-7d | aggregate count").time, [{ key: 'EARLIEST', value: '-7d' }]);
  assert.equal(parseQuery("from nids where a = 1 | aggregate count by b").pipeline, 'aggregate count by b');
});

test('QL: refuses what the query language refuses, such as NOT IN, with the reason', () => {
  assert.throws(() => parseQuery("from thirdparty where log_type not in ('5001')"), /write !IN rather than NOT IN/);
  assert.throws(() => parseQuery("from nids where x = 'open"), QlError);
  assert.throws(() => parseQuery('where x = 1'), /expected FROM/);
  assert.throws(() => parseQuery("from nids where x !matches_regex 'a'"), /!MATCHES_REGEX isn't an operator/);
});

test('QL: runs a query on a record the way Data Lake Search and rules do', () => {
  const rec = { sensor_type: 'OpenCanary', log_type: '5002', severity: 'MEDIUM', title: 'OpenCanary: Nmap OS scan', source_address: '203.0.113.99', additional_data: { record: [{ key: 'honeycred', value: 'true' }] } };
  const m = (q) => matches(parseQuery(`from thirdparty where ${q}`).where, rec);
  assert.ok(m("sensor_type = 'opencanary'"), '= is case-insensitive');
  assert.ok(m("log_type in ('5002', '5003')") && !m("log_type !in ('5002')"));
  assert.ok(m("title contains 'nmap'") && m("title !contains 'ssh'"));
  assert.ok(m("title matches 'OpenCanary: Nmap*'") && !m("title matches 'Nmap*'"));
  assert.ok(m("title matches_regex 'nmap (os|null)'"));
  assert.ok(m("severity = 'medium'") && m("severity != 'HIGH'"));
  assert.ok(m("source_address = '203.0.113.0/24'") && !m("source_address = '198.51.100.0/24'"), 'CIDR on an address');
  assert.ok(m("additional_data.record.key = 'honeycred'"), 'a path through a repeated field matches any element');
  // A missing field passes the negated operators and fails the rest, as a lab tenant showed for !=.
  assert.ok(m("missing_field != 'x'") && m("missing_field !in ('x')") && !m("missing_field = 'x'") && !m("missing_field contains 'x'"));
  assert.ok(m('missing_field is null') && m('title is not null') && !m('title is null'));
  assert.ok(m("not (log_type = '5001')") && !m("log_type = '5001' or log_type = '5000'"));
  assert.deepEqual(valuesAt({ a: [{ b: 1 }, { b: [2, 3] }] }, 'a.b'), [1, 2, 3]);
});

test('QL: a rule query reads one schema and fields rules can match, with enums by name', () => {
  const probs = (q, schemaId = null) => ruleQueryProblems(parseQuery(q), { schemaId }).map((p) => `${p.level} ${p.message}`).join('\n');
  assert.equal(probs("from thirdparty where sensor_type = 'OpenCanary' and severity = 'HIGH'", 'scwx.thirdpartyalert'), '');
  assert.match(probs("from thirdparty where severity = 4"), /severity is an enum.*refuses a number/);
  assert.match(probs("from thirdparty where severity = 'NOPE'"), /severity is an enum/);
  assert.match(probs("from nids, netflow where sensor_type = 'x'"), /names 2/);
  assert.match(probs("from nids where sensor_type = 'x' | aggregate count"), /pipeline/);
  assert.match(probs("from nids where sensor_type = 'x' earliest=-1d"), /EARLIEST/);
  assert.match(probs("from auth where src_ipgeo_summary.country = 'x'"), /can't match src_ipgeo_summary on auth/);
  assert.match(probs("from nids where hostname = 'x'"), /can't match hostname/);
  assert.match(probs("from nids where sensor_id = 'abc'"), /never sensor_id/);
  assert.match(probs("from nids where nope = 'x'"), /nope is not a field of scwx.nids/);
  assert.match(probs("from nids where sensor_type = 'x'", 'scwx.auth'), /the entry is for scwx.auth/);
  assert.match(probs("from widgets where a = 1"), /not a schema/);
  assert.equal(schemaFromQlName('thirdpartyalert'), 'scwx.thirdpartyalert');
  // Rules take FROM thirdpartyalert, but Data Lake Search refuses it, so a rule query can't use it.
  assert.match(probs("from thirdpartyalert where sensor_type = 'OpenCanary'", 'scwx.thirdpartyalert'), /write FROM thirdparty: Data Lake Search refuses FROM thirdpartyalert/);
  assert.match(probs("FROM Third_Party_Alert where sensor_type = 'OpenCanary'"), /write FROM thirdparty/);
  assert.equal(probs("FROM ThirdParty where sensor_type = 'OpenCanary'"), '');
  assert.equal(schemaFromQlName('management_event'), 'scwx.managementevent');
  assert.deepEqual(pinnedSensorTypes(parseQuery("from nids where sensor_type in ('a', 'b') and priority = 1")), ['a', 'b']);
  assert.deepEqual(pinnedSensorTypes(parseQuery("from nids where sensor_type = 'a' or priority = 1")), [], 'an OR doesn\'t pin it');
});

test('QL: regex stays inside the rule engine\'s limits', () => {
  assert.deepEqual(regexLimits('^ssh-\\d+\\.[a-z]+$'), []);
  assert.deepEqual(regexLimits('[(?=]+\\(\\?=x'), [], 'escaped and in a class, these are text');
  assert.deepEqual(regexLimits('(a)\\1'), ['a backreference']);
  assert.deepEqual(regexLimits('a(?=b)'), ['a lookahead or lookbehind']);
  assert.deepEqual(regexLimits('(?<!a)b'), ['a lookahead or lookbehind']);
  assert.ok(regexLimits('(?>a|ab)c').includes('an atomic group'));
  assert.ok(regexLimits('a++b').includes('a possessive quantifier'));
  assert.ok(regexLimits('a{2}+').includes('a possessive quantifier'));
  assert.match(regexLimits('(a')[0], /doesn't compile/);
  const p = ruleQueryProblems(parseQuery("from thirdparty where title matches_regex '(a)\\1'"));
  assert.ok(p.some((x) => x.code === 'regex' && /backreference/.test(x.message)));
});

// ---------------------------------------------------------------- the entries in the library

test('every rule entry in the library passes its checks', () => {
  assert.ok(rules.length >= 2);
  const results = new Map(rules.map((e) => [e.id, validateRuleEntry(e, opts())]));
  for (const [id, v] of results) assert.equal(v.ok, true, `${id}\n${errors(v)}`);
  assert.deepEqual(crossLibraryProblems(rules, results), {});
});

test('the OpenCanary rules trigger exactly the lines tests.json lists', async () => {
  const e = rules.find((x) => x.id === DET);
  const parser = library.find((x) => x.id === 'thinkst/opencanary');
  const { runParsers } = await import('../studio/core/engine.js');
  const hits = ruleHits(compileRules(e.parsedRules), runParsers(parser.parsers, parser.samples, { now: parser.meta.reference_time }));
  const tests = JSON.parse(e.files.find((f) => f.path === 'tests.json').content);
  assert.deepEqual(compareTests(tests, hits, e.ruleNames), []);
  assert.deepEqual(hits[11], ['OpenCanary login with a planted credential']);
  assert.deepEqual(hits[0], [], 'OpenCanary\'s own start-up line stays generic and quiet');
});

test('tests.json is held exactly: a missing, extra or doubled line fails', () => {
  const names = ['A', 'B'];
  const hits = [['A'], [], ['B'], []];
  assert.deepEqual(compareTests({ triggers: { A: [1], B: [3] }, quiet: [2, 4] }, hits, names), []);
  assert.match(compareTests({ triggers: { A: [1, 2], B: [3] }, quiet: [4] }, hits, names).join(), /line 2 should trigger "A"/);
  assert.match(compareTests({ triggers: { A: [1] }, quiet: [2] }, hits, names).join(), /"B" has no lines|line 3 triggers "B"/);
  assert.match(compareTests({ triggers: { A: [1], B: [3] }, quiet: [] }, hits, names).join(), /needs "quiet"/);
  assert.match(compareTests({ triggers: { A: [1], B: [3, 9] }, quiet: [2] }, hits, names).join(), /9 under "B" is not a line/);
  assert.match(compareTests({ triggers: { A: [1], B: [3] }, quiet: [1] }, hits, names).join(), /both quiet and under "A"/);
  assert.match(compareTests({ triggers: { A: [1], B: [1] }, quiet: [2] }, [['A', 'B'], [], [], []], names).join(), /triggers 2 rules/);
});

test('detection checks: the contributor rules CI can check fail when broken', () => {
  const check = (file, edit, more = {}) => errors(validateRuleEntry(variant(DET, file, edit), opts(more)));
  const firstQuery = "from thirdparty\n      where sensor_type = 'OpenCanary'\n        and alert_category = 'Login attempt'\n        and severity = 'HIGH'";
  const swapQuery = (q) => (t) => t.replace(firstQuery, q);
  // 1. The parser must be in the library, and the query must pin a sensor type it writes.
  assert.match(check('meta.json', metaEdit((m) => { m.parser = 'parsers/acme/nothing'; })), /not a parser entry in the library/);
  assert.match(check('meta.json', metaEdit((m) => { m.sensor_types = ['OpenCanary', 'Other']; })), /Other isn't a sensor type parsers\/thinkst\/opencanary writes/);
  assert.match(check('rules.yaml', swapQuery("from thirdparty where alert_category = 'Login attempt' and severity = 'HIGH'")), /must pin the sensor type/);
  // 2. A sensor type Sophos's own rules name is a built-in one.
  const denied = { ...coverage, schemas: { ...coverage.schemas, 'scwx.nids': { ...coverage.schemas['scwx.nids'], named_sensor_types: ['^OpenCanary$'] } } };
  assert.match(errors(validateRuleEntry(rules.find((x) => x.id === DET), opts({ coverage: denied }))), /OpenCanary is a sensor type Sophos's own rules name/);
  // 3. No IOC rules.
  assert.match(check('rules.yaml', swapQuery("from thirdparty where sensor_type = 'OpenCanary' and source_address in ('203.0.113.9', '198.51.100.4')")), /only matches literal IP addresses/);
  assert.match(check('rules.yaml', swapQuery("from thirdparty where sensor_type = 'OpenCanary' and domain_name = 'bad.example.net'")), /only matches literal IP addresses/);
  // A dotted event name, such as vault.export, looks like a domain but isn't an IOC.
  assert.doesNotMatch(check('rules.yaml', swapQuery("from thirdparty where sensor_type = 'OpenCanary' and alert_category in ('vault.export', 'repo.destroy')")), /only matches literal IP addresses/);
  // 6. A condition beyond sensor_type, and Low rules ship off.
  assert.match(check('rules.yaml', swapQuery("from thirdparty where sensor_type = 'OpenCanary'")), /needs a condition beyond sensor_type/);
  assert.match(check('rules.yaml', (t) => t.replace('severity: critical', 'severity: low')), /is low, so it ships off/);
  assert.match(check('meta.json', metaEdit((m) => { delete m.volume; })), /volume is required/);
  // 8. The MDR note is in public words.
  assert.match(check('meta.json', metaEdit((m) => { m.mdr_note = 'MDR Premier will work these on its roadmap.'; })), /reads as an internal tier/);
  // The fields of the Create Rule form only, valid MITRE IDs, and the query checks.
  assert.match(check('rules.yaml', (t) => t.replace('    enabled_by_default: true\n', '    enabled_by_default: true\n    group_key: x\n')), /"group_key" is not a field/);
  assert.match(check('rules.yaml', (t) => t.replace('- T1078', '- Credential Access')), /MITRE ATT&CK technique IDs/);
  assert.match(check('rules.yaml', swapQuery("from thirdparty where sensor_type = 'OpenCanary' and severity = 4")), /severity is an enum/);
  // tests.json is held to the rules.
  assert.match(check('tests.json', (t) => t.replace('"OpenCanary Nmap scan": [16, 17, 18, 19]', '"OpenCanary Nmap scan": [16, 17, 18]')), /sample line 19 triggers "OpenCanary Nmap scan"/);
  // The folder follows vendor and title, and links resolve.
  assert.match(check('meta.json', metaEdit((m) => { m.title = 'Something else'; })), /vendor and title make it rules\/thinkst\/something-else/);
  assert.match(check('meta.json', metaEdit((m) => { m.links.playbooks = ['playbooks/acme/nothing']; })), /not a playbook in the library/);
  // Secrets and personal data: the same scan as every entry.
  assert.match(check('rules.yaml', (t) => t.replace("sensor_type = 'OpenCanary'\n        and log_type = '5000'", "sensor_type = 'OpenCanary'\n        and log_type = '5000'\n        and source_address != '8.8.8.8'")), /8\.8\.8\.8/);
});

test('detection checks: rule names are unique across the library, and no line triggers two entries', () => {
  const copy = { ...rules.find((x) => x.id === DET), id: 'thinkst/opencanary-copy' };
  const all = [...rules, copy];
  assert.match(errors(validateRuleEntry(copy, opts({ rules: all }))), /same name as a rule in rules\/thinkst\/opencanary-honeypot-activity/);
  const results = new Map(all.map((e) => [e.id, validateRuleEntry(e, opts({ rules: all }))]));
  const cross = crossLibraryProblems(all, results);
  assert.match(cross[DET].map((p) => p.message).join(), /sample line 4 triggers .* in rules\/thinkst\/opencanary-copy/);
});

test('detection checks: overlap with Sophos\'s rules and regex are warnings for the reviewer', () => {
  const shared = { ...coverage, schemas: { ...coverage.schemas, 'scwx.thirdpartyalert': { ...coverage.schemas['scwx.thirdpartyalert'], any_sensor_techniques: ['T1110.001'] } } };
  const v = validateRuleEntry(rules.find((x) => x.id === DET), opts({ coverage: shared }));
  assert.equal(v.ok, true);
  assert.match(v.problems.filter((p) => p.code === 'review').map((p) => p.message).join('\n'), /shares T1110 with Sophos rules on scwx.thirdpartyalert/);
  assert.deepEqual(sharedTechniques(shared, 'scwx.thirdpartyalert', ['T1110', 'T1046']), ['T1110']);
  const { exact, patterns } = coveragePatterns({ schemas: { 'scwx.nids': { named_sensor_types: ['^SuricataEve$', 'Zeek', '^(MICROSOFT_GRAPH_SIGN_IN|MICROSOFT_OFFICE_MANAGEMENT)$', '(Cisco eStreamer|isensor)', '(microsoft|azure)'] } } });
  assert.deepEqual([...exact.keys()].sort(), ['microsoft_graph_sign_in', 'microsoft_office_management', 'suricataeve', 'zeek']);
  assert.deepEqual(patterns.map((p) => p.pattern), ['(Cisco eStreamer|isensor)', '(microsoft|azure)'], 'an unanchored alternation matches any sensor type containing a name');
  const rx = errors(validateRuleEntry(variant(DET, 'rules.yaml', (t) => t.replace("and log_type = '5000'", "and log_type = '5000'\n        and title matches_regex 'SMB.*'")), opts()));
  assert.equal(rx, '');
});

test('case checks: the filter takes only the entry\'s own Medium and higher custom detections', () => {
  const check = (edit) => errors(validateRuleEntry(variant(CASE, 'case-rule.yaml', edit), opts()));
  assert.match(check((t) => t.replace('state: TEST', 'state: ENABLED')), /state must be TEST/);
  assert.match(check((t) => t.replace("metadata.creator.detector.detector_id = 'app:event-filter-ql' and ", '')), /must take only custom detections/);
  assert.match(check((t) => t.replace("and title in (", "or title in (")), /must take only custom detections|must name the rules/);
  assert.match(check((t) => t.replace("'OpenCanary Nmap scan'", "'Somebody elses rule'")), /isn't a rule in rules\/thinkst\/opencanary-honeypot-activity/);
  assert.match(check((t) => t.replace("ip + ' opencanary_one_case_per_source_ip'", 'ip')), /must carry the rule's name/);
  assert.match(check((t) => t.replace('    status: OPEN\n', '    status: OPEN\n    assignee: 12345\n')), /leave out the assignee/);
  assert.match(check((t) => t.replace('type: SECURITY_INVESTIGATION', 'type: INCIDENT_RESPONSE')), /SECURITY_INVESTIGATION/);
  assert.match(check((t) => t.replace('template_name: opencanary_honeypot_unofficial', 'template_name: other_template')), /template_name must be the template in the same file/);
  assert.match(check((t) => t.split('---')[0]), /two documents/);
  // A Low rule can't be collected: case rules act only on Medium and higher detections.
  const lowRules = rules.map((e) => (e.id === DET ? { ...e, parsedRules: e.parsedRules.map((r) => (r.name === 'OpenCanary Nmap scan' ? { ...r, severity: 'low' } : r)) } : e));
  assert.match(errors(validateRuleEntry(rules.find((x) => x.id === CASE), opts({ rules: lowRules }))), /a low rule\. Case rules act only on Medium/);
  const v = validateRuleEntry(variant(CASE, 'case-rule.yaml', (t) => t.replace('append_filter: ""', "append_filter: from detection where severity >= 0.6")), opts());
  assert.match(v.problems.map((p) => p.message).join('\n'), /Review: append_filter adds detections/);
  assert.deepEqual(caseRuleTitles("from detection where metadata.creator.detector.detector_id = 'app:event-filter-ql' and title = 'One'"), ['One']);
});

test('case checks: a case rule on FileMod detections groups on hostId, since they carry no host name', () => {
  const QNAP = 'qnap/qnap-one-case-per-nas';
  assert.equal(errors(validateRuleEntry(rules.find((x) => x.id === QNAP), opts())), '');
  const byHost = (t) => t.replace(/\$\{alertEntities\(inputs\)\.filter\(e, e\.startsWith\('hostId:'\)\)\.map\(e, e\.split\(':'\)\[1\] \+ ' qnap_one_case_per_nas'\)\}/, "${alertHostnames(inputs).map(h, h + ' qnap_one_case_per_nas')}");
  assert.notEqual(byHost(rules.find((x) => x.id === QNAP).files.find((f) => f.path === 'case-rule.yaml').content), rules.find((x) => x.id === QNAP).files.find((f) => f.path === 'case-rule.yaml').content, 'the test edit applies');
  assert.match(errors(validateRuleEntry(variant(QNAP, 'case-rule.yaml', byHost), opts())), /a FileMod detection carries no host name.*hostId/);
  // Other schemas have a host name, and alertHostnames groups their detections.
  assert.doesNotMatch(errors(validateRuleEntry(rules.find((x) => x.id === 'airlock-digital/airlock-digital-one-case-per-host'), opts())), /host name/);
});

test('case checks: links must point both ways, and a case entry has no search record', () => {
  const v = validateRuleEntry(variant(CASE, 'meta.json', metaEdit((m) => { m.tested.search = '2026-11-22'; m.links.detection_rules = 'rules/thinkst/nothing'; })), opts());
  assert.match(errors(v), /tested.search is for detection rules/);
  assert.match(errors(v), /not a detection rule entry in the library/);
  assert.equal(testedState({ tested: { search: '2026-11-22', tenant: null } }).key, 'search');
  assert.equal(testedState({ tested: { search: null, tenant: { date: '2026-11-22', region: 'us01' } } }).label, 'ran in a tenant 2026-11-22');
});

test('YAML: a case rule file reads as its two documents, with lines from the whole file', async () => {
  const text = await readFile(path.join(ROOT, 'rules', CASE, 'case-rule.yaml'), 'utf8');
  const docs = parseYamlDocuments(text);
  assert.deepEqual(docs.map((d) => toJS(d).kind), ['rule', 'template']);
  const doc = readCaseRuleYaml(text);
  assert.equal(doc.lines.filter, 10);
  assert.ok(doc.templateLine > 15);
  assert.throws(() => parseYamlDocuments('a: 1\n---\nb: [\n'), (e) => e instanceof YamlError && e.line === 3);
});

// ---------------------------------------------------------------- report and merge

test('merge: rules never merge on their own, with the playbook reason', () => {
  assert.match(reviewReasons(['rules/thinkst/opencanary-honeypot-activity/rules.yaml']).join(), /changes rules, which act on tenants like playbooks and can take detections from other case rules, so the owner always reviews them/);
  assert.doesNotMatch(reviewReasons(['rules/thinkst/x/meta.json']).join(), /outside parsers/);
  assert.match(reviewReasons(['rules/sophos-coverage.json']).join(), /changes rules/);
});

async function ciRun(change) {
  const dir = await mkdtemp(path.join(tmpdir(), 'xsl-rules-ci-'));
  try {
    const base = path.join(dir, 'base');
    const pr = path.join(dir, 'pr');
    for (const d of [base, pr]) {
      await mkdir(d, { recursive: true });
      for (const f of ['parsers', 'rules', 'playbooks', 'connectors']) await cp(path.join(ROOT, f), path.join(d, f), { recursive: true });
    }
    const changed = await change(pr);
    await writeFile(path.join(dir, 'changed.txt'), changed.join('\n'));
    let code = 0;
    try {
      execFileSync(process.execPath, [path.join(ROOT, 'tools/validate-library.mjs'), '--root', pr, '--base', base, '--changed-files', path.join(dir, 'changed.txt'), '--author', 'Aaronjacobs000', '--report', path.join(dir, 'report.json'), '--markdown', path.join(dir, 'report.md')], { stdio: 'pipe' });
    } catch (e) { code = e.status; }
    return { code, report: JSON.parse(await readFile(path.join(dir, 'report.json'), 'utf8')), md: await readFile(path.join(dir, 'report.md'), 'utf8') };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('CI: a rule change is checked, reported with reviewer warnings, and waits for the owner', async () => {
  const { code, report, md } = await ciRun(async () => [`rules/${DET}/rules.yaml`]);
  assert.equal(code, 0, md);
  assert.equal(report.passed, true);
  assert.equal(report.eligible, false);
  assert.deepEqual(report.entries.map((e) => e.id).sort(), [`rules/${DET}`, `rules/${CASE}`].sort(), 'the case entry that collects it is checked too');
  assert.match(md, /\*\*rules\/thinkst\/opencanary-honeypot-activity\*\* \(changed\): passed/);
  assert.match(md, /Warning in `meta.json`: Review: check the stated volume/);
  assert.match(md, /This change needs a maintainer review: changes rules/);
  assert.match(md, /Rule checks are offline too: run each query in Data Lake Search before a rule goes live/);
});

test('CI: a broken rule fails the checks, and a parser change checks the rules that need it', async () => {
  const broken = await ciRun(async (pr) => {
    const f = path.join(pr, 'rules', DET, 'tests.json');
    await writeFile(f, (await readFile(f, 'utf8')).replace('[16, 17, 18, 19]', '[16, 17]'));
    return [`rules/${DET}/tests.json`];
  });
  assert.equal(broken.code, 1);
  assert.match(broken.md, /sample line 18 triggers "OpenCanary Nmap scan"/);
  const parser = await ciRun(async (pr) => {
    const f = path.join(pr, 'parsers/thinkst/opencanary/meta.json');
    await writeFile(f, await readFile(f, 'utf8'));
    return ['parsers/thinkst/opencanary/meta.json'];
  });
  assert.equal(parser.code, 0, parser.md);
  assert.ok(parser.report.entries.some((e) => e.id === `rules/${DET}`));
  assert.equal(parser.report.eligible, true, 'a parser-only change still merges on its own');
});

// ---------------------------------------------------------------- search test and install tool

test('ql-check rules: the searches it sends, and how it compares them with the offline check', () => {
  const e = rules.find((x) => x.id === DET);
  const q = ruleQueries(e.meta, e.parsedRules, { earliest: '-14d', where: "host_id = 'opencanary-1'" });
  assert.equal(q.universe, "from thirdparty where sensor_type in ('OpenCanary') and (host_id = 'opencanary-1') earliest=-14d");
  assert.match(q.rules[3].text, /^from thirdparty where \(sensor_type = 'OpenCanary'\s+and alert_category = 'Port scan'\s+and log_type != '5001'\) and \(host_id = 'opencanary-1'\) earliest=-14d$/);
  const parser = library.find((x) => x.id === 'thinkst/opencanary');
  const tests = JSON.parse(e.files.find((f) => f.path === 'tests.json').content);
  // Data Lake rows: the parser's records with the raw line, and unset strings as "".
  const rows = parser.expected.filter((x) => x.schema === 'scwx.thirdpartyalert').map((x, i) => ({ resource_id: `r${i}`, alert_category: '', ...x.normalized, original_data: parser.samples[x.line - 1] }));
  const byRule = new Map(e.parsedRules.map((r) => [r.name, rows.filter((row) => matches(parseQuery(r.query).where, row))]));
  const report = compareRuleSearches(e.parsedRules, rows, byRule, { samples: parser.samples, tests });
  const out = formatRuleReport(report);
  assert.equal(out.agree, true, out.text);
  assert.match(out.text, /OpenCanary Nmap scan: Data Lake Search returned 4, the offline check predicts 4, the same records/);
  byRule.set('OpenCanary Nmap scan', byRule.get('OpenCanary Nmap scan').slice(1));
  const off = formatRuleReport(compareRuleSearches(e.parsedRules, rows, byRule, { samples: parser.samples, tests }));
  assert.equal(off.agree, false);
  assert.match(off.text, /1 only offline/);
});

function fakeCases({ rules: start = [], templates = [] } = {}) {
  const state = { rules: start.map((r) => ({ ...r })), templates: [...templates], calls: [] };
  const client = {
    resolveTenant: async () => 'tenant', getToken: async () => 'token',
    async request(op, v) {
      state.calls.push(op);
      if (!CASE_DOCUMENTS[op]) throw new Error(`unknown ${op}`);
      if (op === 'caseRules') return { totalCount: state.rules.length, rules: state.rules };
      if (op === 'caseRule') return state.rules.find((r) => (v.a.id ? r.id === v.a.id : r.name === v.a.name)) || null;
      if (op === 'caseTemplate') { const t = state.templates.find((x) => x.name === v.a.name); if (!t) throw new Error('record not found'); return t; }
      if (op === 'updateCaseRule') { const r = state.rules.find((x) => x.id === v.i.id); Object.assign(r, { updatedAt: 'later' }); state.update = v.i; return r; }
      if (op === 'createCaseRule') { const t = state.templates.find((x) => x.id === v.i.templateId); const r = { ...v.i, id: 'new-rule', updatedAt: 'now', template: { id: t.id, name: t.name } }; state.rules.push(r); state.create = v.i; return r; }
      throw new Error(op);
    },
  };
  return { client, state };
}

test('case-rule-install: reads the entry, and only writes with --install', async () => {
  assert.deepEqual(installArgs([`rules/${CASE}`, '--install']), { dir: `rules/${CASE}`, envFile: null, tenant: null, method: 'import', install: true });
  assert.throws(() => installArgs([`rules/${CASE}`, '--method', 'paste']), /import or create/);
  const entry = await readEntry(path.join(ROOT, 'rules', CASE));
  assert.equal(entry.rule.name, 'opencanary_one_case_per_source_ip');
  await assert.rejects(readEntry(path.join(ROOT, 'rules', DET)), /Only a case rule installs this way/);
  assert.match(templateText(entry.yaml), /^apiVersion: v0\.0\.1\nkind: template\n/);
  const tenant = [{ id: 't1', name: 'tenant_rule', order: 1, state: 'ENABLED', updatedAt: 'a' }, { id: 't2', name: 'other', order: 2, state: 'TEST', updatedAt: 'b' }];
  const dry = fakeCases({ rules: tenant });
  const lines = [];
  assert.deepEqual(await install(dry.client, entry, { log: (m) => lines.push(m) }), { installed: false });
  assert.deepEqual([...new Set(dry.state.calls)].sort(), ['caseRules', 'caseTemplate'], 'a dry run only reads');
  assert.match(lines.join('\n'), /at order 3.*Would import case-rule.yaml/s);
  await assert.rejects(install(fakeCases({ rules: [...tenant, { id: 'x', name: 'opencanary_one_case_per_source_ip', order: 3, state: 'TEST' }] }).client, entry, { write: true }), /already has a case rule named/);
});

test('case-rule-install: import, then one save with no change; or the template, then createCaseRule after the last rule', async () => {
  const tenant = [{ id: 't1', name: 'tenant_rule', order: 1, state: 'ENABLED', updatedAt: 'a' }];
  const entry = await readEntry(path.join(ROOT, 'rules', CASE));
  const wait = { tries: 1, waitMs: 0 };
  // The import path: importYaml is a multipart POST, so the fake client's fetch takes it.
  const imp = fakeCases({ rules: tenant });
  imp.client.fetch = async (url, init) => {
    assert.ok(init.body instanceof FormData);
    const map = JSON.parse(init.body.get('map'));
    assert.deepEqual(map, { 0: ['variables.input.file'] });
    imp.state.rules.push({ id: 'imp', name: entry.rule.name, order: 2, state: 'TEST', updatedAt: 'x', title: entry.rule.title, filter: entry.rule.filter, groupBy: entry.rule.group_by, groupCount: 1, skipDetectionPrioritization: true, isGlobal: false, template: { id: 'tpl', name: entry.template.name } });
    return new Response(JSON.stringify({ data: { importInvestigationResources: [{ __typename: 'InvestigationRule', id: 'imp' }] } }), { status: 200 });
  };
  const a = await install(imp.client, entry, { write: true, wait });
  assert.deepEqual([a.installed, a.order, a.state, a.template, a.moved], [true, 2, 'TEST', 'opencanary_honeypot_unofficial', []]);
  assert.equal(imp.state.update.id, 'imp');
  assert.equal(imp.state.update.order, undefined, 'the save names no order, so nothing moves');
  assert.equal(imp.state.update.templateId, 'tpl');
  // The create path.
  const cre = fakeCases({ rules: tenant });
  cre.client.fetch = async (url, init) => {
    const file = await init.body.get('0').text();
    assert.match(file, /^apiVersion: v0\.0\.1\nkind: template\n/);
    cre.state.templates.push({ id: 'tpl2', name: entry.template.name });
    return new Response(JSON.stringify({ data: { importInvestigationResources: [{ __typename: 'InvestigationTemplate', id: 'tpl2' }] } }), { status: 200 });
  };
  const b = await install(cre.client, entry, { method: 'create', write: true, wait });
  assert.deepEqual([b.installed, b.order, b.moved], [true, 2, []]);
  assert.deepEqual(cre.state.create, createInput(entry.rule, 'tpl2', 2));
  assert.equal(cre.state.create.skipDetectionPrioritization, true);
  assert.equal(cre.state.create.state, 'TEST');
  assert.deepEqual(Object.keys(resaveInput({ id: 'x', order: 4, title: 't', filter: 'f', template: { id: 'y' } })).sort(), ['filter', 'id', 'templateId', 'title']);
});

test('the rule entries load from disk with their parsed rules, and the snapshot reads', async () => {
  const e = await loadRuleEntry(path.join(ROOT, 'rules', DET), ROOT);
  assert.equal(e.id, DET);
  assert.equal(e.ruleNames.length, 4);
  assert.ok(coverage && coverage.schemas['scwx.thirdpartyalert']);
  const s = coverage.schemas['scwx.thirdpartyalert'];
  assert.deepEqual(Object.keys(s).sort(), ['any_sensor_rules', 'any_sensor_techniques', 'named_sensor_types', 'rules'], 'counts, techniques and sensor types only: no rule names or logic');
  assert.doesNotMatch(JSON.stringify(coverage), /"(name|query|filter|description)"\s*:/);
});

test('parserLabel names a parser entry without saying the vendor twice', () => {
  assert.equal(parserLabel({ vendor: 'Thinkst', product: 'OpenCanary' }), 'Thinkst OpenCanary');
  assert.equal(parserLabel({ vendor: '1Password', product: '1Password Business' }), '1Password Business');
  assert.equal(parserLabel({ vendor: 'GitHub', product: 'GitHub Enterprise Cloud audit log' }), 'GitHub Enterprise Cloud audit log');
  assert.equal(parserLabel({ vendor: 'Acme', product: '' }), 'Acme');
});
