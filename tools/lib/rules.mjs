// Checks for the library's rule entries: custom detection rule sets and automatic case rules for
// sources that reach Sophos NG-SIEM through a library parser.
//
//   rules/<vendor>/<name>/     meta.json, then rules.yaml and tests.json for a detection entry, or
//                              case-rule.yaml for a case entry, and an optional README.md
//   rules/sophos-coverage.json what Sophos's own rules cover, by schema (see the file's "about")
//
// Rules act on tenants: they make detections, and a case rule takes detections that other case
// rules would have had. So the owner reviews every rule entry and nothing under rules/ merges on its
// own. These checks catch what review shouldn't have to, offline: files and metadata, the query
// language subset and the fields each query reads, regex the rule engine refuses, the rules run on
// the linked parser's samples against tests.json, the contributor rules in CONTRIBUTING.md, and the
// secret and personal data scan. Data Lake Search, and a live rule, in a tenant are the authority.

import { parseYaml, parseYamlDocuments, toJS, get, YamlError } from './yaml.mjs';
import { runParsers } from '../../studio/core/engine.js';
import { parseQuery, ruleQueryProblems, pinnedSensorTypes, topConjuncts, conditions, schemaFromQlName, QlError } from '../../studio/core/ql.js';
import { compileRules, ruleHits, compareTests, RULE_KINDS, SEVERITIES, CASE_SEVERITIES, CUSTOM_DETECTOR, RULE_PATH, PARSER_PATH } from '../../studio/core/rules.js';
import { SCHEMA_IDS } from '../../studio/core/schemas.js';
import { scanText } from '../../studio/core/scan.js';
import { gitleaksProblems } from '../../studio/core/gitleaks.js';
import { slug, LICENSES } from '../../studio/core/library.js';
import { aboutProblems } from '../../studio/core/notes.js';

export const RULE_FILES = { detection: ['meta.json', 'rules.yaml', 'tests.json', 'README.md'], case: ['meta.json', 'case-rule.yaml', 'README.md'] };
const REQUIRED = { detection: ['meta.json', 'rules.yaml', 'tests.json'], case: ['meta.json', 'case-rule.yaml'] };
export const COVERAGE = 'rules/sophos-coverage.json';
export const LIMITS = { rules: 20, name: 100, description: 1000, query: 4000 };
export const RULE_KEYS = ['name', 'description', 'severity', 'mitre', 'query', 'enabled_by_default'];
const META_KEYS = {
  detection: ['kind', 'title', 'vendor', 'product', 'parser', 'schema', 'sensor_types', 'volume', 'mdr_note', 'tested', 'author', 'license', 'docs', 'summary', 'notes', 'links'],
  case: ['kind', 'title', 'vendor', 'product', 'parser', 'mdr_note', 'tested', 'author', 'license', 'docs', 'summary', 'notes', 'links'],
};
const CASE_RULE_KEYS = ['apiVersion', 'kind', 'name', 'title', 'description', 'tags', 'type', 'order', 'state', 'filter', 'append_filter', 'group_by', 'group_count', 'skip_alert_prioritization', 'is_global', 'template_name'];
const TEMPLATE_KEYS = ['apiVersion', 'kind', 'name', 'title', 'description', 'tags', 'investigation'];
const INVESTIGATION_KEYS = ['tags', 'type', 'title', 'status', 'priority', 'assignee', 'generate_key_findings', 'usages'];

const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const MITRE = /^T\d{4}(?:\.\d{3})?$/;
const CASE_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const PLAYBOOK_PATH = /^playbooks\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/;
// What an MDR note leaves out: internal tiers, plans and dates. The note says, in public words,
// that the detections and cases are the customer's to work.
const MDR_DENY = /\b(premier|roadmap|internal|confidential|nda|eap|beta|coming soon|planned|not yet released|under nda)\b/i;
const IOC = { ip: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-f:]+:[0-9a-f:]*(\/\d{1,3})?$/i, hash: /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i, domain: /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i };

class Report {
  constructor() { this.problems = []; }
  add(level, code, message, file = null, line = null) { this.problems.push({ level, code, message, file, line }); }
  error(code, message, file, line) { this.add('error', code, message, file, line); }
  warn(code, message, file, line) { this.add('warning', code, message, file, line); }
  // A warning for the reviewer: what CI can only flag.
  review(message, file = null) { this.add('warning', 'review', `Review: ${message}`, file, null); }
}

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const text = (v, max) => typeof v === 'string' && v.trim() && v.length <= max;
const lineOf = (s, index) => s.slice(0, index).split('\n').length;

// ---------------------------------------------------------------- coverage snapshot

// The snapshot's named sensor types, as exact names (the denylist) and other patterns.
export function coveragePatterns(coverage) {
  const exact = new Map();
  const patterns = [];
  for (const [schemaId, s] of Object.entries((coverage && coverage.schemas) || {})) {
    for (const p of (s && s.named_sensor_types) || []) {
      const names = literalNames(p);
      if (names) for (const n of names) exact.set(n.toLowerCase(), { name: n, schemaId });
      else {
        try { patterns.push({ re: new RegExp(p, 'i'), pattern: p, schemaId }); } catch { /* left out */ }
      }
    }
  }
  return { exact, patterns };
}

// The names a sensor type pattern stands for when it is only names: X, ^X$, and ^(A|B)$ or
// ^(A|B)_SUFFIX$. An alternation without anchors, such as (microsoft|azure), matches any sensor
// type that contains one of them, so it stays a pattern.
function literalNames(p) {
  const raw = String(p);
  const anchored = raw.startsWith('^') && raw.endsWith('$');
  const s = raw.replace(/^\^/, '').replace(/\$$/, '');
  const alt = /^\(([^()]+)\)([A-Za-z0-9_ ]*)$/.exec(s);
  if (alt) return anchored && alt[1].split('|').every((x) => /^[A-Za-z0-9_ ]+$/.test(x)) ? alt[1].split('|').map((x) => x + alt[2]) : null;
  return /^[A-Za-z0-9_ ]+$/.test(s) ? [s] : null;
}

// Sophos rules on the schema that match every sensor type and share a technique with the rule:
// [technique id]. T1078 and T1078.004 share T1078.
export function sharedTechniques(coverage, schemaId, mitre) {
  const s = coverage && coverage.schemas && coverage.schemas[schemaId];
  if (!s || !Array.isArray(s.any_sensor_techniques) || !Array.isArray(mitre)) return [];
  const base = (t) => String(t).split('.')[0];
  const theirs = new Set(s.any_sensor_techniques.map(base));
  return [...new Set(mitre.filter((t) => theirs.has(base(t))))];
}

// ---------------------------------------------------------------- reading the files

function readYamlFile(r, content, name) {
  try {
    return parseYaml(content);
  } catch (e) {
    if (!(e instanceof YamlError)) throw e;
    r.error('yaml', `${name} is not YAML this check can read: ${e.reason}`, name, e.line);
    return null;
  }
}

// rules.yaml as [{name, description, severity, mitre, query, enabled_by_default, line}], or null.
export function readRulesYaml(content, r = new Report()) {
  const root = readYamlFile(r, content, 'rules.yaml');
  if (!root) return null;
  if (root.kind !== 'map' || !get(root, 'rules')) { r.error('yaml', 'rules.yaml must be a mapping with one key, "rules", holding a list of rules', 'rules.yaml', root.line); return null; }
  for (const e of root.entries) if (e.key !== 'rules') r.error('yaml', `rules.yaml: "${e.key}" is not a key (only "rules")`, 'rules.yaml', e.line);
  const list = get(root, 'rules');
  if (list.kind !== 'seq') { r.error('yaml', 'rules must be a list', 'rules.yaml', list.line); return null; }
  return list.items.map((n) => ({ ...(n.kind === 'map' ? toJS(n) : {}), line: n.line, isMap: n.kind === 'map' }));
}

// case-rule.yaml as {rule, template, lines}, or null.
export function readCaseRuleYaml(content, r = new Report()) {
  let docs;
  try {
    docs = parseYamlDocuments(content);
  } catch (e) {
    if (!(e instanceof YamlError)) throw e;
    r.error('yaml', `case-rule.yaml is not YAML this check can read: ${e.reason}`, 'case-rule.yaml', e.line);
    return null;
  }
  const [a, b] = docs;
  if (docs.length !== 2 || !a || !b || a.kind !== 'map' || b.kind !== 'map' || toJS(get(a, 'kind')) !== 'rule' || toJS(get(b, 'kind')) !== 'template') {
    r.error('yaml', 'case-rule.yaml must hold two documents, as Automatic Cases exports a rule with its template: kind: rule, then --- and kind: template', 'case-rule.yaml', docs[0] ? docs[0].line : 1);
    return null;
  }
  const lines = {};
  for (const e of a.entries) lines[e.key] = e.line;
  return { rule: toJS(a), template: toJS(b), lines, templateLine: b.line };
}

// ---------------------------------------------------------------- meta.json

function checkMeta(r, entry, ctx) {
  const m = entry.meta;
  const err = (msg) => r.error('meta', msg, 'meta.json');
  if (!isObj(m)) { err('meta.json must be a JSON object'); return false; }
  if (!RULE_KINDS.includes(m.kind)) { err(`kind must be ${RULE_KINDS.join(' or ')}`); return false; }
  for (const k of ['title', 'vendor', 'product']) if (!text(m[k], 80)) err(`${k} is required (text up to 80 characters)`);
  if (typeof m.vendor === 'string' && typeof m.title === 'string') {
    const want = `${slug(m.vendor)}/${slug(m.title)}`;
    if (want !== entry.id) r.error('folder', `the folder is rules/${entry.id}, but vendor and title make it rules/${want}`, 'meta.json');
  }
  if (typeof m.author !== 'string' || !HANDLE.test(m.author)) err('author must be a GitHub handle, without the @');
  if (!LICENSES.includes(m.license)) err(`license must be one of ${LICENSES.join(', ')}`);
  if (!Array.isArray(m.docs) || !m.docs.length || m.docs.some((u) => typeof u !== 'string' || !/^https:\/\//.test(u))) err('docs must list the https pages of the public docs the entry follows');
  for (const p of aboutProblems(m, { kind: 'rule' })) r.add(p.level, 'about', p.message, 'meta.json');
  if (!text(m.mdr_note, 800)) err('mdr_note is required: in public words, that the detections and cases are the customer\'s to work, and Sophos MDR doesn\'t work them (up to 800 characters)');
  else if (MDR_DENY.test(m.mdr_note)) err(`mdr_note: "${MDR_DENY.exec(m.mdr_note)[0]}" reads as an internal tier, plan or date. Use the public wording only.`);
  const t = m.tested;
  if (!isObj(t)) err('tested must be an object like {"search": null, "tenant": null}');
  else {
    for (const k of Object.keys(t)) if (!['search', 'tenant'].includes(k)) err(`tested.${k} is not a field (search, tenant)`);
    if (t.search !== null && !(typeof t.search === 'string' && DATE.test(t.search))) err('tested.search must be null or the date (YYYY-MM-DD) each query returned its sample lines, and only them, in Data Lake Search');
    if (m.kind === 'case' && t.search) err('tested.search is for detection rules: a case rule has no search to run, so leave it null');
    if (t.tenant !== null && !(isObj(t.tenant) && DATE.test(t.tenant.date || '') && /^[a-z]{2}\d{2}$/.test(t.tenant.region || ''))) err('tested.tenant must be null or {"date": "YYYY-MM-DD", "region": "eu01"}, recorded only after the rules ran live in a real tenant');
  }
  for (const k of Object.keys(m)) if (!META_KEYS[m.kind].includes(k)) err(`"${k}" is not a ${m.kind} entry meta.json field`);
  // The parser entry the rules need, by its library path.
  ctx.parser = null;
  if (typeof m.parser !== 'string' || !PARSER_PATH.test(m.parser)) err('parser must be the library path of the parser entry the rules need, such as "parsers/thinkst/opencanary"');
  else {
    ctx.parser = (ctx.library || []).find((e) => `parsers/${e.id}` === m.parser) || null;
    if (!ctx.parser) r.error('parser', `${m.parser} is not a parser entry in the library. Rules are only for sources that reach Sophos NG-SIEM through a library parser.`, 'meta.json');
  }
  const links = m.links === undefined ? {} : m.links;
  if (!isObj(links)) err('links must be an object');
  else if (m.kind === 'detection') {
    for (const k of Object.keys(links)) if (!['case_rule', 'playbooks'].includes(k)) err(`links.${k} is not a field (case_rule, playbooks)`);
    if (links.case_rule !== undefined && links.case_rule !== null) {
      if (typeof links.case_rule !== 'string' || !RULE_PATH.test(links.case_rule)) err('links.case_rule must be the path of a case entry, such as "rules/acme/acme-one-case-per-host"');
      else {
        const c = (ctx.rules || []).find((x) => `rules/${x.id}` === links.case_rule);
        if (!c) r.error('links', `links.case_rule: ${links.case_rule} is not a rule entry in the library`, 'meta.json');
        else if (c.meta && (c.meta.kind !== 'case' || !c.meta.links || c.meta.links.detection_rules !== `rules/${entry.id}`)) r.warn('links', `links.case_rule: ${links.case_rule} doesn't name this entry as its detection_rules`, 'meta.json');
      }
    }
    if (links.playbooks !== undefined) {
      if (!Array.isArray(links.playbooks) || links.playbooks.some((p) => typeof p !== 'string' || !PLAYBOOK_PATH.test(p))) err('links.playbooks must list playbook paths, such as "playbooks/microsoft/teams-case-chat-sync"');
      else if (ctx.playbooks) for (const p of links.playbooks) if (!ctx.playbooks.includes(p)) r.error('links', `links.playbooks: ${p} is not a playbook in the library`, 'meta.json');
    }
  } else {
    for (const k of Object.keys(links)) if (k !== 'detection_rules') err(`links.${k} is not a field (detection_rules)`);
    if (typeof links.detection_rules !== 'string' || !RULE_PATH.test(links.detection_rules)) err('links.detection_rules must be the path of the detection rule entry the case rule collects');
    else {
      ctx.detection = (ctx.rules || []).find((x) => `rules/${x.id}` === links.detection_rules) || null;
      if (!ctx.detection || !ctx.detection.meta || ctx.detection.meta.kind !== 'detection') r.error('links', `links.detection_rules: ${links.detection_rules} is not a detection rule entry in the library`, 'meta.json');
      else if (ctx.detection.meta.parser !== m.parser) err(`parser is ${m.parser}, but the detection rules it collects need ${ctx.detection.meta.parser}`);
    }
  }
  if (m.kind === 'detection') {
    if (!SCHEMA_IDS.includes(m.schema)) err(`schema must be the schema the rules read, one of ${SCHEMA_IDS.join(', ')}`);
    if (!Array.isArray(m.sensor_types) || !m.sensor_types.length || m.sensor_types.some((s) => !text(s, 80))) err('sensor_types must list the sensor types the parser entry writes that the rules match');
    if (!text(m.volume, 600)) err('volume is required: how many detections a day to expect, and when there are more (up to 600 characters)');
  }
  return true;
}

// The sensor types a parser entry's records carry in a schema, from its expected.json.
export function entrySensorTypes(parserEntry, schemaId) {
  const out = new Set();
  for (const e of (parserEntry && Array.isArray(parserEntry.expected) ? parserEntry.expected : [])) {
    if (e && e.schema === schemaId && e.normalized && typeof e.normalized.sensor_type === 'string') out.add(e.normalized.sensor_type);
  }
  return out;
}

// ---------------------------------------------------------------- detection entries

// A value that looks like a domain is only an IOC on a field that holds a host or domain name:
// dotted event names, such as vault.export or repo.destroy, look like domains too.
const DOMAIN_FIELD = /domain|host|dns|query_name|url|uri|fqdn|sni|server_name|referr?er|email|sender|recipient/i;
function iocLiteral(field, l) {
  if (!l || l.kind !== 'string') return false;
  if (IOC.ip.test(l.value) || IOC.hash.test(l.value)) return true;
  return IOC.domain.test(l.value) && DOMAIN_FIELD.test(field);
}

// True when every condition beyond the sensor type compares a field with IPs, domains or hashes.
function iocOnly(parsed) {
  const leaves = conditions(parsed.where).filter((c) => c.field !== 'sensor_type');
  if (!leaves.length) return false;
  return leaves.every((c) => ['=', 'in'].includes(c.op) && (c.values || [c.value]).every((l) => iocLiteral(c.field, l)));
}

function checkRules(r, entry, ctx) {
  const m = entry.meta;
  const f = (entry.files || []).find((x) => x.path === 'rules.yaml');
  if (!f) return null;
  const list = readRulesYaml(f.content, r);
  if (!list) return null;
  if (!list.length) r.error('rules', 'rules.yaml lists no rules', 'rules.yaml');
  if (list.length > LIMITS.rules) r.error('rules', `at most ${LIMITS.rules} rules per entry`, 'rules.yaml');
  const { exact, patterns } = coveragePatterns(ctx.coverage);
  const produced = ctx.parser ? entrySensorTypes(ctx.parser, m.schema) : new Set();
  for (const st of Array.isArray(m.sensor_types) ? m.sensor_types : []) {
    if (typeof st !== 'string') continue;
    if (ctx.parser && !produced.has(st)) r.error('sensor', `sensor_types: ${st} isn't a sensor type ${m.parser} writes to ${m.schema} (its expected.json has ${[...produced].join(', ') || 'none'})`, 'meta.json');
    const hit = exact.get(st.toLowerCase());
    if (hit) r.error('sensor', `sensor_types: ${st} is a sensor type Sophos's own rules name (on ${hit.schemaId}), so it comes from a Sophos product or built-in integration. The library takes rules only for sources Sophos doesn't cover.`, 'meta.json');
    for (const p of patterns.filter((x) => x.schemaId === m.schema && x.re.test(st))) r.review(`Sophos rules on ${m.schema} match sensor types like /${p.pattern}/, which ${st} fits. Check Sophos doesn't already detect this.`, 'meta.json');
  }
  const names = new Set();
  const seen = new Map((ctx.rules || []).filter((x) => x.id !== entry.id && x.ruleNames).flatMap((x) => x.ruleNames.map((n) => [n.toLowerCase(), x.id])));
  for (const rule of list) {
    const at = rule.line;
    const where = `rule ${JSON.stringify(rule.name || '?')}`;
    if (!rule.isMap) { r.error('rules', 'each rule is a mapping of name, description, severity, mitre, query and enabled_by_default', 'rules.yaml', at); continue; }
    for (const k of Object.keys(rule)) if (!['line', 'isMap'].includes(k) && !RULE_KEYS.includes(k)) r.error('rules', `${where}: "${k}" is not a field. rules.yaml holds the Create Rule form's fields only: ${RULE_KEYS.join(', ')}.`, 'rules.yaml', at);
    if (!text(rule.name, LIMITS.name)) r.error('rules', `a rule needs a name (up to ${LIMITS.name} characters), which becomes its detections' title`, 'rules.yaml', at);
    else {
      if (names.has(rule.name.toLowerCase())) r.error('rules', `${where} is in rules.yaml twice`, 'rules.yaml', at);
      names.add(rule.name.toLowerCase());
      if (seen.has(rule.name.toLowerCase())) r.error('rules', `${where} has the same name as a rule in rules/${seen.get(rule.name.toLowerCase())}. Detections carry the rule's name as their title, and case rules filter on it, so names are unique across the library.`, 'rules.yaml', at);
    }
    if (!text(rule.description, LIMITS.description)) r.error('rules', `${where} needs a description (up to ${LIMITS.description} characters)`, 'rules.yaml', at);
    if (!SEVERITIES.includes(rule.severity)) r.error('rules', `${where}: severity must be one of ${SEVERITIES.join(', ')}`, 'rules.yaml', at);
    if (typeof rule.enabled_by_default !== 'boolean') r.error('rules', `${where}: enabled_by_default must be true or false`, 'rules.yaml', at);
    else if ((rule.severity === 'low' || rule.severity === 'informational') && rule.enabled_by_default) r.error('rules', `${where} is ${rule.severity}, so it ships off: set enabled_by_default to false`, 'rules.yaml', at);
    if (!Array.isArray(rule.mitre) || rule.mitre.some((t) => typeof t !== 'string' || !MITRE.test(t))) r.error('rules', `${where}: mitre must list MITRE ATT&CK technique IDs, such as T1110 or T1078.003, or be []`, 'rules.yaml', at);
    else if (!rule.mitre.length) r.warn('rules', `${where} has no MITRE technique`, 'rules.yaml', at);
    if (typeof rule.query !== 'string' || !rule.query.trim() || rule.query.length > LIMITS.query) { r.error('ql', `${where} needs a query (up to ${LIMITS.query} characters)`, 'rules.yaml', at); continue; }
    let parsed;
    try {
      parsed = parseQuery(rule.query);
    } catch (e) {
      if (!(e instanceof QlError)) throw e;
      r.error('ql', `${where}: the query doesn't parse: ${e.message}`, 'rules.yaml', at);
      continue;
    }
    for (const p of ruleQueryProblems(parsed, { schemaId: SCHEMA_IDS.includes(m.schema) ? m.schema : null })) r.add(p.level, p.code, `${where}: ${p.message}`, 'rules.yaml', at);
    const pins = pinnedSensorTypes(parsed);
    if (!pins.length) r.error('sensor', `${where}: the query must pin the sensor type with a top-level sensor_type = '...', so it matches only the library parser's records`, 'rules.yaml', at);
    for (const p of pins) if (Array.isArray(m.sensor_types) && !m.sensor_types.includes(p)) r.error('sensor', `${where}: the query matches sensor type ${p}, which isn't in sensor_types`, 'rules.yaml', at);
    const beyond = conditions(parsed.where).filter((c) => c.field !== 'sensor_type');
    if (!beyond.length) r.error('rules', `${where} matches every event of the sensor type. Each rule needs a condition beyond sensor_type.`, 'rules.yaml', at);
    else if (iocOnly(parsed)) r.error('ioc', `${where} only matches literal IP addresses, domains or hashes. Sophos's IP and Domain Watchlists do that, so the library takes no IOC rules.`, 'rules.yaml', at);
    if (conditions(parsed.where).some((c) => c.op === 'matches_regex' || c.op === '!matches_regex')) r.review(`${where} uses MATCHES_REGEX. Rules and Data Lake Search use different regex engines, so run it as a live rule as well as a search.`, 'rules.yaml');
    const shared = sharedTechniques(ctx.coverage, m.schema, rule.mitre);
    if (shared.length) r.review(`${where} shares ${shared.join(', ')} with Sophos rules on ${m.schema} that match every sensor type. Check in Detector Explorer that Sophos doesn't already detect it.`, 'rules.yaml');
  }
  r.review(`check the stated volume against each query's count over 7 days in Data Lake Search, since CI can't count detections: "${m.volume}"`, 'meta.json');
  return list;
}

// Runs the linked parser on its samples, then the rules on the records, and holds tests.json to it.
function checkTests(r, entry, ctx, list) {
  const f = (entry.files || []).find((x) => x.path === 'tests.json');
  if (!f || !list || !ctx.parser) return null;
  let tests;
  try { tests = JSON.parse(f.content); } catch (e) { r.error('json', `tests.json is not valid JSON: ${e.message}`, 'tests.json'); return null; }
  const p = ctx.parser;
  const results = runParsers(p.parsers || [], p.samples || [], { now: p.meta && p.meta.reference_time });
  const compiled = compileRules(list.filter((x) => typeof x.query === 'string'));
  const hits = ruleHits(compiled, results);
  for (const msg of compareTests(tests, hits, compiled.map((x) => x.name))) r.error('tests', msg, 'tests.json');
  return { hits, results, compiled };
}

// ---------------------------------------------------------------- case entries

function checkCaseRule(r, entry, ctx) {
  const f = (entry.files || []).find((x) => x.path === 'case-rule.yaml');
  if (!f) return null;
  const doc = readCaseRuleYaml(f.content, r);
  if (!doc) return null;
  const { rule, template, lines } = doc;
  const file = 'case-rule.yaml';
  const e = (code, msg, key) => r.error(code, msg, file, lines[key] || null);
  for (const k of Object.keys(rule)) if (!CASE_RULE_KEYS.includes(k)) r.warn('case', `case-rule.yaml: "${k}" isn't a field the library knows in an Automatic Cases rule`, file, lines[k]);
  if (rule.apiVersion !== 'v0.0.1') e('case', 'apiVersion must be v0.0.1, as Automatic Cases exports it', 'apiVersion');
  if (typeof rule.name !== 'string' || !CASE_NAME.test(rule.name)) e('case', 'name must be letters, digits and underscores, starting with a letter', 'name');
  if (!text(rule.title, 120)) e('case', 'title is required', 'title');
  if (rule.type !== 'STATIC') e('case', 'type must be STATIC', 'type');
  if (rule.state !== 'TEST') e('case', 'state must be TEST: a library case rule ships in Test state, and you turn it on after reading its Rule Logs', 'state');
  if (rule.is_global !== false) e('case', 'is_global must be false', 'is_global');
  if (rule.template_name !== template.name) e('case', `template_name must be the template in the same file, ${template.name}`, 'template_name');
  if (rule.append_filter !== undefined && rule.append_filter !== null && rule.append_filter !== '') r.review(`append_filter adds detections to an open case beyond the filter: check it can't reach Sophos's detections: ${String(rule.append_filter).slice(0, 200)}`, file);
  if (!Number.isInteger(rule.group_count) || rule.group_count < 1) e('case', 'group_count must be a whole number, 1 or more', 'group_count');
  // The filter takes this entry's own custom detections and nothing else.
  const want = ctx.detection && ctx.detection.parsedRules ? ctx.detection.parsedRules : null;
  let titles = [];
  if (typeof rule.filter !== 'string' || !rule.filter.trim()) e('filter', 'filter is required', 'filter');
  else {
    let parsed = null;
    try { parsed = parseQuery(rule.filter); } catch (x) { if (!(x instanceof QlError)) throw x; e('filter', `the filter doesn't parse: ${x.message}`, 'filter'); }
    if (parsed) {
      if (parsed.schemas.length !== 1 || parsed.schemas[0].toLowerCase() !== 'detection') e('filter', 'the filter must read from detection', 'filter');
      if (parsed.pipeline !== null || parsed.time.length) e('filter', 'the filter can\'t have a pipeline, EARLIEST or LATEST', 'filter');
      const top = topConjuncts(parsed.where).filter((c) => c.type === 'cmp');
      const detector = top.find((c) => c.field === 'metadata.creator.detector.detector_id' && c.op === '=' && c.value.kind === 'string' && c.value.value === CUSTOM_DETECTOR);
      if (!detector) e('filter', `the filter must take only custom detections: a top-level metadata.creator.detector.detector_id = '${CUSTOM_DETECTOR}'. Otherwise it can reach Sophos's detections.`, 'filter');
      const title = top.find((c) => c.field === 'title' && (c.op === '=' || c.op === 'in'));
      if (!title) e('filter', 'the filter must name the rules it collects: a top-level title = \'...\' or title in (...), with the detection entry\'s rule names', 'filter');
      else titles = (title.values || [title.value]).map((l) => String(l.value));
      if (want) {
        for (const t of titles) {
          const hit = want.find((x) => x.name === t);
          if (!hit) e('filter', `the filter names "${t}", which isn't a rule in ${ctx.detection.id ? `rules/${ctx.detection.id}` : 'the linked entry'}`, 'filter');
          else if (!CASE_SEVERITIES.has(hit.severity)) e('filter', `the filter names "${t}", a ${hit.severity} rule. Case rules act only on Medium and higher detections.`, 'filter');
        }
      }
    }
  }
  if (!Array.isArray(rule.group_by) || !rule.group_by.length || rule.group_by.some((g) => typeof g !== 'string')) e('group', 'group_by must list the expressions that group detections into a case', 'group_by');
  else if (typeof rule.name === 'string' && rule.group_by.some((g) => !g.includes(rule.name))) e('group', `each group_by expression must carry the rule's name, ${rule.name}, so only this rule adds to its cases: grouping isn't tied to a rule`, 'group_by');
  // A detection matches a case rule only if it holds the grouping attributes, and a FileMod
  // detection holds no host name: in a lab tenant a case rule grouped on alertHostnames skipped
  // every one. Its hostId is there.
  if (Array.isArray(rule.group_by) && ctx.detection && ctx.detection.meta && ctx.detection.meta.schema === 'scwx.filemod' && rule.group_by.some((g) => typeof g === 'string' && /\balertHostnames\s*\(/.test(g))) e('group', 'group_by uses alertHostnames, but a FileMod detection carries no host name, so the rule would skip every detection: group on the hostId entity instead, as rules/qnap/qnap-one-case-per-nas does', 'group_by');
  // The template: a Security Case with no assignee.
  const tl = doc.templateLine;
  for (const k of Object.keys(template)) if (!TEMPLATE_KEYS.includes(k)) r.warn('case', `the template's "${k}" isn't a field the library knows`, file, tl);
  if (template.apiVersion !== 'v0.0.1') r.error('case', 'the template\'s apiVersion must be v0.0.1', file, tl);
  if (typeof template.name !== 'string' || !CASE_NAME.test(template.name)) r.error('case', 'the template\'s name must be letters, digits and underscores, starting with a letter', file, tl);
  if (!text(template.title, 120)) r.error('case', 'the template needs a title', file, tl);
  const inv = template.investigation;
  if (!isObj(inv)) r.error('case', 'the template needs an investigation block: the case it opens', file, tl);
  else {
    for (const k of Object.keys(inv)) if (!INVESTIGATION_KEYS.includes(k)) r.warn('case', `investigation.${k} isn't a field the library knows`, file, tl);
    if (inv.type !== 'SECURITY_INVESTIGATION') r.error('case', 'investigation.type must be SECURITY_INVESTIGATION, the Security Case type, which you manage', file, tl);
    if (inv.status !== 'OPEN') r.error('case', 'investigation.status must be OPEN', file, tl);
    if (inv.assignee !== undefined && inv.assignee !== null && inv.assignee !== '') r.error('case', 'leave out the assignee: user IDs differ in every tenant, so you set it after import', file, tl);
    if (!Array.isArray(inv.usages) || !inv.usages.includes('AUTO_INVESTIGATION')) r.error('case', 'investigation.usages must include AUTO_INVESTIGATION, so the case rule can use the template', file, tl);
  }
  r.review(`the filter and group_by. The filter takes only custom detections titled ${titles.map((t) => `"${t}"`).join(', ') || '(none)'}, and group_by carries ${rule.name}.`, file);
  return { rule, template, titles };
}

// ---------------------------------------------------------------- files and scans

function scanFile(r, entry, f) {
  const path = `rules/${entry.id}/${f.path}`;
  for (const s of gitleaksProblems(f.content, path, { source: f.path })) r.error(s.code, s.message, f.path, s.line);
  let content = f.content;
  if (f.path === 'meta.json') {
    try { content = JSON.stringify({ ...JSON.parse(f.content), docs: undefined }, null, 2); } catch { /* scanned as is */ }
  }
  for (const s of scanText(content, { source: f.path })) r.add(s.level, s.code, s.message, f.path, s.line);
  for (const m of f.content.matchAll(UUID)) r.error('id', `${m[0]} looks like a tenant, user or object ID. Rule entries hold none.`, f.path, lineOf(f.content, m.index));
}

// entry: {id: 'vendor/name', files: [{path, content}], meta, loadProblems}
// opts: {library: parser entries, rules: every rule entry (for links and names), playbooks: ['playbooks/<id>'], coverage}
// Returns {ok, problems, rules, hits, caseRule}.
export function validateRuleEntry(entry, opts = {}) {
  const r = new Report();
  for (const p of entry.loadProblems || []) r.add(p.level, p.code, p.message, p.file || null, p.line || null);
  const ctx = { library: opts.library || [], rules: opts.rules || [], playbooks: opts.playbooks || null, coverage: opts.coverage || null, parser: null, detection: null };
  const ok = checkMeta(r, entry, ctx);
  const kind = ok && entry.meta ? entry.meta.kind : null;
  const names = (entry.files || []).map((f) => f.path);
  if (kind) {
    for (const f of names) if (!RULE_FILES[kind].includes(f)) r.error('files', `${f} is not allowed in a ${kind} entry (allowed: ${RULE_FILES[kind].join(', ')})`, f);
    for (const f of REQUIRED[kind]) if (!names.includes(f)) r.error('files', `${f} is missing`, f);
  }
  for (const f of entry.files || []) scanFile(r, entry, f);
  let list = null;
  let tested = null;
  let caseRule = null;
  if (kind === 'detection') {
    list = checkRules(r, entry, ctx);
    tested = checkTests(r, entry, ctx, list);
  } else if (kind === 'case') {
    caseRule = checkCaseRule(r, entry, ctx);
  }
  return { ok: !r.problems.some((p) => p.level === 'error'), problems: r.problems, rules: list, hits: tested ? tested.hits : null, caseRule };
}

// Every detection rule across the library, against every line of each parser entry's samples: no
// line may trigger rules from two entries. Returns {id: [problem]} for the entries involved.
export function crossLibraryProblems(ruleEntries, results) {
  const byParser = new Map();
  for (const e of ruleEntries) {
    const res = results.get(e.id);
    if (!res || !res.hits || !e.meta || e.meta.kind !== 'detection') continue;
    if (!byParser.has(e.meta.parser)) byParser.set(e.meta.parser, []);
    byParser.get(e.meta.parser).push({ id: e.id, hits: res.hits });
  }
  const out = {};
  for (const [parser, list] of byParser) {
    if (list.length < 2) continue;
    const n = Math.max(...list.map((x) => x.hits.length));
    for (let i = 0; i < n; i++) {
      const who = list.filter((x) => x.hits[i] && x.hits[i].length);
      if (who.length < 2) continue;
      for (const w of who) {
        (out[w.id] = out[w.id] || []).push({ level: 'error', code: 'overlap', file: 'rules.yaml', line: null,
          message: `${parser} sample line ${i + 1} triggers "${w.hits[i].join('", "')}" here and ${who.filter((x) => x !== w).map((x) => `"${x.hits[i].join('", "')}" in rules/${x.id}`).join(', ')}. Each line triggers one rule across the library.` });
      }
    }
  }
  return out;
}

// The parsed rules of a detection entry, without checks, for the site and for case entries.
export function parsedRules(entry) {
  const f = (entry.files || []).find((x) => x.path === 'rules.yaml');
  if (!f) return null;
  const list = readRulesYaml(f.content);
  return list ? list.filter((x) => x.isMap).map(({ line, isMap, ...rest }) => rest) : null;
}

// The rule names a case rule's filter takes: its top-level title = '...' or title in (...).
export function caseRuleTitles(filter) {
  try {
    const t = topConjuncts(parseQuery(filter).where).find((c) => c.type === 'cmp' && c.field === 'title' && (c.op === '=' || c.op === 'in'));
    return t ? (t.values || [t.value]).map((l) => String(l.value)) : [];
  } catch {
    return [];
  }
}

export function parsedCaseRule(entry) {
  const f = (entry.files || []).find((x) => x.path === 'case-rule.yaml');
  return f ? readCaseRuleYaml(f.content) : null;
}

export { schemaFromQlName };
