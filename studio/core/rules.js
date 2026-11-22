// Rule entries: custom detection rule sets and automatic case rules for sources that reach Sophos
// NG-SIEM through a library parser. The page and the Node tools share this; reading the YAML files
// and the checks CI runs are in tools/lib/rules.mjs.
//
// rules/<vendor>/<name>/
//   meta.json        kind (detection or case), title, vendor, product, parser, schema, sensor_types,
//                    volume, mdr_note, tested, author, license, docs, summary, notes, links
//   rules.yaml       a detection entry's rules: the fields of the console's Create Rule form
//   tests.json       the parser entry's sample lines each rule must trigger, and lines none may
//   case-rule.yaml   a case entry's automatic case rule and its case template, as Automatic Cases exports them
//   README.md        optional

import { parseQuery, matches, schemaFromQlName } from './ql.js';

export const RULE_KINDS = ['detection', 'case'];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
// Automatic case rules act only on Medium and higher detections.
export const CASE_SEVERITIES = new Set(['critical', 'high', 'medium']);
// The severity bands in the docs, for the page.
export const SEVERITY_BANDS = { critical: '0.8 to 1', high: '0.6 to 0.799', medium: '0.4 to 0.599', low: '0.2 to 0.399', informational: '0 to 0.199' };
// Custom detections come from this detector, and each one's title is its rule's name.
export const CUSTOM_DETECTOR = 'app:event-filter-ql';
export const RULE_PATH = /^rules\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const PARSER_PATH = /^parsers\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/;

// rules: [{name, query, severity, ...}] -> the same with {parsed, schemaId} or {error}.
export function compileRules(rules) {
  return (Array.isArray(rules) ? rules : []).map((r) => {
    try {
      const parsed = parseQuery(r && r.query);
      return { ...r, parsed, schemaId: schemaFromQlName(parsed.schemas[0]) };
    } catch (e) {
      return { ...r, error: e.message };
    }
  });
}

// The rules each parsed line triggers: results are the emulator's, as runParsers returns them, and
// a rule runs only on records of its own schema. Returns a list of rule names per result.
export function ruleHits(compiled, results) {
  return (results || []).map((res) => (compiled || [])
    .filter((c) => !c.error && c.parsed && c.parsed.where && res && res.normalized && c.schemaId === res.schema && matches(c.parsed.where, res.normalized))
    .map((c) => c.name));
}

// tests.json: {"triggers": {"<rule name>": [line numbers]}, "quiet": [line numbers]}. Each line of the
// parser entry's samples.log must trigger exactly the rules that list it, so a line no rule lists
// must trigger none, and quiet lists lines that must not trigger any. Returns problem messages.
export function compareTests(tests, hits, ruleNames) {
  const out = [];
  if (!tests || typeof tests !== 'object' || Array.isArray(tests)) return ['tests.json must be an object with "triggers" and "quiet"'];
  const triggers = tests.triggers && typeof tests.triggers === 'object' && !Array.isArray(tests.triggers) ? tests.triggers : null;
  if (!triggers) out.push('tests.json needs "triggers": each rule\'s name with the sample lines it must trigger');
  if (!Array.isArray(tests.quiet) || !tests.quiet.length) out.push('tests.json needs "quiet": sample lines that must trigger no rule');
  for (const k of Object.keys(tests)) if (!['triggers', 'quiet'].includes(k)) out.push(`tests.json: "${k}" is not a field (triggers, quiet)`);
  const n = hits.length;
  const isLine = (x) => Number.isInteger(x) && x >= 1 && x <= n;
  const want = new Map();
  for (const [name, lines] of Object.entries(triggers || {})) {
    if (!ruleNames.includes(name)) { out.push(`tests.json: "${name}" is not a rule in rules.yaml`); continue; }
    if (!Array.isArray(lines) || !lines.length) { out.push(`tests.json: "${name}" needs at least one sample line it triggers`); continue; }
    for (const l of lines) {
      if (!isLine(l)) { out.push(`tests.json: ${JSON.stringify(l)} under "${name}" is not a line of samples.log (1 to ${n})`); continue; }
      if (!want.has(l)) want.set(l, new Set());
      want.get(l).add(name);
    }
  }
  for (const name of ruleNames) if (triggers && !Object.prototype.hasOwnProperty.call(triggers, name)) out.push(`tests.json: the rule "${name}" has no lines under triggers`);
  for (const l of Array.isArray(tests.quiet) ? tests.quiet : []) {
    if (!isLine(l)) out.push(`tests.json: quiet line ${JSON.stringify(l)} is not a line of samples.log (1 to ${n})`);
    else if (want.has(l)) out.push(`tests.json: line ${l} is both quiet and under "${[...want.get(l)].join('", "')}"`);
  }
  hits.forEach((got, i) => {
    const line = i + 1;
    const exp = want.get(line) || new Set();
    const extra = got.filter((x) => !exp.has(x));
    const missing = [...exp].filter((x) => !got.includes(x));
    if (missing.length) out.push(`sample line ${line} should trigger "${missing.join('", "')}" and doesn't`);
    if (extra.length) out.push(`sample line ${line} triggers "${extra.join('", "')}", which tests.json doesn't list for it`);
    if (got.length > 1) out.push(`sample line ${line} triggers ${got.length} rules of this entry; each line triggers one rule at most`);
  });
  return out;
}

// The badge an entry's tested record earns: ran in a tenant, search-tested, or offline checks only.
export function testedState(meta) {
  const t = meta && meta.tested;
  if (t && t.tenant && t.tenant.date) return { key: 'tenant', label: `ran in a tenant ${t.tenant.date}`, tone: 'green' };
  if (t && t.search) return { key: 'search', label: `search-tested ${t.search}`, tone: 'green' };
  return { key: 'offline', label: 'offline checks only', tone: 'amber' };
}

// The text the Rules search matches: kind, title, vendor, product, author, parser, schema, sensor
// types, and each rule's name, severity and MITRE IDs.
export function ruleSearchText(meta, rules = []) {
  const m = meta && typeof meta === 'object' ? meta : {};
  return JSON.stringify([m.kind, m.title, m.vendor, m.product, m.author, m.parser, m.schema, m.sensor_types,
    (Array.isArray(rules) ? rules : []).map((r) => [r && r.name, r && r.severity, r && r.mitre])]).toLowerCase();
}
