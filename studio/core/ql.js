// A small reader for the part of the Sophos Fusion query language that custom detection rules use:
// FROM <one schema> WHERE <conditions>, the conditions joined with AND, OR, NOT and parentheses.
// It parses a rule's query, checks its fields against the schema data, checks regex against the
// rule engine's limits, and runs the query on a parsed record, so the library can test rules on a
// parser entry's samples without a tenant. The page and the Node tools share it.
//
// The operators, from the docs' Advanced Search query language page: =, !=, <, <=, >, >=, IN, !IN,
// CONTAINS, !CONTAINS, MATCHES (a glob with * and ?), !MATCHES, MATCHES_REGEX, IS NULL and IS NOT
// NULL. Operators and values are case-insensitive. A plain '...' string is taken as written, and an
// e'...' string reads backslash escapes, the only way to put a quote in one.
//
// Measured in a lab tenant with validateQLFilter (22/11/2026): an enum field takes its member name,
// such as severity = 'HIGH', and refuses a number; "NOT IN" is a syntax error, and !IN works;
// FROM thirdpartyalert reads as FROM thirdparty. Earlier (20/11/2026): a field missing from the event
// matches != in both Data Lake Search and a live rule. What isn't measured: whether MATCHES_REGEX
// finds a match anywhere or needs the whole value (this reads it as anywhere), and CIDR in a rule.

import { SCHEMA_IDS, schemaInfo, typeKind, enumMembers, messageType, GENERIC } from './schemas.js';

export class QlError extends Error {
  constructor(message, at = null) {
    super(at === null ? message : `${message} (at character ${at + 1})`);
    this.reason = message;
    this.at = at;
  }
}

const WORDS = new Set(['FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'CONTAINS', 'MATCHES', 'MATCHES_REGEX', 'IS', 'NULL', 'EARLIEST', 'LATEST', 'TRUE', 'FALSE']);

export function tokenize(text) {
  const s = String(text ?? '');
  const out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    const at = i;
    if (c === "'" || ((c === 'e' || c === 'E') && s[i + 1] === "'")) {
      const escapes = c !== "'";
      i += escapes ? 2 : 1;
      let v = '';
      for (;;) {
        if (i >= s.length) throw new QlError('a string is never closed', at);
        const d = s[i];
        if (escapes && d === '\\' && i + 1 < s.length) {
          const n = s[i + 1];
          v += n === 'n' ? '\n' : n === 't' ? '\t' : n;
          i += 2;
          continue;
        }
        if (d === "'") { i++; break; }
        v += d;
        i++;
      }
      out.push({ t: 'string', v, at });
      continue;
    }
    if (/[0-9]/.test(c) || (c === '-' && /[0-9]/.test(s[i + 1] || '') && !/^(ident|number|string)$/.test((out[out.length - 1] || {}).t || ''))) {
      const m = /^-?[0-9]+(?:\.[0-9]+)?(?:[smhdw]\b)?/.exec(s.slice(i));
      out.push({ t: /[smhdw]$/.test(m[0]) ? 'time' : 'number', v: m[0], at });
      i += m[0].length;
      continue;
    }
    if (/[A-Za-z_@]/.test(c)) {
      const m = /^[A-Za-z_@][A-Za-z0-9_@]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/.exec(s.slice(i));
      const up = m[0].toUpperCase();
      out.push(WORDS.has(up) ? { t: 'kw', v: up, at } : { t: 'ident', v: m[0], at });
      i += m[0].length;
      continue;
    }
    const two = s.slice(i, i + 2);
    if (['!=', '<=', '>=', '<>'].includes(two)) { out.push({ t: 'op', v: two === '<>' ? '!=' : two, at }); i += 2; continue; }
    if ('=<>'.includes(c)) { out.push({ t: 'op', v: c, at }); i++; continue; }
    if ('(),|!'.includes(c)) { out.push({ t: c, v: c, at }); i++; continue; }
    throw new QlError(`"${c}" isn't part of the query language`, at);
  }
  return out;
}

// QL schema names, such as nids or thirdparty, as schema ids. FROM thirdpartyalert works too, and an
// underscore is optional (management_event).
export function schemaFromQlName(name) {
  const n = String(name || '').toLowerCase().replace(/_/g, '');
  if (n === 'thirdparty' || n === 'thirdpartyalert') return 'scwx.thirdpartyalert';
  const id = `scwx.${n}`;
  return SCHEMA_IDS.includes(id) ? id : null;
}

export const qlName = (schemaId) => (schemaId === 'scwx.thirdpartyalert' ? 'thirdparty' : String(schemaId).replace(/^scwx\./, ''));

class Reader {
  constructor(tokens) { this.t = tokens; this.i = 0; }
  peek(k = 0) { return this.t[this.i + k]; }
  next() { return this.t[this.i++]; }
  is(t, v) { const x = this.peek(); return Boolean(x) && x.t === t && (v === undefined || x.v === v); }
  kw(v) { return this.is('kw', v); }
  expect(t, v, what) {
    const x = this.next();
    if (!x || x.t !== t || (v !== undefined && x.v !== v)) throw new QlError(`expected ${what}${x ? `, found "${x.v}"` : ' at the end'}`, x ? x.at : null);
    return x;
  }
}

// {schemas: [ql names], where: node, whereText, time: [{key, value}], pipeline: text|null}
// whereText is the condition as written, for a tool that adds to it.
// node: {type: 'and'|'or', items} | {type: 'not', item} | {type: 'cmp', field, op, value?, values?, at}
// op: = != < <= > >= in !in contains !contains matches !matches matches_regex null notnull
export function parseQuery(text) {
  const src = String(text ?? '');
  const bar = pipeIndex(src);
  const tokens = tokenize(bar === -1 ? src : src.slice(0, bar));
  const r = new Reader(tokens);
  r.expect('kw', 'FROM', 'FROM');
  const schemas = [r.expect('ident', undefined, 'a schema name').v];
  while (r.is(',')) { r.next(); schemas.push(r.expect('ident', undefined, 'a schema name').v); }
  let where = null;
  const time = [];
  const readTime = () => {
    while (r.kw('EARLIEST') || r.kw('LATEST')) {
      const k = r.next();
      r.expect('op', '=', '=');
      const v = r.next();
      if (!v || !['time', 'string', 'ident', 'number'].includes(v.t)) throw new QlError(`${k.v} needs a time`, k.at);
      time.push({ key: k.v, value: v.v });
    }
  };
  readTime();
  let whereText = null;
  if (r.kw('WHERE')) {
    r.next();
    const from = r.peek() ? r.peek().at : src.length;
    where = orExpr(r);
    whereText = src.slice(from, r.peek() ? r.peek().at : bar === -1 ? src.length : bar).trim();
  }
  readTime();
  if (r.peek()) throw new QlError(`unexpected "${r.peek().v}"`, r.peek().at);
  return { schemas, where, whereText, time, pipeline: bar === -1 ? null : src.slice(bar + 1).trim() };
}

// The first | outside a string.
function pipeIndex(s) {
  let inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) { if (c === "'") inStr = false; else if (c === '\\' && inStr === 'e') i++; continue; }
    if (c === "'") inStr = i > 0 && /[eE]/.test(s[i - 1]) && (i < 2 || /[^A-Za-z0-9_]/.test(s[i - 2])) ? 'e' : true;
    else if (c === '|') return i;
  }
  return -1;
}

function orExpr(r) {
  const items = [andExpr(r)];
  while (r.kw('OR')) { r.next(); items.push(andExpr(r)); }
  return items.length === 1 ? items[0] : { type: 'or', items };
}

function andExpr(r) {
  const items = [notExpr(r)];
  while (r.kw('AND')) { r.next(); items.push(notExpr(r)); }
  return items.length === 1 ? items[0] : { type: 'and', items };
}

function notExpr(r) {
  if (r.kw('NOT') || (r.is('!') && r.peek(1) && r.peek(1).t === '(')) { r.next(); return { type: 'not', item: notExpr(r) }; }
  if (r.is('(')) {
    r.next();
    const e = orExpr(r);
    r.expect(')', undefined, ')');
    return e;
  }
  return comparison(r);
}

function literal(r) {
  const x = r.next();
  if (!x) throw new QlError('expected a value at the end');
  if (x.t === 'string') return { kind: 'string', value: x.v };
  if (x.t === 'number') return { kind: 'number', value: Number(x.v) };
  if (x.t === 'kw' && (x.v === 'TRUE' || x.v === 'FALSE')) return { kind: 'bool', value: x.v === 'TRUE' };
  throw new QlError(`expected a value in single quotes or a number, found "${x.v}"`, x.at);
}

function comparison(r) {
  const f = r.next();
  if (!f || f.t !== 'ident') throw new QlError(`expected a field name${f ? `, found "${f.v}"` : ' at the end'}`, f ? f.at : null);
  const at = f.at;
  if (r.is('op')) {
    const op = r.next().v;
    return { type: 'cmp', field: f.v, op, value: literal(r), at };
  }
  let neg = false;
  if (r.is('!')) { r.next(); neg = true; }
  if (r.kw('NOT')) throw new QlError(`write !${(r.peek(1) || {}).v || 'IN'} rather than NOT ${(r.peek(1) || {}).v || 'IN'}: the query language refuses NOT between a field and its operator`, r.peek().at);
  const w = r.next();
  if (!w || w.t !== 'kw') throw new QlError(`expected an operator after ${f.v}`, w ? w.at : null);
  if (w.v === 'IN') {
    r.expect('(', undefined, '(');
    const values = [literal(r)];
    while (r.is(',')) { r.next(); values.push(literal(r)); }
    r.expect(')', undefined, ')');
    return { type: 'cmp', field: f.v, op: neg ? '!in' : 'in', values, at };
  }
  if (w.v === 'CONTAINS' || w.v === 'MATCHES' || w.v === 'MATCHES_REGEX') {
    if (neg && w.v === 'MATCHES_REGEX') throw new QlError('!MATCHES_REGEX isn\'t an operator: put NOT before the condition', w.at);
    return { type: 'cmp', field: f.v, op: `${neg ? '!' : ''}${w.v.toLowerCase()}`, value: literal(r), at };
  }
  if (w.v === 'IS' && !neg) {
    const not = r.kw('NOT');
    if (not) r.next();
    r.expect('kw', 'NULL', 'NULL');
    return { type: 'cmp', field: f.v, op: not ? 'notnull' : 'null', at };
  }
  throw new QlError(`"${w.v}" isn't an operator here`, w.at);
}

// Every comparison in the tree.
export function conditions(node, out = []) {
  if (!node) return out;
  if (node.type === 'cmp') out.push(node);
  else if (node.type === 'not') conditions(node.item, out);
  else for (const x of node.items) conditions(x, out);
  return out;
}

// The comparisons that every match has to pass: the top-level AND, or the one condition.
export function topConjuncts(node) {
  if (!node) return [];
  if (node.type === 'and') return node.items;
  return [node];
}

// ---------------------------------------------------------------- running a query on a record

// The values at a dotted path, through lists: none when the field is missing.
export function valuesAt(record, path) {
  let cur = [record];
  for (const k of String(path).split('.')) {
    const next = [];
    for (const v of cur.flatMap((x) => (Array.isArray(x) ? x : [x]))) {
      if (v && typeof v === 'object' && v[k] !== undefined && v[k] !== null) next.push(v[k]);
    }
    cur = next;
  }
  return cur.flatMap((x) => (Array.isArray(x) ? x : [x])).filter((v) => typeof v !== 'object');
}

const lower = (v) => String(v).toLowerCase();
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const ipNum = (s) => { const m = IPV4.exec(s); return m && m.slice(1).every((x) => Number(x) < 256) ? m.slice(1).reduce((a, x) => a * 256 + Number(x), 0) : null; };

function inCidr(value, cidr) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  const v = ipNum(String(value));
  const base = ipNum(m[1]);
  const bits = Number(m[2]);
  if (v === null || base === null || bits > 32) return false;
  const block = 2 ** (32 - bits);
  return Math.floor(v / block) === Math.floor(base / block);
}

function equals(v, lit) {
  if (lit.kind === 'number') return v !== '' && Number(v) === lit.value;
  if (lit.kind === 'bool') return v === lit.value || lower(v) === String(lit.value);
  const cidr = inCidr(v, lit.value);
  if (cidr !== null) return cidr;
  return lower(v) === lower(lit.value);
}

const globCache = new Map();
function glob(pattern) {
  if (!globCache.has(pattern)) globCache.set(pattern, new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'is'));
  return globCache.get(pattern);
}
const regexCache = new Map();
function regex(pattern) {
  if (!regexCache.has(pattern)) regexCache.set(pattern, new RegExp(pattern, 'i'));
  return regexCache.get(pattern);
}

function test(op, vals, node) {
  switch (op) {
    case '=': return vals.some((v) => equals(v, node.value));
    case '<': case '<=': case '>': case '>=': {
      const n = node.value.value;
      return vals.some((v) => {
        const x = Number(v);
        if (v === '' || !Number.isFinite(x)) return false;
        return op === '<' ? x < n : op === '<=' ? x <= n : op === '>' ? x > n : x >= n;
      });
    }
    case 'in': return vals.some((v) => node.values.some((l) => equals(v, l)));
    case 'contains': return vals.some((v) => lower(v).includes(lower(node.value.value)));
    case 'matches': return vals.some((v) => glob(String(node.value.value)).test(String(v)));
    case 'matches_regex': return vals.some((v) => regex(String(node.value.value)).test(String(v)));
    default: throw new QlError(`can't run the operator ${op}`);
  }
}

export function matches(node, record) {
  if (!node) return true;
  if (node.type === 'and') return node.items.every((x) => matches(x, record));
  if (node.type === 'or') return node.items.some((x) => matches(x, record));
  if (node.type === 'not') return !matches(node.item, record);
  const vals = valuesAt(record, node.field);
  if (node.op === 'null') return vals.length === 0;
  if (node.op === 'notnull') return vals.length > 0;
  // A negated operator holds when the positive one holds for no value, so a missing field passes it.
  if (node.op === '!=') return !test('=', vals, node);
  if (node.op.startsWith('!')) return !test(node.op.slice(1), vals, node);
  return test(node.op, vals, node);
}

// ---------------------------------------------------------------- checks for a rule's query

// Fields custom detection rules can't match, from the custom detection rules docs.
export const NO_MATCH_FIELDS = {
  all: ['hostname'],
  'scwx.auth': ['dest_ipgeo_summary', 'src_ipgeo_summary', 'src_ipblacklist_hits', 'dest_ipblacklist_hits'],
  'scwx.netflow': ['dest_ipgeo_summary', 'src_ipgeo_summary', 'src_ipblacklist_hits', 'dest_ipblacklist_hits'],
  'scwx.dnsquery': ['dest_ipgeo_summary', 'src_ipgeo_summary', 'src_ipblacklist_hits', 'dest_ipblacklist_hits', 'whois'],
};

// Regex constructs the rule engine refuses, from the custom detection rules docs: backreferences,
// lookarounds (arbitrary zero-width assertions), atomic groups and possessive quantifiers. Returns
// the reasons, or [] when the pattern is inside the limits and compiles.
export function regexLimits(pattern) {
  const p = String(pattern);
  const out = new Set();
  let inClass = false;
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '\\') {
      const n = p[i + 1] || '';
      if (!inClass && (/[1-9]/.test(n) || n === 'k')) out.add('a backreference');
      i++;
      continue;
    }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; if (p[i + 1] === ']') i++; else if (p[i + 1] === '^' && p[i + 2] === ']') i += 2; continue; }
    if (c === '(' && p[i + 1] === '?') {
      const rest = p.slice(i + 2, i + 4);
      if (rest[0] === '=' || rest[0] === '!' || rest === '<=' || rest === '<!') out.add('a lookahead or lookbehind');
      else if (rest[0] === '>') out.add('an atomic group');
    }
    const quant = c === '*' || c === '+' || c === '?' || c === '}';
    if (quant && p[i + 1] === '+' && !(c === '?' && p[i - 1] === '(')) out.add('a possessive quantifier');
  }
  try { new RegExp(p); } catch (e) { out.add(`a pattern that doesn't compile (${e.message.replace(/^Invalid regular expression: /, '')})`); }
  return [...out];
}

const fieldDefs = (fields, name) => (fields || []).find((f) => f.name === name) || null;

// The definition of a dotted field path in a schema: {def, kind} or {missing: 'part'} or {opaque: true}
// when the path goes into a type the schema data doesn't describe.
export function fieldPath(schemaId, path) {
  const info = schemaInfo(schemaId);
  if (!info) return { missing: path };
  const parts = String(path).split('.');
  let def = fieldDefs(info.fields, parts[0]);
  if (!def) return { missing: parts[0] };
  for (const part of parts.slice(1)) {
    const sub = messageType(def.type);
    if (!sub) return { opaque: true, def };
    const next = fieldDefs(sub, part);
    if (!next) return { missing: `${def.name}.${part}` };
    def = next;
  }
  return { def, kind: typeKind(def.type) };
}

// Problems with a detection rule's query, as {level, code, message}. parsed is parseQuery's result.
// schemaId, when given, is the schema the entry says the rule is for.
export function ruleQueryProblems(parsed, { schemaId = null } = {}) {
  const out = [];
  const err = (code, message) => out.push({ level: 'error', code, message });
  const warn = (code, message) => out.push({ level: 'warning', code, message });
  if (parsed.schemas.length !== 1) err('ql', `a rule matches one schema, and this query names ${parsed.schemas.length}: ${parsed.schemas.join(', ')}`);
  if (parsed.pipeline !== null) err('ql', 'a rule query can\'t have a | pipeline such as aggregate: rules match one event at a time');
  if (parsed.time.length) err('ql', 'leave EARLIEST and LATEST out: a rule runs on events as they arrive');
  if (!parsed.where) err('ql', 'a rule query needs a WHERE condition');
  const sid = schemaFromQlName(parsed.schemas[0]);
  if (!sid) { err('ql', `${parsed.schemas[0]} is not a schema a custom parser writes to`); return out; }
  if (schemaId && sid !== schemaId) err('ql', `the query reads ${parsed.schemas[0]} (${sid}), but the entry is for ${schemaId}`);
  if (sid === GENERIC) warn('ql', 'the generic schema has only a few fields, so check the query matches the raw text you expect');
  const banned = new Set([...NO_MATCH_FIELDS.all, ...(NO_MATCH_FIELDS[sid] || [])]);
  for (const c of conditions(parsed.where)) {
    if (/^@/.test(c.field)) { err('ql', `${c.field}: logical types such as @ip search across schemas, which a rule can't`); continue; }
    const top = c.field.split('.')[0];
    if (banned.has(top)) { err('field', `${c.field}: custom detection rules can't match ${top} on ${qlName(sid)}`); continue; }
    if (top === 'sensor_id' || top === 'host_id' || top === 'tenant_id' || top === 'sensor_tenant') { err('field', `${c.field}: match on sensor_type, never ${top}, which differs in every tenant`); continue; }
    const f = fieldPath(sid, c.field);
    if (f.missing) { err('field', `${c.field}: ${f.missing} is not a field of ${sid}`); continue; }
    if (f.opaque) continue;
    const lits = c.values || (c.value ? [c.value] : []);
    if (f.kind === 'enum') {
      const names = enumMembers(f.def.type) || [];
      for (const l of lits) {
        if (l.kind !== 'string' || !names.some((n) => n.toLowerCase() === String(l.value).toLowerCase())) {
          err('enum', `${c.field} is an enum: compare it with one of ${names.join(', ')} by name, in quotes. Sophos refuses ${l.kind === 'number' ? 'a number' : `'${l.value}'`} there.`);
        }
      }
      if (['<', '<=', '>', '>='].includes(c.op)) err('enum', `${c.field} is an enum, so ${c.op} doesn't apply`);
    }
    if (['<', '<=', '>', '>='].includes(c.op) && f.kind === 'scalar' && !/int|float|double/.test(f.def.type)) warn('ql', `${c.field} is ${f.def.type}, so ${c.op} compares it as a number`);
    if (c.op === 'matches_regex') for (const why of regexLimits(c.value.value)) err('regex', `${c.field} MATCHES_REGEX '${c.value.value}' uses ${why}, which the rule engine refuses`);
  }
  return out;
}

// The sensor types a query pins: a top-level sensor_type = 'x' or sensor_type IN (...).
export function pinnedSensorTypes(parsed) {
  for (const c of topConjuncts(parsed.where)) {
    if (c.type !== 'cmp' || c.field !== 'sensor_type') continue;
    if (c.op === '=' && c.value.kind === 'string') return [c.value.value];
    if (c.op === 'in' && c.values.every((v) => v.kind === 'string')) return c.values.map((v) => v.value);
  }
  return [];
}
