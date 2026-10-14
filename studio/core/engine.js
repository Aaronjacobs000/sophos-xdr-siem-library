// The emulator: runs parser scripts over sample lines the way the docs describe the Sophos
// NG-SIEM engine doing it. It is our reading of the docs, not the Sophos engine.
//
// Flow per line: the root step splits off the syslog header, every top-level parser's confirm
// string is tried, the matching parser runs, then its children's confirm strings are tried
// and the first match runs. The last parser's schema decides the normalized record.

import {
  JsonValue, ObjValue, MatchValue, RecordValue, TimeValue, RuntimeError, ParseErrorSignal,
  toStr, toBool, looseEqual, wrapJson, isList, typeName, hasOwn, asNumber, parseGoFloat,
} from './values.js';
import { parseScript, parseExpression, walk } from './language.js';
import { FUNCTIONS, LAZY, stringOf } from './functions.js';
import { compileGo } from './goregex.js';
import { query, isMultiPath } from './jsonpath.js';
import { rootSplit } from './formats.js';
import { goParse } from './gotime.js';
import { normalize } from './normalize.js';
import { GENERIC, schemaInfo } from './schemas.js';

export const ENGINE_NOTE = 'Emulator result, not run in Sophos NG-SIEM.';

class Ctx {
  constructor(vars, opts, sink) {
    this.vars = new Map(vars);
    this.now = opts.now;
    this.sink = sink;
    this.parser = null;
    this.line = null;
  }
  note(level, code, message) {
    this.sink.push({ level, code, message, parser: this.parser, line: this.line });
  }
  // Reading a variable that was never assigned fails the event in the engine (checked in a
  // lab tenant). A variable assigned NULL is fine.
  get(name) {
    if (this.vars.has(name)) return this.vars.get(name);
    if (this.lenient) return null;
    throw new RuntimeError(`variable ${name} is not set`, 'unset-var');
  }
  set(target, value) {
    const parts = target.split('.');
    if (parts.length === 1) { this.vars.set(target, value); return; }
    let rec = this.vars.get(parts[0]);
    // A field can be set on a record or on an object such as a CEF(), URL_PARSE() or
    // SPLIT_NAME_VALUES() value, which gains the key. On a variable that holds anything else, such
    // as a capture result, text, NULL, a number, TRUE, a list, a DATETIME or a JSON value, it fails
    // the event: "variable r is not Object type at path element 0" (checked in a lab tenant).
    if (this.vars.has(parts[0]) && !(rec instanceof RecordValue || rec instanceof ObjValue)) {
      const holds = rec instanceof MatchValue ? 'a capture result' : `a value of type ${typeName(rec)}`;
      throw new RuntimeError(`variable ${parts[0]} is not Object type at path element 0: it holds ${holds}, so ${target} can't set a field on it. Use another name for the record.`, 'not-object');
    }
    if (!rec) { rec = new RecordValue(); this.vars.set(parts[0], rec); }
    let fields = rec instanceof ObjValue ? rec.map : rec.fields;
    for (const p of parts.slice(1, -1)) {
      let next = fields.get(p);
      if (!(next instanceof RecordValue)) { next = new RecordValue(); fields.set(p, next); }
      fields = next.fields;
    }
    fields.set(parts[parts.length - 1], value);
  }
  sanitizeNow() { this.flagsNow = { ...(this.flagsNow || {}), sanitize: true }; }
  trimNow() { this.flagsNow = { ...(this.flagsNow || {}), trim: true }; }
}

function index(base, idx) {
  if (base === null || base === undefined) return null;
  if (base instanceof MatchValue) {
    if (base.nomatch) return null;
    if (typeof idx === 'number') {
      if (idx < 0 || idx >= base.groups.length) throw new RuntimeError(`regex group ${idx} is out of range (the pattern has ${base.groups.length - 1} groups)`, 'group-range');
      return base.groups[idx] ?? '';
    }
    if (!hasOwn(base.named, idx)) throw new RuntimeError(`regex group "${idx}" is not in the pattern`, 'group-name');
    return base.named[idx] ?? '';
  }
  if (base instanceof JsonValue) {
    // j["key"] without "$." is a plain key lookup (checked in a lab tenant).
    if (typeof idx === 'string' && !idx.trimStart().startsWith('$')) {
      const o = base.value;
      return o && typeof o === 'object' && !Array.isArray(o) && hasOwn(o, idx) ? wrapJson(o[idx]) : null;
    }
    if (typeof idx === 'string') {
      const r = query(base.value, idx);
      if (r === null) return null;
      if (!Array.isArray(r) || !isMultiPath(idx)) return wrapJson(r);
      // A path that can select several nodes but selects one gives that node, not a list of one;
      // |preserve_structure keeps the list (checked in a lab tenant).
      if (r.length === 1 && !/\|preserve_structure\s*$/.test(idx)) return wrapJson(r[0]);
      return r.map(wrapJson);
    }
    if (typeof idx === 'number' && Array.isArray(base.value)) return wrapJson(base.value[idx < 0 ? base.value.length + idx : idx]);
    return null;
  }
  if (base instanceof ObjValue) {
    // A number reads a CEF or LEEF header field by its key, "0" and on (see withHeaderKeys).
    if (typeof idx === 'number') return base.header ? base.get(String(idx)) : null;
    return base.get(toStr(idx));
  }
  if (isList(base)) {
    if (typeof idx !== 'number') return null;
    const k = idx < 0 ? base.length + idx : idx;
    return k >= 0 && k < base.length ? base[k] ?? null : null;
  }
  return null;
}

// <, >, <= and >= compare as floats when both sides are numbers, TRUE or FALSE, or text that
// reads as a number, so "10" > "9". Anything else compares as text: " 10" > 9 is false and
// "abc" > 5 is true. NULL reads as "", so NULL < 1 is true and NULL >= 0 is false (checked in a
// lab tenant).
function compare(op, a, b) {
  if (a === null || a === undefined) a = '';
  if (b === null || b === undefined) b = '';
  if (a instanceof TimeValue && b instanceof TimeValue) return cmp(op, a.usec, b.usec);
  const x = asNumber(a), y = asNumber(b);
  if (x !== null && y !== null) return cmp(op, x, y);
  return cmp(op, toStr(a), toStr(b));
}
const cmp = (op, a, b) => (op === '<' ? a < b : op === '>' ? a > b : op === '<=' ? a <= b : a >= b);

// == and != compare a DATETIME value with another one or with a number of microseconds. With
// anything else, NULL included, the engine fails the event (checked in a lab tenant).
function equal(a, b) {
  noRegex(a); noRegex(b);
  const ta = a instanceof TimeValue, tb = b instanceof TimeValue;
  if (!ta && !tb) return looseEqual(a, b);
  if (ta && tb) return a.usec === b.usec;
  const other = ta ? b : a;
  if (typeof other === 'number') return (ta ? a : b).usec === other;
  throw new RuntimeError(`cannot convert time to string: a DATETIME value can be compared with another DATETIME or a number, not ${typeName(other)}`, 'time-compare');
}

function memberLabel(e) {
  if (e.t === 'var') return e.name;
  if (e.t === 'member') return `${memberLabel(e.e)}.${e.name}`;
  return '(value)';
}

function noRegex(v) {
  if (v instanceof MatchValue) throw new RuntimeError('cannot convert regex to string; index the capture, for example m[1]', 'regex-compare');
  return v;
}

// Arithmetic runs in float64, the engine's only number type: a time value counts as its
// microseconds, and nothing wraps. 9223372036854775807 + 1 and 1000000000000 * 1000000000 stay
// floats (checked in a lab tenant). STRING() and % convert to int64 (see functions.js and %).
function plus(a, b) {
  noRegex(a); noRegex(b);
  if (a === null || a === undefined) return b ?? null;
  if (b === null || b === undefined) return a;
  a = jsonList(a); b = jsonList(b);
  if (isList(a)) return [...a, ...(isList(b) ? b : [b])];
  if (isList(b)) return [a, ...b];
  if (a instanceof TimeValue && typeof b === 'number') return a.usec + b;
  if (typeof a === 'number' && b instanceof TimeValue) return a + b.usec;
  if (a instanceof TimeValue && typeof b === 'string') return a.usec + timeAddend(b);
  if (typeof a === 'string' && b instanceof TimeValue) return timeAddend(a) + b.usec;
  // Two DATETIME values add as microseconds, and TRUE counts as 1 and FALSE as 0 (checked in a
  // lab tenant).
  if (a instanceof TimeValue && (b instanceof TimeValue || typeof b === 'boolean')) return a.usec + num(b, '+');
  if (typeof a === 'boolean' && b instanceof TimeValue) return Number(a) + b.usec;
  // Numbers, TRUE and FALSE, and text that reads as a number add as numbers when at least one side
  // isn't text: 5 + TRUE is 6, "5" + 5 is 10 and "1e3" + TRUE is 1001. Two texts join, so
  // "5" + "5" is "55", and so does text that isn't a number: "abc" + 5 is "abc5" and " 5" + 5 is
  // " 55" (checked in a lab tenant).
  if (typeof a !== 'string' || typeof b !== 'string') {
    const x = asNumber(a), y = asNumber(b);
    if (x !== null && y !== null) return x + y;
  }
  return joinText(a) + joinText(b);
}

// The value JSON() returned joins to text as {}, whatever it holds: "a" + JSON("5") is "a{}". An
// object, such as a CEF() or URL_PARSE() value, a record or an object part of a JSON value, joins
// as STRING() writes it: keys sorted, <, > and & escaped and NULL as 0 (checked in a lab tenant).
const joinText = (v) => (v instanceof JsonValue && v.doc ? '{}' : v instanceof JsonValue || v instanceof ObjValue || v instanceof RecordValue ? stringOf(v) : toStr(v));

// An array part of a JSON value adds like a list: "pre-" + json["$.c"] with [1,null,"y"] gives
// ["pre-",1,NULL,"y"], which a string field stores as pre-,1,,y (checked in a lab tenant).
const jsonList = (v) => (v instanceof JsonValue && !v.doc && Array.isArray(v.value) ? v.value.map(wrapJson) : v);

// Text added to a DATETIME value counts as a number when all of it reads as one, the way Go's
// strconv.ParseFloat reads it ("5", "-5", "5.5", "1e3", "1_000", "0x1p4"). Any other text, "",
// " 5", "1__0", "0x10" and "1e400" included, fails the event with "unable to add: cannot
// convert time to string" (checked in a lab tenant).
function timeAddend(s) {
  const n = parseGoFloat(s);
  if (n !== null) return n;
  throw new RuntimeError('unable to add: cannot convert time to string. To join a DATETIME value to text, use STRING() on it first', 'time-add');
}

// -, *, / and % read text the way strconv.ParseFloat does, and fail the event on text it can't
// read, such as " 5", "" or "abc" (checked in a lab tenant).
function num(v, op) {
  if (typeof v === 'number') return v;
  if (v instanceof TimeValue) return v.usec;
  if (typeof v === 'boolean') return Number(v);
  if (typeof v === 'string') {
    const n = parseGoFloat(v);
    if (n === null) throw new RuntimeError(`"${op}" needs numbers, and ${JSON.stringify(v)} doesn't read as one`);
    return n;
  }
  const n = Number(v);
  if (v === null || Number.isNaN(n)) throw new RuntimeError(`"${op}" needs numbers, got ${typeName(v)}`);
  return n;
}

// Go's float64 to int64 conversion: the whole part, or the minimum int64 when it doesn't fit.
function toInt64(n) {
  const t = Math.trunc(n);
  return t < 2 ** 63 && t >= -(2 ** 63) ? BigInt(t) : -(2n ** 63n);
}

export function evaluate(ctx, e) {
  switch (e.t) {
    case 'lit': return e.v;
    case 'var': return ctx.get(e.name);
    case 'list': return e.items.map((x) => evaluate(ctx, x));
    case 'if': return toBool(evaluate(ctx, e.c)) ? evaluate(ctx, e.a) : evaluate(ctx, e.b);
    case 'not': return !toBool(evaluate(ctx, e.e));
    case 'member': {
      // Reading x.field$ before it was assigned fails the event, like any unset variable. That
      // includes the docs' append pattern eventMetadata$.record$ = eventMetadata$.record$ + [r]
      // when nothing set the list first (checked in a lab tenant).
      const label = memberLabel(e);
      if (e.e.t === 'var' && !ctx.vars.has(e.e.name)) {
        if (ctx.lenient) return null;
        throw new RuntimeError(`variable ${label} is not set`, 'unset-var');
      }
      const base = evaluate(ctx, e.e);
      if (base instanceof RecordValue && base.fields.has(e.name)) return base.fields.get(e.name);
      if (ctx.lenient) return null;
      throw new RuntimeError(`variable ${label} is not set`, 'unset-var');
    }
    case 'index': return index(evaluate(ctx, e.e), evaluate(ctx, e.i));
    case 'call': {
      if (LAZY[e.name]) {
        const [min, max, fn] = LAZY[e.name];
        if (e.args.length < min || e.args.length > max) throw new RuntimeError(`${e.name}() takes ${min === max ? min : `${min} to ${max}`} arguments`);
        return fn(ctx, e.args, (a) => evaluate(ctx, a));
      }
      const f = FUNCTIONS[e.name];
      if (!f) throw new RuntimeError(`${e.name}() is not a documented function`, 'unknown-function');
      const [min, max, fn] = f;
      if (e.args.length < min || e.args.length > max) throw new RuntimeError(`${e.name}() takes ${min === max ? min : `${min} to ${max}`} arguments, got ${e.args.length}`);
      return fn(ctx, e.args.map((a) => evaluate(ctx, a)));
    }
    case 'bin': {
      // AND and OR evaluate both sides, so an error on the right fails the event even when the
      // left side decides the result (checked in a lab tenant).
      if (e.op === 'AND' || e.op === 'OR') {
        const l = toBool(evaluate(ctx, e.l));
        const r = toBool(evaluate(ctx, e.r));
        return e.op === 'AND' ? l && r : l || r;
      }
      const a = evaluate(ctx, e.l);
      const b = evaluate(ctx, e.r);
      switch (e.op) {
        case '==': return equal(a, b);
        case '!=': return !equal(a, b);
        case '<': case '>': case '<=': case '>=': return compare(e.op, a, b);
        case '+': return plus(a, b);
        case '-': return num(a, '-') - num(b, '-');
        case '*': return num(a, '*') * num(b, '*');
        // Division always gives a float: 3 / 2 is 1.5, -3 / 2 is -1.5 and 4 / 2 is 2. Dividing by
        // zero fails the event (checked in a lab tenant).
        case '/': { const d = num(b, '/'); if (d === 0) throw new RuntimeError('division by zero'); return num(a, '/') / d; }
        // % converts each side to int64 first, so (7 / 2) % 2 is 1 and 9223372036854775807 % 10
        // is -8, because that literal is the float 2^63, which doesn't fit. A right side that
        // converts to 0 fails the event (checked in a lab tenant).
        case '%': {
          const d = toInt64(num(b, '%'));
          if (d === 0n) throw new RuntimeError('modulo by zero');
          return Number(toInt64(num(a, '%')) % d);
        }
        default: throw new RuntimeError(`unknown operator ${e.op}`);
      }
    }
    default: throw new RuntimeError(`unknown expression ${e.t}`);
  }
}

// ---------------------------------------------------------------- compiled parsers

export function compileParser(p) {
  const script = parseScript(p.text);
  const name = p.name || 'UNNAMED_PARSER';
  const parent = p.parent || script.directives.PARENT || null;
  let confirm = null;
  if (script.directives.CONFIRMWITH === 'EXPRESSION' && script.directives.CONFIRMSTRING !== undefined) {
    try { confirm = { kind: 'EXPRESSION', ...parseExpression(script.directives.CONFIRMSTRING) }; } catch (e) { confirm = { kind: 'EXPRESSION', error: e.message }; }
  } else if (script.directives.CONFIRMWITH === 'PATTERN' && script.directives.CONFIRMSTRING !== undefined) {
    confirm = { kind: 'PATTERN', pattern: script.directives.CONFIRMSTRING.replace(/\s+$/, '') };
  }
  return { ...p, name, parent, script, confirm, schema: script.directives.SCHEMA || null, flags: script.flags };
}

function confirms(p, ctx) {
  if (!p.confirm || p.confirm.error) return false;
  if (p.confirm.kind === 'PATTERN') {
    const re = compileGo(p.confirm.pattern);
    return re.test(toStr(ctx.get('originalData$')) ?? '');
  }
  ctx.parser = p.name;
  ctx.line = p.script.directiveLines.CONFIRMSTRING ?? null;
  try {
    return toBool(evaluate(ctx, p.confirm.ast));
  } catch (e) {
    ctx.note('warning', 'confirm-error', `${p.name}: the confirm expression raised "${e.message}", so it counts as no match`);
    return false;
  }
}

function runStatements(p, ctx, byName, depth = 0) {
  try {
    runStatementsInner(p, ctx, byName, depth);
  } catch (e) {
    // Remember where it failed, so the result names the right parser and line.
    if (e instanceof RuntimeError && !e.where) e.where = { parser: ctx.parser, line: ctx.line };
    throw e;
  }
}

function runStatementsInner(p, ctx, byName, depth) {
  if (depth > 10) throw new RuntimeError('!IMPORT nests more than 10 deep');
  for (const st of p.script.statements) {
    ctx.parser = p.name;
    ctx.line = st.line;
    if (st.kind === 'import') {
      const imported = byName.get(st.target);
      if (!imported) throw new RuntimeError(`!IMPORT=${st.target}: no parser with that name in this set`, 'import');
      runStatementsInner(imported, ctx, byName, depth + 1);
      ctx.parser = p.name;
      continue;
    }
    if (st.kind === 'capture') {
      const src = st.sourceExpr ? evaluate(ctx, st.sourceExpr) : ctx.get(st.source);
      const match = capture(st.pattern, src === null ? '' : toStr(src));
      ctx.set(st.target, match);
      if (match.nomatch) ctx.note('info', 'capture-miss', `${st.target}: the capture pattern matched nothing in ${st.sourceText || st.source}, so ${st.target}[n] gives NULL`);
      continue;
    }
    ctx.set(st.target, evaluate(ctx, st.expr));
  }
}

// The engine keeps every match of a capture pattern (checked in a lab tenant).
function capture(pattern, text) {
  const re = compileGo(pattern, 'g');
  re.lastIndex = 0;
  const all = [];
  let m;
  while ((m = re.exec(text))) {
    all.push(m);
    if (m[0] === '') re.lastIndex++;
    if (all.length > 10000) break;
  }
  if (!all.length) return new MatchValue([], {}, 0);
  const fix = (x) => (x === undefined ? '' : x);
  if (all.length === 1) return new MatchValue([...all[0]].map(fix), Object.fromEntries(Object.entries(all[0].groups || {}).map(([k, v]) => [k, fix(v)])), 1);
  const groups = all[0].map((_, i) => all.map((x) => fix(x[i])));
  const named = Object.fromEntries(Object.keys(all[0].groups || {}).map((k) => [k, all.map((x) => fix(x.groups[k]))]));
  return new MatchValue(groups, named, all.length);
}

// Variables a child's confirm string reads from its parent, so the lint can tell carrier
// fields like eventType$ apart from typos.
function confirmVars(p) {
  const out = new Set();
  if (p.confirm && p.confirm.ast) walk(p.confirm.ast, (n) => { if (n.t === 'var') out.add(n.name); });
  return out;
}

// The first syntax error in the set, in a statement or in a confirm expression, or null.
function firstSyntaxError(compiled) {
  for (const p of compiled) {
    const confirmLine = p.script.directiveLines.CONFIRMSTRING ?? null;
    const errors = p.script.problems.filter((x) => x.code === 'syntax').map((x) => ({ line: x.line, message: x.message }));
    if (p.confirm && p.confirm.error) errors.push({ line: confirmLine, message: `confirm expression: ${p.confirm.error}` });
    errors.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
    if (errors.length) return { parser: p.name, ...errors[0] };
  }
  return null;
}

// parsers: [{name, text, parent?, role?}]; samples: [string]; opts: {now}
export function runParsers(parsers, samples, opts = {}) {
  const now = opts.now || new Date().toISOString();
  const nowUsec = Date.parse(now) * 1000;
  const compiled = parsers.map(compileParser);
  // A syntax error, in a statement or in the confirm expression, makes Run Test reject the whole
  // parser: it returns no records for any line, only the error (checked in a lab tenant).
  const bad = firstSyntaxError(compiled);
  if (bad) {
    const where = `${bad.parser}${bad.line ? ` line ${bad.line}` : ''}`;
    return samples.map((sample, n) => ({
      line: n + 1, sample, extractor_path: null, schema: GENERIC, normalized: null, notes: [],
      error: `${where}: syntax error: ${bad.message}`,
      errorAt: { parser: bad.parser, line: bad.line },
      result: 'Run Test rejects a parser with a syntax error, so no line gets a record.',
      rejected: true,
    }));
  }
  const byName = new Map(compiled.map((p) => [p.name, p]));
  const active = compiled.filter((p) => !p.flags.has('IMPORTONLY') && !p.flags.has('DISABLED'));
  const childrenOf = new Map();
  const top = [];
  for (const p of active) {
    if (p.parent && byName.has(p.parent)) {
      if (!childrenOf.has(p.parent)) childrenOf.set(p.parent, []);
      childrenOf.get(p.parent).push(p);
    } else {
      top.push(p);
    }
  }
  const carriers = new Set();
  for (const p of active) for (const v of confirmVars(p)) carriers.add(v);

  return samples.map((sample, n) => {
    const notes = [];
    const root = new Ctx(rootVars(sample, now), { now }, notes);
    const result = { line: n + 1, sample, extractor_path: null, schema: GENERIC, normalized: null, notes };
    let matched;
    try {
      matched = top.filter((p) => confirms(p, root));
    } catch (e) {
      result.error = `confirm string: ${e.message}`;
      return result;
    }
    if (!matched.length) {
      result.result = 'No parser matched. The line stays in the generic schema only.';
      return result;
    }
    if (matched.length > 1) {
      notes.push({ level: 'warning', code: 'overlap', message: `${matched.map((p) => p.name).join(', ')} all match this line. The engine tries parsers in no particular order, so this line could go to any of them. The emulator used ${matched[0].name}.` });
    }
    let current = matched[0];
    const path = [current.name];
    if (current.parent && !byName.has(current.parent)) {
      notes.push({ level: 'info', code: 'global-parent', parser: current.name, message: `${current.name} extends the global parser ${current.parent}. The emulator can't run built-in parsers, so anything ${current.parent} sets is missing here.` });
    }
    let ctx = root;
    const ingest = root.vars.get('eventTimeUsec$');
    try {
      runStatements(current, ctx, byName);
      const kids = childrenOf.get(current.name) || [];
      if (kids.length) {
        const hits = kids.filter((k) => confirms(k, new Ctx(ctx.vars, { now }, notes)));
        if (hits.length > 1) notes.push({ level: 'warning', code: 'child-overlap', message: `children ${hits.map((k) => k.name).join(', ')} all match; the emulator used ${hits[0].name}` });
        if (hits.length) {
          const child = hits[0];
          const cctx = new Ctx(ctx.vars, { now }, notes);
          runStatements(child, cctx, byName);
          path.push(child.name);
          current = child;
          ctx = cctx;
        }
      }
      result.extractor_path = path.join(' > ');
      // The parser left eventTimeUsec$ at the ingest time the root parser gave it.
      const kept = typeof ingest === 'number' && ctx.vars.get('eventTimeUsec$') === ingest;
      const parentP = path.length > 1 ? byName.get(path[0]) : null;
      const schema = current.schema || (parentP && parentP.schema) || GENERIC;
      result.schema = schema;
      // !SCHEMA can list several schemas; the engine then stores one event in each.
      const schemas = schemaList(schema);
      const bad = schemas.filter((x) => !schemaInfo(x));
      if (bad.length) {
        result.error = `!SCHEMA=${bad.join(',')} is not a schema custom parsers can use`;
        return result;
      }
      const real = schemas.filter((x) => x !== GENERIC);
      if (!real.length) {
        result.result = path.length === 1 && (childrenOf.get(path[0]) || []).length
          ? 'The parent matched but no child did. The line stays in the generic schema only.'
          : 'This parser targets the generic schema.';
        // The generic event still carries the common fields the parsers set.
        const vars = timedVars(ctx.vars, nowUsec, notes, current.name);
        result.normalized = withEventTime(normalize(vars, GENERIC, { sanitize: true, trim: !current.flags.has('TRIMALLOFF'), carriers: new Set([...vars.keys()]) }).record, nowUsec, now, notes, current.name, kept);
        return result;
      }
      const flags = current.flags;
      const opts2 = {
        sanitize: !flags.has('SANITIZEALLOFF') || Boolean(ctx.flagsNow && ctx.flagsNow.sanitize),
        trim: !flags.has('TRIMALLOFF') || Boolean(ctx.flagsNow && ctx.flagsNow.trim),
        carriers,
        parser: current.name,
      };
      const vars = timedVars(ctx.vars, nowUsec, notes, current.name);
      const records = real.map((sid) => ({ schema: sid, ...normalize(vars, sid, opts2) }));
      records.forEach((r, i) => withEventTime(r.record, nowUsec, now, i ? [] : notes, current.name, kept));
      result.normalized = records[0].record;
      if (records.length > 1) result.also = records.slice(1).map((r) => ({ schema: r.schema, normalized: r.record }));
      for (const r of records) {
        notes.push(...r.notes);
        if (!Object.keys(r.record).some((k) => !ROOT_FIELDS.has(k))) notes.push({ level: 'warning', code: 'empty-record', parser: current.name, message: `${current.name} matched this line but set no ${schemaInfo(r.schema).name} fields of its own` });
      }
    } catch (e) {
      if (e instanceof ParseErrorSignal) {
        result.error = e.message;
        result.result = e.makeGeneric ? 'PARSE_ERROR raised. A generic event is still created.' : 'PARSE_ERROR raised with no generic event.';
      } else if (e instanceof RuntimeError) {
        const where = e.where || { parser: current.name, line: null };
        result.error = `${where.parser || current.name}${where.line ? ` line ${where.line}` : ''}: ${e.message}`;
        result.errorAt = where;
        result.result = 'The parser stopped with an error. The line stays in the generic schema only.';
      } else {
        throw e;
      }
      result.extractor_path = path.join(' > ');
      result.schema = GENERIC;
      result.normalized = null;
    }
    return result;
  });
}

// The comparable part of a result, as stored in a library entry's expected.json.
export function expectedShape(r) {
  const out = { line: r.line, extractor_path: r.extractor_path, schema: r.schema, normalized: r.normalized };
  if (r.also) out.also = r.also;
  if (r.error) out.error = true;
  return out;
}

export function schemaList(schema) {
  return String(schema || GENERIC).split(',').map((x) => x.trim()).filter(Boolean);
}

// What the engine does with the event time after the parsers run (checked in a lab tenant). A
// time ahead of ingest is read as a time zone set wrong: it moves back by the fewest whole hours
// that bring it to or before ingest, when that is at most 24 hours and lands it no more than 50
// minutes before ingest. Any other future time becomes the ingest time.
const HOUR = 3600e6;
export function settleEventTime(usec, nowUsec) {
  if (usec <= nowUsec) return { usec };
  const hours = Math.ceil((usec - nowUsec) / HOUR);
  const back = usec - hours * HOUR;
  if (hours <= 24 && nowUsec - back <= 50 * 60e6) return { usec: back, hours };
  return { usec: nowUsec };
}

// eventTimeUsec$ after settleEventTime, as a copy of the variables when it changes.
function timedVars(vars, nowUsec, notes, parser) {
  const t = vars.get('eventTimeUsec$');
  const usec = t instanceof TimeValue ? t.usec : typeof t === 'number' && Number.isFinite(t) ? t : null;
  if (usec === null || !Number.isFinite(nowUsec)) return vars;
  const settled = settleEventTime(usec, nowUsec);
  if (settled.usec === usec) return vars;
  notes.push({ level: 'warning', code: 'future-time', parser, message: settled.hours
    ? `the event time is ${settled.hours} hour${settled.hours === 1 ? '' : 's'} ahead of the ingest time, so the engine moves it back ${settled.hours} hour${settled.hours === 1 ? '' : 's'}, reading it as a time zone set wrong. Check the time zone the parser reads.`
    : 'the event time is in the future, so the engine stores the ingest time instead' });
  const out = new Map(vars);
  out.set('eventTimeUsec$', settled.usec);
  return out;
}

// A record with no event time, because nothing set one or DATETIME couldn't read it, gets the
// ingest time (checked in a lab tenant). The emulator's ingest time is its "now". kept is true
// when the record has the ingest time because the parser never changed eventTimeUsec$.
function withEventTime(record, nowUsec, now, notes, parser, kept = false) {
  if ((record.event_time_usec !== undefined && !kept) || !Number.isFinite(nowUsec)) return record;
  record.event_time_usec ??= nowUsec;
  notes.push({ level: 'info', code: 'ingest-time', parser, message: `no event time, so the engine stores the ingest time; the emulator uses ${now}` });
  return record;
}

// Fields the engine's root parser fills before any custom parser runs.
export const ROOT_FIELDS = new Set(['sensor_type', 'sensor_id', 'event_time_usec', 'event_time_fidelity']);

// What the engine's root parser sets before custom parsers run (checked in a lab tenant):
// sensorType$ "Generic", sensorId$ the syslog host, eventTimeUsec$ the syslog time in UTC and
// the current year, eventTimeFidelity$ "MICRO", and message, the line after the BSD header.
// With no plain BSD header, eventTimeUsec$ is the ingest time in microseconds, a number rather
// than a DATETIME value.
export function rootVars(sample, now) {
  const rs = rootSplit(sample);
  let time = null;
  if (rs.time) {
    try { time = goParse('Jan _2 15:04:05', rs.time, { handle2DigitYear: true, now }); } catch { time = null; }
  } else {
    const usec = (now === undefined ? Date.now() : Date.parse(now)) * 1000;
    time = Number.isFinite(usec) ? usec : null;
  }
  return [['originalData$', sample], ['message', rs.message], ['sensorType$', 'Generic'], ['sensorId$', rs.host], ['eventTimeUsec$', time], ['eventTimeFidelity$', 'MICRO']];
}

// Run one script's statements with some starting variables and return every variable.
// Used by the tests and handy for trying a function on its own.
export function execute(text, vars = {}, opts = {}) {
  const p = compileParser({ name: 'SCRIPT', text });
  if (p.script.problems.some((x) => x.level === 'error')) throw new Error(p.script.problems.map((x) => `line ${x.line}: ${x.message}`).join('; '));
  const notes = [];
  const ctx = new Ctx(Object.entries(vars), { now: opts.now }, notes);
  runStatements(p, ctx, new Map([[p.name, p]]));
  return { vars: ctx.vars, notes };
}
