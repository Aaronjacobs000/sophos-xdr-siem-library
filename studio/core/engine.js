// The emulator: runs parser scripts over sample lines the way the docs describe the Sophos
// NG-SIEM engine doing it. It is our reading of the docs, not the Sophos engine.
//
// Flow per line: the root step splits off the syslog header, every top-level parser's confirm
// string is tried, the matching parser runs, then its children's confirm strings are tried
// and the first match runs. The last parser's schema decides the normalized record.

import {
  JsonValue, ObjValue, MatchValue, RecordValue, TimeValue, RuntimeError, ParseErrorSignal,
  toStr, truthy, looseEqual, wrapJson, isList, typeName, hasOwn,
} from './values.js';
import { parseScript, parseExpression, walk } from './language.js';
import { FUNCTIONS, LAZY } from './functions.js';
import { compileGo } from './goregex.js';
import { query, isMultiPath } from './jsonpath.js';
import { splitSyslog } from './formats.js';
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
  get(name) {
    return this.vars.has(name) ? this.vars.get(name) : null;
  }
  set(target, value) {
    const parts = target.split('.');
    if (parts.length === 1) { this.vars.set(target, value); return; }
    let rec = this.vars.get(parts[0]);
    if (!(rec instanceof RecordValue)) { rec = new RecordValue(); this.vars.set(parts[0], rec); }
    for (const p of parts.slice(1, -1)) {
      let next = rec.fields.get(p);
      if (!(next instanceof RecordValue)) { next = new RecordValue(); rec.fields.set(p, next); }
      rec = next;
    }
    rec.fields.set(parts[parts.length - 1], value);
  }
  sanitizeNow() { this.flagsNow = { ...(this.flagsNow || {}), sanitize: true }; }
  trimNow() { this.flagsNow = { ...(this.flagsNow || {}), trim: true }; }
}

function index(base, idx) {
  if (base === null || base === undefined) return null;
  if (base instanceof MatchValue) {
    if (typeof idx === 'number') {
      if (idx < 0 || idx >= base.groups.length) throw new RuntimeError(`regex group ${idx} is out of range (the pattern has ${base.groups.length - 1} groups)`, 'group-range');
      return base.groups[idx] ?? '';
    }
    if (!hasOwn(base.named, idx)) throw new RuntimeError(`regex group "${idx}" is not in the pattern`, 'group-name');
    return base.named[idx] ?? '';
  }
  if (base instanceof JsonValue) {
    if (typeof idx === 'string') {
      const r = query(base.value, idx);
      if (r === null) return null;
      return Array.isArray(r) && isMultiPath(idx) ? r.map(wrapJson) : wrapJson(r);
    }
    if (typeof idx === 'number' && Array.isArray(base.value)) return wrapJson(base.value[idx < 0 ? base.value.length + idx : idx]);
    return null;
  }
  if (base instanceof ObjValue) {
    if (typeof idx === 'number') return base.header && idx >= 0 && idx < base.header.length ? base.header[idx] : null;
    return base.get(toStr(idx));
  }
  if (isList(base)) {
    if (typeof idx !== 'number') return null;
    const k = idx < 0 ? base.length + idx : idx;
    return k >= 0 && k < base.length ? base[k] ?? null : null;
  }
  return null;
}

function compare(op, a, b) {
  if (a === null || b === null) return false;
  const na = typeof a === 'number' ? a : Number(a);
  const nb = typeof b === 'number' ? b : Number(b);
  if (a instanceof TimeValue && b instanceof TimeValue) return cmp(op, a.usec, b.usec);
  if (!Number.isNaN(na) && !Number.isNaN(nb) && a !== '' && b !== '') return cmp(op, na, nb);
  return cmp(op, toStr(a), toStr(b));
}
const cmp = (op, a, b) => (op === '<' ? a < b : op === '>' ? a > b : op === '<=' ? a <= b : a >= b);

function plus(a, b) {
  if (a === null || a === undefined) return b ?? null;
  if (b === null || b === undefined) return a;
  if (isList(a)) return [...a, ...(isList(b) ? b : [b])];
  if (isList(b)) return [a, ...b];
  if (a instanceof TimeValue && typeof b === 'number') return new TimeValue(a.usec + b, a.offset, a.zone);
  if (typeof a === 'number' && typeof b === 'number') return a + b;
  return toStr(a) + toStr(b);
}

function num(v, op) {
  if (typeof v === 'number') return v;
  if (v instanceof TimeValue) return v.usec;
  const n = Number(v);
  if (v === null || Number.isNaN(n)) throw new RuntimeError(`"${op}" needs numbers, got ${typeName(v)}`);
  return n;
}

export function evaluate(ctx, e) {
  switch (e.t) {
    case 'lit': return e.v;
    case 'var': return ctx.get(e.name);
    case 'list': return e.items.map((x) => evaluate(ctx, x));
    case 'if': return truthy(evaluate(ctx, e.c)) ? evaluate(ctx, e.a) : evaluate(ctx, e.b);
    case 'neg': return -num(evaluate(ctx, e.e), '-');
    case 'member': {
      const base = evaluate(ctx, e.e);
      return base instanceof RecordValue ? (base.fields.has(e.name) ? base.fields.get(e.name) : null) : null;
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
      if (e.op === 'AND') return truthy(evaluate(ctx, e.l)) && truthy(evaluate(ctx, e.r));
      if (e.op === 'OR') return truthy(evaluate(ctx, e.l)) || truthy(evaluate(ctx, e.r));
      const a = evaluate(ctx, e.l);
      const b = evaluate(ctx, e.r);
      switch (e.op) {
        case '==': return looseEqual(a, b);
        case '!=': return !looseEqual(a, b);
        case '<': case '>': case '<=': case '>=': return compare(e.op, a, b);
        case '+': return plus(a, b);
        case '-': return num(a, '-') - num(b, '-');
        case '*': return num(a, '*') * num(b, '*');
        case '/': { const d = num(b, '/'); if (d === 0) throw new RuntimeError('division by zero'); const r = num(a, '/') / d; return Number.isInteger(num(a, '/')) && Number.isInteger(d) ? Math.trunc(r) : r; }
        case '%': return num(a, '%') % num(b, '%');
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
    return truthy(evaluate(ctx, p.confirm.ast));
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
      const src = ctx.get(st.source);
      const re = compileGo(st.pattern);
      const m = src === null ? null : re.exec(toStr(src));
      if (!m) ctx.note('info', 'capture-miss', `${st.target}: the capture pattern matched nothing in ${st.source}, so ${st.target} is NULL`);
      ctx.vars.set(st.target, m ? new MatchValue([...m].map((x) => (x === undefined ? '' : x)), { ...(m.groups || {}) }) : null);
      continue;
    }
    ctx.set(st.target, evaluate(ctx, st.expr));
  }
}

// Variables a child's confirm string reads from its parent, so the lint can tell carrier
// fields like eventType$ apart from typos.
function confirmVars(p) {
  const out = new Set();
  if (p.confirm && p.confirm.ast) walk(p.confirm.ast, (n) => { if (n.t === 'var') out.add(n.name); });
  return out;
}

// parsers: [{name, text, parent?, role?}]; samples: [string]; opts: {now}
export function runParsers(parsers, samples, opts = {}) {
  const now = opts.now || new Date().toISOString();
  const compiled = parsers.map(compileParser);
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
    const header = splitSyslog(sample);
    const root = new Ctx([['originalData$', sample], ['message', header ? header.body : sample]], { now }, notes);
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
      const parentP = path.length > 1 ? byName.get(path[0]) : null;
      const schema = current.schema || (parentP && parentP.schema) || GENERIC;
      result.schema = schema;
      if (!schemaInfo(schema)) {
        result.error = `!SCHEMA=${schema} is not a schema custom parsers can use`;
        return result;
      }
      if (schema === GENERIC) {
        result.result = path.length === 1 && (childrenOf.get(path[0]) || []).length
          ? 'The parent matched but no child did. The line stays in the generic schema only.'
          : 'This parser targets the generic schema.';
        return result;
      }
      const flags = current.flags;
      const norm = normalize(ctx.vars, schema, {
        sanitize: !flags.has('SANITIZEALLOFF') || Boolean(ctx.flagsNow && ctx.flagsNow.sanitize),
        trim: !flags.has('TRIMALLOFF') || Boolean(ctx.flagsNow && ctx.flagsNow.trim),
        carriers,
        parser: current.name,
      });
      result.normalized = norm.record;
      notes.push(...norm.notes);
      if (!Object.keys(norm.record).length) notes.push({ level: 'warning', code: 'empty-record', parser: current.name, message: `${current.name} matched this line but set no ${schemaInfo(schema).name} fields` });
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
  if (r.error) out.error = true;
  return out;
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
