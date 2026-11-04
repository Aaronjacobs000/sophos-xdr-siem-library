// A small CEL evaluator for tests: enough of the language to run the let expressions of the case chat
// sync playbooks on sample cases, so a test can check what a card would say. It walks the tree that
// tools/lib/cel.mjs parses. Strings index by code point, as Sophos Fusion's evaluator does, and a
// missing key is an error unless it is read with .? or [?]. It is not a full CEL: no timestamps,
// durations, bytes or unsigned ints, and int and double are both JS numbers.
import { parseCel } from '../tools/lib/cel.mjs';

class Optional {
  constructor(has, value) { this.has = has; this.value = value; }
}
const NONE = new Optional(false, undefined);
const some = (v) => new Optional(true, v);

const cp = (s) => Array.from(s);
const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Optional);
const typeName = (v) => (v === null ? 'null' : Array.isArray(v) ? 'list' : v instanceof Optional ? 'optional' : typeof v === 'object' ? 'map' : typeof v);

function fail(msg) { throw new Error(msg); }

function equal(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => equal(x, b[i]));
  if (isMap(a) && isMap(b)) {
    const ka = Object.keys(a);
    return ka.length === Object.keys(b).length && ka.every((k) => k in b && equal(a[k], b[k]));
  }
  return a === b;
}

function indexOfCp(s, sub, last) {
  const i = last ? s.lastIndexOf(sub) : s.indexOf(sub);
  return i < 0 ? -1 : cp(s.slice(0, i)).length;
}

function substring(s, args) {
  const c = cp(s);
  const [a, b = c.length] = args;
  if (a < 0 || a > c.length || b < a || b > c.length) fail(`substring(${args.join(', ')}) out of range for a string of ${c.length}`);
  return c.slice(a, b).join('');
}

const STRING_METHODS = {
  startsWith: (s, [x]) => s.startsWith(x),
  endsWith: (s, [x]) => s.endsWith(x),
  contains: (s, [x]) => s.includes(x),
  split: (s, [sep]) => s.split(sep),
  replace: (s, [a, b]) => s.split(a).join(b),
  trim: (s) => s.trim(),
  lowerAscii: (s) => s.replace(/[A-Z]/g, (ch) => ch.toLowerCase()),
  upperAscii: (s) => s.replace(/[a-z]/g, (ch) => ch.toUpperCase()),
  substring: (s, args) => substring(s, args),
  indexOf: (s, [x]) => indexOfCp(s, x, false),
  lastIndexOf: (s, [x]) => indexOfCp(s, x, true),
  size: (s) => cp(s).length,
};

const LIST_METHODS = {
  join: (l, [sep = '']) => {
    if (!l.every((x) => typeof x === 'string')) fail('join on a list that is not all strings');
    return l.join(sep);
  },
  slice: (l, [a, b]) => {
    if (a < 0 || b < a || b > l.length) fail(`slice(${a}, ${b}) out of range for a list of ${l.length}`);
    return l.slice(a, b);
  },
  size: (l) => l.length,
};

const GLOBALS = {
  size: ([x]) => (typeof x === 'string' ? cp(x).length : Array.isArray(x) ? x.length : isMap(x) ? Object.keys(x).length : fail(`size of ${typeName(x)}`)),
  int: ([x]) => (typeof x === 'number' ? Math.trunc(x) : typeof x === 'string' && /^-?\d+$/.test(x) ? Number(x) : fail(`int of ${JSON.stringify(x)}`)),
  string: ([x]) => (typeof x === 'string' ? x : typeof x === 'number' || typeof x === 'boolean' ? String(x) : fail(`string of ${typeName(x)}`)),
};

const MACROS = new Set(['map', 'filter', 'exists', 'all']);

function select(target, field, opt) {
  if (target instanceof Optional) {
    if (!target.has) return NONE;
    return select(target.value, field, true);
  }
  if (isMap(target)) {
    if (field in target) return opt ? some(target[field]) : target[field];
    return opt ? NONE : fail(`no such key: ${field}`);
  }
  if (opt && target === null) return NONE;
  return fail(`select .${field} on ${typeName(target)}`);
}

function index(target, key, opt) {
  if (target instanceof Optional) {
    if (!target.has) return NONE;
    return index(target.value, key, true);
  }
  if (Array.isArray(target)) {
    if (typeof key !== 'number') fail('list index is not a number');
    if (key >= 0 && key < target.length) return opt ? some(target[key]) : target[key];
    return opt ? NONE : fail(`index ${key} out of range`);
  }
  if (isMap(target)) {
    const k = String(key);
    if (k in target) return opt ? some(target[k]) : target[k];
    return opt ? NONE : fail(`no such key: ${k}`);
  }
  return fail(`index on ${typeName(target)}`);
}

function binary(op, l, r) {
  switch (op) {
    case '==': return equal(l, r);
    case '!=': return !equal(l, r);
    case '<': case '<=': case '>': case '>=':
      if (typeof l !== typeof r || !['number', 'string'].includes(typeof l)) fail(`${op} on ${typeName(l)} and ${typeName(r)}`);
      return op === '<' ? l < r : op === '<=' ? l <= r : op === '>' ? l > r : l >= r;
    case '+':
      if (typeof l === 'string' && typeof r === 'string') return l + r;
      if (typeof l === 'number' && typeof r === 'number') return l + r;
      if (Array.isArray(l) && Array.isArray(r)) return [...l, ...r];
      return fail(`+ on ${typeName(l)} and ${typeName(r)}`);
    case '-': case '*': case '/': case '%':
      if (typeof l !== 'number' || typeof r !== 'number') fail(`${op} on ${typeName(l)} and ${typeName(r)}`);
      if ((op === '/' || op === '%') && r === 0) fail('divide by zero');
      if (op === '-') return l - r;
      if (op === '*') return l * r;
      if (op === '/') return Number.isInteger(l) && Number.isInteger(r) ? Math.trunc(l / r) : l / r;
      return l % r;
    case 'in':
      if (Array.isArray(r)) return r.some((x) => equal(x, l));
      if (isMap(r)) return String(l) in r;
      return fail(`in on ${typeName(r)}`);
    default: return fail(`unknown operator ${op}`);
  }
}

function truthy(v, what) {
  if (typeof v !== 'boolean') fail(`${what} is ${typeName(v)}, not bool`);
  return v;
}

function evaluate(n, scope, fns) {
  const ev = (x, s = scope) => evaluate(x, s, fns);
  switch (n.t) {
    case 'lit': return n.v;
    case 'id':
      if (n.name in scope) return scope[n.name];
      return fail(`undeclared reference to ${n.name}`);
    case 'sel': return select(ev(n.target), n.field, n.opt);
    case 'idx': return index(ev(n.target), ev(n.index), n.opt);
    case 'un': {
      const x = ev(n.x);
      if (n.op === '!') return !truthy(x, '!');
      if (typeof x !== 'number') fail('- on a non-number');
      return -x;
    }
    case 'bin':
      if (n.op === '&&') return truthy(ev(n.l), '&&') ? truthy(ev(n.r), '&&') : false;
      if (n.op === '||') return truthy(ev(n.l), '||') ? true : truthy(ev(n.r), '||');
      return binary(n.op, ev(n.l), ev(n.r));
    case 'cond': return truthy(ev(n.c), '?:') ? ev(n.a) : ev(n.b);
    case 'list': return n.items.map((x) => ev(x));
    case 'map': {
      const out = {};
      for (const e of n.entries) out[String(ev(e.k))] = ev(e.v);
      return out;
    }
    case 'call': {
      if (n.fn === 'bind' && n.target && n.target.t === 'id' && n.target.name === 'cel') {
        return ev(n.args[2], { ...scope, [n.args[0].name]: ev(n.args[1]) });
      }
      if (!n.target) {
        const args = n.args.map((a) => ev(a));
        if (n.fn in fns) return fns[n.fn](...args);
        if (n.fn in GLOBALS) return GLOBALS[n.fn](args);
        return fail(`undeclared function ${n.fn}`);
      }
      const target = ev(n.target);
      if (target instanceof Optional) {
        if (n.fn === 'orValue') return target.has ? target.value : ev(n.args[0]);
        if (n.fn === 'hasValue') return target.has;
        if (n.fn === 'value') return target.has ? target.value : fail('optional has no value');
        return fail(`${n.fn} on an optional`);
      }
      if (MACROS.has(n.fn) && Array.isArray(target)) {
        const v = n.args[0].name;
        const at = (x) => ({ ...scope, [v]: x });
        if (n.fn === 'map') {
          if (n.args.length === 3) return target.filter((x) => truthy(ev(n.args[1], at(x)), 'map filter')).map((x) => ev(n.args[2], at(x)));
          return target.map((x) => ev(n.args[1], at(x)));
        }
        if (n.fn === 'filter') return target.filter((x) => truthy(ev(n.args[1], at(x)), 'filter'));
        if (n.fn === 'exists') return target.some((x) => truthy(ev(n.args[1], at(x)), 'exists'));
        return target.every((x) => truthy(ev(n.args[1], at(x)), 'all'));
      }
      const args = n.args.map((a) => ev(a));
      if (typeof target === 'string' && n.fn in STRING_METHODS) {
        if (n.fn !== 'substring' && !args.every((a) => typeof a === 'string')) fail(`${n.fn} takes strings`);
        return STRING_METHODS[n.fn](target, args);
      }
      if (Array.isArray(target) && n.fn in LIST_METHODS) return LIST_METHODS[n.fn](target, args);
      return fail(`no method ${n.fn} on ${typeName(target)}`);
    }
    default: return fail(`unsupported expression ${n.t}`);
  }
}

// Evaluates one CEL expression. vars: the names it may read; fns: the platform functions it may call.
export function evalCel(text, vars = {}, fns = {}) {
  const out = evaluate(parseCel(text), vars, fns);
  if (out instanceof Optional) fail('the expression ends in an optional; read it with orValue()');
  return out;
}
