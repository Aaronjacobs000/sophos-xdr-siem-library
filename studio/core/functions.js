// Built-in functions from the Fusion "Custom parser syntax" page.
// Each entry: [minArgs, maxArgs, implementation(ctx, args, rawArgs)]. Most take evaluated
// arguments; TENANT_LOOKUP takes its third argument unevaluated, as the docs describe.

import {
  JsonValue, ObjValue, RecordValue, TimeValue, MatchValue, RuntimeError, ParseErrorSignal,
  toStr, toPlain, wrapJson, isList, typeName, truthy,
} from './values.js';
import { query } from './jsonpath.js';
import { goParse, goParseAuto } from './gotime.js';
import { goReplaceAll } from './goregex.js';
import { parseCef, parseLeef, splitCsv, splitNameValues, urlParse, idxOfTld, isValidIp, isRfc1918 } from './formats.js';

const str = (v) => (v === null || v === undefined ? null : toStr(v));

function utf8Length(s) {
  return new TextEncoder().encode(s).length;
}

function lengthOf(v, mode) {
  if (mode !== undefined && mode !== null) {
    const m = String(mode).toLowerCase();
    if (m === 'list') {
      if (v === null) return 0;
      if (isList(v)) return v.length;
      if (v instanceof JsonValue && Array.isArray(v.value)) return v.value.length;
      if (typeof v === 'string') return v.trim() ? 1 : 0;
      return null;
    }
    if (m === 'bytes' || m === 'string') return v === null ? 0 : typeof v === 'string' ? utf8Length(v) : null;
    if (m === 'keys' || m === 'object') {
      if (v === null) return 0;
      if (v instanceof ObjValue) return v.map.size;
      if (v instanceof JsonValue && v.value && typeof v.value === 'object' && !Array.isArray(v.value)) return Object.keys(v.value).length;
      return null;
    }
    throw new RuntimeError(`LENGTH mode "${mode}" is not one of list, bytes, string, keys, object`);
  }
  if (v === null) return 0;
  if (typeof v === 'string') return utf8Length(v);
  if (isList(v)) return v.length;
  if (v instanceof ObjValue) return v.map.size;
  if (v instanceof JsonValue) {
    if (Array.isArray(v.value)) return v.value.length;
    if (v.value && typeof v.value === 'object') return Object.keys(v.value).length;
  }
  throw new RuntimeError(`LENGTH does not take a ${typeName(v)}`);
}

function unwrapList(v) {
  if (v === null || v === undefined) return [];
  if (isList(v)) return v;
  if (v instanceof JsonValue && Array.isArray(v.value)) return v.value.map(wrapJson);
  return [v];
}

function objectEntries(v) {
  if (v instanceof ObjValue) return [...v.map];
  if (v instanceof JsonValue && v.value && typeof v.value === 'object' && !Array.isArray(v.value)) return Object.entries(v.value);
  return null;
}

// INT() is strict, like Go's strconv.ParseInt: "1 " with a trailing space is an error that
// fails the event (checked in a lab tenant). The base is required: the engine rejects a parser
// that calls INT(value) with one argument.
function parseIntGo(s, base) {
  if (typeof s === 'number') return Math.trunc(s);
  if (s === null || s === undefined) return null;
  const b = Number(base ?? 10);
  let t = String(s);
  let neg = false;
  if (t.startsWith('-') || t.startsWith('+')) { neg = t[0] === '-'; t = t.slice(1); }
  const digits = '0123456789abcdefghijklmnopqrstuvwxyz'.slice(0, b);
  if (!t || [...t.toLowerCase()].some((c) => !digits.includes(c))) throw new RuntimeError(`INT could not read "${s}" in base ${b}`, 'int');
  const n = parseInt(t, b);
  return neg ? -n : n;
}

// FLATTEN sorts keys and keeps string leaves only; numbers, booleans and nulls are dropped
// (checked in a lab tenant).
function flatten(v, keyLabel, valueLabel) {
  const kf = (keyLabel ?? 'key').endsWith('$') ? keyLabel ?? 'key' : `${keyLabel ?? 'key'}$`;
  const vf = (valueLabel ?? 'value').endsWith('$') ? valueLabel ?? 'value' : `${valueLabel ?? 'value'}$`;
  const out = [];
  const walk = (prefix, node) => {
    if (Array.isArray(node)) node.forEach((x, i) => walk(prefix ? `${prefix}.${i}` : String(i), x));
    else if (node && typeof node === 'object') Object.keys(node).sort().forEach((k) => walk(prefix ? `${prefix}.${k}` : k, node[k]));
    else if (typeof node === 'string') out.push(new RecordValue(new Map([[kf, prefix], [vf, node]])));
  };
  walk('', toPlain(v));
  return out;
}

// TRIM() and TRIM_ALL(): strip space, tab and newline (not \r), then remove a matching
// enclosing pair of {} [] () <> "" or ''. TRIM() repeats; TRIM_ALL removes one pair.
const PAIRS = { '{': '}', '[': ']', '(': ')', '<': '>', '"': '"', "'": "'" };
function enclosed(t) {
  return t.length >= 2 && PAIRS[t[0]] === t[t.length - 1];
}

export function trimPairs(s, repeat) {
  let t = s.replace(/^[ \t\n]+|[ \t\n]+$/g, '');
  while (enclosed(t)) {
    t = t.slice(1, -1);
    if (!repeat) break;
    t = t.replace(/^[ \t\n]+|[ \t\n]+$/g, '');
  }
  return t;
}

// STRING(): a float loses its fraction, NULL becomes "", and a list, JSON object or JSON array,
// SPLIT_NAME_VALUES object or record comes out as JSON the way Go's encoding/json writes it
// (checked in a lab tenant): ["a","b"] with no spaces, object keys sorted, <, > and & escaped, a
// NULL item or member written as 0 and a DATETIME one as {}. A NULL inside the value JSON()
// returned stays null (see JsonValue), but that value inside a list or a record is written as {}.
// TRIM_ALL then takes the brackets off a top-level field, leaving "a","b". STRING() of the value
// JSON() returned writes it as JSON whatever it holds, so JSON("\"s<\"") gives "s\u003c" with
// its quotes, JSON("5") gives 5 and JSON("null") gives null. A number becomes an
// int64 first: the whole part in full, or -9223372036854775808 when it doesn't fit, as with
// (3 / 2) * 9223372036854775807 and 9223372036854775807 itself, which is the float 2^63.
const INT64_LIMIT = 2 ** 63;
export function stringOf(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number') { const t = Math.trunc(v); return t < INT64_LIMIT && t >= -INT64_LIMIT ? BigInt(t).toString() : '-9223372036854775808'; }
  if (isList(v)) return goJsonList(v);
  if (v instanceof JsonValue && v.doc) return goJsonPlain(v.value, 'null');
  if (v instanceof JsonValue && v.value !== null && typeof v.value === 'object') return goJsonPlain(v.value, '0');
  if (v instanceof ObjValue || v instanceof RecordValue) return goJson(v);
  return toStr(v);
}

const GO_HTML = { '<': '\\u003c', '>': '\\u003e', '&': '\\u0026', '\u2028': '\\u2028', '\u2029': '\\u2029' };
const goQuote = (s) => JSON.stringify(typeof s.toWellFormed === 'function' ? s.toWellFormed() : s).replace(/[<>&\u2028\u2029]/g, (ch) => GO_HTML[ch]);

function goJsonList(list) {
  return `[${list.map(goJson).join(',')}]`;
}

// A float the way Go's encoding/json writes it, which JavaScript's String() matches: 1e-7, 1e+21,
// 9223372036854776000. 0 / -1 is -0, which Go writes as -0.
const goJsonNumber = (n) => (Object.is(n, -0) ? '-0' : String(n));

// An item of a list or a member of an object or record.
function goJson(v) {
  if (v === null || v === undefined) return '0';
  if (typeof v === 'string') return goQuote(v);
  if (typeof v === 'number') return goJsonNumber(v);
  if (typeof v === 'boolean') return toStr(v);
  if (isList(v)) return goJsonList(v);
  if (v instanceof TimeValue) return '{}';
  if (v instanceof JsonValue) return v.doc ? '{}' : goJsonPlain(v.value, '0');
  if (v instanceof ObjValue) return goJsonObject([...v.map]);
  if (v instanceof RecordValue) return goJsonObject([...v.fields]);
  return goJsonPlain(toPlain(v));
}

// Parsed JSON, with each NULL written as nul. Its numbers are float64 in Go, so a whole number
// past 2^53 prints rounded, the way JavaScript prints it.
function goJsonPlain(v, nul = 'null') {
  if (v === null || v === undefined) return nul;
  if (Array.isArray(v)) return `[${v.map((x) => goJsonPlain(x, nul)).join(',')}]`;
  if (typeof v === 'object') return goJsonObject(Object.entries(v), (x) => goJsonPlain(x, nul));
  if (typeof v === 'number') return goJsonNumber(v);
  return goJson(v);
}

function goJsonObject(entries, write = goJson) {
  return `{${entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, x]) => `${goQuote(k)}:${write(x)}`).join(',')}}`;
}

// CEF() and LEEF() objects also hold their header fields under the keys "0", "1" and on, so
// STRING() writes them, LENGTH() and OBJKEYS() count them and values["0"] reads one. An extension
// with the same key, such as 0=x, takes its place (checked in a lab tenant).
function withHeaderKeys(o) {
  return o ? new ObjValue(new Map([...o.header.map((h, i) => [String(i), h]), ...o.map]), o.header) : o;
}

// The engine's name for a value's type in its "invalid data type" errors (checked in a lab
// tenant for NULL, NUMBER, BOOLEAN, LIST, OBJECT and TIME).
function engineType(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'string') return 'STRING';
  if (typeof v === 'number') return 'NUMBER';
  if (typeof v === 'boolean') return 'BOOLEAN';
  if (isList(v) || (v instanceof JsonValue && Array.isArray(v.value))) return 'LIST';
  if (v instanceof TimeValue) return 'TIME';
  return 'OBJECT';
}

// IS_VALID_IP() and IS_PRIVATE_IP() take text only. NULL, a number, TRUE or a list fails the
// event: "expected a string, but received invalid data type for IS_VALID_IP(): NULL" (checked in
// a lab tenant).
function ipText(fn, v) {
  if (typeof v === 'string') return v;
  throw new RuntimeError(`expected a string, but received invalid data type for ${fn}(): ${engineType(v)}. Check the value is set and use STRING() on anything that isn't text.`, 'type');
}

// UPPERCASE() and LOWERCASE() take text, and NULL, which gives "". A number, TRUE, a list, an
// object or a DATETIME value fails the event: "invalid data type for UPPERCASE(): NUMBER"
// (checked in a lab tenant).
function caseText(fn, v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  throw new RuntimeError(`invalid data type for ${fn}(): ${engineType(v)}. Use STRING() on the value first.`, 'type');
}

export const FUNCTIONS = {
  // The separator is read as the first character of a CSV separator (see splitCsv).
  SPLIT: [2, 3, (c, [s, d, greedy]) => {
    if (s === null) return null;
    const parts = splitCsv(toStr(s), toStr(d) ?? '');
    return truthy(greedy) ? parts.filter((p) => p !== '') : parts;
  }],
  // The quote character is required: the engine rejects a parser that calls SPLIT_NAME_VALUES
  // with 3 arguments ("requires 4 parameters", checked in a lab tenant).
  SPLIT_NAME_VALUES: [4, 4, (c, [s, d, sep, q]) => splitNameValues(str(s), str(d), str(sep), str(q))],
  JSON: [1, 1, (c, [s]) => {
    if (s === null) return null;
    if (s instanceof JsonValue) return s;
    try { return new JsonValue(JSON.parse(toStr(s)), true); } catch (e) { throw new RuntimeError(`JSON could not read the data: ${e.message}`, 'json'); }
  }],
  // CEF(NULL) fails the event the way CEF("") does (checked in a lab tenant).
  CEF: [1, 1, (c, [s]) => {
    if (s === null || s === undefined) throw new RuntimeError('message is not in LEEF format: CEF() got NULL. Check the value is set before you read it as CEF.', 'cef-header');
    return withHeaderKeys(parseCef(str(s)));
  }],
  // LEEF(NULL) fails the event too, with or without a delimiter, and so does text with no LEEF:
  // (see parseLeef; checked in a lab tenant).
  LEEF: [1, 2, (c, [s, d]) => {
    if (s === null || s === undefined) throw new RuntimeError('message is not in LEEF format: LEEF() got NULL. Check the value is set before you read it as LEEF.', 'leef-header');
    return withHeaderKeys(parseLeef(str(s), d === undefined ? null : str(d)));
  }],
  DATETIME: [1, 3, (c, [s, layout, two]) => {
    if (s === null) return null;
    if (s instanceof TimeValue) return s;
    const opts = { handle2DigitYear: truthy(two ?? false), now: c.now };
    // A value DATETIME can't read gives NULL, not an error (checked in a lab tenant).
    try {
      if (layout === undefined || layout === null) return goParseAuto(s, opts);
      return goParse(toStr(layout), toStr(s), opts);
    } catch (e) {
      c.note('warning', 'datetime-failed', `${e.message}. The engine leaves the result NULL.`);
      return null;
    }
  }],
  IS_PRIVATE_IP: [1, 1, (c, [s]) => isRfc1918(ipText('IS_PRIVATE_IP', s))],
  IS_VALID_IP: [1, 1, (c, [s]) => isValidIp(ipText('IS_VALID_IP', s))],
  REPLACE: [3, 3, (c, [s, a, b]) => (s === null ? null : toStr(s).split(toStr(a) ?? '').join(toStr(b) ?? ''))],
  REPLACE_REGEX: [3, 3, (c, [s, p, b]) => (s === null ? null : goReplaceAll(toStr(s), toStr(p), toStr(b) ?? ''))],
  LENGTH: [1, 2, (c, [v, mode]) => lengthOf(v, mode)],
  STRLEN: [1, 1, (c, [v]) => {
    if (v === null) return 0;
    if (typeof v !== 'string') throw new RuntimeError(`STRLEN takes a STRING, not ${typeName(v)}`);
    return utf8Length(v);
  }],
  UPPERCASE: [1, 1, (c, [s]) => caseText('UPPERCASE', s).toUpperCase()],
  LOWERCASE: [1, 1, (c, [s]) => caseText('LOWERCASE', s).toLowerCase()],
  TRIM: [1, 1, (c, [s]) => (s === null ? null : trimPairs(toStr(s), true))],
  SANITIZE_ALL: [0, 0, (c) => { c.sanitizeNow(); return null; }],
  TRIM_ALL: [0, 0, (c) => { c.trimNow(); return null; }],
  ADDFIELD: [3, 3, (c, [coll, name, values]) => {
    const vals = unwrapList(values);
    const field = toStr(name);
    if (coll === null || coll === undefined) return vals.map((x) => new RecordValue(new Map([[field, x]])));
    const list = unwrapList(coll);
    return list.map((rec, i) => {
      const r = rec instanceof RecordValue ? rec : new RecordValue();
      r.fields.set(field, i < vals.length ? vals[i] : null);
      return r;
    });
  }],
  URL_PARSE: [1, 2, (c, [u, silent]) => urlParse(str(u), truthy(silent ?? false))],
  CONTAINS: [2, 2, (c, [s, sub]) => (s === null ? false : toStr(s).includes(toStr(sub) ?? ''))],
  IDX_OF_TLD: [1, 1, (c, [s]) => { c.note('inferred', 'idx-of-tld', 'IDX_OF_TLD(): the docs give examples but no algorithm; the emulator guesses'); return idxOfTld(str(s)); }],
  PARSE_ERROR: [1, 2, (c, [text, generic]) => { throw new ParseErrorSignal(toStr(text) ?? '', generic === undefined ? true : truthy(generic)); }],
  BASE64_DECODE: [1, 1, (c, [s]) => {
    if (s === null) return null;
    const t = toStr(s).trim().replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new RuntimeError('BASE64_DECODE: not base64');
    const bin = typeof atob === 'function' ? atob(t.padEnd(Math.ceil(t.length / 4) * 4, '=')) : Buffer.from(t, 'base64').toString('binary');
    return new TextDecoder().decode(Uint8Array.from(bin, (ch) => ch.charCodeAt(0)));
  }],
  INT: [2, 2, (c, [s, base]) => parseIntGo(s, base)],
  STRING: [1, 1, (c, [v]) => stringOf(v)],
  OBJKEYS: [1, 1, (c, [v]) => { const e = objectEntries(v); return e ? e.map(([k]) => k).sort() : null; }],
  OBJVALUES: [1, 1, (c, [v]) => {
    const e = objectEntries(v);
    if (!e) return null;
    return e.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, x]) => (x !== null && typeof x === 'object' ? toStr(wrapJson(toPlain(x))) : x));
  }],
  FLATTEN: [1, 3, (c, [v, k, val]) => flatten(v, k === undefined ? null : toStr(k), val === undefined ? null : toStr(val))],
  VALIDATE_ALL_JSONPATHS_EXIST: [2, 2, (c, [s, paths]) => {
    try {
      const text = toStr(s) ?? '';
      const at = text.lastIndexOf('}') === text.trimEnd().length - 1 ? findJsonStart(text) : -1;
      if (at === -1) return false;
      const obj = JSON.parse(text.slice(at));
      return toStr(paths).split(',').every((p) => query(obj, p.trim()) !== null);
    } catch {
      return false;
    }
  }],
};
FUNCTIONS.OBJVALS = FUNCTIONS.OBJVALUES;

// TENANT_LOOKUP evaluates its default lazily. The emulator has no tenant directory, so it
// always takes the default.
export const LAZY = {
  TENANT_LOOKUP: [3, 3, (c, rawArgs, evalArg) => {
    c.note('info', 'tenant-lookup', 'TENANT_LOOKUP(): the emulator has no tenant directory, so the default is used');
    evalArg(rawArgs[0]);
    evalArg(rawArgs[1]);
    return evalArg(rawArgs[2]);
  }],
};

// Index of the "{" that opens the JSON object at the end of the text, or -1.
function findJsonStart(text) {
  const end = text.trimEnd().length - 1;
  let depth = 0, inStr = false;
  for (let i = end; i >= 0; i--) {
    const ch = text[i];
    if (inStr) {
      if (ch === '"' && text[i - 1] !== '\\') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === '}') depth++;
    else if (ch === '{') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

export const FUNCTION_NAMES = new Set([...Object.keys(FUNCTIONS), ...Object.keys(LAZY)]);
export const DEPRECATED = { STRLEN: 'STRLEN() is deprecated; use LENGTH(value) or LENGTH(value, "bytes")' };
export const ARITY = Object.fromEntries([...Object.entries(FUNCTIONS), ...Object.entries(LAZY)].map(([k, [a, b]]) => [k, [a, b]]));

export { MatchValue };
