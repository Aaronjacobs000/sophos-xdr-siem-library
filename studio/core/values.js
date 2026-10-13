// Runtime value types for the emulator. Plain JS values stand in for STRING, number, bool
// and NULL; the classes below cover the rest of the language's value kinds.

export class JsonValue {
  constructor(value) { this.value = value; }
}

// OBJECT values from SPLIT_NAME_VALUES, CEF, LEEF and URL_PARSE. CEF and LEEF also carry
// their header fields, which are read with a number index.
export class ObjValue {
  constructor(map = new Map(), header = null) { this.map = map; this.header = header; }
  get(key) { return this.map.has(key) ? this.map.get(key) : null; }
}

// A capture result. The engine keeps every match: with one match each group is a string,
// with several each group is the list of values across matches. A capture that matched
// nothing still exists; indexing it gives "" (checked in a lab tenant).
export class MatchValue {
  constructor(groups, named, count = 1) { this.groups = groups; this.named = named; this.count = count; }
  get nomatch() { return this.count === 0; }
}

// A dotted variable such as grp.key$ or fileHash$.sha1$.
export class RecordValue {
  constructor(fields = new Map()) { this.fields = fields; }
}

// DATETIME() result. usec is microseconds since the Unix epoch, offset is minutes east of UTC.
export class TimeValue {
  constructor(usec, offset = 0, zone = 'UTC') { this.usec = usec; this.offset = offset; this.zone = zone; }
}

export class RuntimeError extends Error {
  constructor(message, code = 'runtime') { super(message); this.code = code; }
}

export class ParseErrorSignal extends Error {
  constructor(text, makeGeneric) { super(`PARSE_ERROR: ${text}`); this.text = text; this.makeGeneric = makeGeneric; }
}

export const isList = Array.isArray;

export function typeName(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'string') return 'STRING';
  if (typeof v === 'boolean') return 'BOOL';
  if (typeof v === 'number') return Number.isInteger(v) ? 'INT' : 'FLOAT';
  if (isList(v)) return 'LIST';
  if (v instanceof JsonValue) return 'JSON';
  if (v instanceof ObjValue) return 'OBJECT';
  if (v instanceof MatchValue) return 'MATCH';
  if (v instanceof RecordValue) return 'RECORD';
  if (v instanceof TimeValue) return 'TIME';
  return 'UNKNOWN';
}

// Plain JSON-able form of any value, for display and for STRING().
export function toPlain(v) {
  if (v === null || v === undefined) return null;
  if (v instanceof JsonValue) return v.value;
  if (v instanceof ObjValue) return Object.fromEntries([...v.map].map(([k, x]) => [k, toPlain(x)]));
  if (v instanceof RecordValue) return Object.fromEntries([...v.fields].map(([k, x]) => [k, toPlain(x)]));
  if (v instanceof MatchValue) return v.groups;
  if (v instanceof TimeValue) return formatTime(v);
  if (isList(v)) return v.map(toPlain);
  return v;
}

const pad = (n, w = 2) => String(Math.abs(n)).padStart(w, '0');

// Go's default time.Time String(): 2018-09-21 17:35:54 +0000 UTC
export function formatTime(t) {
  const ms = Math.floor(t.usec / 1000) + t.offset * 60000;
  const d = new Date(ms);
  const frac = ((t.usec % 1_000_000) + 1_000_000) % 1_000_000;
  const f = frac ? '.' + String(frac).padStart(6, '0').replace(/0+$/, '') : '';
  const sign = t.offset < 0 ? '-' : '+';
  const off = `${sign}${pad(Math.trunc(Math.abs(t.offset) / 60))}${pad(Math.abs(t.offset) % 60)}`;
  return `${String(d.getUTCFullYear()).padStart(4, '0')}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}${f} ${off} ${t.zone}`;
}

export function compactJson(v) {
  return JSON.stringify(v);
}

// String form used by + concatenation and comparisons with mixed types.
export function toStr(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(v);
  if (v instanceof TimeValue) return formatTime(v);
  return compactJson(toPlain(v));
}

// IF conditions: TRUE, a non-empty string other than "false", a non-zero number, or a
// non-empty list count as true. The docs show IF on a plain value (RepeatingFields page),
// so conditions are not limited to booleans. INFERRED beyond that example.
export function truthy(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') { const t = v.trim(); return t !== '' && t.toLowerCase() !== 'false'; }
  if (typeof v === 'number') return v !== 0;
  if (isList(v)) return v.length > 0;
  if (v instanceof JsonValue) return v.value !== null && v.value !== false;
  return true;
}

export function looseEqual(a, b) {
  if (a === null || a === undefined || b === null || b === undefined) return (a ?? null) === (b ?? null);
  if (typeof a === typeof b && (typeof a !== 'object')) return a === b;
  if (typeof a === 'number' && typeof b === 'string') return String(a) === b || Number(b) === a;
  if (typeof b === 'number' && typeof a === 'string') return String(b) === a || Number(a) === b;
  return toStr(a) === toStr(b);
}

// Wrap a JSON-parsed value for the language: objects and arrays stay JSON so they can be
// indexed with JSONPath again; scalars become plain values.
export function wrapJson(v) {
  if (v !== null && typeof v === 'object') return new JsonValue(v);
  return v === undefined ? null : v;
}

export function hasOwn(obj, key) {
  return obj !== null && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);
}
