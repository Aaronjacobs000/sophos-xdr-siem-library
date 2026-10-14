// Runtime value types for the emulator. Plain JS values stand in for STRING, number, bool
// and NULL; the classes below cover the rest of the language's value kinds.

// doc is true for the value JSON() returns, and false for a part of it read with an index such
// as json["$.o"]. STRING() writes a NULL inside a doc as null and inside a part as 0 (checked in
// a lab tenant).
export class JsonValue {
  constructor(value, doc = false) { this.value = value; this.doc = doc; }
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
  if (typeof v === 'number') return goFloatText(v);
  if (v instanceof TimeValue) return formatTime(v);
  return compactJson(toPlain(v));
}

// Every number in the engine is a float64, whole numbers and literals included, so
// 9007199254740993 is 9007199254740992 (checked in a lab tenant). As text, joined or stored in a
// string field, a number is written the way Go's strconv.FormatFloat(f, 'f', -1, 64) writes it:
// the fewest digits that read back as the same float, and never an exponent. 1 / 10000000 is
// 0.0000001, 0 / -1 is -0 and 9223372036854775807 is 9223372036854776000.
export function goFloatText(n) {
  if (n === 0) return Object.is(n, -0) ? '-0' : '0';
  if (!Number.isFinite(n)) return Number.isNaN(n) ? 'NaN' : n > 0 ? '+Inf' : '-Inf';
  const [m, e] = Math.abs(n).toExponential().split('e');
  const digits = m.replace('.', '');
  const exp = Number(e);
  let out;
  if (exp >= digits.length - 1) out = digits + '0'.repeat(exp - digits.length + 1);
  else if (exp >= 0) out = `${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
  else out = `0.${'0'.repeat(-exp - 1)}${digits}`;
  return n < 0 ? `-${out}` : out;
}

// Text counts as a number when Go's strconv.ParseFloat reads all of it: "5", "+5", "-5", "5.",
// ".5", "1e3", "1_000" and the hex float "0x1p4". Spaces, "", "0x10", "inf", "NaN" and a value
// out of range such as "1e400" don't (checked in a lab tenant). Returns the number or null.
export function parseGoFloat(s) {
  if (typeof s !== 'string') return null;
  let i = 0;
  if (s[i] === '+' || s[i] === '-') i++;
  let hex = false;
  if (i + 2 < s.length && s[i] === '0' && (s[i + 1] === 'x' || s[i + 1] === 'X')) { hex = true; i += 2; }
  const isDigit = (c) => (c >= '0' && c <= '9') || (hex && /^[a-fA-F]$/.test(c));
  let sawDot = false, sawDigits = false, mant = '', frac = 0;
  for (; i < s.length; i++) {
    const c = s[i];
    if (c === '_') continue;
    if (c === '.') { if (sawDot) break; sawDot = true; continue; }
    if (!isDigit(c)) break;
    sawDigits = true;
    mant += c;
    if (sawDot) frac++;
  }
  if (!sawDigits) return null;
  let exp = 0;
  if (i < s.length && s[i].toLowerCase() === (hex ? 'p' : 'e')) {
    i++;
    let sign = 1;
    if (s[i] === '+') i++;
    else if (s[i] === '-') { sign = -1; i++; }
    if (!(s[i] >= '0' && s[i] <= '9')) return null;
    let e = '';
    for (; i < s.length && ((s[i] >= '0' && s[i] <= '9') || s[i] === '_'); i++) if (s[i] !== '_') e += s[i];
    exp = sign * Number(e);
  } else if (hex) {
    return null;
  }
  if (i !== s.length || (s.includes('_') && !underscoreOK(s))) return null;
  const v = hex ? Number(BigInt(`0x${mant}`)) * 2 ** (exp - 4 * frac) : Number(s.replace(/_/g, ''));
  if (!Number.isFinite(v)) return null;
  return s[0] === '-' && hex ? -v : v;
}

// Go's rule for _ in a number: only between digits, or between a base prefix and a digit.
function underscoreOK(s) {
  let saw = '^';
  let i = 0;
  if (s[0] === '+' || s[0] === '-') s = s.slice(1);
  let hex = false;
  if (s.length >= 2 && s[0] === '0' && /^[bBoOxX]$/.test(s[1])) { i = 2; saw = '0'; hex = /^[xX]$/.test(s[1]); }
  for (; i < s.length; i++) {
    const c = s[i];
    if ((c >= '0' && c <= '9') || (hex && /^[a-fA-F]$/.test(c))) { saw = '0'; continue; }
    if (c === '_') { if (saw !== '0') return false; saw = '_'; continue; }
    if (saw === '_') return false;
    saw = '!';
  }
  return saw !== '_';
}

// A number, TRUE or FALSE (1 or 0), or text that reads as a number, as a float; otherwise null.
export function asNumber(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'string') return parseGoFloat(v);
  return null;
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

// IF, AND and OR read their operands like truthy(), except for lists (checked in a lab tenant):
// an empty list is false, a list of one counts as its item, and a list of two or more fails
// the event with "cannot convert list to bool". A JSON array counts as a list.
export function toBool(v) {
  const list = isList(v) ? v : v instanceof JsonValue && Array.isArray(v.value) ? v.value.map(wrapJson) : null;
  if (!list) return truthy(v);
  if (list.length > 1) throw new RuntimeError(`cannot convert list to bool: the condition is a list of ${list.length}. Test LENGTH(list) > 0 or one item instead.`, 'list-bool');
  return list.length === 1 && truthy(list[0]);
}

// NULL equals "" as well as NULL (checked in a lab tenant). When both sides are numbers, TRUE or
// FALSE, or text that reads as a number, they compare as floats: "5" == "5.0", "1" == TRUE and
// 9223372036854775807 == 9223372036854775806. Anything else compares as text, so TRUE == "true"
// but not "TRUE", and " 5" != 5 (checked in a lab tenant).
export function looseEqual(a, b) {
  if (a === null || a === undefined || b === null || b === undefined) {
    const x = a ?? null, y = b ?? null;
    return x === y || x === '' || y === '';
  }
  const x = asNumber(a), y = asNumber(b);
  if (x !== null && y !== null) return x === y;
  if (typeof a === typeof b && (typeof a !== 'object')) return a === b;
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
