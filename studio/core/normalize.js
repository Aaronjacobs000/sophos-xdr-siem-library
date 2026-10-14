// Turns the $ fields a parser set into a normalized record for its schema.
// Field names, types and enum names come from the public schema pages. How values are
// coerced into each type follows what the engine did in a lab tenant; notes point out
// values that change or fail on the way in.

import { JsonValue, ObjValue, RecordValue, TimeValue, MatchValue, RuntimeError, toStr, toPlain, isList, hasOwn, wrapJson } from './values.js';
import { fieldsByParser, schemaInfo, typeKind, enumMembers, enumNumbers, messageType, INT_TYPES } from './schemas.js';
import { trimPairs, stringOf } from './functions.js';
import { AUTH0_LOG_TYPES } from './auth0-log-types.js';

// SANITIZE_ALL turns these into NULL, after trimming whitespace. Case-sensitive. "(null)" is
// not in the docs but the engine does it.
export const SANITIZE_VALUES = new Set(['N/A', 'n/a', 'null', 'nil', '-', '', '(null)']);
// originalData$ is the raw line, and the engine ignores ingestTimeUsec$ (checked in a lab tenant).
const NOT_FIELDS = new Set(['originalData$', 'ingestTimeUsec$']);
// The engine leaves out an enum field set to its zero member, as protobuf does with a default,
// except Auth's logon_type, which it keeps (checked in a lab tenant).
const KEEPS_ZERO = new Set(['scwx.auth:logon_type']);
const U64 = 18446744073709551616;

// SANITIZE_ALL and TRIM_ALL apply to top-level $ fields only, never inside records or lists.
function topLevelString(s, opts, where, notes) {
  let v = s;
  if (opts.trim) {
    const t = trimPairs(v, false);
    const ws = v.replace(/^[ \t\n]+|[ \t\n]+$/g, '');
    if (t !== ws) notes.push({ level: 'warning', code: 'trim-braces', field: where, message: `${where}: TRIM_ALL removed the enclosing ${ws[0]}${ws[ws.length - 1]} from the value. Add !TRIMALLOFF if the field should keep it.` });
    v = t;
  }
  if (opts.sanitize && SANITIZE_VALUES.has(v.trim())) {
    if (v.trim() !== '') notes.push({ level: 'info', code: 'sanitized', field: where, message: `${where}: SANITIZE_ALL turned "${v.trim()}" into NULL` });
    return null;
  }
  return v;
}

// With TRIM_ALL on, a record in a top-level string field has each text member trimmed the way
// TRIM_ALL trims a field: r.c$ = " (y) " is written as "y". So does an object such as a CEF(),
// LEEF(), SPLIT_NAME_VALUES() or URL_PARSE() value, CEF and LEEF header fields included, and an
// object part of a JSON value such as json["$.o"]. A member that is a record, an object or a list,
// or a record inside a list, isn't trimmed (checked in a lab tenant).
function trimMembers(rec, where, notes) {
  let braces = false;
  const trim = ([k, x]) => {
    if (typeof x !== 'string') return [k, x];
    const t = trimPairs(x, false);
    if (t !== x.replace(/^[ \t\n]+|[ \t\n]+$/g, '')) braces = true;
    return [k, t];
  };
  const json = rec instanceof JsonValue;
  const members = json ? Object.entries(rec.value).map(trim) : [...(rec instanceof ObjValue ? rec.map : rec.fields)].map(trim);
  if (braces) notes.push({ level: 'warning', code: 'trim-braces', field: where, message: `${where}: TRIM_ALL removed the enclosing brackets or quotes from text members of the ${rec instanceof RecordValue ? 'record' : 'object'} stored here. Add !TRIMALLOFF if they should keep them.` });
  if (json) return new JsonValue(Object.fromEntries(members));
  return rec instanceof ObjValue ? new ObjValue(new Map(members), rec.header) : new RecordValue(new Map(members));
}

const isJsonObject = (v) => v instanceof JsonValue && !v.doc && v.value !== null && typeof v.value === 'object' && !Array.isArray(v.value);

// Lists into a string field come out comma-joined without quotes. A list inside the list, a JSON
// array part included, is joined the same way in its place, so [["a","<b>"],"c"] gives a,<b>,c
// and [["a"],[],"c"] gives a,,c. A record, an object such as a CEF() value, or an object part of a
// JSON value is written the way STRING() writes it: keys sorted, <, > and & escaped and a NULL
// member as 0. Nothing in a list is trimmed (checked in a lab tenant).
function joinList(list) {
  return list.map(joinItem).join(',');
}

function joinItem(x) {
  if (x === null || x === undefined) return '';
  if (typeof x === 'string') return x;
  if (isList(x)) return joinList(x);
  if (x instanceof JsonValue && !x.doc && Array.isArray(x.value)) return joinList(x.value.map(wrapJson));
  if (x instanceof RecordValue || x instanceof ObjValue || isJsonObject(x)) return stringOf(x);
  return toStr(x);
}

// A number is written the way the engine writes a float as text (see goFloatText). The value
// JSON() returned is written as {} whatever it holds, and an object, such as a CEF() value, a
// part of a JSON value or a record, as STRING() writes it: keys sorted, <, > and & escaped and a
// NULL member as 0 (checked in a lab tenant).
function asString(v, where, notes, opts, top) {
  if (typeof v === 'string') return top ? topLevelString(v, opts, where, notes) : v;
  if (typeof v === 'number' || typeof v === 'boolean') return toStr(v);
  // A DATETIME value in a top-level string field, alone or in a list, fails the whole parser in
  // the engine with "cannot convert time to string", so Run Test returns no events at all
  // (checked in a lab tenant).
  if (v instanceof TimeValue && (top || opts.topList)) throw new RuntimeError(`Field ${where}: cannot convert time to string. The engine fails the whole parser on this, not just the event. Use STRING() on the DATETIME value first.`, 'time-string');
  if (v instanceof TimeValue) {
    notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: a DATETIME value in a string field comes out in Go's time format` });
    return toStr(v);
  }
  if (v instanceof JsonValue && v.doc) return '{}';
  if ((v instanceof RecordValue || v instanceof ObjValue || isJsonObject(v)) && top && opts.trim) return stringOf(trimMembers(v, where, notes));
  if (isList(v)) return joinList(v);
  if (v instanceof JsonValue && Array.isArray(v.value)) return joinList(v.value.map(wrapJson));
  if (v instanceof JsonValue || v instanceof ObjValue || v instanceof RecordValue) return stringOf(v);
  return toStr(v);
}

// Strings into integer fields: the engine keeps the digits, "-" and ".", reads that as a
// number and drops the fraction. Nothing left means the field stays unset; a lone "-" fails
// the event. Negative values wrap in unsigned fields and big values wrap in 32-bit ones.
function asInt(v, type, where, notes, opts, top) {
  let n = v;
  if (v instanceof TimeValue) n = v.usec;
  if (typeof v === 'boolean') n = v ? 1 : 0;
  if (typeof v === 'string') {
    const s = top ? topLevelString(v, opts, where, notes) : v;
    if (s === null) return null;
    const kept = s.replace(/[^0-9.-]/g, '');
    if (kept === '') {
      if (s.trim()) notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: "${s}" has no digits, so the engine leaves this ${type} field unset` });
      return null;
    }
    const f = Number.parseFloat(kept);
    if (Number.isNaN(f)) throw new RuntimeError(`Field ${where}: strconv.ParseFloat: parsing "${kept}": invalid syntax`, 'int-parse');
    if (kept !== s.trim() || !/^-?\d+$/.test(kept)) notes.push({ level: 'warning', code: 'int-from-string', field: where, message: `${where}: the engine reads "${s}" as ${Math.trunc(f)}. Clean the value or use INT(value, 10).` });
    n = f;
  }
  if (typeof n !== 'number' || Number.isNaN(n)) {
    notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} field set to ${JSON.stringify(toPlain(v))}` });
    return undefined;
  }
  n = Math.trunc(n);
  if (type === 'uint32') {
    const w = ((n % 4294967296) + 4294967296) % 4294967296;
    if (w !== n) notes.push({ level: 'error', code: 'wrap', field: where, message: `${where}: ${n} doesn't fit a uint32 field; the engine stores ${w}` });
    return w;
  }
  if (type === 'int32' || type === 'sint32') {
    const w = Number(BigInt.asIntN(32, BigInt(n)));
    if (w !== n) notes.push({ level: 'error', code: 'wrap', field: where, message: `${where}: ${n} doesn't fit a ${type} field; the engine stores ${w}` });
    return w;
  }
  if (type === 'uint64' && n < 0) {
    notes.push({ level: 'error', code: 'wrap', field: where, message: `${where}: ${n} is negative in a uint64 field, so the engine stores a huge number (2^64 ${n})` });
    return U64 + n;
  }
  return n;
}

// Strings into bool fields: "false" in any case is false, any other non-empty string is true.
function asBool(v, where, notes, opts, top) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') {
    const s = top ? topLevelString(v, opts, where, notes) : v;
    if (s === null || s.trim() === '') return null;
    const b = s.trim().toLowerCase() !== 'false';
    if (!/^(true|false)$/i.test(s.trim())) notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: the engine reads "${s}" as ${b}; only "false" is false` });
    return b;
  }
  notes.push({ level: 'error', code: 'type', field: where, message: `${where}: bool field set to ${JSON.stringify(toPlain(v))}` });
  return undefined;
}

function asFloat(v, type, where, notes, opts, top) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const s = top ? topLevelString(v, opts, where, notes) : v;
    if (s === null) return null;
    const f = Number.parseFloat(s.replace(/[^0-9.eE+-]/g, ''));
    if (!Number.isNaN(f)) return f;
  }
  notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} field set to ${JSON.stringify(toPlain(v))}` });
  return undefined;
}

// Enum fields take a name in any case, a number, or a digit string, after trimming. Anything
// else fails the event. Stored records show the name.
function asEnum(v, type, where, notes, opts, top, parserField) {
  const members = enumMembers(type);
  const numbers = enumNumbers(type);
  let s = v;
  if (typeof s === 'string') {
    s = top ? topLevelString(s, opts, where, notes) : s;
    if (s === null) return null;
    s = s.trim();
    const hit = members.find((m) => m.toLowerCase() === s.toLowerCase());
    if (hit) {
      if (hit !== s) notes.push({ level: 'info', code: 'enum-case', field: where, message: `${where}: "${s}" is stored as ${hit}` });
      return hit;
    }
    if (/^\d+$/.test(s) && numbers[s]) return numbers[s];
  }
  if (typeof s === 'number' && Number.isInteger(s) && numbers[String(s)]) return numbers[String(s)];
  if (typeof s === 'boolean') s = String(s);
  throw new RuntimeError(`Field ${parserField} value ${JSON.stringify(toPlain(v))}: not a ${type} name or number (${members.join(', ')}). The engine fails the event.`, 'enum');
}

// An object such as a CEF() value with sub-fields set on it, as in c.key$ = "k", works like a
// record: the engine stores the sub-fields and drops its other keys (checked in a lab tenant).
function asMessage(v, type, where, notes, opts, parserField) {
  const def = messageType(type);
  const members = v instanceof RecordValue ? v.fields : v instanceof ObjValue ? v.map : null;
  if (!members) {
    notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} needs sub-fields set one by one (for example ${parserField}.<sub>$ = ...)` });
    return undefined;
  }
  if (!def) {
    notes.push({ level: 'info', code: 'opaque-type', field: where, message: `${where}: the ${type} type isn't published, so its sub-fields aren't checked` });
    return Object.fromEntries([...members].map(([k, x]) => [k.replace(/\$$/, ''), toPlain(x)]));
  }
  const out = {};
  let stopped = false;
  for (const [k, x] of members) {
    const sub = def.find((f) => f.parser === k);
    if (!sub) {
      notes.push({ level: 'warning', code: 'sub-field', field: where, message: `${where}.${k} is not a field of ${type} (fields: ${def.map((f) => f.parser).join(', ')}). The engine drops it.` });
      continue;
    }
    // An event_metadata key or value set to a DATETIME value, alone or in a list, stops the
    // engine reading that record: the member is unset, and so is a member set after it. The
    // record stays in the list, empty if nothing came before (checked in a lab tenant; once in
    // nine runs the engine also dropped the member set before it).
    if (type === 'KeyValueRecordIndexed' && (x instanceof TimeValue || (isList(x) && x.some((i) => i instanceof TimeValue)))) {
      notes.push({ level: 'warning', code: 'time-in-record', field: `${where}.${sub.name}`, message: `${where}.${sub.name}: the engine leaves a DATETIME value in a record unset, and the record's members set after it too. Use STRING() on it to store the time as text.` });
      stopped = true;
      break;
    }
    const val = coerce(x, sub, `${where}.${sub.name}`, notes, opts, false, `${parserField}.${k}`);
    if (val !== undefined && val !== null && !(typeof val === 'string' && val === '')) out[sub.name] = val;
  }
  return Object.keys(out).length || stopped ? out : null;
}

export function coerce(v, field, where, notes, opts, top = true, parserField = field.parser) {
  if (v === null || v === undefined) return null;
  if (v instanceof MatchValue) throw new RuntimeError(`Field ${parserField}: cannot convert regex to string; index the capture, for example m[1]`, 'regex-compare');
  if (field.repeated) {
    let list = v;
    if (v instanceof JsonValue && Array.isArray(v.value)) list = v.value.map((x) => (x !== null && typeof x === 'object' ? new JsonValue(x) : x));
    // A single value goes through SANITIZE_ALL and TRIM_ALL like any top-level field, so
    // fromEmailAddress$ = "" stores nothing. The items of a list don't (checked in a lab tenant).
    const single = !isList(list);
    if (single) {
      notes.push({ level: 'info', code: 'repeated-single', field: where, message: `${where}: a single value in a repeated field becomes a list of one` });
      list = [list];
    }
    const items = [];
    const itemOpts = top && !single ? { ...opts, topList: true } : opts;
    list.forEach((x, i) => {
      const val = coerce(x, { ...field, repeated: false }, `${where}[${i}]`, notes, itemOpts, top && single, parserField);
      if (val !== undefined && val !== null) items.push(val);
    });
    return items.length ? items : null;
  }
  const kind = typeKind(field.type);
  if (kind === 'enum') return asEnum(v, field.type, where, notes, opts, top, parserField);
  if (kind === 'message' || kind === 'opaque') return asMessage(v, field.type, where, notes, opts, parserField);
  if (INT_TYPES.has(field.type)) return asInt(v, field.type, where, notes, opts, top);
  if (field.type === 'bool') return asBool(v, where, notes, opts, top);
  if (field.type === 'float' || field.type === 'double') return asFloat(v, field.type, where, notes, opts, top);
  return asString(v, where, notes, opts, top);
}

// In the Auth schema the engine stores an event_metadata value that is an Auth0 log type code as
// the code's description, whatever the key (see auth0-log-types.js).
function auth0Codes(val, notes) {
  if (!val || !Array.isArray(val.record)) return;
  val.record.forEach((r, i) => {
    const code = typeof r.value === 'string' ? r.value.toLowerCase() : null;
    if (code === null || !hasOwn(AUTH0_LOG_TYPES, code)) return;
    notes.push({ level: 'warning', code: 'auth0-code', field: `event_metadata.record[${i}].value`, message: `event_metadata.record[${i}].value: the Auth schema reads "${r.value}" as an Auth0 log type code, so the engine stores "${AUTH0_LOG_TYPES[code]}" instead` });
    r.value = AUTH0_LOG_TYPES[code];
  });
}

// vars: Map of every variable after the parser ran. Returns {record, notes}.
export function normalize(vars, schemaId, opts = {}) {
  const info = schemaInfo(schemaId);
  const fields = fieldsByParser(schemaId);
  const notes = [];
  const record = {};
  const o = { sanitize: opts.sanitize !== false, trim: opts.trim !== false };
  for (const [name, value] of vars) {
    if (!name.endsWith('$') || NOT_FIELDS.has(name)) continue;
    const field = fields.get(name);
    if (!field) {
      if (opts.carriers && opts.carriers.has(name)) continue;
      notes.push({ level: 'warning', code: 'not-a-field', field: name, message: `${name} isn't in the documented ${info.name} field table, so the emulator drops it. The engine's schemas have more fields than the docs list, so Run Test may still store it.` });
      continue;
    }
    const val = coerce(value, field, field.name, notes, o);
    if (schemaId === 'scwx.auth' && field.name === 'event_metadata') auth0Codes(val, notes);
    // "" is the protobuf default, so it isn't stored.
    if (val === undefined || val === null || val === '') continue;
    if (!field.repeated && typeKind(field.type) === 'enum' && enumNumbers(field.type)['0'] === val && !KEEPS_ZERO.has(`${schemaId}:${field.name}`)) {
      notes.push({ level: 'info', code: 'enum-zero', field: field.name, message: `${field.name}: ${val} is the zero value of ${field.type}, so the engine leaves the field out` });
      continue;
    }
    record[field.name] = val;
  }
  return { record, notes };
}
