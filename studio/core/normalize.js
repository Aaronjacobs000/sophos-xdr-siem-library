// Turns the $ fields a parser set into a normalized record for its schema.
// Field names, types and enum names come from the schema pages. How values are coerced
// into each type is our reading of the docs; notes say where the emulator had to guess.

import { JsonValue, ObjValue, RecordValue, TimeValue, MatchValue, toStr, toPlain, isList } from './values.js';
import { fieldsByParser, schemaInfo, typeKind, enumMembers, messageType, INT_TYPES } from './schemas.js';

export const SANITIZE_VALUES = new Set([' ', 'N/A', 'n/a', 'null', 'nil', '-', '']);
const NOT_FIELDS = new Set(['originalData$']);

function cleanString(v, opts, where, notes) {
  let s = v;
  if (opts.sanitize && SANITIZE_VALUES.has(s)) {
    if (s !== '') notes.push({ level: 'info', code: 'sanitized', field: where, message: `${where}: SANITIZE_ALL turned "${s}" into NULL` });
    return null;
  }
  if (opts.trim) {
    const t = s.replace(/^\s+|\s+$/g, '');
    // The statements section of the docs says TRIM_ALL also removes leading and trailing
    // braces and brackets, which is why JSON parents use !TRIMALLOFF.
    const b = t.replace(/^[{}[\]]+|[{}[\]]+$/g, '');
    if (b !== t) notes.push({ level: 'warning', code: 'trim-braces', field: where, message: `${where}: TRIM_ALL removed braces from the value. Add !TRIMALLOFF if this field should keep JSON.` });
    s = b;
  }
  if (opts.sanitize && SANITIZE_VALUES.has(s)) return null;
  return s;
}

// List into a string field: the docs show a JSONPath list assigned to OUTPUT$ coming out as
// "Nigel Rees","Evelyn Waugh",... so the emulator joins quoted items with commas.
function listToString(list) {
  return list.map((x) => JSON.stringify(typeof x === 'string' ? x : toStr(x))).join(',');
}

function scalar(v, type, where, notes, opts) {
  if (v instanceof MatchValue) {
    notes.push({ level: 'error', code: 'type', field: where, message: `${where}: a regex match is not a value; index it, for example m[1]` });
    return undefined;
  }
  if (v instanceof RecordValue) {
    notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} field set to an object with sub-fields` });
    return undefined;
  }
  if (type === 'string' || type === 'bytes') {
    if (typeof v === 'string') return cleanString(v, opts, where, notes);
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (v instanceof TimeValue) {
      notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: a DATETIME value in a string field comes out in Go's time format` });
      return toStr(v);
    }
    if (isList(v)) return cleanString(listToString(v), opts, where, notes);
    if (v instanceof JsonValue && Array.isArray(v.value)) return cleanString(listToString(v.value), opts, where, notes);
    if (v instanceof JsonValue || v instanceof ObjValue) {
      notes.push({ level: 'info', code: 'type', field: where, message: `${where}: an object in a string field is stored as JSON text` });
      return cleanString(JSON.stringify(toPlain(v)), opts, where, notes);
    }
    return toStr(v);
  }
  if (type === 'bool') {
    if (typeof v === 'boolean') return v;
    if (typeof v === 'string') {
      const s = cleanString(v, opts, where, notes);
      if (s === null) return null;
      if (/^(true|false)$/i.test(s)) {
        notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: the string "${s}" in a bool field. Compare it instead, for example x == "true".` });
        return s.toLowerCase() === 'true';
      }
    }
    notes.push({ level: 'error', code: 'type', field: where, message: `${where}: bool field set to ${JSON.stringify(toPlain(v))}` });
    return undefined;
  }
  if (INT_TYPES.has(type)) {
    if (v instanceof TimeValue) return v.usec;
    let n = v;
    if (typeof v === 'string') {
      const s = cleanString(v, opts, where, notes);
      if (s === null) return null;
      if (!/^-?\d+$/.test(s)) {
        notes.push({ level: 'error', code: 'type', field: where, message: `${where}: "${s}" is not a whole number for a ${type} field` });
        return undefined;
      }
      notes.push({ level: 'warning', code: 'int-from-string', field: where, message: `${where}: the string "${s}" in a ${type} field. Wrap it in INT(value, 10).` });
      n = Number(s);
    }
    if (typeof n === 'boolean') n = n ? 1 : 0;
    if (typeof n !== 'number' || Number.isNaN(n)) {
      notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} field set to ${JSON.stringify(toPlain(v))}` });
      return undefined;
    }
    if (!Number.isInteger(n)) {
      notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: ${n} has a fraction; a ${type} field keeps the whole number` });
      n = Math.trunc(n);
    }
    if (type.startsWith('uint') && n < 0) notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${n} is negative in an unsigned ${type} field` });
    if (type.endsWith('32') && Math.abs(n) > 4294967295) notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${n} does not fit a ${type} field` });
    return n;
  }
  if (type === 'float' || type === 'double') {
    if (typeof v === 'number') return v;
    if (typeof v === 'string') {
      const s = cleanString(v, opts, where, notes);
      if (s === null) return null;
      if (/^-?\d+(\.\d+)?([eE][-+]?\d+)?$/.test(s)) {
        notes.push({ level: 'warning', code: 'type', field: where, message: `${where}: the string "${s}" in a ${type} field` });
        return Number(s);
      }
    }
    notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} field set to ${JSON.stringify(toPlain(v))}` });
    return undefined;
  }
  return toPlain(v);
}

function enumValue(v, type, where, notes, opts) {
  const members = enumMembers(type);
  let s = v;
  if (typeof s === 'string') s = cleanString(s, opts, where, notes);
  if (s === null) return null;
  if (typeof s === 'string') {
    if (members.includes(s)) return s;
    const hint = members.find((m) => m.toLowerCase() === s.toLowerCase());
    notes.push({ level: 'error', code: 'enum', field: where, message: `${where}: "${s}" is not a ${type} name${hint ? `; did you mean "${hint}"?` : `. Use one of ${members.join(', ')}.`}` });
    return s;
  }
  if (typeof s === 'number') {
    notes.push({ level: 'warning', code: 'enum-number', field: where, message: `${where}: ${type} set by number. The docs never show this; assign the enum name.` });
    return s;
  }
  notes.push({ level: 'error', code: 'enum', field: where, message: `${where}: ${type} field set to ${JSON.stringify(toPlain(v))}` });
  return undefined;
}

function message(v, type, where, notes, opts) {
  const def = messageType(type);
  if (!(v instanceof RecordValue)) {
    if (v instanceof JsonValue || v instanceof ObjValue) {
      notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} needs sub-fields set one by one (for example ${where}.<sub>$ = ...), not a whole object` });
    } else {
      notes.push({ level: 'error', code: 'type', field: where, message: `${where}: ${type} field set to ${JSON.stringify(toPlain(v))}; set its sub-fields instead` });
    }
    return undefined;
  }
  if (!def) {
    notes.push({ level: 'info', code: 'opaque-type', field: where, message: `${where}: the ${type} type isn't published, so its sub-fields aren't checked` });
    return Object.fromEntries([...v.fields].map(([k, x]) => [k.replace(/\$$/, ''), toPlain(x)]));
  }
  const out = {};
  for (const [k, x] of v.fields) {
    const sub = def.find((f) => f.parser === k);
    if (!sub) {
      notes.push({ level: 'error', code: 'sub-field', field: where, message: `${where}.${k} is not a field of ${type} (fields: ${def.map((f) => f.parser).join(', ')}). The engine drops it.` });
      continue;
    }
    const val = coerce(x, sub, `${where}.${sub.name}`, notes, opts);
    if (val !== undefined && val !== null) out[sub.name] = val;
  }
  return Object.keys(out).length ? out : null;
}

export function coerce(v, field, where, notes, opts) {
  if (v === null || v === undefined) return null;
  if (field.repeated) {
    let list = v;
    if (v instanceof JsonValue && Array.isArray(v.value)) list = v.value.map((x) => (x !== null && typeof x === 'object' ? new JsonValue(x) : x));
    if (!isList(list)) {
      notes.push({ level: 'info', code: 'repeated-single', field: where, message: `${where}: a single value in a repeated field becomes a list of one` });
      list = [list];
    }
    const items = [];
    list.forEach((x, i) => {
      const val = coerce(x, { ...field, repeated: false }, `${where}[${i}]`, notes, opts);
      if (val !== undefined && val !== null) items.push(val);
    });
    return items.length ? items : null;
  }
  const kind = typeKind(field.type);
  if (kind === 'enum') return enumValue(v, field.type, where, notes, opts);
  if (kind === 'message' || kind === 'opaque') return message(v, field.type, where, notes, opts);
  return scalar(v, field.type, where, notes, opts);
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
      notes.push({ level: 'warning', code: 'not-a-field', field: name, message: `${name} is not a parser field of the ${info.name} schema. The engine drops it without an error.` });
      continue;
    }
    if (field.derived) notes.push({ level: 'warning', code: 'undocumented-parser-field', field: name, message: `${name}: the ${info.name} schema page gives no parser field for ${field.name}; ${name} is the emulator's guess` });
    const val = coerce(value, field, field.name, notes, o);
    if (val === undefined || val === null) continue;
    record[field.name] = val;
  }
  return { record, notes };
}
