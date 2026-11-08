// Compares real parsed records, read from a tenant with a QL search, with a library entry:
// first with the fields its expected.json sets, then value by value with what the emulator makes
// of each record's raw line (original_data). No network here, so the tests can cover all of it.
//
// What real records look like (measured on lab tenants, 08/11/2026):
// - normalizer_revision is the parser path, such as "Master -> PARENT -> CHILD". Custom parsers
//   appear under their own names. sensor_type is whatever the parser set, and a built-in parser
//   can set the same one, so the search filters on normalizer_revision.
// - original_data is the raw line the parsers saw.
// - Every field of the schema comes back: unset strings as "", numbers as 0, booleans as false,
//   messages as null and enums as their zero member, by name. So a field counts as set in a real
//   record only when it holds something else.
// - Sophos Fusion adds fields after parsing (enrichSummary, normalizer, ingest, visibility and
//   others), and the schema's own tenant, resource and ingest fields.

import { runParsers } from '../../studio/core/engine.js';
import { schemaInfo, typeKind, enumNumbers, messageType, GENERIC } from '../../studio/core/schemas.js';

// Schema ids as QL names them. Thirdparty is the one whose name differs.
const QL_NAMES = { 'scwx.thirdpartyalert': 'thirdparty' };
export const qlSchema = (id) => QL_NAMES[id] || String(id).replace(/^scwx\./, '');
export const schemaFromQl = (name) => Object.entries(QL_NAMES).find(([, v]) => v === name)?.[0] || `scwx.${name}`;

// Schema fields a parser can't set: the platform fills them in.
export const PLATFORM_FIELDS = new Set(['original_data', 'ingest_time_usec', 'tenant_id', 'sensor_tenant', 'resource_id', 'normalizer', 'normalizer_version', 'normalizer_revision', 'visibility', 'schema_type']);

const quote = (s) => `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

// Every schema the entry's parsers write to, as schema ids.
export function entrySchemas(entry) {
  const out = new Set();
  for (const p of entry.meta.parsers || []) for (const s of String(p.schema || GENERIC).split(',')) if (s.trim()) out.add(s.trim());
  return [...out];
}

export function parserNames(entry) {
  return (entry.meta.parsers || []).map((p) => p.name).filter(Boolean);
}

// The QL search for an entry's records: every schema its parsers write to, and a parser path that
// names one of its parsers. where replaces the parser filter. earliest and latest are QL time
// values: a relative one such as -7d, or an ISO time, which is quoted.
export function buildQuery(entry, { earliest = '-7d', latest = null, where = null } = {}) {
  const from = entrySchemas(entry).map(qlSchema).join(', ');
  const filter = where || parserNames(entry).map((n) => `normalizer_revision contains ${quote(n)}`).join(' or ');
  const time = (k, v) => (v ? ` ${k}=${/^-\d+[smhdw]$/.test(v) || v === 'now' ? v : quote(v)}` : '');
  return `from ${from} where ${filter}${time('earliest', earliest)}${time('latest', latest)}`;
}

// The parser names in a real record's path, and the last one, which made the record.
export function pathOf(row) {
  return String((row && row.normalizer_revision) || '').split(/\s*->\s*/).map((s) => s.trim()).filter(Boolean);
}

// The entry parser that made the record, or null when no parser in its path is the entry's. A
// search with "contains" also finds a longer name that holds an entry parser's name.
export function entryParserOf(row, names) {
  const path = pathOf(row);
  const last = path[path.length - 1];
  return names.includes(last) ? last : null;
}

// ------------------------------------------------------------------ flattening

// A record as path -> value. Nested objects join with dots. A key-value list (objects that each
// have a key, as event_metadata.record and additional_data.record hold) becomes one path per key,
// event_metadata.record[region_code]. Other lists of objects merge their items under [], and a
// list of plain values stays one value.
export function flatten(value, prefix = '', out = new Map()) {
  if (Array.isArray(value)) {
    if (value.length && value.every((x) => x && typeof x === 'object' && !Array.isArray(x) && typeof x.key === 'string')) {
      for (const item of value) {
        const rest = { ...item };
        delete rest.key;
        const p = `${prefix}[${item.key}]`;
        if (Object.keys(rest).length === 1 && 'value' in rest) addLeaf(out, p, rest.value);
        else flatten(rest, p, out);
      }
    } else if (value.length && value.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
      for (const item of value) flatten(item, `${prefix}[]`, out);
    } else {
      addLeaf(out, prefix, value);
    }
    return out;
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (!keys.length && prefix) addLeaf(out, prefix, value);
    for (const k of keys) flatten(value[k], prefix ? `${prefix}.${k}` : k, out);
    return out;
  }
  if (prefix) addLeaf(out, prefix, value);
  return out;
}

// A path that repeats inside a list ([]) keeps every value it takes.
function addLeaf(out, path, v) {
  if (!out.has(path)) out.set(path, v);
  else {
    const cur = out.get(path);
    out.set(path, cur && cur.multi ? { multi: [...cur.multi, v] } : { multi: [cur, v] });
  }
}

const leafValues = (v) => (v && v.multi ? v.multi : [v]);

// ------------------------------------------------------------------ field types

// The schema's definition of a flattened path, walking into message types, or null when the
// schema doesn't list it. A path under a key-value list is a string value.
export function fieldDef(schemaId, path) {
  const info = schemaInfo(schemaId);
  if (!info) return null;
  const parts = path.split('.');
  const top = parts[0].replace(/\[.*$/, '');
  let def = info.fields.find((f) => f.name === top) || null;
  if (!def) return null;
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i];
    if (i > 0) {
      const t = messageType(def.type);
      const name = seg.replace(/\[.*$/, '');
      def = t ? t.find((f) => f.name === name) || null : null;
      if (!def) return null;
    }
    // record[key] holds the value of that key.
    if (/\[[^\]]+\]$/.test(seg)) return { name: path, type: 'string' };
  }
  return def;
}

export const isSchemaField = (schemaId, path) => fieldDef(schemaId, path) !== null;

function zeroEnum(def) {
  if (!def || def.repeated || typeKind(def.type) !== 'enum') return null;
  return enumNumbers(def.type)['0'] ?? null;
}

// The value a real record holds for a field nothing set.
export function isDefault(v, def = null) {
  if (v === null || v === undefined || v === '' || v === false || v === 0) return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === 'object') return v.multi ? v.multi.every((x) => isDefault(x, def)) : Object.keys(v).length === 0;
  if (typeof v === 'string') {
    const zero = zeroEnum(def);
    if (zero !== null) return v === zero;
    // An enum the schema data doesn't know: its zero member is UNKNOWN, UNSET or *_UNKNOWN.
    if (!def) return /^(UNKNOWN|UNSET)(_[A-Z_]+)?$|^[A-Z_]+_UNKNOWN$/.test(v);
  }
  return false;
}

export function shapeOf(v) {
  if (v === null || v === undefined) return 'null';
  if (Array.isArray(v)) return 'list';
  if (v && v.multi) return [...new Set(v.multi.map(shapeOf))].join('|');
  return typeof v;
}

// ------------------------------------------------------------------ field report

// How often each path is set across a set of records, and the shapes it takes.
function fieldStats(records, schemaId, { real }) {
  const stats = new Map();
  for (const rec of records) {
    for (const [path, v] of flatten(rec)) {
      const def = fieldDef(schemaId, path);
      if (real && isDefault(v, def)) {
        if (!stats.has(path)) stats.set(path, { set: 0, defaults: 0, shapes: new Set() });
        stats.get(path).defaults++;
        continue;
      }
      if (!stats.has(path)) stats.set(path, { set: 0, defaults: 0, shapes: new Set() });
      const s = stats.get(path);
      s.set++;
      for (const x of leafValues(v)) s.shapes.add(shapeOf(x));
    }
  }
  return stats;
}

// expected: normalized records from expected.json for one schema (and parser). real: rows from the
// search for the same. Returns the per-field result.
export function compareFields(expected, real, schemaId) {
  const e = fieldStats(expected, schemaId, { real: false });
  const r = fieldStats(real, schemaId, { real: true });
  const out = { schema: schemaId, expectedRecords: expected.length, realRecords: real.length, both: [], realOnly: [], platform: [], expectedOnly: [], mismatches: [], enumForm: [] };
  for (const [path, es] of e) {
    const rs = r.get(path);
    if (rs && rs.set) {
      out.both.push({ path, expected: es.set, real: rs.set });
      const eShapes = [...es.shapes].sort(), rShapes = [...rs.shapes].sort();
      if (eShapes.join() !== rShapes.join()) {
        const def = fieldDef(schemaId, path);
        const item = { path, expected: eShapes.join('|'), real: rShapes.join('|') };
        if (def && typeKind(def.type) === 'enum' && [...eShapes, ...rShapes].includes('number') && [...eShapes, ...rShapes].includes('string')) out.enumForm.push(item);
        else out.mismatches.push(item);
      }
    } else {
      // A field expected.json sets to false or 0 looks the same as unset in a real record.
      const defaultOnly = expected.every((rec) => { const v = flatten(rec).get(path); return v === undefined || isDefault(v, fieldDef(schemaId, path)); });
      out.expectedOnly.push({ path, expected: es.set, realDefaults: rs ? rs.defaults : 0, defaultOnly });
    }
  }
  for (const [path, rs] of r) {
    if (!rs.set || e.has(path)) continue;
    const top = path.replace(/[.[].*$/, '');
    const item = { path, real: rs.set };
    if (PLATFORM_FIELDS.has(top) || !isSchemaField(schemaId, path)) out.platform.push(item);
    else out.realOnly.push(item);
  }
  for (const k of ['both', 'realOnly', 'platform', 'expectedOnly', 'mismatches', 'enumForm']) out[k].sort((a, b) => a.path.localeCompare(b.path));
  return out;
}

// The normalized records expected.json holds for a schema, and for one parser when given: a line's
// own record, and its copies in other schemas (also).
export function expectedRecords(expected, schemaId, parser = null) {
  const out = [];
  for (const r of expected || []) {
    const last = String(r.extractor_path || '').split(' > ').pop();
    if (parser && last !== parser) continue;
    if (r.schema && r.schema.split(',').map((s) => s.trim())[0] === schemaId && r.normalized) out.push(r.normalized);
    for (const a of r.also || []) if (a.schema === schemaId && a.normalized) out.push(a.normalized);
  }
  return out;
}

// Real rows grouped by schema and the entry parser that made them. A row from another parser is
// counted in other and left out, unless anyParser is set (a search with its own where clause):
// then it is grouped by its own parser, marked entryParser false.
export function groupRows(rows, names, { anyParser = false } = {}) {
  const groups = new Map();
  let other = 0;
  for (const row of rows) {
    let parser = entryParserOf(row, names);
    const entryParser = parser !== null;
    if (!parser) {
      if (!anyParser) { other++; continue; }
      parser = pathOf(row).pop() || '(no parser path)';
    }
    const schema = schemaFromQl(row.schema_type);
    const key = `${schema} ${parser}`;
    if (!groups.has(key)) groups.set(key, { schema, parser, entryParser, rows: [] });
    groups.get(key).rows.push(row);
  }
  return { groups: [...groups.values()].sort((a, b) => a.schema.localeCompare(b.schema) || a.parser.localeCompare(b.parser)), other };
}

// ------------------------------------------------------------------ the emulator on real lines

// The emulator's record for a raw line, in the schema the real record is in. now is the real
// record's ingest time, so a line without its own time gets the same one.
export function emulate(entry, row) {
  const usec = Number(row.ingest_time_usec);
  const now = Number.isFinite(usec) && usec > 0 ? new Date(Math.floor(usec / 1000)).toISOString() : entry.meta.reference_time;
  const [res] = runParsers(entry.parsers, [String(row.original_data)], { now });
  const schema = schemaFromQl(row.schema_type);
  const path = res.extractor_path ? res.extractor_path.split(' > ') : [];
  let record = null;
  if (res.normalized && String(res.schema).split(',')[0].trim() === schema) record = res.normalized;
  for (const a of res.also || []) if (a.schema === schema) record = a.normalized;
  return { path, schema: res.schema, record, error: res.error || null };
}

// Two leaf values are the same when they hold the same thing: lists in order, numbers as numbers.
function sameValue(a, b) {
  if (a && a.multi) a = a.multi;
  if (b && b.multi) b = b.multi;
  if (Array.isArray(a) || Array.isArray(b)) {
    const x = Array.isArray(a) ? a : [a], y = Array.isArray(b) ? b : [b];
    return x.length === y.length && x.every((v, i) => sameValue(v, y[i]));
  }
  if (typeof a === 'number' || typeof b === 'number') return Number(a) === Number(b);
  if (a && typeof a === 'object' && b && typeof b === 'object') return JSON.stringify(a) === JSON.stringify(b);
  return a === b;
}

// Compares, field by field, what the emulator makes of each real record's raw line with the real
// record. Returns per-path counts and, for differences, the first pair of values.
export function compareValues(entry, rows, schemaId) {
  const out = { schema: schemaId, records: 0, noRaw: 0, pathSame: 0, pathDiffer: 0, noRecord: 0, paths: new Map(), schemas: new Map(), errorLines: 0, errors: [], fields: new Map() };
  const field = (path) => {
    if (!out.fields.has(path)) out.fields.set(path, { same: 0, differ: 0, emulatorOnly: 0, realOnly: 0, example: null });
    return out.fields.get(path);
  };
  for (const row of rows) {
    if (typeof row.original_data !== 'string' || !row.original_data) { out.noRaw++; continue; }
    out.records++;
    const emu = emulate(entry, row);
    const realPath = pathOf(row);
    const names = parserNames(entry);
    const realEntryPath = realPath.filter((p) => names.includes(p));
    const emuPath = emu.path.join(' > ') || '(no parser matched)';
    out.paths.set(emuPath, (out.paths.get(emuPath) || 0) + 1);
    if (emu.path.join(' > ') === realEntryPath.join(' > ')) out.pathSame++;
    else out.pathDiffer++;
    if (emu.error) out.errorLines++;
    if (emu.error && out.errors.length < 5 && !out.errors.includes(emu.error)) out.errors.push(emu.error);
    if (!emu.record) {
      out.noRecord++;
      out.schemas.set(String(emu.schema), (out.schemas.get(String(emu.schema)) || 0) + 1);
      continue;
    }
    const e = flatten(emu.record);
    const r = flatten(row);
    for (const [path, ev] of e) {
      const rv = r.get(path);
      const f = field(path);
      if (rv === undefined || isDefault(rv, fieldDef(schemaId, path))) {
        if (isDefault(ev, fieldDef(schemaId, path)) && rv !== undefined) f.same++;
        else { f.emulatorOnly++; f.example ??= { emulator: ev, real: rv ?? null }; }
      } else if (sameValue(ev, rv)) f.same++;
      else { f.differ++; f.example ??= { emulator: ev, real: rv }; }
    }
    for (const [path, rv] of r) {
      if (e.has(path) || isDefault(rv, fieldDef(schemaId, path))) continue;
      const top = path.replace(/[.[].*$/, '');
      if (PLATFORM_FIELDS.has(top) || !isSchemaField(schemaId, path)) continue;
      const f = field(path);
      f.realOnly++;
      f.example ??= { emulator: null, real: rv };
    }
  }
  return out;
}

// ------------------------------------------------------------------ text report

const list = (items, fmt) => (items.length ? items.map(fmt).join(', ') : 'none');
const clip = (v) => { const s = JSON.stringify(v && v.multi ? v.multi : v); return s.length > 80 ? `${s.slice(0, 77)}...` : s; };

export function formatFieldReport(f, parser, { entryParser = true } = {}) {
  const n = f.realRecords;
  const of = (k) => (k === n ? '' : ` (${k} of ${n})`);
  const lines = [`${qlSchema(f.schema)} from ${parser}: ${n} real record${n === 1 ? '' : 's'}, ${f.expectedRecords} in expected.json`];
  if (!entryParser) lines.push(`  ${parser} is not one of the entry's parsers, so these are compared with every expected.json record in ${qlSchema(f.schema)}.`);
  if (!f.expectedRecords) lines.push('  expected.json has no record for this parser and schema, so every field below is new to it.');
  lines.push(`  Both set (${f.both.length}): ${list(f.both, (x) => `${x.path}${of(x.real)}`)}`);
  lines.push(`  Real records set, expected.json doesn't (${f.realOnly.length}): ${list(f.realOnly, (x) => `${x.path}${of(x.real)}`)}`);
  lines.push(`  expected.json sets, real records never do (${f.expectedOnly.length}): ${list(f.expectedOnly, (x) => `${x.path}${x.defaultOnly ? ' (expected.json holds false or 0, which looks unset)' : ''}`)}`);
  lines.push(`  Type or shape mismatches (${f.mismatches.length}): ${list(f.mismatches, (x) => `${x.path} expected ${x.expected}, real ${x.real}`)}`);
  lines.push(`  Enum names vs numbers (${f.enumForm.length}): ${list(f.enumForm, (x) => `${x.path} expected ${x.expected}, real ${x.real}`)}`);
  lines.push(`  Added by Sophos Fusion or not in the schema table (${f.platform.length}): ${list(f.platform, (x) => x.path)}`);
  return lines.join('\n');
}

export function formatValueReport(v, { showValues = false, entryParser = true } = {}) {
  const lines = [`  Emulator on the real raw lines: ${v.records} record${v.records === 1 ? '' : 's'}${v.noRaw ? `, ${v.noRaw} without original_data skipped` : ''}`];
  if (!v.records) return lines.join('\n');
  const tally = (m) => [...m].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} (${n})`).join(', ');
  lines.push(`    Emulator parser path: ${tally(v.paths)}${entryParser ? `; ${v.pathSame} the same as the real path, ${v.pathDiffer} different` : ''}`);
  if (v.noRecord) lines.push(`    No record in ${qlSchema(v.schema)} from the emulator for ${v.noRecord}: it used ${tally(new Map([...v.schemas].map(([k, n]) => [k.split(',').map((x) => qlSchema(x.trim())).join(','), n])))}`);
  // An error message can quote a value from the line, so it shows only with the values.
  if (v.errorLines) lines.push(`    Emulator errors on ${v.errorLines} line${v.errorLines === 1 ? '' : 's'}${showValues ? `: ${v.errors.join('; ')}` : ' (--show-values prints them)'}`);
  const rows = [...v.fields].sort((a, b) => a[0].localeCompare(b[0]));
  const pick = (k) => rows.filter(([, f]) => f[k]);
  const show = (path, f) => `${path}${f.example && showValues ? ` (emulator ${clip(f.example.emulator)}, real ${clip(f.example.real)})` : ''}`;
  const same = rows.filter(([, f]) => f.same && !f.differ && !f.emulatorOnly && !f.realOnly);
  const total = (f) => f.same + f.differ + f.emulatorOnly + f.realOnly;
  lines.push(`    Same value in every record (${same.length}): ${list(same, ([p]) => p)}`);
  lines.push(`    Different value (${pick('differ').length}): ${list(pick('differ'), ([p, f]) => `${show(p, f)} ${f.differ} of ${total(f)}`)}`);
  lines.push(`    Emulator sets, real record doesn't (${pick('emulatorOnly').length}): ${list(pick('emulatorOnly'), ([p, f]) => `${show(p, f)} ${f.emulatorOnly} of ${total(f)}`)}`);
  lines.push(`    Real record sets, emulator doesn't (${pick('realOnly').length}): ${list(pick('realOnly'), ([p, f]) => `${show(p, f)} ${f.realOnly} of ${total(f)}`)}`);
  let same2 = 0, all = 0;
  for (const [, f] of rows) { same2 += f.same; all += total(f); }
  lines.push(`    Field values: ${same2} of ${all} the same`);
  return lines.join('\n');
}
