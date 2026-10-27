// Turns the sample analysis into an editable plan (parser shape, schemas, mappings), and the
// plan into parser scripts.

import { analyseSample, shapeOf, timeLayout, patternFields } from '../core/detect.js';
import { suggestMappings, pickSchema, makeMapping } from '../core/mapping.js';
import { generateParsers, baseName, childName } from '../core/generate.js';
import { hasEventMetadata, GENERIC } from '../core/schemas.js';

export function analyse(lines) {
  return analyseSample(lines);
}

// Key stats restricted to some lines.
export function keysFor(analysis, lineIdx) {
  const keys = new Map();
  for (const i of lineIdx) {
    const e = analysis.events[i];
    if (!e) continue;
    for (const f of e.fields) {
      if (!keys.has(f.key)) keys.set(f.key, { key: f.key, path: f.path, index: f.index, header: f.header, label: f.label, values: [], lines: 0 });
      const k = keys.get(f.key);
      k.values.push(f.value);
      k.lines++;
    }
  }
  for (const k of keys.values()) {
    const shapes = {};
    for (const v of k.values) { const s = shapeOf(k.key, v); if (s !== 'empty') shapes[s] = (shapes[s] || 0) + 1; }
    k.shape = Object.entries(shapes).sort((a, b) => b[1] - a[1])[0]?.[0] || 'empty';
    if (k.shape === 'time') k.layout = timeLayout(String(k.values.find((v) => v !== '' && v !== null)));
  }
  return [...keys.values()];
}

function extractFor(analysis) {
  const x = {};
  if (analysis.format === 'json') x.jsonAtEnd = analysis.events.some((e) => e.jsonAtEnd);
  if (analysis.format === 'kv') {
    // The parser cuts each line at its first key, so text in front of it doesn't join that key.
    const first = [...new Set(analysis.events.filter((e) => e.kv && e.fields[0]).map((e) => e.fields[0].key))];
    const kv = analysis.events.find((e) => e.kv);
    Object.assign(x, kv ? kv.kv : { delim: ' ', sep: '=' });
    if (first.length === 1) x.firstKey = first[0];
    else if (first.length > 1) x.firstKeys = first;
  }
  if (analysis.format === 'text' && analysis.template) x.pattern = analysis.template;
  if (analysis.format === 'csv') {
    const c = analysis.events.find((e) => e.csv);
    x.delim = c ? c.csv.delim : ',';
  }
  return x;
}

function joinDateTime(mappings, keys) {
  const date = keys.find((k) => k.key.toLowerCase() === 'date');
  const time = keys.find((k) => k.key.toLowerCase() === 'time');
  if (!date || !time) return mappings;
  const out = mappings.filter((m) => m.field !== 'eventTimeUsec$');
  const sampleD = String(date.values[0] ?? ''), sampleT = String(time.values[0] ?? '');
  const layout = timeLayout(`${sampleD} ${sampleT}`) || '2006-01-02 15:04:05';
  out.push({ key: date.key, path: date.path, index: date.index, field: 'eventTimeUsec$', origin: 'shape', transform: { kind: 'datetime', layout, join: time.key } });
  return out;
}

export function makeUnit(analysis, { eventType = null, lines, schema = null, taken, base }) {
  const keys = keysFor(analysis, lines);
  const sid = schema || pickSchema(keys, eventType ?? '', { child: eventType !== null, extraText: analysis.hintText || '' });
  const mappings = sid === GENERIC ? [] : joinDateTime(suggestMappings(keys.filter((k) => !analysis.split || k.key !== analysis.split.key), sid), keys);
  return {
    eventType, lines, keys, schema: sid, mappings, constants: [],
    metadata: sid !== GENERIC && hasEventMetadata(sid),
    name: eventType === null ? `${base}_STANDALONE_${sid.split('.')[1].toUpperCase()}` : sid === GENERIC ? `${base}_CHILD_GENERIC` : childName(base, sid, eventType, taken),
  };
}

// source: {vendor, product, version, shipMethod}
export function buildPlan(analysis, source) {
  const base = baseName(source.vendor || analysis.vendor, source.product || analysis.product, analysis.format);
  const plan = {
    vendor: source.vendor || analysis.vendor || '',
    product: source.product || analysis.product || '',
    version: source.version || '',
    shipMethod: source.shipMethod || 'syslog',
    format: analysis.format,
    sensorType: [source.product || analysis.product || source.vendor || analysis.vendor].filter(Boolean).join(' ').slice(0, 60),
    baseName: base,
    parentName: `${base}_PARENT`,
    confirm: { ...analysis.confirm },
    extract: extractFor(analysis),
    split: analysis.split ? { key: analysis.split.key, path: analysis.split.path, index: analysis.split.index } : null,
    keys: analysis.keys,
    units: [],
  };
  const taken = new Set([plan.parentName]);
  if (analysis.split && analysis.types.length > 1) {
    for (const t of analysis.types) {
      const lines = analysis.events.map((e, i) => [e, i]).filter(([e]) => e.fields.some((f) => f.key === analysis.split.key && f.value === t)).map(([, i]) => i);
      plan.units.push(makeUnit(analysis, { eventType: t, lines, taken, base }));
    }
  } else {
    plan.split = null;
    plan.units.push(makeUnit(analysis, { lines: analysis.events.map((_, i) => i), taken, base }));
  }
  return plan;
}

export function setUnitSchema(plan, analysis, unit, schema) {
  const taken = new Set([plan.parentName, ...plan.units.filter((u) => u !== unit).map((u) => u.name)]);
  const fresh = makeUnit(analysis, { eventType: unit.eventType, lines: unit.lines, schema, taken, base: plan.baseName });
  Object.assign(unit, { schema: fresh.schema, mappings: fresh.mappings, metadata: fresh.metadata, name: unit.eventType === null ? fresh.name : fresh.name, constants: [] });
}

export function renameAll(plan) {
  const taken = new Set();
  plan.baseName = baseName(plan.vendor, plan.product, plan.format);
  plan.parentName = `${plan.baseName}_PARENT`;
  taken.add(plan.parentName);
  for (const u of plan.units) {
    u.name = u.eventType === null ? `${plan.baseName}_STANDALONE_${(u.schema || GENERIC).split('.')[1].toUpperCase()}` : childName(plan.baseName, u.schema, u.eventType, taken);
  }
}

export function remap(unit, key, field) {
  const k = unit.keys.find((x) => x.key === key);
  if (!k) return null;
  return makeMapping(k, field, unit.schema, 'you');
}

export function writeParsers(plan, lines) {
  const active = { ...plan, units: plan.units.filter((u) => u.schema && u.schema !== GENERIC) };
  if (!active.units.length) active.units = [{ ...plan.units[0], schema: GENERIC }];
  // Constants go in as fixed-value mappings.
  active.units = active.units.map((u) => ({
    ...u,
    mappings: [...(u.constants || []).filter((c) => c.field && c.value !== '').map((c) => ({ key: c.field, field: c.field, transform: { kind: 'const', value: c.value }, origin: 'you' })), ...u.mappings],
  }));
  if (plan.split && plan.units.length > 1) active.forceParent = true;
  return generateParsers(active, lines);
}

// A new capture pattern for plain-text sources: re-read every line's fields and suggest
// mappings again for groups that are new.
export function setPattern(plan, analysis, pattern) {
  plan.extract.pattern = pattern;
  for (const e of analysis.events) e.fields = patternFields(e.line, pattern) || [];
  for (const u of plan.units) {
    const before = new Map(u.mappings.map((m) => [m.key, m]));
    u.keys = keysFor(analysis, u.lines);
    const fresh = u.schema === GENERIC ? [] : suggestMappings(u.keys, u.schema);
    u.mappings = u.keys.flatMap((k) => (before.has(k.key) ? u.mappings.filter((m) => m.key === k.key) : fresh.filter((m) => m.key === k.key)));
  }
  plan.keys = keysFor(analysis, analysis.events.map((_, i) => i));
}

export function patternMatches(analysis, pattern) {
  return analysis.events.filter((e) => patternFields(e.line, pattern)).length;
}
