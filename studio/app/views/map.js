import { h, clear, pill, select, ext } from '../dom.js';
import { state } from '../store.js';
import { go } from '../nav.js';
import { steps } from './common.js';
import { setUnitSchema, remap, writeParsers, setPattern, patternMatches } from '../plan.js';
import { schemaInfo, typeKind, enumMembers, messageType, hasEventMetadata, SCHEMA_IDS, GENERIC, INT_TYPES } from '../../core/schemas.js';
import { enumDefault, enumStem, guessEnum } from '../../core/mapping.js';
import { upperSlug } from '../../core/generate.js';

const COMMON = ['sensorType$', 'hostId$', 'eventTimeUsec$', 'sensorEventId$', 'sensorId$', 'sensorVersion$'];
const ORIGIN_KIND = { alias: 'grey', shape: 'grey', enum: 'blue', you: 'amber' };

function fieldOptions(schemaId) {
  const s = schemaInfo(schemaId);
  const all = [];
  for (const f of s.fields) {
    if (f.parser === 'originalData$' || f.parser === 'tenantId$' || f.parser === 'resourceId$' || f.parser === 'ingestTimeUsec$') continue;
    const kind = typeKind(f.type);
    if (kind === 'message' && f.type !== 'KeyValuePairsIndexed' && !f.repeated) {
      for (const sub of messageType(f.type)) {
        if (typeKind(sub.type) === 'message') continue;
        all.push({ value: `${f.parser}.${sub.parser}`, label: `${f.parser}.${sub.parser}  ${sub.type}`, f });
      }
    } else if (kind !== 'message' && kind !== 'opaque') {
      all.push({ value: f.parser, label: `${f.parser}  ${f.repeated ? `${f.type}[]` : f.type}${f.derived ? ' (guess)' : ''}`, f });
    }
  }
  const common = all.filter((o) => COMMON.includes(o.value));
  const rest = all.filter((o) => !COMMON.includes(o.value)).sort((a, b) => a.value.localeCompare(b.value));
  return [{ value: '', label: '(not mapped)' }, { group: 'Common', options: common }, { group: `${s.name} fields`, options: rest }];
}

function fieldType(schemaId, field) {
  const [head, sub] = String(field).split('.');
  const f = schemaInfo(schemaId).fields.find((x) => x.parser === head);
  if (!f) return null;
  if (sub) { const sf = (messageType(f.type) || []).find((x) => x.parser === sub); return sf ? sf.type : null; }
  return f.type;
}

function transformOptions(type, field) {
  if (!type) return [{ value: 'none', label: 'as is' }];
  if (typeKind(type) === 'enum') return [{ value: 'enum', label: 'map to enum names' }];
  if (INT_TYPES.has(type)) {
    const out = [{ value: 'none', label: 'as is (a number)' }, { value: 'int', label: 'INT() a string' }];
    if (/Usec\$$/.test(field)) out.push({ value: 'datetime', label: 'DATETIME() with a layout' }, { value: 'epoch-s', label: 'epoch seconds' }, { value: 'epoch-ms', label: 'epoch milliseconds' });
    if (field === 'protocol$') out.push({ value: 'protocol', label: 'protocol name to number' });
    return out;
  }
  if (type === 'bool') return [{ value: 'bool', label: 'true if "true"' }, { value: 'none', label: 'as is' }];
  return [{ value: 'none', label: 'as is' }, { value: 'lower', label: 'lowercase' }, { value: 'upper', label: 'uppercase' }, { value: 'replace', label: 'replace text' }, { value: 'string', label: 'STRING()' }];
}

export function renderMap(root) {
  const plan = state.plan;
  const mapped = plan.units.reduce((n, u) => n + u.mappings.filter((m) => m.field).length, 0);
  root.append(steps('map', `Rules only · nothing has left this page · ${mapped} fields mapped`));
  const grid = h('div', { class: 'grid g-map' });
  root.append(grid);
  const main = h('section', { class: 'panel' });
  const side = h('aside', { class: 'panel', 'aria-label': 'Enum values' });
  grid.append(main, side);
  draw(main, side);
}

function tabsFor(plan) {
  const tabs = [];
  if (plan.split) tabs.push({ kind: 'parent', label: 'Parent' });
  plan.units.forEach((u, i) => tabs.push({ kind: 'unit', i, label: u.eventType ?? (schemaInfo(u.schema)?.name || u.schema) }));
  return tabs;
}

function draw(main, side) {
  clear(main);
  clear(side);
  const plan = state.plan;
  const tabs = tabsFor(plan);
  if (state.mapTab >= tabs.length) state.mapTab = 0;
  const tab = tabs[state.mapTab];
  const unit = tab.kind === 'unit' ? plan.units[tab.i] : null;

  if (unit) {
    const s = schemaInfo(unit.schema);
    main.append(h('h2', { text: unit.schema === GENERIC ? `${unit.eventType} stays in the generic schema` : `${unit.eventType ?? 'Every line'} to the ${s.name} schema` }));
    const n = unit.mappings.filter((m) => m.field).length;
    const left = unit.keys.filter((k) => !unit.mappings.some((m) => m.key === k.key && m.field) && (!plan.split || k.key !== plan.split.key)).length;
    main.append(h('p', { class: 'sub' }, `${n} keys mapped, ${left} left in original_data. Field names and enum values come from the `, ext(s.page, `${s.name} schema page`), '.'));
  } else {
    main.append(h('h2', { text: 'Parent: recognize the source and split event types' }));
    main.append(h('p', { class: 'sub', text: 'The parent matches every line from this source, parses it once, and hands the result to one child per event type.' }));
  }
  const tabbar = h('div', { class: 'tabs', role: 'tablist' });
  tabs.forEach((t, i) => {
    const u = t.kind === 'unit' ? plan.units[t.i] : null;
    const b = h('button', { class: `tab${i === state.mapTab ? ' on' : ''}`, role: 'tab', 'aria-selected': i === state.mapTab ? 'true' : 'false', onclick: () => { state.mapTab = i; draw(main, side); } }, t.kind === 'parent' ? 'Parent' : `${t.label}`);
    if (u) b.append(u.schema === GENERIC ? pill('generic', 'grey') : pill(`${u.mappings.filter((m) => m.field).length} mapped`, 'green'));
    tabbar.append(b);
  });
  main.append(tabbar);
  if (!unit) drawParent(main, side);
  else drawUnit(main, side, unit);

  main.append(h('div', { class: 'actions' },
    h('button', { class: 'btn quiet', onclick: () => go('#/build/sample'), text: 'Back to the sample' }),
    h('span', { class: 'note', text: 'Every mapping becomes a line of parser script you can edit on the next step.' }),
    h('button', { class: 'btn primary', onclick: write, text: 'Write parsers and run samples' })));
}

function write() {
  if (state.edited && !confirm('You edited the parser scripts by hand. Writing them again from the map replaces those edits. Continue?')) return;
  state.parsers = writeParsers(state.plan, state.lines);
  state.edited = false;
  state.testTab = state.parsers.length > 1 ? 1 : 0;
  state.selectedLine = 0;
  go('#/build/test');
}

function drawParent(main, side) {
  const plan = state.plan;
  const box = h('div');
  box.style.marginTop = '14px';
  const names = h('div', { class: 'fields' },
    h('div', { class: 'field' }, h('label', { text: 'Parser name prefix', for: 'base' }), h('input', { class: 'input mono', id: 'base', value: plan.baseName, oninput: (e) => { plan.baseName = upperSlug(e.target.value) || plan.baseName; plan.parentName = `${plan.baseName}_PARENT`; const t = new Set([plan.parentName]); for (const u of plan.units) { renameUnit(plan, u, t); } } })),
    h('div', { class: 'field' }, h('label', { text: 'sensor_type (sensorType$)', for: 'stype' }), h('input', { class: 'input', id: 'stype', value: plan.sensorType, oninput: (e) => { plan.sensorType = e.target.value; } })));
  box.append(names);
  const dl = h('dl', { class: 'kv' });
  dl.style.marginTop = '14px';
  dl.append(h('dt', { text: 'Confirm with' }), h('dd', { class: 'mono', text: `${plan.confirm.kind}: ${plan.confirm.text}` }));
  dl.append(h('dt', { text: 'Reads the line' }), h('dd', { text: { json: plan.extract.jsonAtEnd ? 'Cuts the JSON object off the end of the line with a capture, then JSON()' : 'JSON(originalData$)', cef: 'CEF(originalData$)', leef: plan.extract.leefPipes ? 'LEEF(originalData$), with | as the delimiter on lines with | between their pairs' : 'LEEF(originalData$)', kv: 'SPLIT_NAME_VALUES() on the key=value part', csv: 'SPLIT() on the delimiter', text: 'Capture patterns you write', xml: 'Capture patterns you write' }[plan.format] || plan.format }));
  dl.append(h('dt', { text: 'Splits on' }), h('dd', {}, plan.split ? h('span', { class: 'mono', text: `eventType$ = ${plan.split.path || plan.split.key}` }) : 'nothing (standalone)'));
  box.append(dl);
  if (plan.format === 'kv') {
    const kv = h('div', { class: 'fields three' },
      h('div', { class: 'field' }, h('label', { text: 'Pair delimiter' }), h('input', { class: 'input mono', value: plan.extract.delim === ' ' ? '(space)' : plan.extract.delim, oninput: (e) => { plan.extract.delim = e.target.value === '(space)' ? ' ' : e.target.value; } })),
      h('div', { class: 'field' }, h('label', { text: 'Key/value separator' }), h('input', { class: 'input mono', value: plan.extract.sep, oninput: (e) => { plan.extract.sep = e.target.value; } })),
      h('div', { class: 'field' }, h('label', { text: 'First key' }), h('input', { class: 'input mono', value: plan.extract.firstKey || '', placeholder: (plan.extract.firstKeys || []).join(' or '), oninput: (e) => { plan.extract.firstKey = e.target.value || null; } })));
    kv.style.marginTop = '12px';
    box.append(kv);
  }
  main.append(box);
  main.append(h('h3', { text: 'Children' }));
  const list = h('div', { class: 'tree' });
  for (const u of plan.units) list.append(h('div', { class: 'row' }, h('span', { class: 'name', text: u.schema === GENERIC ? '(no child)' : u.name }), pill(u.schema, u.schema === GENERIC ? 'grey' : 'blue'), h('span', { class: 'why', text: `eventType$ == "${u.eventType}"` })));
  main.append(list);
  side.append(h('h2', { text: 'Enum values' }), h('p', { class: 'sub', text: 'Open a child tab to map source values to enum names.' }));
}

function renameUnit(plan, u, taken) {
  const s = (schemaInfo(u.schema)?.name || 'GENERIC').toUpperCase();
  let name = u.eventType === null ? `${plan.baseName}_STANDALONE_${s}` : `${plan.baseName}_CHILD_${s}`;
  while (taken.has(name)) name += '_2';
  taken.add(name);
  u.name = name;
}

function drawUnit(main, side, unit) {
  const plan = state.plan;
  const schemaOpts = [{ value: GENERIC, label: 'stay generic (no child)' }, ...SCHEMA_IDS.filter((x) => x !== GENERIC).map((id) => ({ value: id, label: `${id} (${schemaInfo(id).name})` }))];
  const top = h('div', { class: 'fields' },
    h('div', { class: 'field' }, h('label', { text: 'Destination schema' }), select(plan.split ? schemaOpts : schemaOpts.slice(1), unit.schema, (v) => {
      if (unit.mappings.some((m) => m.origin === 'you') && !confirm('Changing the schema suggests the mappings again and drops your changes on this tab. Continue?')) { draw(main, side); return; }
      setUnitSchema(plan, state.analysis, unit, v);
      draw(main, side);
    }, { class: 'input' })),
    h('div', { class: 'field' }, h('label', { text: 'Parser name' }), h('input', { class: 'input mono', value: unit.name, oninput: (e) => { unit.name = upperSlug(e.target.value) || unit.name; } })));
  top.style.marginTop = '14px';
  main.append(top);
  if (plan.format === 'text' && plan.extract.pattern !== undefined) main.append(patternBox(main, side));
  if (unit.schema === GENERIC) {
    main.append(h('p', { class: 'empty', text: 'No child parser is written for this event type, so its lines stay in the generic schema. Pick a schema to normalize them.' }));
    side.append(h('h2', { text: 'Enum values' }), h('p', { class: 'sub', text: 'Nothing to map on this tab.' }));
    return;
  }
  const opts = fieldOptions(unit.schema);
  const table = h('table', { class: 'map' });
  table.append(h('thead', {}, h('tr', {}, h('th', { text: 'Source key' }), h('th', { text: 'Sample value' }), h('th', { text: 'Parser field' }), h('th', { text: 'Transform' }), h('th', { text: 'From' }), h('th', {}, h('span', { class: 'sr', text: 'Actions' })))));
  const tbody = h('tbody');
  table.append(tbody);
  const keys = unit.keys.filter((k) => !plan.split || k.key !== plan.split.key);
  for (const k of keys) {
    const ms = unit.mappings.filter((m) => m.key === k.key);
    const rows = ms.length ? ms : [null];
    rows.forEach((m, ri) => tbody.append(mappingRow(main, side, unit, k, m, ri, opts)));
  }
  main.append(h('div', { class: 'tablewrap' }, table));

  // Fixed values
  main.append(h('h3', { text: 'Fixed values' }));
  const consts = h('div', { class: 'problems' });
  (unit.constants ||= []).forEach((c, i) => {
    const type = fieldType(unit.schema, c.field);
    const valueInput = type && typeKind(type) === 'enum'
      ? select([{ value: '', label: 'choose…' }, ...enumMembers(type).map((m) => ({ value: m }))], c.value, (v) => { c.value = v; }, { class: 'input' })
      : h('input', { class: 'input', value: c.value, placeholder: 'value', oninput: (e) => { c.value = e.target.value; } });
    consts.append(h('div', { class: 'fields three' },
      select(opts, c.field, (v) => { c.field = v; c.value = ''; draw(main, side); }, { class: 'input mono', 'aria-label': 'Field' }),
      valueInput,
      h('button', { class: 'btn quiet small', onclick: () => { unit.constants.splice(i, 1); draw(main, side); }, text: 'Remove' })));
  });
  main.append(consts, h('button', { class: 'btn quiet small', onclick: () => { unit.constants.push({ field: '', value: '' }); draw(main, side); }, text: 'Add a fixed value' }));

  // Unmapped keys
  const rest = keys.filter((k) => !unit.mappings.some((m) => m.key === k.key && m.field));
  const meta = hasEventMetadata(unit.schema);
  const box = h('div', { class: 'restbox' });
  if (meta) {
    const cb = h('input', { type: 'checkbox', checked: unit.metadata, onchange: (e) => { unit.metadata = e.target.checked; } });
    box.append(h('label', { class: 'check' }, cb, h('span', {}, `Send the ${rest.length} unmapped key${rest.length === 1 ? '' : 's'} to event_metadata as key/value records`)));
  } else {
    box.append(document.createTextNode(`${schemaInfo(unit.schema).name} has no documented event_metadata field, so these stay searchable in original_data in generic: `));
  }
  box.append(h('div', { class: 'mono', text: rest.map((k) => k.key).join(' · ') || 'none' }));
  main.append(box);

  drawEnums(side, unit, main);
}

function mappingRow(main, side, unit, k, m, ri, opts) {
  const sampleValue = k.values.find((v) => v !== '' && v !== null && v !== undefined);
  const type = m && m.field ? fieldType(unit.schema, m.field) : null;
  const tr = h('tr', { class: `${m && m.transform && m.transform.kind === 'enum' ? 'enum' : ''}${!m || !m.field ? ' unmapped' : ''}` });
  tr.append(h('td', { class: 'src' }, ri ? '' : breakable(k.key)));
  tr.append(h('td', { class: 'val', title: String(sampleValue ?? ''), text: ri ? '' : String(sampleValue ?? '') }));
  const fsel = select(opts, m ? m.field : '', (v) => {
    const idx = m ? unit.mappings.indexOf(m) : -1;
    if (!v) { if (idx >= 0) unit.mappings.splice(idx, 1); draw(main, side); return; }
    const fresh = remap(unit, k.key, v);
    if (idx >= 0) unit.mappings[idx] = fresh; else unit.mappings.push(fresh);
    draw(main, side);
  }, { class: 'field', 'aria-label': `Parser field for ${k.key}` });
  tr.append(h('td', {}, fsel));
  const tcell = h('td');
  if (m && m.field) {
    const tsel = select(transformOptions(type, m.field), m.transform.kind, (v) => {
      m.transform = v === 'enum' ? { kind: 'enum', type, map: [], default: enumDefault(enumMembers(type)) } : v === 'datetime' ? { kind: 'datetime', layout: k.layout || '2006-01-02T15:04:05Z07:00' } : v === 'replace' ? { kind: 'replace', from: '', to: '' } : { kind: v };
      m.origin = 'you';
      draw(main, side);
    }, { 'aria-label': `Transform for ${k.key}` });
    tcell.append(tsel);
    if (m.transform.kind === 'datetime') {
      const lay = h('input', { class: 'mono', value: m.transform.layout, title: 'Go layout: write Mon Jan 2 15:04:05 MST 2006 in your format', 'aria-label': 'Go time layout', oninput: (e) => { m.transform.layout = e.target.value; m.origin = 'you'; } });
      lay.style.marginTop = '4px';
      lay.style.width = '100%';
      tcell.append(lay);
    }
    if (m.transform.kind === 'replace') {
      const from = h('input', { class: 'mono', value: m.transform.from, placeholder: 'find', 'aria-label': 'Find text', oninput: (e) => { m.transform.from = e.target.value; } });
      const to = h('input', { class: 'mono', value: m.transform.to, placeholder: 'replace with', 'aria-label': 'Replace with', oninput: (e) => { m.transform.to = e.target.value; } });
      from.style.width = to.style.width = '48%';
      from.style.marginTop = to.style.marginTop = '4px';
      tcell.append(h('div', {}, from, ' ', to));
    }
  }
  tr.append(tcell);
  tr.append(h('td', {}, m && m.field ? pill(m.origin === 'you' ? 'you' : m.origin, ORIGIN_KIND[m.origin] || 'grey') : ''));
  const act = h('td');
  if (m && m.field) act.append(h('button', { class: 'x', title: 'Map this key to another field too', 'aria-label': `Map ${k.key} to another field`, onclick: () => { unit.mappings.splice(unit.mappings.indexOf(m) + 1, 0, { key: k.key, path: k.path, index: k.index, field: '', origin: 'you', transform: { kind: 'none' } }); draw(main, side); }, text: '+' }));
  if (ri > 0 || (m && !m.field)) act.append(h('button', { class: 'x', 'aria-label': 'Remove this row', onclick: () => { unit.mappings.splice(unit.mappings.indexOf(m), 1); draw(main, side); }, text: '×' }));
  tr.append(act);
  return tr;
}

function drawEnums(side, unit, main) {
  side.append(h('h2', { text: 'Enum values' }), h('p', { class: 'sub', text: 'Enum fields are set by name. The docs never show an enum assignment, so check the first Parse Message.' }));
  const enums = unit.mappings.filter((m) => m.field && m.transform && m.transform.kind === 'enum');
  if (!enums.length) {
    side.append(h('p', { class: 'empty', text: 'No source key is mapped to an enum field on this tab. Use Fixed values for a constant, such as countermeasureAuthor$ = VENDOR_OF_SENSOR.' }));
    return;
  }
  for (const m of enums) {
    const k = unit.keys.find((x) => x.key === m.key);
    const members = enumMembers(m.transform.type);
    const card = h('div', { class: 'enumcard' });
    card.append(h('div', { class: 'eh' }, h('b', { text: m.field }), pill(m.transform.type, 'grey')));
    const memberOpts = members.map((x) => ({ value: x }));
    m.transform.map.forEach((r, i) => {
      card.append(h('div', { class: 'er' },
        select([{ value: 'contains', label: 'contains' }, { value: 'equals', label: 'equals' }], r.kind, (v) => { r.kind = v; }, { 'aria-label': 'Match kind' }),
        h('input', { class: 'mono', value: r.match, 'aria-label': 'Source value', oninput: (e) => { r.match = e.target.value; } }),
        h('span', { 'aria-hidden': 'true', text: '→' }),
        select(memberOpts, r.member, (v) => { r.member = v; }, { 'aria-label': 'Enum name' }),
        h('button', { class: 'x', 'aria-label': 'Remove this value', onclick: () => { m.transform.map.splice(i, 1); redraw(); }, text: '×' }),
        r.seen ? h('div', { class: 'seen', text: `"${r.seen}" in your sample` }) : h('div', { class: 'seen', text: 'your rule' })));
    });
    const seen = [...new Set((k ? k.values : []).map(String))];
    const uncovered = seen.filter((v) => !m.transform.map.some((r) => (r.kind === 'equals' ? v.toLowerCase() === String(r.match).toLowerCase() : v.toLowerCase().includes(String(r.match).toLowerCase())) && r.match !== ''));
    if (uncovered.length) card.append(h('div', { class: 'er other' }, h('span', { class: 'mono', text: `not mapped yet: ${uncovered.slice(0, 4).join(', ')}` })));
    card.append(h('div', { class: 'er other' }, h('span', { class: 'mono', text: 'anything else' }), h('span', { 'aria-hidden': 'true', text: '→' }), select(memberOpts, m.transform.default, (v) => { m.transform.default = v; }, { 'aria-label': 'Default enum name' })));
    const add = h('button', { class: 'btn quiet small', onclick: () => {
      const v = uncovered[0];
      m.transform.map.push({ kind: 'contains', match: v ? enumStem(v) : '', member: (v && guessEnum(m.transform.type, v)) || members[0], seen: v || null });
      redraw();
    }, text: uncovered.length ? `Add "${uncovered[0]}"` : 'Add a value' });
    add.style.margin = '8px 10px';
    card.append(add);
    side.append(card);
  }
  function redraw() { clear(side); drawEnums(side, unit, main); }
}

// Plain-text sources: one capture pattern with named groups; each group is a key to map.
function patternBox(main, side) {
  const plan = state.plan;
  const a = state.analysis;
  const box = h('div', { class: 'restbox' });
  const input = h('textarea', { class: 'input mono', rows: '3', spellcheck: 'false', 'aria-label': 'Capture pattern' });
  input.value = plan.extract.pattern || '';
  const status = h('div', { class: 'sub' });
  const paint = () => {
    const n = patternMatches(a, input.value);
    status.textContent = `Matches ${n} of ${a.events.length} lines. Named groups such as (?P<user>\\S+) become the keys below. Go regex (RE2) syntax.`;
  };
  input.addEventListener('input', paint);
  paint();
  box.append(h('label', { class: 'lbl', text: 'Capture pattern (read from originalData$)' }), input, status,
    h('div', { class: 'actions' }, h('button', { class: 'btn quiet small', onclick: () => { setPattern(plan, a, input.value.trim()); draw(main, side); }, text: 'Use this pattern' })));
  return box;
}

// Lets long keys such as dns.queries[0].rrname wrap after dots and underscores.
function breakable(text) {
  const out = [];
  for (const part of String(text).split(/(?<=[._\]])/)) { out.push(part, h('wbr')); }
  out.pop();
  return out;
}
