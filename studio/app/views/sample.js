import { h, clear, pill, select, bytes, toast } from '../dom.js';
import { state, sampleLines, subscribe } from '../store.js';
import { go } from '../nav.js';
import { highlightSample } from '../highlight.js';
import { analyse, buildPlan, keysFor, makeUnit } from '../plan.js';
import { headerLabel } from '../../core/detect.js';
import { compileGo, checkRe2 } from '../../core/goregex.js';
import { call } from '../emulator-client.js';
import { SCHEMA_IDS, GENERIC, schemaInfo } from '../../core/schemas.js';
import { pickSchema } from '../../core/mapping.js';
import { loadEntry, lintEntries } from '../library-client.js';
import { steps, SHIP_LABELS, FORMAT_LABELS } from './common.js';

const MAX_LINES = 500;
let overlapSeq = 0;

export function renderSample(root) {
  const lineCount = state.lines.length;
  root.append(steps('sample', lineCount ? `${lineCount} line${lineCount === 1 ? '' : 's'} · nothing has left this page` : 'Nothing you paste leaves this page'));
  const grid = h('div', { class: 'grid g-sample' });
  root.append(grid);
  const left = h('section', { class: 'panel', 'aria-labelledby': 'sl-h' });
  const right = h('section', { class: 'panel', 'aria-labelledby': 'found-h' });
  grid.append(left, right);
  drawLeft(left, right);
  drawRight(right);
  const off = subscribe((what) => {
    if (!document.body.contains(right)) { off(); return; }
    if (what !== 'library') return;
    drawRight(right);
    const ex = left.querySelector('[data-examples]');
    if (ex) ex.replaceWith(exampleLoader(left, right));
  });
}

function setRaw(raw, fileName, right, left, keepExample = false) {
  if (!keepExample) state.exampleFrom = null;
  state.raw = raw;
  state.fileName = fileName;
  const lines = sampleLines(raw);
  if (lines.length > MAX_LINES) toast(`Using the first ${MAX_LINES} of ${lines.length} lines`);
  state.lines = lines.slice(0, MAX_LINES);
  state.analysis = state.lines.length ? analyse(state.lines) : null;
  if (state.analysis) {
    if (!state.source.vendor && state.analysis.vendor) state.source.vendor = state.analysis.vendor;
    if (!state.source.product && state.analysis.product) state.source.product = state.analysis.product;
  }
  state.plan = null;
  if (!state.edited) state.parsers = null;
  state.unitSchemas = null;
  if (left) drawLeft(left, right);
  drawRight(right);
}

function drawLeft(left, right) {
  clear(left);
  left.append(h('h2', { id: 'sl-h', text: 'Sample lines' }), h('p', { class: 'sub', text: 'One event per line, 5 to 20 lines covering each event type. The best copy is Original Data from Data Lake Search, because that is what the parser sees.' }));
  const fileInput = h('input', { type: 'file', class: 'sr', accept: '.log,.txt,.json,.csv,.cef,.leef,text/plain,application/json', 'aria-label': 'Choose a log file' });
  fileInput.addEventListener('change', async () => {
    const f = fileInput.files && fileInput.files[0];
    if (f) setRaw(await f.text(), f.name, right, left);
  });
  const ext = state.fileName ? (state.fileName.split('.').pop() || 'log').slice(0, 5) : 'log';
  const drop = h('div', { class: 'drop' },
    h('span', { class: 'ext', text: `.${ext}` }),
    h('div', { class: 'grow' },
      h('div', { class: 'file', text: state.fileName || (state.lines.length ? 'Pasted lines' : 'Drop a log file here, or paste lines below') }),
      h('div', { class: 'sub', text: state.lines.length ? `${state.lines.length} lines · ${bytes(new TextEncoder().encode(state.raw).length)}${state.analysis && state.analysis.types.length > 1 ? ` · ${state.analysis.types.length} event types` : ''}` : 'Read in this tab only. Nothing is uploaded.' })),
    h('button', { class: 'btn quiet', onclick: () => fileInput.click(), text: state.fileName ? 'Replace file' : 'Choose a file' }),
    fileInput);
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', async (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) setRaw(await f.text(), f.name, right, left);
  });
  left.append(drop);

  const editing = !state.lines.length || state.editingSample;
  if (editing) {
    const ta = h('textarea', { class: 'code', placeholder: 'Paste sample lines here, one event per line.\n\nFor example:\nOct  8 09:22:40 host01 app[123]: {"event_type":"login","user":"jsmith","src_ip":"192.0.2.10"}', 'aria-label': 'Sample lines', spellcheck: 'false' });
    ta.value = state.raw;
    ta.style.marginTop = '12px';
    ta.addEventListener('input', () => { clearTimeout(ta._t); ta._t = setTimeout(() => { state.fileName = null; setRaw(ta.value, null, right, null); }, 400); });
    left.append(ta);
    if (state.lines.length) left.append(h('div', { class: 'actions' }, h('button', { class: 'btn quiet small', onclick: () => { state.editingSample = false; drawLeft(left, right); }, text: 'Done editing' })));
    setTimeout(() => { if (!state.lines.length) ta.focus(); }, 0);
  } else {
    const view = h('div', { class: 'code codeview', role: 'region', 'aria-label': 'Sample lines', tabindex: '0' });
    view.style.marginTop = '12px';
    state.lines.forEach((l, i) => view.append(h('div', { class: 'row' }, h('span', { class: 'ln', text: String(i + 1) }), h('span', { class: 'txt' }, highlightSample(l)))));
    left.append(view, h('div', { class: 'actions' },
      h('button', { class: 'btn quiet small', onclick: () => { state.editingSample = true; drawLeft(left, right); }, text: 'Edit lines' }),
      h('button', { class: 'btn quiet small', onclick: () => { state.editingSample = false; setRaw('', null, right, left); }, text: 'Clear' })));
  }
  left.append(exampleLoader(left, right));
}

function exampleLoader(left, right) {
  const box = h('div', { class: 'actions', 'data-examples': '1' });
  const entries = state.library.entries || [];
  if (!entries.length) {
    box.append(h('span', { class: 'note', text: state.library.status === 'ready' ? 'No library examples available.' : 'Loading library examples…' }));
    return box;
  }
  const opts = [{ value: '', label: 'Load samples from a library entry…' }, ...entries.map((e) => ({ value: e.id, label: `${e.meta.vendor} ${e.meta.product}` }))];
  box.append(h('span', { class: 'note', text: 'No logs to hand? Start from a library entry\'s synthetic samples.' }), select(opts, '', async (id) => {
    const e = entries.find((x) => x.id === id);
    if (!e) return;
    try {
      await loadEntry(e);
      state.source = { vendor: e.meta.vendor, product: e.meta.product, version: (e.meta.versions || [])[0] || '', shipMethod: e.meta.ship_method };
      state.edited = false;
      state.parsers = null;
      state.origin = null;
      state.exampleFrom = e.id;
      state.editingSample = false;
      setRaw(e.samples.join('\n'), `${e.id.replace('/', '-')}.log`, right, left, true);
    } catch (err) {
      toast(`Couldn't load ${e.id}: ${err.message}`);
    }
  }, { class: 'input', 'aria-label': 'Load samples from a library entry' }));
  // Sized to its longest entry, but never wider than the page, so a phone doesn't scroll sideways.
  box.lastChild.style.width = 'auto';
  box.lastChild.style.maxWidth = '100%';
  return box;
}

function drawRight(right) {
  clear(right);
  right.append(h('h2', { id: 'found-h', text: 'What the page found' }));
  const a = state.analysis;
  if (!a) {
    right.append(h('p', { class: 'sub', text: 'Paste or drop sample lines to start. The page reads the format, splits event types, suggests a parent and children, and proposes a confirm string. Mapping uses rules only: no AI service and no upload.' }));
    right.append(h('h3', { text: 'What to paste' }));
    for (const t of ['5 to 20 raw lines covering every event type you want parsed.', 'Synthetic or test data if you plan to share the parser. Customer logs stay on this page, but don\'t put them in the library.', 'Lines as Sophos NG-SIEM receives them. A forwarder in the middle can change the format.']) right.append(h('div', { class: 'dotline' }, h('span', { class: 'dot grey' }), h('span', { text: t })));
    return;
  }
  const dl = h('dl', { class: 'kv' });
  const tag = a.tagName ? `, tag ${a.tagName}${a.tagPid ? '[pid]' : ''}` : '';
  dl.append(h('dt', { text: 'Header' }), h('dd', { text: `${headerLabel(a.header)}${tag}` }));
  dl.append(h('dt', { text: 'Body' }), h('dd', { text: `${FORMAT_LABELS[a.format] || a.format}${a.format === 'json' && a.events.some((e) => e.jsonAtEnd) ? ' object at the end of the line' : ''}` }));
  dl.append(h('dt', { text: 'Split on' }), h('dd', {}, a.split && a.types.length > 1 ? h('span', {}, h('span', { class: 'mono', text: a.split.path || a.split.key }), `, ${a.types.length} values`) : 'One event type, so one standalone parser'));
  right.append(dl);

  // Suggested shape
  right.append(h('h3', { text: 'Suggested shape' }));
  const tree = h('div', { class: 'tree' });
  state.unitSchemas ||= {};
  const schemaOpts = [{ value: GENERIC, label: 'stay generic (no child)' }, ...SCHEMA_IDS.filter((x) => x !== GENERIC).map((id) => ({ value: id, label: `${id} (${schemaInfo(id).name})` }))];
  if (a.split && a.types.length > 1) {
    tree.append(h('div', { class: 'row' }, h('span', { class: 'name', text: '…_PARENT' }), pill('scwx.generic', 'grey'), h('span', { class: 'why', text: `all ${a.lines} lines` })));
    for (const t of a.types) {
      const idx = a.events.map((e, i) => [e, i]).filter(([e]) => e.fields.some((f) => f.key === a.split.key && f.value === t)).map(([, i]) => i);
      if (!state.unitSchemas[t]) state.unitSchemas[t] = childSchema(keysFor(a, idx), t);
      tree.append(h('div', { class: 'row child' }, h('span', { class: 'name', text: '…_CHILD' }),
        select(schemaOpts, state.unitSchemas[t], (v) => { state.unitSchemas[t] = v; state.plan = null; mapBtn.textContent = mapLabel(); }, { 'aria-label': `Schema for ${t}` }),
        h('span', { class: 'why', text: `${t} · ${idx.length} line${idx.length === 1 ? '' : 's'}` })));
    }
  } else {
    if (!state.unitSchemas.__single) state.unitSchemas.__single = pickSchema(a.keys, '', { extraText: a.hintText });
    tree.append(h('div', { class: 'row' }, h('span', { class: 'name', text: '…_STANDALONE' }),
      select(schemaOpts.slice(1), state.unitSchemas.__single, (v) => { state.unitSchemas.__single = v; state.plan = null; }, { 'aria-label': 'Schema' }),
      h('span', { class: 'why', text: `all ${a.lines} lines` })));
  }
  right.append(tree);

  // Confirm string
  right.append(h('h3', { text: a.split && a.types.length > 1 ? 'Confirm string for the parent' : 'Confirm string' }));
  state.confirm ||= { ...a.confirm };
  if (state.confirmFor !== state.raw) { state.confirm = { ...a.confirm }; state.confirmFor = state.raw; }
  const status = h('div');
  const input = h('input', { class: 'input mono', value: state.confirm.text, 'aria-label': 'Confirm string', spellcheck: 'false' });
  const kind = select([{ value: 'PATTERN', label: 'PATTERN' }, { value: 'EXPRESSION', label: 'EXPRESSION' }], state.confirm.kind, (v) => { state.confirm.kind = v; state.plan = null; paintStatus(); }, { class: 'input', 'aria-label': 'Confirm with' });
  let mapBtn = null;
  input.addEventListener('input', () => { state.confirm.text = input.value; state.plan = null; paintStatus(); if (mapBtn) mapBtn.disabled = !state.confirm.text; });
  right.append(h('div', { class: 'confirmbox' }, kind, input), status);
  function paintStatus() {
    clear(status);
    const c = state.confirm;
    if (!c.text) { status.append(h('div', { class: 'dotline' }, h('span', { class: 'dot red' }), h('span', { text: 'Write a confirm string that names the vendor or product.' }))); return; }
    if (c.kind === 'PATTERN') {
      const issues = checkRe2(c.text).filter((i) => i.level === 'error');
      if (issues.length) { status.append(h('div', { class: 'dotline' }, h('span', { class: 'dot red' }), h('span', { text: issues[0].message }))); return; }
      let re;
      try { re = compileGo(c.text); } catch (e) { status.append(h('div', { class: 'dotline' }, h('span', { class: 'dot red' }), h('span', { text: e.message }))); return; }
      const n = state.lines.filter((l) => re.test(l)).length;
      status.append(h('div', { class: 'dotline' }, h('span', { class: `dot ${n === state.lines.length ? '' : 'amber'}` }), h('span', { text: n === state.lines.length ? `Matches all ${n} lines` : `Matches ${n} of ${state.lines.length} lines` })));
    } else {
      status.append(h('div', { class: 'dotline' }, h('span', { class: 'dot grey' }), h('span', { text: 'Expression confirm strings are checked on the Test step.' })));
    }
    const lib = (state.library.entries || []).filter((e) => e.loaded);
    const line = h('div', { class: 'dotline' }, h('span', { class: 'dot grey' }), h('span', { text: state.library.status !== 'ready' ? 'Checking overlap once the library loads…' : 'Checking overlap with the library…' }));
    status.append(line);
    if (state.library.status !== 'ready') return;
    // Library patterns are other people's regexes, so they run in the worker, which can be stopped.
    const total = (state.library.entries || []).reduce((k, e) => k + (e.meta.parsers || []).length, 0);
    const mine = ++overlapSeq;
    call('overlap', { parsers: [{ name: 'Your confirm string', text: `!CONFIRMWITH=${c.kind}\n!CONFIRMSTRING=${c.text}\n` }], samples: state.lines, library: lintEntries(lib), selfId: state.exampleFrom }).then((o) => {
      if (mine !== overlapSeq) return;
      line.replaceWith(h('div', { class: 'dotline' }, h('span', { class: `dot ${o.length ? 'red' : ''}` }), h('span', { text: o.length ? o[0] : `No overlap with the ${total} library parsers${lib.length < state.library.entries.length ? ` (${lib.length} of ${state.library.entries.length} entries checked so far)` : ''}` })));
    }).catch((e) => { if (mine === overlapSeq) line.replaceWith(h('div', { class: 'dotline' }, h('span', { class: 'dot amber' }), h('span', { text: `Overlap check stopped: ${e.message}` }))); });
  }
  paintStatus();
  ensureLibraryLoaded().then((changed) => { if (changed && document.body.contains(status)) paintStatus(); });

  if (a.notes.length) {
    right.append(h('h3', { text: 'Worth knowing' }));
    for (const n of a.notes) right.append(h('div', { class: 'dotline' }, h('span', { class: 'dot amber' }), h('span', { text: n.replace(/`/g, '') })));
  }

  right.append(h('h3', { text: 'About the source' }));
  const src = state.source;
  const inp = (key, label, placeholder) => h('div', { class: 'field' }, h('label', { text: label, for: `src-${key}` }), h('input', { class: 'input', id: `src-${key}`, value: src[key], placeholder, oninput: (e) => { src[key] = e.target.value; state.plan = null; } }));
  right.append(h('div', { class: 'fields' }, inp('vendor', 'Vendor', 'for example ESET'), inp('product', 'Product', 'for example ESET PROTECT On-Prem')));
  const ship = h('div', { class: 'field' }, h('label', { text: 'Shipped by', for: 'src-ship' }), select(Object.entries(SHIP_LABELS).map(([value, label]) => ({ value, label })), src.shipMethod, (v) => { src.shipMethod = v; }, { class: 'input', id: 'src-ship' }));
  const fields2 = h('div', { class: 'fields' }, inp('version', 'Version', 'optional'), ship);
  fields2.style.marginTop = '10px';
  right.append(fields2);

  // Counts the children that get a parser, so a schema pick above updates it.
  function mapLabel() {
    const n = a.split && a.types.length > 1 ? a.types.filter((t) => state.unitSchemas[t] !== GENERIC).length : 1;
    return n > 1 ? `Map fields for ${n} event types` : 'Map fields';
  }
  mapBtn = h('button', { class: 'btn primary', disabled: !state.confirm.text, onclick: () => next(), text: mapLabel() });
  right.append(h('div', { class: 'actions' },
    h('span', { class: 'note', text: 'Names follow the pattern in the Sophos docs, for example VENDOR_PRODUCT_JSON_PARENT.' }),
    mapBtn));
}

function childSchema(keys, type) {
  return pickSchema(keys, type, { child: true, extraText: state.analysis ? state.analysis.hintText : '' });
}

let loadingAll = null;
// Overlap checks need every entry's parsers and samples.
function ensureLibraryLoaded() {
  if (state.library.status !== 'ready') return Promise.resolve(false);
  const todo = state.library.entries.filter((e) => !e.loaded);
  if (!todo.length) return Promise.resolve(false);
  if (!loadingAll) loadingAll = Promise.all(todo.map((e) => loadEntry(e).catch(() => null))).then(() => { loadingAll = null; return true; });
  return loadingAll;
}

function next() {
  if (state.edited && state.parsers && !confirm('You edited the parser scripts by hand. Writing them again from the map replaces those edits. Continue?')) return;
  const a = state.analysis;
  const plan = buildPlan(a, state.source);
  plan.confirm = { ...state.confirm };
  // Apply the schema picks from the shape tree.
  if (plan.split) {
    for (const u of plan.units) {
      const want = state.unitSchemas[u.eventType];
      if (want && want !== u.schema) Object.assign(u, rebuild(plan, a, u, want));
    }
  } else if (state.unitSchemas.__single && plan.units[0].schema !== state.unitSchemas.__single) {
    Object.assign(plan.units[0], rebuild(plan, a, plan.units[0], state.unitSchemas.__single));
  }
  state.plan = plan;
  state.mapTab = plan.split ? 1 : 0;
  state.edited = false;
  state.parsers = null;
  go('#/build/map');
}

function rebuild(plan, a, u, schema) {
  if (schema === GENERIC) return { schema: GENERIC, mappings: [], metadata: false };
  const taken = new Set([plan.parentName, ...plan.units.filter((x) => x !== u).map((x) => x.name)]);
  const fresh = makeUnit(a, { eventType: u.eventType, lines: u.lines, schema, taken, base: plan.baseName });
  return { schema: fresh.schema, mappings: fresh.mappings, metadata: fresh.metadata, name: fresh.name };
}

