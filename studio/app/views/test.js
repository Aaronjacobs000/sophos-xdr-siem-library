import { h, clear, pill, copyText, download, isoTime, toast } from '../dom.js';
import { state } from '../store.js';
import { go } from '../nav.js';
import { steps, problemRow, schemaPill } from './common.js';
import { createEditor } from '../editor.js';
import { call } from '../emulator-client.js';
import { writeParsers } from '../plan.js';
import { schemaInfo } from '../../core/schemas.js';
import { makeZip } from '../../core/zip.js';
import { TOOL_NAME, TOOL_VERSION, REPO } from '../../core/version.js';
import { openShare, draftEntry } from './share.js';
import { lintEntries, loadEntry } from '../library-client.js';

export function libraryForLint() {
  return lintEntries(state.library.entries || []);
}

export function enginePayload() {
  return state.parsers.map((p) => ({ name: p.name, text: p.text, parent: p.parent, role: p.role }));
}

export function renderTest(root) {
  root.append(steps('test', `${state.parsers.length} parser${state.parsers.length === 1 ? '' : 's'} · ${state.lines.length} sample${state.lines.length === 1 ? '' : 's'}`));
  const grid = h('div', { class: 'grid g-test' });
  root.append(grid);
  const left = h('section', { class: 'panel' });
  const right = h('section', { class: 'panel', 'aria-live': 'polite' });
  grid.append(left, right);
  if (state.testTab >= state.parsers.length) state.testTab = 0;
  let editor;
  const title = h('h2');
  const sub = h('p', { class: 'sub' });
  const tabs = h('div', { class: 'tabs', role: 'tablist' });
  const tools = h('div', { class: 'editortools' });
  left.append(title, sub, tabs, tools);
  const slot = h('div');
  left.append(slot);

  function drawLeft() {
    const p = state.parsers[state.testTab];
    title.textContent = p.name;
    clear(sub);
    const s = schemaInfo(p.schema || 'scwx.generic');
    sub.append(`${p.role === 'child' ? `Child of ${p.parent}` : p.role === 'parent' ? 'Parent' : 'Standalone'} · ${p.schema || 'schema from the parent'}${s ? '' : ''} · amber marks the first use of each behavior the docs don't show.`);
    clear(tabs);
    state.parsers.forEach((x, i) => tabs.append(h('button', { class: `tab${i === state.testTab ? ' on' : ''}`, role: 'tab', 'aria-selected': i === state.testTab ? 'true' : 'false', onclick: () => { state.testTab = i; drawLeft(); paintMarkers(); } }, x.role === 'parent' ? 'Parent' : x.role === 'child' ? x.name.replace(/^.*_CHILD_/, 'Child: ') : 'Parser')));
    clear(tools);
    tools.append(h('span', { class: 'sub', text: state.edited ? 'Edited by hand. Results update as you type.' : 'Edit the script here; results update as you type.' }));
    const btns = h('span', { class: 'actions' });
    btns.style.marginTop = '0';
    btns.append(h('button', { class: 'btn quiet small', onclick: () => copyText(state.parsers[state.testTab].text, `Copied ${p.name}`), text: 'Copy this script' }));
    if (state.plan) btns.append(h('button', { class: 'btn quiet small', onclick: () => go('#/build/map'), text: 'Back to the map' }));
    if (state.plan && state.edited) btns.append(h('button', { class: 'btn quiet small', onclick: () => { if (confirm('Write the scripts again from the map? Your hand edits are lost.')) { state.parsers = writeParsers(state.plan, state.lines); state.edited = false; drawLeft(); run(); } }, text: 'Write again from the map' }));
    tools.append(btns);
    clear(slot);
    editor = createEditor({ value: p.text, label: `${p.name} script`, onChange: (v) => { p.text = v; state.edited = true; run(); } });
    slot.append(editor.el);
  }

  function paintMarkers() {
    if (!editor || !state.lint) return;
    const p = state.parsers[state.testTab];
    editor.setMarkers(state.lint.problems.filter((x) => x.parser === p.name && x.line));
  }

  function jump(parser, line) {
    const i = state.parsers.findIndex((p) => p.name === parser);
    if (i === -1) return;
    if (i !== state.testTab) { state.testTab = i; drawLeft(); paintMarkers(); }
    editor.focusLine(line);
  }

  let seq = 0;
  async function run() {
    const mine = ++seq;
    state.running = true;
    try {
      const lint = await call('lint', { parsers: enginePayload(), samples: state.lines, now: state.now || undefined, library: libraryForLint(), selfId: state.origin ? state.origin.id : state.exampleFrom || null });
      if (mine !== seq) return;
      state.lint = lint;
      state.runError = null;
    } catch (e) {
      if (mine !== seq || e.message === 'cancelled') return;
      state.runError = e.message;
    }
    state.running = false;
    drawRight(right, jump);
    paintMarkers();
  }

  drawLeft();
  drawRight(right, jump);
  run();
  // Overlap checks need every library entry's parsers and samples.
  const todo = (state.library.entries || []).filter((e) => !e.loaded);
  if (todo.length) Promise.all(todo.map((e) => loadEntry(e).catch(() => null))).then(() => { if (document.body.contains(right)) run(); });
}

function recordRows(obj, prefix = '') {
  const rows = [];
  for (const [k, v] of Object.entries(obj || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      if (Array.isArray(v.record) && Object.keys(v).length === 1) {
        rows.push([`${key}.record`, v.record.map((r) => `${r.key ?? ''} = ${r.value ?? 'NULL'}`).join('\n')]);
      } else rows.push(...recordRows(v, key));
    } else if (Array.isArray(v)) {
      rows.push([key, v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join('\n')]);
    } else {
      let text = String(v);
      if (/_usec$/.test(k) && typeof v === 'number') { const t = isoTime(v); if (t) text += `  (${t})`; }
      rows.push([key, text]);
    }
  }
  return rows;
}

export function resultCard(r, on, onclick) {
  const n = r.normalized ? recordRows(r.normalized).length : 0;
  const card = h('button', { class: `linecard${on ? ' on' : ''}`, onclick, 'aria-pressed': on ? 'true' : 'false' });
  const head = h('span', { class: 'lh' }, `Line ${r.line}`);
  if (r.error) head.append(pill('error', 'red'));
  else if (r.normalized) head.append(pill(`${r.schema} · ${n} fields`, 'green'));
  else head.append(pill('generic only', 'grey'));
  card.append(head, h('span', { class: 'path', text: r.extractor_path ? shortPath(r.extractor_path) : r.rejected ? 'syntax error, parser rejected' : 'no parser matched' }));
  return card;
}

export function resultDetail(r) {
  const box = h('div');
  if (r.normalized) {
    box.append(h('h3', { text: `Parsed record, line ${r.line}` }));
    const t = h('table', { class: 'rec' });
    const tb = h('tbody');
    for (const [k, v] of recordRows(r.normalized)) tb.append(h('tr', {}, h('td', { text: k }), h('td', { text: v })));
    if (!Object.keys(r.normalized).length) tb.append(h('tr', {}, h('td', { text: '(empty)' }), h('td', { text: 'The parser set no fields of this schema.' })));
    t.append(tb);
    box.append(t);
  } else {
    box.append(h('h3', { text: `Line ${r.line}` }));
    box.append(h('p', { class: 'sub', text: r.result || '' }));
    if (r.error) box.append(h('div', { class: 'dotline' }, h('span', { class: 'dot red' }), h('span', { class: 'mono', text: r.error })));
  }
  for (const extra of r.also || []) {
    box.append(h('h3', { text: `Also stored in ${extra.schema}` }));
    const t2 = h('table', { class: 'rec' });
    const tb2 = h('tbody');
    for (const [k, v] of recordRows(extra.normalized)) tb2.append(h('tr', {}, h('td', { text: k }), h('td', { text: v })));
    t2.append(tb2);
    box.append(t2);
  }
  const notes = (r.notes || []).filter((n) => n.level !== 'info' || n.code === 'sanitized');
  if (notes.length) {
    const list = h('div', { class: 'problems' });
    for (const n of notes) list.append(problemRow(n));
    box.append(list);
  }
  return box;
}

function drawRight(right, jump) {
  clear(right);
  const lint = state.lint;
  right.append(h('h2', { text: `Results on ${state.lines.length} sample${state.lines.length === 1 ? '' : 's'}` }));
  if (state.runError) {
    right.append(h('div', { class: 'callout' }, pill('Stopped', 'red'), h('span', { text: state.runError })));
    return;
  }
  if (!lint) { right.append(h('p', { class: 'empty', text: 'Running the emulator…' })); return; }
  const results = lint.results || [];
  if (state.selectedLine >= results.length) state.selectedLine = 0;
  const cards = h('div', { class: 'linecards' });
  results.forEach((r, i) => cards.append(resultCard(r, i === state.selectedLine, () => { state.selectedLine = i; drawRight(right, jump); })));
  right.append(cards);
  if (results[state.selectedLine]) right.append(resultDetail(results[state.selectedLine]));

  right.append(h('h3', { text: 'Checks' }));
  const s = lint.stats;
  const probs = lint.problems;
  const has = (code) => probs.some((p) => p.code === code);
  const sanitized = probs.filter((p) => p.code === 'sanitized').length;
  const inferred = probs.filter((p) => p.level === 'inferred');
  const libCount = (state.library.entries || []).reduce((n, e) => n + (e.meta.parsers || []).length, 0);
  const libLoaded = (state.library.entries || []).filter((e) => e.loaded).length;
  const checks = h('div', { class: 'checks' });
  const add = (ok, text, level) => checks.append(h('div', { class: 'dotline' }, h('span', { class: `dot ${ok ? '' : level || 'red'}` }), h('span', { text })));
  add(s.fieldsKnown === s.fieldsSet && !has('not-a-field'), `${s.fieldsKnown} of ${s.fieldsSet} fields exist in their schemas`, 'amber');
  add(!has('enum') && s.enumsBad === 0, s.enumsChecked ? 'Enum values are valid names' : 'No enum fields set', 'red');
  add(s.regexBad === 0, s.regexes ? 'Regex is RE2 safe' : 'No regex to check', 'red');
  add(!has('overlap'), state.library.status !== 'ready' ? 'Library overlap: waiting for the library' : has('overlap') ? 'Overlaps a library parser' : `No overlap with ${libCount} library parsers${libLoaded < state.library.entries.length ? ' (still loading)' : ''}`, 'red');
  add(!inferred.length, inferred.length ? `Inferred: ${inferred.length} behavior${inferred.length === 1 ? '' : 's'} the docs don't show` : 'Nothing inferred', 'amber');
  add(!sanitized, sanitized ? `SANITIZE_ALL nulled ${sanitized} value${sanitized === 1 ? '' : 's'}` : 'No values nulled by SANITIZE_ALL', 'amber');
  right.append(checks);
  const shown = probs.filter((p) => p.code !== 'sanitized');
  if (shown.length) {
    const list = h('div', { class: 'problems' });
    for (const p of shown) list.append(problemRow(p, jump));
    right.append(list);
  }
  right.append(h('div', { class: 'callout' }, pill('Emulator', 'amber'), h('span', { text: 'Run in this browser, not in Sophos NG-SIEM. Next: add each parser under Security Operations > Integrations > Custom Parsers in Sophos Fusion, add the samples, Run Test 12 to 15 times, then turn on the parent before its children.' })));
  const errors = probs.filter((p) => p.level === 'error').length;
  right.append(h('div', { class: 'actions' },
    h('button', { class: 'btn quiet', onclick: () => downloadPack(results), text: 'Download test pack' }),
    h('button', { class: 'btn quiet', onclick: () => openShare(results), text: 'Share to the library', title: errors ? 'Fix the errors first; the library checks will fail on them' : null }),
    h('button', { class: 'btn primary', onclick: () => copyAll(), text: state.parsers.length > 1 ? `Copy ${state.parsers.length} parser scripts` : 'Copy the parser script' })));
}

function copyAll() {
  const order = [...state.parsers].sort((a, b) => (a.role === 'parent' ? -1 : b.role === 'parent' ? 1 : 0));
  const text = order.length === 1 ? order[0].text : order.map((p) => `#### ${p.name} (${p.role}${p.parent ? ` of ${p.parent}` : ''}, ${p.schema || 'parent schema'}) ####\n${p.text}`).join('\n');
  copyText(text, order.length === 1 ? 'Copied the script' : `Copied ${order.length} scripts. Paste each one into its own parser in Sophos Fusion.`);
}

function downloadPack(results) {
  const entry = draftEntry(results);
  const order = [...state.parsers].sort((a, b) => (a.role === 'parent' ? -1 : b.role === 'parent' ? 1 : 0));
  const readme = [
    `${TOOL_NAME} ${TOOL_VERSION} test pack`,
    `https://github.com/${REPO}`,
    '',
    'Emulator result, not run in Sophos NG-SIEM.',
    '',
    'Add the parsers in Sophos Fusion under Security Operations > Integrations > Custom Parsers, in this order:',
    ...order.map((p, i) => `  ${i + 1}. ${p.name} (${p.role === 'child' ? `child of ${p.parent}` : p.role}, ${p.schema || 'parent schema'})`),
    '',
    'Add the lines in samples.log as sample messages, use Parse Message and Run Test (12 to 15 runs),',
    'and check the extractor path and the normalized fields against expected.json.',
    'Turn on the parent before its children.',
    '',
    'Files:',
    '  *.parser.txt   one script per parser',
    '  samples.log    the sample lines',
    '  expected.json  what the emulator produced for each line',
    '  meta.json      draft metadata, in case you share the parsers in the library',
  ].join('\n');
  const files = [{ path: 'README.txt', content: readme + '\n' }, ...order.map((p) => ({ path: `${p.name}.parser.txt`, content: p.text.endsWith('\n') ? p.text : `${p.text}\n` })),
    { path: 'samples.log', content: state.lines.join('\n') + '\n' },
    { path: 'expected.json', content: JSON.stringify(entry.expected, null, 2) + '\n' },
    { path: 'meta.json', content: JSON.stringify(entry.meta, null, 2) + '\n' }];
  const name = `${(state.plan ? state.plan.baseName : order[0].name).toLowerCase()}-test-pack.zip`;
  download(name, makeZip(files), 'application/zip');
  toast(`Downloaded ${name}`);
}

// ACME_FW_JSON_PARENT > ACME_FW_JSON_CHILD_NIDS reads as PARENT > CHILD_NIDS on the cards.
function shortPath(path) {
  const names = path.split(' > ');
  if (names.length < 2) return path;
  let p = names[0];
  for (const n of names) while (p && !n.startsWith(p)) p = p.slice(0, -1);
  p = p.slice(0, p.lastIndexOf('_') + 1);
  return names.map((n) => n.slice(p.length) || n).join(' > ');
}
