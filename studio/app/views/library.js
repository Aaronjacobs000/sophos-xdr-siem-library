import { h, clear, pill, ext, copyText, toast } from '../dom.js';
import { state } from '../store.js';
import { go } from '../nav.js';
import { loadEntry, engineParsers, githubUrl } from '../library-client.js';
import { highlightSample, highlightScript } from '../highlight.js';
import { call } from '../emulator-client.js';
import { resultCard, resultDetail } from './test.js';
import { problemRow, SHIP_LABELS, FORMAT_LABELS } from './common.js';
import { analyse } from '../plan.js';

const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

function sourceLine() {
  const L = state.library;
  const wrap = h('div', { class: 'status' });
  if (L.status !== 'ready') { wrap.append(h('span', { class: 'dot grey' }), 'Loading the library from GitHub…'); return wrap; }
  const at = L.at ? new Date(L.at).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  if (L.source === 'github') wrap.append(h('span', { class: 'dot' }), `Loaded from GitHub (main branch) at ${at}`);
  else if (L.source === 'snapshot') wrap.append(h('span', { class: 'dot amber' }), `GitHub is unreachable (${L.error}), so this is the copy bundled with the page, built ${at}`);
  else wrap.append(h('span', { class: 'dot red' }), `The library couldn't load: ${L.error}`);
  wrap.append(' ', h('button', { class: 'linkbtn', onclick: () => window.dispatchEvent(new Event('parser-studio:refresh-library')), text: 'Refresh' }));
  return wrap;
}

export function renderLibrary(root) {
  const head = h('div', { class: 'libhead' },
    h('div', {}, h('h1', { text: 'Community parser library' }), h('p', { class: 'sub', text: 'Parsers people have shared, each with synthetic samples and the emulator\'s expected output. Open one to read it, test it against your own line, or fork it.' })),
    h('div', { class: 'actions' }, h('a', { class: 'btn quiet', href: githubUrl('/tree/main/parsers'), target: '_blank', rel: 'noopener noreferrer', text: 'Browse on GitHub' }), h('a', { class: 'btn primary', href: '#/build/sample', text: 'Build a parser' })));
  root.append(head, sourceLine());
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Search vendor, product, schema or author', 'aria-label': 'Search the library', value: state.libQuery || '' });
  const cards = h('div', { class: 'cards' });
  root.append(h('div', { class: 'libtools' }, search), cards);
  const draw = () => {
    clear(cards);
    const q = (state.libQuery || '').toLowerCase().trim();
    const list = state.library.entries.filter((e) => !q || JSON.stringify([e.meta.vendor, e.meta.product, e.meta.author, e.meta.format, (e.meta.parsers || []).map((p) => [p.name, p.schema])]).toLowerCase().includes(q));
    if (!list.length) { cards.append(h('p', { class: 'empty', text: state.library.status === 'ready' ? 'No entries match.' : 'Loading…' })); return; }
    for (const e of list) cards.append(card(e));
  };
  search.addEventListener('input', () => { state.libQuery = search.value; draw(); });
  draw();
  root.append(h('div', { class: 'callout blue' }, pill('Read first', 'blue'), h('span', { text: 'Library parsers have passed the emulator and the repo checks, not Sophos. A parser marked "emulator only" has never run in a tenant. Test every parser with Run Test in Sophos Fusion before you turn it on. Sophos does not maintain or support custom parsers.' })));
}

function card(e) {
  const m = e.meta;
  const schemas = [...new Set((m.parsers || []).map((p) => p.schema).filter((s) => s && s !== 'scwx.generic'))];
  const a = h('a', { class: 'card', href: `#/library/${e.id}` });
  a.append(h('span', { class: 'vendor', text: m.vendor }), h('h2', { text: m.product }));
  const pills = h('span', { class: 'pills' }, pill(FORMAT_LABELS[m.format] || m.format, 'grey'), pill(SHIP_LABELS[m.ship_method] || m.ship_method, 'grey'));
  for (const s of schemas) pills.append(pill(s, 'blue'));
  a.append(pills);
  a.append(h('span', { class: 'sub', text: `${(m.parsers || []).length} parser${(m.parsers || []).length === 1 ? '' : 's'}${m.versions && m.versions.length ? ` · versions ${m.versions.join(', ')}` : ''}` }));
  a.append(h('span', { class: 'foot2' }, h('span', { text: HANDLE.test(m.author || '') ? `@${m.author}` : '' }), m.tested && m.tested.tenant ? pill(`tenant-tested ${m.tested.tenant}`, 'green') : pill('emulator only', 'amber')));
  return a;
}

export function renderEntry(root, id) {
  const e = state.library.entries.find((x) => x.id === id);
  root.append(h('div', { class: 'libhead' }, h('div', {}, h('a', { href: '#/library', text: '← Library' }))));
  if (!e) {
    root.append(h('p', { class: 'empty', text: state.library.status === 'ready' ? `No library entry ${id}.` : 'Loading the library…' }));
    return;
  }
  const holder = h('div');
  root.append(holder);
  holder.append(h('p', { class: 'empty', text: 'Loading the entry…' }));
  loadEntry(e).then(() => { clear(holder); drawEntry(holder, e); }).catch((err) => { clear(holder); holder.append(h('div', { class: 'callout' }, h('span', { text: `Couldn't load ${id}: ${err.message}` }))); });
}

function drawEntry(root, e) {
  const m = e.meta;
  const head = h('div', { class: 'libhead' },
    h('div', {}, h('span', { class: 'sub', text: m.vendor }), h('h1', { text: m.product })),
    h('div', { class: 'actions' },
      h('button', { class: 'btn quiet', onclick: () => openInStudio(e, 'library'), text: 'Open in the studio' }),
      h('button', { class: 'btn primary', onclick: () => openInStudio(e, 'fork'), text: 'Fork it' })));
  root.append(head);
  const grid = h('div', { class: 'grid g-entry' });
  root.append(grid);
  const left = h('section', { class: 'panel' });
  const right = h('section', { class: 'panel' });
  grid.append(left, right);

  // About
  const dl = h('dl', { class: 'kv' });
  const row = (k, v) => dl.append(h('dt', { text: k }), h('dd', {}, v));
  row('Format', FORMAT_LABELS[m.format] || m.format);
  row('Shipped by', SHIP_LABELS[m.ship_method] || m.ship_method);
  row('Versions', m.versions && m.versions.length ? m.versions.join(', ') : 'not stated');
  row('Author', HANDLE.test(m.author || '') ? ext(`https://github.com/${m.author}`, `@${m.author}`) : 'unknown');
  row('License', m.license);
  row('Samples', m.sample_source === 'vendor-docs' ? 'from public vendor docs' : 'synthetic');
  row('Tested', m.tested && m.tested.tenant ? `passed Run Test in a tenant on ${m.tested.tenant}` : `emulator only (Parser Studio ${m.tested ? m.tested.emulator : ''})`);
  if (m.forked_from) row('Forked from', h('a', { href: `#/library/${m.forked_from}`, text: m.forked_from }));
  if (Array.isArray(m.docs) && m.docs.length) {
    const d = h('span');
    m.docs.filter((u) => /^https:\/\//.test(u)).forEach((u, i) => { if (i) d.append(h('br')); d.append(ext(u, u.replace(/^https:\/\//, '').slice(0, 70))); });
    row('Vendor docs', d);
  }
  left.append(h('h2', { text: 'About this entry' }), dl);
  if (m.notes) left.append(h('p', { class: 'sub', text: m.notes }));
  left.append(h('p', { class: 'sub' }, ext(githubUrl(`/tree/main/parsers/${e.id}`), 'View the files on GitHub')));

  // Parsers
  left.append(h('h3', { text: 'Parsers' }));
  const tabs = h('div', { class: 'tabs', role: 'tablist' });
  const code = h('pre', { class: 'code codeview' });
  code.style.whiteSpace = 'pre';
  let cur = 0;
  const showParser = () => {
    clear(tabs);
    m.parsers.forEach((p, i) => tabs.append(h('button', { class: `tab${i === cur ? ' on' : ''}`, onclick: () => { cur = i; showParser(); } }, p.role === 'parent' ? 'Parent' : p.role === 'child' ? p.name.replace(/^.*_CHILD_/, 'Child: ') : 'Parser', p.schema ? pill(p.schema, p.schema === 'scwx.generic' ? 'grey' : 'blue') : null)));
    clear(code);
    code.append(highlightScript(e.texts[m.parsers[cur].name] || ''));
  };
  showParser();
  left.append(tabs, h('div', { class: 'editortools' }, h('span', { class: 'sub', text: '' }), h('button', { class: 'btn quiet small', onclick: () => copyText(e.texts[m.parsers[cur].name] || '', `Copied ${m.parsers[cur].name}`), text: 'Copy this script' })), code);

  left.append(h('h3', { text: `Samples (${e.samples.length})` }));
  const sv = h('div', { class: 'code codeview' });
  e.samples.forEach((l, i) => sv.append(h('div', { class: 'row' }, h('span', { class: 'ln', text: String(i + 1) }), h('span', { class: 'txt' }, highlightSample(l)))));
  left.append(sv);

  // Test with your own line
  right.append(h('h2', { text: 'Test it with your own lines' }), h('p', { class: 'sub', text: 'Paste lines from your source. They run through these parsers in this tab and go nowhere else.' }));
  const ta = h('textarea', { class: 'code', placeholder: 'Paste one or more lines…', 'aria-label': 'Your sample lines', spellcheck: 'false' });
  ta.style.minHeight = '120px';
  const out = h('div');
  const runBtn = h('button', { class: 'btn primary', text: 'Run the parsers' });
  const useLib = h('button', { class: 'btn quiet', text: 'Run the entry\'s samples' });
  right.append(ta, h('div', { class: 'actions' }, useLib, runBtn), out);
  let sel = 0;
  async function run(lines) {
    clear(out);
    if (!lines.length) { out.append(h('p', { class: 'empty', text: 'Paste at least one line.' })); return; }
    out.append(h('p', { class: 'sub', text: 'Running…' }));
    try {
      const lint = await call('lint', { parsers: engineParsers(e), samples: lines, now: m.reference_time });
      sel = 0;
      const paint = () => {
        clear(out);
        const cards = h('div', { class: 'linecards' });
        lint.results.forEach((r, i) => cards.append(resultCard(r, i === sel, () => { sel = i; paint(); })));
        out.append(cards);
        if (lint.results[sel]) out.append(resultDetail(lint.results[sel]));
        const unmatched = lint.results.filter((r) => !r.extractor_path).length;
        if (unmatched) out.append(h('div', { class: 'callout' }, h('span', { text: `${unmatched} line${unmatched === 1 ? '' : 's'} matched none of these parsers. Your source may send a different format or version than the samples; fork the entry to adapt it.` })));
        const errs = lint.problems.filter((p) => p.level === 'error' && p.code === 'runtime');
        if (errs.length) { const l = h('div', { class: 'problems' }); errs.forEach((p) => l.append(problemRow(p))); out.append(l); }
      };
      paint();
    } catch (err) {
      clear(out);
      out.append(h('div', { class: 'callout' }, h('span', { text: err.message })));
    }
  }
  runBtn.addEventListener('click', () => run(ta.value.split(/\r?\n/).filter((l) => l.trim())));
  useLib.addEventListener('click', () => run(e.samples));
  right.append(h('div', { class: 'callout blue' }, pill('Emulator', 'blue'), h('span', { text: 'These results come from the Parser Studio emulator. Run Test in your own tenant before you turn a parser on.' })));
}

function openInStudio(e, kind) {
  state.lines = [...e.samples];
  state.raw = e.samples.join('\n');
  state.fileName = `${e.id.replace('/', '-')}.log`;
  state.analysis = analyse(state.lines);
  state.confirm = null;
  state.unitSchemas = null;
  state.plan = null;
  state.parsers = e.meta.parsers.map((p) => ({ name: p.name, role: p.role, parent: p.parent, schema: p.schema, text: e.texts[p.name] || '' }));
  state.edited = true;
  state.testTab = 0;
  state.selectedLine = 0;
  state.lint = null;
  state.now = e.meta.reference_time;
  state.source = { vendor: e.meta.vendor, product: e.meta.product, version: (e.meta.versions || [])[0] || '', shipMethod: e.meta.ship_method };
  state.origin = { kind, id: e.id, meta: e.meta };
  state.shareAuthor = kind === 'library' ? e.meta.author : '';
  toast(kind === 'fork' ? `Forked ${e.id}. Edit it, then share it back.` : `Opened ${e.id}`);
  go('#/build/test');
}
