import { h, pill, clear } from '../dom.js';
import { state } from '../store.js';
import { stars } from '../stars.js';
import { SORTS, sortEntries } from '../sort.js';
import { go } from '../nav.js';
import { schemaInfo } from '../../core/schemas.js';
import { noteBlocks } from '../../core/notes.js';

export function steps(current, right) {
  const order = ['sample', 'map', 'test'];
  const labels = { sample: 'Sample', map: 'Map fields', test: 'Test and export' };
  const can = { sample: true, map: Boolean(state.plan), test: Boolean(state.parsers) };
  const idx = order.indexOf(current);
  const out = h('nav', { class: 'steps', 'aria-label': 'Steps' });
  order.forEach((s, i) => {
    if (i) out.append(h('span', { class: 'bar', 'aria-hidden': 'true' }));
    const cls = i < idx ? 'done' : i === idx ? 'on' : '';
    out.append(h('button', {
      class: `step ${cls}`, disabled: !can[s] || i === idx, 'aria-current': i === idx ? 'step' : null,
      onclick: () => go(`#/build/${s}`),
    }, h('i', { text: i < idx ? '✓' : String(i + 1) }), labels[s]));
  });
  if (right) out.append(h('span', { class: 'right' }, right));
  return out;
}

export function schemaPill(id, extra = '') {
  const s = schemaInfo(id);
  return pill(`${id}${extra}`, id === 'scwx.generic' ? 'grey' : s && s.documentedId ? 'blue' : 'blue');
}

export function levelDot(level) {
  return h('span', { class: `dot ${level === 'error' ? 'red' : level === 'warning' || level === 'inferred' ? 'amber' : level === 'ok' ? '' : 'grey'}`, 'aria-hidden': 'true' });
}

export const LEVEL_LABEL = { error: 'Error', warning: 'Warning', inferred: 'Inferred', info: 'Note' };

export function problemRow(p, onLine) {
  const where = [p.parser, p.line ? `line ${p.line}` : null].filter(Boolean).join(' ');
  const row = h('div', { class: 'prob' }, levelDot(p.level), h('span', { class: 'lvl pill p-' + (p.level === 'error' ? 'red' : p.level === 'info' ? 'grey' : 'amber'), text: LEVEL_LABEL[p.level] || p.level }));
  const body = h('span', {}, p.message);
  if (p.lines && p.lines.length) body.append(h('span', { class: 'where', text: `  sample line${p.lines.length > 1 ? 's' : ''} ${p.lines.slice(0, 8).join(', ')}${p.lines.length > 8 ? '…' : ''}` }));
  row.append(body);
  if (where) {
    const w = onLine && p.line ? h('button', { class: 'linkbtn where', onclick: () => onLine(p.parser, p.line), text: where }) : h('span', { class: 'where', text: where });
    row.append(w);
  }
  return row;
}

export const SHIP_LABELS = { syslog: 'Syslog to the data collector', 'http-ingest': 'HTTP Ingest', s3: 'Amazon S3', azure: 'Azure Event Hubs', other: 'Other' };
export const FORMAT_LABELS = { json: 'JSON', cef: 'CEF', leef: 'LEEF', kv: 'key=value', syslog: 'Plain syslog text', text: 'Plain text', csv: 'Delimited (CSV)', xml: 'XML', other: 'Other' };

// An entry's notes as labelled sections with bullets and paragraphs. Every block goes in as text.
export function notesView(text) {
  const box = h('div', { class: 'notes' });
  for (const b of noteBlocks(text)) {
    if (b.type === 'label') box.append(h('p', { class: 'nlabel' }, h('strong', { text: b.text })));
    else if (b.type === 'list') box.append(h('ul', {}, b.items.map((t) => h('li', { text: t }))));
    else box.append(h('p', { text: b.text }));
  }
  return box;
}

// The search box and Sort menu over a library list, then its cards: the same on Parsers, Rules,
// Playbooks and Connectors. section is parsers, rules, playbooks or connectors, text gives the text
// the search matches for an entry's metadata (and the entry), card draws an entry, and none is what
// an empty list says. filter, for Rules, adds controls under the search: {el, test(entry),
// subscribe(redraw), shown(list)}. Each list keeps its own search and sort while the tab is open.
export function searchList(root, { section, entries, placeholder, label, text, card, none, filter = null }) {
  const keep = state.lists[section] || (state.lists[section] = { q: '', sort: 'az' });
  const search = h('input', { class: 'input', type: 'search', placeholder, 'aria-label': label, value: keep.q });
  const sort = sortPicker(section, entries, keep.sort, () => { keep.sort = sort.value; draw(); });
  const cards = h('div', { class: 'cards' });
  root.append(h('div', { class: 'libtools' }, search, h('label', { class: 'sortpick' }, 'Sort', sort)));
  if (filter) root.append(filter.el);
  root.append(cards);
  const draw = () => {
    clear(cards);
    const q = keep.q.toLowerCase().trim();
    const list = entries.filter((e) => (!q || text(e.meta, e).includes(q)) && (!filter || filter.test(e)));
    if (filter && filter.shown) filter.shown(list);
    if (!list.length) { cards.append(h('p', { class: 'empty', text: state.library.status !== 'ready' ? 'Loading…' : entries.length ? 'No entries match.' : none })); return; }
    for (const e of sortEntries(list, sort.value, { section, ...stars.snapshot() })) cards.append(card(e));
  };
  search.addEventListener('input', () => { keep.q = search.value; draw(); });
  if (filter) filter.subscribe(draw);
  draw();
}

// The Sort menu. The sorts by count stay off until the counts load, and Newest when no entry has a
// date. The choice lasts while the tab is open, like the search.
function sortPicker(section, entries, chosen, onchange) {
  const can = (s) => !s.needs || (s.needs === 'stats' ? stars.ready() : entries.some((e) => e.added));
  const current = SORTS.find((s) => s.value === chosen && can(s)) ? chosen : 'az';
  const sel = h('select', { class: 'sortsel', dataset: { sort: section }, onchange });
  for (const s of SORTS) sel.append(h('option', { value: s.value, selected: s.value === current, disabled: !can(s), dataset: s.needs ? { needs: s.needs } : null, text: s.label }));
  return sel;
}
