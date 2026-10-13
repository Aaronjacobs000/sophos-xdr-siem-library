import { h, pill } from '../dom.js';
import { state } from '../store.js';
import { go } from '../nav.js';
import { schemaInfo } from '../../core/schemas.js';

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
