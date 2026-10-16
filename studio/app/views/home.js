import { h, pill } from '../dom.js';
import { state } from '../store.js';
import { githubUrl } from '../library-client.js';
import { SITE_NAME } from '../../core/version.js';

// The site's home: what the library holds, with a card for each section.
export function renderHome(root) {
  const L = state.library;
  const ready = L.status === 'ready';
  const parsers = L.entries.reduce((k, e) => k + ((e.meta && Array.isArray(e.meta.parsers)) ? e.meta.parsers.length : 0), 0);
  root.append(h('div', { class: 'libhead' },
    h('div', {}, h('h1', { text: SITE_NAME }), h('p', { class: 'sub', text: 'Custom parsers for Sophos NG-SIEM that people share, and Parser Studio to write and test your own in the browser. A personal project, not from Sophos.' })),
    h('div', { class: 'actions' }, h('a', { class: 'btn quiet', href: githubUrl(), target: '_blank', rel: 'noopener noreferrer', text: 'The repo on GitHub' }))));
  const cards = h('div', { class: 'cards' });
  cards.append(
    section('#/parsers', 'Library', 'Parsers', 'Custom parsers for Sophos NG-SIEM, each with synthetic samples and the emulator\'s expected output. Open one to read it, test it against your own lines, or fork it.',
      ready ? `${L.entries.length} entries · ${parsers} parsers` : 'Loading…'),
    section('#/build/sample', 'Tool', 'Parser Studio', 'Write a custom parser in your browser: paste sample lines, map the fields, and test the scripts in an emulator of the parser language. Then share them to the library.',
      'Runs in this tab. Nothing is uploaded.'));
  root.append(cards);
  root.append(h('div', { class: 'callout blue' }, pill('Read first', 'blue'), h('span', { text: 'Everything here is a starting point that people share. Test a parser with Run Test in your own Sophos Fusion tenant before you turn it on. Sophos does not maintain or support any of it.' })));
}

function section(href, kind, title, text, foot) {
  return h('a', { class: 'card', href },
    h('span', { class: 'vendor', text: kind }),
    h('h2', { text: title }),
    h('span', { class: 'sub', text }),
    h('span', { class: 'foot2' }, h('span', { text: foot })));
}
