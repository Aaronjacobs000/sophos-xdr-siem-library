// Playbooks and connectors: lists, and a page for each with its metadata, setup steps and YAML.
// The page shows the files as they are in the library; there is no editor.

import { h, clear, pill, ext, copyText, toast, download } from '../dom.js';
import { state } from '../store.js';
import { loadAutomationEntry, githubUrl } from '../library-client.js';
import { renderMarkdown } from '../markdown.js';

const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const TIER_PILL = { lookup: 'green', notify: 'blue', 'reversible action': 'amber', destructive: 'red' };
const TIERS = {
  lookup: 'Reads data and changes nothing.',
  notify: 'Sends a message or adds a comment, and changes nothing else.',
  'reversible action': 'Changes something on a device or account that can be undone, such as a lock.',
  destructive: 'Changes something that can\'t be undone. Needs a recorded run in a real tenant before it can be in the library.',
};
const KIND = {
  playbooks: { one: 'playbook', file: 'template.yaml', title: 'Playbooks', sub: 'Sophos Fusion playbook templates that people share. Each one ships with dry run on, and you set up its trigger and connections in your tenant.' },
  connectors: { one: 'connector', file: 'connector.yaml', title: 'Connectors', sub: 'Custom connectors for Sophos Fusion playbooks, for products that have no connector from Sophos. Each one calls only hosts its vendor documents.' },
};

const tierPill = (t) => pill(t || 'no tier', TIER_PILL[t] || 'grey');
function testedText(t, folder) {
  if (t && t.tenant && t.tenant.date) return `Ran in a tenant in the ${t.tenant.region} region on ${t.tenant.date}.`;
  if (t && t.validated) return folder === 'playbooks' ? `Passed playbookValidateDSLV2 in a tenant on ${t.validated}. Not run in a tenant yet.` : `Imported into a tenant on ${t.validated}. Not run against the product yet.`;
  return 'Not validated in a tenant yet.';
}
const testedPill = (t) => (t && t.tenant && t.tenant.date ? pill(`tenant-tested ${t.tenant.date}`, 'green') : t && t.validated ? pill('validated, not run', 'amber') : pill('untested', 'grey'));

function readFirst(kind) {
  return h('div', { class: 'callout' }, pill('Read first', 'amber'), h('span', { text: kind === 'playbooks'
    ? 'Playbooks act on your tenant. Every one here ships with dry run on, and its configured playbook stays off until you turn it on. Sophos doesn\'t make, maintain or support them. Import it, run it against a test target, and read what it did before you rely on it.'
    : 'A connector calls an outside API with a credential you store in Sophos Fusion. Give the credential the least role that works. Sophos doesn\'t make, maintain or support these connectors.' }));
}

export function renderAutomationList(root, folder) {
  const k = KIND[folder];
  const L = state.library;
  root.append(h('div', { class: 'libhead' },
    h('div', {}, h('h1', { text: k.title }), h('p', { class: 'sub', text: k.sub })),
    h('div', { class: 'actions' }, h('a', { class: 'btn quiet', href: githubUrl(`/tree/main/${folder}`), target: '_blank', rel: 'noopener noreferrer', text: 'Browse on GitHub' }))));
  root.append(readFirst(folder));
  const cards = h('div', { class: 'cards' });
  root.append(cards);
  const list = L[folder] || [];
  if (!list.length) cards.append(h('p', { class: 'empty', text: L.status === 'ready' ? `No ${folder} yet.` : 'Loading…' }));
  for (const e of list) cards.append(folder === 'playbooks' ? playbookCard(e) : connectorCard(e));
  if (folder === 'playbooks') root.append(tierLegend());
}

function playbookCard(e) {
  const m = e.meta;
  const a = h('a', { class: 'card', href: `#/playbooks/${e.id}` });
  a.append(h('span', { class: 'vendor', text: `${m.vendor} · ${m.product}` }), h('h2', { text: m.title }));
  const pills = h('span', { class: 'pills' }, tierPill(m.risk_tier));
  if (m.connector) pills.append(pill('needs a library connector', 'cyan'));
  a.append(pills, h('span', { class: 'sub', text: m.use_case }));
  a.append(h('span', { class: 'foot2' }, h('span', { text: HANDLE.test(m.author || '') ? `@${m.author}` : '' }), testedPill(m.tested)));
  return a;
}

function connectorCard(e) {
  const m = e.meta;
  const a = h('a', { class: 'card', href: `#/connectors/${e.id}` });
  a.append(h('span', { class: 'vendor', text: m.vendor }), h('h2', { text: m.title }));
  const tiers = [...new Set(Object.values(m.functions || {}))];
  const pills = h('span', { class: 'pills' }, pill(`${Object.keys(m.functions || {}).length} functions`, 'grey'));
  for (const t of tiers) pills.append(tierPill(t));
  a.append(pills, h('span', { class: 'sub', text: m.auth }));
  a.append(h('span', { class: 'foot2' }, h('span', { text: HANDLE.test(m.author || '') ? `@${m.author}` : '' }), testedPill(m.tested)));
  return a;
}

function tierLegend() {
  const row = (t) => h('div', { class: 'lgrow' }, tierPill(t), h('span', { text: TIERS[t] }));
  return h('div', { class: 'legend' }, h('h3', { text: 'What the risk tiers mean' }), ...Object.keys(TIERS).map(row),
    h('p', { class: 'sub', text: 'The library\'s checks work out the least tier from the functions a playbook calls, so an entry can\'t claim less. Wipe-type actions are refused for now.' }));
}

export function renderAutomationEntry(root, folder, id) {
  const k = KIND[folder];
  const e = (state.library[folder] || []).find((x) => x.id === id);
  root.append(h('div', { class: 'libhead' }, h('div', {}, h('a', { href: `#/${folder}`, text: `← ${k.title}` }))));
  if (!e) {
    root.append(h('p', { class: 'empty', text: state.library.status === 'ready' ? `No ${k.one} ${id}.` : 'Loading the library…' }));
    return;
  }
  const holder = h('div', {}, h('p', { class: 'empty', text: `Loading the ${k.one}…` }));
  root.append(holder);
  loadAutomationEntry(folder, e)
    .then(() => { clear(holder); (folder === 'playbooks' ? drawPlaybook : drawConnector)(holder, e); })
    .catch((err) => { clear(holder); holder.append(h('div', { class: 'callout' }, h('span', { text: `Couldn't load ${id}: ${err.message}` }))); });
}

function kv(rows) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of rows) if (v !== null && v !== undefined && v !== '') dl.append(h('dt', { text: k }), h('dd', {}, v));
  return dl;
}

function docsLinks(m) {
  if (!Array.isArray(m.docs) || !m.docs.length) return null;
  const d = h('span');
  m.docs.filter((u) => /^https:\/\//.test(u)).forEach((u, i) => { if (i) d.append(h('br')); d.append(ext(u, u.replace(/^https:\/\//, '').slice(0, 70))); });
  return d;
}

// The YAML with Copy and Download, as it is in the library: import this file as it is.
function yamlPanel(folder, e, file) {
  const text = e.texts[file] || '';
  const code = h('pre', { class: 'code codeview yamlview', tabindex: '0', 'aria-label': file });
  code.textContent = text;
  return h('section', { class: 'panel yamlpanel', 'aria-label': file },
    h('div', { class: 'editortools' }, h('h2', { text: file }), h('span', { class: 'btnrow' },
      h('button', { class: 'btn quiet small', onclick: () => copyText(text, `Copied ${file}`), text: 'Copy' }),
      h('button', { class: 'btn primary small', onclick: () => { download(`${e.id.replace('/', '-')}-${file}`, text, 'application/yaml'); toast(`Downloaded ${file}`); }, text: 'Download' }))),
    h('p', { class: 'sub', text: `Import this file as it is. ${folder === 'playbooks' ? 'A single-quoted value in a template is text and anything else is an expression, so don\'t let an editor rewrite the quoting.' : 'Your credential goes in the connection, never in this file.'}` }),
    code);
}

function mdPanel(title, text, base) {
  return h('section', { class: 'panel mdpanel' }, h('h2', { text: title }), h('div', { class: 'mdview' }, renderMarkdown(text, { base })));
}

function steps(items) {
  const ol = h('ol', { class: 'steps-list' });
  for (const s of items) ol.append(h('li', { text: s }));
  return ol;
}

function drawPlaybook(root, e) {
  const m = e.meta;
  root.append(h('div', { class: 'libhead' }, h('div', {}, h('span', { class: 'sub', text: `${m.vendor} · ${m.product}` }), h('h1', { text: m.title })),
    h('div', { class: 'actions' }, tierPill(m.risk_tier), testedPill(m.tested))));
  root.append(readFirst('playbooks'));
  const connector = m.connector ? (state.library.connectors || []).find((c) => `connectors/${c.id}` === m.connector) : null;
  const grid = h('div', { class: 'grid g-entry' });
  root.append(grid);
  const left = h('section', { class: 'panel' }, h('h2', { text: 'About this playbook' }), kv([
    ['Use case', m.use_case],
    ['Risk tier', h('span', {}, tierPill(m.risk_tier), ' ', TIERS[m.risk_tier] || '')],
    ['Trigger to set', m.trigger],
    ['Connections', Array.isArray(m.connections) ? h('ul', { class: 'plain' }, ...m.connections.map((c) => h('li', { text: c }))) : null],
    ['Library connector', m.connector ? (connector ? h('a', { href: `#/${m.connector}`, text: connector.meta.title }) : m.connector) : 'None'],
    ['Requires', m.requires],
    ['MDR', m.mdr_note],
    ['Rollback', m.rollback],
    ['Tested', testedText(m.tested, 'playbooks')],
    ['Author', HANDLE.test(m.author || '') ? ext(`https://github.com/${m.author}`, `@${m.author}`) : 'unknown'],
    ['License', m.license],
    ['Docs', docsLinks(m)],
  ]));
  if (m.notes) left.append(h('p', { class: 'sub', text: m.notes }));
  left.append(h('p', { class: 'sub' }, ext(githubUrl(`/tree/main/playbooks/${e.id}`), 'View the files on GitHub')));
  const right = h('section', { class: 'panel' }, h('h2', { text: 'Import it' }), steps([
    m.connector ? 'Import the library connector it needs under Security Operations > Automations > Connectors > Connector Library > Import, then add a connection to it.' : 'Check you have a connection for each connector it lists.',
    'Download template.yaml below and import it under Security Operations > Automations > Playbooks > Templates > Import.',
    'Choose Use this Template, set it up as the steps below say, and leave the playbook off.',
    'Run it once against a test target with dry run on, read what it did, then turn it on.',
  ]));
  grid.append(left, right);
  if (e.texts['SETUP.md']) root.append(mdPanel('Setup', e.texts['SETUP.md'], githubUrl(`/blob/main/playbooks/${e.id}/`)));
  root.append(yamlPanel('playbooks', e, 'template.yaml'));
  if (e.texts['README.md']) root.append(mdPanel('README', e.texts['README.md'], githubUrl(`/blob/main/playbooks/${e.id}/`)));
}

function drawConnector(root, e) {
  const m = e.meta;
  root.append(h('div', { class: 'libhead' }, h('div', {}, h('span', { class: 'sub', text: m.vendor }), h('h1', { text: m.title })),
    h('div', { class: 'actions' }, testedPill(m.tested))));
  root.append(readFirst('connectors'));
  const fns = h('table', { class: 'rec fntable' });
  for (const [f, t] of Object.entries(m.functions || {})) fns.append(h('tr', {}, h('td', { text: f }), h('td', {}, tierPill(t))));
  const usedBy = (state.library.playbooks || []).filter((p) => p.meta.connector === `connectors/${e.id}`);
  const grid = h('div', { class: 'grid g-entry' });
  root.append(grid);
  const left = h('section', { class: 'panel' }, h('h2', { text: 'About this connector' }), kv([
    ['Product', m.product],
    ['Sign-in', m.auth],
    ['Tested', testedText(m.tested, 'connectors')],
    ['Used by', usedBy.length ? h('span', {}, ...usedBy.flatMap((p, i) => [i ? ', ' : '', h('a', { href: `#/playbooks/${p.id}`, text: p.meta.title })])) : 'No library playbook yet'],
    ['Author', HANDLE.test(m.author || '') ? ext(`https://github.com/${m.author}`, `@${m.author}`) : 'unknown'],
    ['License', m.license],
    ['Docs', docsLinks(m)],
  ]), h('h3', { text: 'Functions' }), fns);
  if (m.notes) left.append(h('p', { class: 'sub', text: m.notes }));
  left.append(h('p', { class: 'sub' }, ext(githubUrl(`/tree/main/connectors/${e.id}`), 'View the files on GitHub')));
  const right = h('section', { class: 'panel' }, h('h2', { text: 'Import it' }), steps([
    'Download connector.yaml below and import it under Security Operations > Automations > Connectors > Connector Library > Import.',
    'Add a connection to it with your own credential, as its README says.',
    'Use Test on the connection, then import the playbooks that use it.',
  ]));
  grid.append(left, right);
  if (e.texts['README.md']) root.append(mdPanel('README', e.texts['README.md'], githubUrl(`/blob/main/connectors/${e.id}/`)));
  root.append(yamlPanel('connectors', e, 'connector.yaml'));
}
