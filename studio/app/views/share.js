// "Share to the library": packages the parsers, samples, expected output and metadata, runs
// the same checks as the repo's CI, then hands off to GitHub. No backend and no token: the
// person submitting signs in to GitHub themselves.

import { h, clear, select, copyText, download, toast, ext } from '../dom.js';
import { state } from '../store.js';
import { call } from '../emulator-client.js';
import { libraryForLint, enginePayload } from './test.js';
import { problemRow, SHIP_LABELS, FORMAT_LABELS } from './common.js';
import { entryId, entryFiles, packBundle, expectedFrom, FORMATS, LICENSES } from '../../core/library.js';
import { makeZip } from '../../core/zip.js';
import { TOOL_VERSION, BRANCH } from '../../core/version.js';
import { githubUrl } from '../library-client.js';

const FORMAT_FROM_ANALYSIS = { json: 'json', cef: 'cef', leef: 'leef', kv: 'kv', csv: 'csv', xml: 'xml', text: 'syslog' };
const MAX_URL = 7500;

export function draftEntry(results) {
  const plan = state.plan;
  const origin = state.origin && state.origin.meta ? state.origin.meta : null;
  const meta = {
    vendor: (plan && plan.vendor) || state.source.vendor || (origin && origin.vendor) || '',
    product: (plan && plan.product) || state.source.product || (origin && origin.product) || '',
    versions: state.source.version ? [state.source.version] : origin ? origin.versions || [] : [],
    format: plan ? FORMAT_FROM_ANALYSIS[plan.format] || 'other' : origin ? origin.format : 'other',
    ship_method: state.source.shipMethod || (origin && origin.ship_method) || 'syslog',
    ...(origin && origin.collector ? { collector: origin.collector } : {}),
    author: state.shareAuthor || '',
    license: 'MIT',
    sample_source: 'synthetic',
    reference_time: state.now || new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    tested: { emulator: TOOL_VERSION, tenant: null },
    docs: origin && origin.docs ? [...origin.docs] : [],
    notes: origin && origin.notes ? origin.notes : '',
    parsers: state.parsers.map((p) => {
      const o = { name: p.name, file: `${p.name}.parser.txt`, role: p.role };
      if (p.parent) o.parent = p.parent;
      if (p.schema) o.schema = p.schema;
      return o;
    }),
  };
  if (state.origin && state.origin.kind === 'fork') meta.forked_from = state.origin.id;
  const texts = Object.fromEntries(state.parsers.map((p) => [p.name, p.text]));
  return { id: entryId(meta), meta, texts, samples: [...state.lines], expected: results ? expectedFrom(results) : [] };
}

export function openShare() {
  const entry = draftEntry(null);
  const m = entry.meta;
  const dlg = h('dialog', { 'aria-labelledby': 'share-h' });
  const body = h('div', { class: 'dlg' });
  dlg.append(body);
  document.body.append(dlg);
  dlg.addEventListener('close', () => dlg.remove());

  const field = (label, input, hint) => h('div', { class: 'field' }, h('label', { text: label }), input, hint ? h('div', { class: 'sub', text: hint }) : null);
  const vendor = h('input', { class: 'input', value: m.vendor });
  const product = h('input', { class: 'input', value: m.product });
  const versions = h('input', { class: 'input', value: m.versions.join(', '), placeholder: 'for example 11.1, 12' });
  const author = h('input', { class: 'input', value: m.author, placeholder: 'your-github-handle', autocomplete: 'username' });
  const format = select(FORMATS.map((f) => ({ value: f, label: FORMAT_LABELS[f] || f })), m.format, () => {}, { class: 'input' });
  const ship = select(Object.entries(SHIP_LABELS).map(([value, label]) => ({ value, label })), m.ship_method, () => {}, { class: 'input' });
  const license = select(LICENSES.map((l) => ({ value: l })), m.license, () => {}, { class: 'input' });
  const source = select([{ value: 'synthetic', label: 'Synthetic (made up)' }, { value: 'vendor-docs', label: 'From public vendor docs' }], m.sample_source, () => {}, { class: 'input' });
  const docs = h('textarea', { class: 'input', rows: '2', placeholder: 'https://vendor.example.com/docs/log-format (one per line)' });
  docs.value = m.docs.join('\n');
  const notes = h('textarea', { class: 'input', rows: '3', placeholder: 'How to set up the source, what the parsers cover, what they leave out.' });
  notes.value = m.notes;
  const synthetic = h('input', { type: 'checkbox' });
  const agree = h('input', { type: 'checkbox' });
  const results = h('div');
  const routes = h('div');

  body.append(
    h('h2', { id: 'share-h', text: 'Share to the library' }),
    h('p', { class: 'sub' }, 'The library lives in a public GitHub repo. The page packages your parsers with these details and runs the same checks as the repo, then you submit with your own GitHub account. ', ext(githubUrl('/blob/main/CONTRIBUTING.md'), 'How contributing works')),
    h('div', { class: 'fields' }, field('Vendor', vendor), field('Product', product)),
    h('div', { class: 'fields' }, field('Versions seen', versions), field('Your GitHub handle', author, 'Shown as the author. It must match the account you submit from.')),
    h('div', { class: 'fields' }, field('Log format', format), field('Shipped by', ship)),
    h('div', { class: 'fields' }, field('Samples are', source), field('License', license)),
    field('Vendor docs for the log format', docs),
    field('Notes', notes),
    h('label', { class: 'check' }, synthetic, h('span', { text: 'The samples are synthetic or copied from public vendor docs. They hold no customer data, real IP addresses, hostnames, user names, email addresses or keys.' })),
    h('label', { class: 'check' }, agree, h('span', {}, 'I agree to publish these parsers under the license above, in a public repo anyone can read.')),
    h('div', { class: 'actions' }, h('button', { class: 'btn primary', onclick: () => check(), text: 'Run the library checks' }), h('button', { class: 'btn quiet', onclick: () => dlg.close(), text: 'Close' })),
    results, routes);
  dlg.showModal();

  function collect() {
    state.shareAuthor = author.value.trim().replace(/^@/, '');
    Object.assign(m, {
      vendor: vendor.value.trim(), product: product.value.trim(),
      versions: versions.value.split(',').map((v) => v.trim()).filter(Boolean),
      author: state.shareAuthor, format: format.value, ship_method: ship.value, license: license.value, sample_source: source.value,
      docs: docs.value.split(/\s+/).map((d) => d.trim()).filter(Boolean), notes: notes.value.trim(),
      reference_time: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    });
    entry.id = entryId(m);
  }

  async function check() {
    collect();
    clear(results);
    clear(routes);
    if (!synthetic.checked || !agree.checked) {
      results.append(h('div', { class: 'callout' }, h('span', { text: 'Tick both boxes first. The library is public, so it only takes synthetic samples.' })));
      return;
    }
    results.append(h('p', { class: 'sub', text: 'Checking…' }));
    try {
      const run = await call('run', { parsers: enginePayload(), samples: entry.samples, now: m.reference_time });
      entry.expected = expectedFrom(run);
      const v = await call('validate', { entry: { ...entry, files: undefined }, library: libraryForLint().filter((e) => e.id !== entry.id) });
      clear(results);
      const errors = v.problems.filter((p) => p.level === 'error');
      const warnings = v.problems.filter((p) => p.level === 'warning');
      results.append(h('h3', { text: errors.length ? `${errors.length} problem${errors.length === 1 ? '' : 's'} to fix` : 'All library checks pass' }));
      const list = h('div', { class: 'problems' });
      for (const p of [...errors, ...warnings].slice(0, 30)) list.append(problemRow({ ...p, message: `${p.file ? `${p.file}: ` : ''}${p.message}` }));
      results.append(list);
      if (!errors.length) drawRoutes();
      else results.append(h('p', { class: 'sub', text: 'The repo runs these same checks on every submission and turns away anything with errors.' }));
    } catch (e) {
      clear(results);
      results.append(h('div', { class: 'callout' }, h('span', { text: e.message })));
    }
  }

  function drawRoutes() {
    clear(routes);
    const id = entry.id;
    const files = entryFiles({ ...entry, id: null });
    const zipName = `${id.replace('/', '--')}.zip`;
    const uploadUrl = githubUrl(`/upload/${BRANCH}/parsers/${id.split('/').map(encodeURIComponent).join('/')}`);
    const bundle = packBundle(entry);
    const issueBase = githubUrl('/issues/new');
    const params = new URLSearchParams({ template: 'parser-submission.yml', title: `Parser: ${m.vendor} ${m.product}`.slice(0, 120) });
    const withBundle = new URLSearchParams(params);
    withBundle.set('bundle', bundle);
    const prefill = `${issueBase}?${withBundle}`.length <= MAX_URL;
    const issueUrl = prefill ? `${issueBase}?${withBundle}` : `${issueBase}?${params}`;

    routes.append(h('h3', { text: 'Submit it' }), h('div', { class: 'routes' },
      h('div', { class: 'route' },
        h('h3', { text: 'Pull request in the browser' }),
        h('ol', {},
          h('li', {}, h('button', { class: 'linkbtn', onclick: () => { download(zipName, makeZip(files), 'application/zip'); toast(`Downloaded ${zipName}`); }, text: `Download ${zipName}` }), ' and unzip it.'),
          h('li', {}, ext(uploadUrl, 'Open the upload page'), ` for parsers/${id}. GitHub asks you to sign in and makes a fork for you.`),
          h('li', { text: 'Drag in all the unzipped files, then choose Propose changes and Create pull request.' })),
        h('p', { class: 'sub', text: 'The repo checks the pull request. When every check passes and the entry is new or yours, it can merge without waiting for a person.' })),
      h('div', { class: 'route' },
        h('h3', { text: 'Issue form, no git' }),
        h('ol', {},
          h('li', {}, h('button', { class: 'linkbtn', onclick: () => copyText(bundle, 'Copied the submission'), text: 'Copy the submission' }), prefill ? ' (the form is filled in for you too).' : '.'),
          h('li', {}, ext(issueUrl, 'Open the issue form'), prefill ? '.' : ' and paste the submission into the Submission box.'),
          h('li', { text: 'Submit the issue. A workflow checks it and opens the pull request for you.' })),
        h('p', { class: 'sub', text: 'You still need a free GitHub account to open an issue.' }))));
  }
}
