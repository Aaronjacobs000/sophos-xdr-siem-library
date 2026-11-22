// Rules: the list, with filters, and a page for each detection rule set and case rule. Also the
// "Rules for this source" panel on a parser entry's page and the rule hits for its tester. The page
// shows the files as they are in the library; nothing here talks to a tenant.

import { h, clear, pill, ext, copyText, toast, download } from '../dom.js';
import { state } from '../store.js';
import { loadRuleEntry, loadEntry, githubUrl } from '../library-client.js';
import { renderMarkdown } from '../markdown.js';
import { notesView, searchList } from './common.js';
import { starSlot, popularSlot } from '../stars.js';
import { compileRules, ruleHits, ruleSearchText, testedState, SEVERITIES, SEVERITY_BANDS } from '../../core/rules.js';
import { qlName } from '../../core/ql.js';

const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const SEV_PILL = { critical: 'red', high: 'amber', medium: 'grey', low: 'grey', informational: 'grey' };
const SEV_NAME = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational' };
const sevPill = (s) => pill(SEV_NAME[s] || s, SEV_PILL[s] || 'grey');
const kindPill = (k) => (k === 'case' ? pill('case rule', 'cyan') : pill('detection rules', 'blue'));
const testedPill = (m) => { const t = testedState(m); return pill(t.label, t.tone); };
const author = (m) => (HANDLE.test(m.author || '') ? `@${m.author}` : '');
const parserOf = (m) => (m && typeof m.parser === 'string' ? state.library.entries.find((e) => `parsers/${e.id}` === m.parser) || null : null);
const parserName = (m) => { const p = parserOf(m); return p ? `${p.meta.vendor} ${p.meta.product}` : (m && m.parser) || 'unknown'; };
const ruleById = (path) => (state.library.rules || []).find((r) => `rules/${r.id}` === path) || null;
const order = (list) => [...list].sort((a, b) => SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b));

function readFirst(kind) {
  return h('div', { class: 'callout' }, pill('Read first', 'amber'), h('span', { text: kind === 'case'
    ? 'Your tenant\'s case rules run before your partner\'s and stop at the first match, so a broad rule can take detections other rules were meant to handle. Library case rules take only their own custom detections, ship in Test state, and open cases Managed By Self, which Sophos MDR doesn\'t work.'
    : kind === 'detection'
      ? 'Rules create detections in your tenant. Sophos MDR doesn\'t work custom detections. A rule that makes more than 5,000 detections in an hour, or 100,000 in a day, is turned off and its author emailed. Run each query in Data Lake Search before you add the rule.'
      : 'Rules create detections and cases in your tenant. Sophos MDR doesn\'t work custom detections, and cases your own case rules open are Managed By Self. Run a rule\'s query in Data Lake Search before you add it, and leave a case rule in Test state until its Rule Logs look right. Sophos doesn\'t make, maintain or support these rules.' }));
}

// ---------------------------------------------------------------- the list

const FILTERS = { kind: 'all', schema: '', severity: '', parser: '', tested: '' };

export function renderRulesList(root) {
  const L = state.library;
  const all = L.rules || [];
  root.append(h('div', { class: 'libhead' },
    h('div', {}, h('h1', { text: 'Rules' }), h('p', { class: 'sub', text: 'Custom detection rules and automatic case rules for sources that reach Sophos NG-SIEM through a library parser. Each entry names the parser it needs, the sample lines that trigger it, and how many detections to expect.' })),
    h('div', { class: 'actions' }, h('a', { class: 'btn quiet', href: githubUrl('/tree/main/rules'), target: '_blank', rel: 'noopener noreferrer', text: 'Browse on GitHub' }))));
  root.append(readFirst('list'));
  const keep = state.lists.rulesFilter || (state.lists.rulesFilter = { ...FILTERS });
  const listeners = [];
  const changed = () => listeners.forEach((fn) => fn());
  const select = (key, label, options) => {
    const sel = h('select', { class: 'sortsel', 'aria-label': label, onchange: () => { keep[key] = sel.value; changed(); } });
    for (const [value, text] of options) sel.append(h('option', { value, selected: keep[key] === value, text }));
    return h('label', { class: 'sortpick' }, label, sel);
  };
  const count = (k) => all.filter((e) => k === 'all' || e.meta.kind === k).length;
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Kind' });
  const segs = [['all', 'All'], ['detection', 'Detection rules'], ['case', 'Case rules']].map(([k, label]) => {
    const b = h('button', { type: 'button', class: keep.kind === k ? 'on' : '', 'aria-pressed': String(keep.kind === k), onclick: () => { keep.kind = k; segs.forEach((x) => { x.classList.toggle('on', x.dataset.kind === k); x.setAttribute('aria-pressed', String(x.dataset.kind === k)); }); changed(); }, dataset: { kind: k } }, label, h('span', { class: 'n', text: String(count(k)) }));
    seg.append(b);
    return b;
  });
  const schemas = [...new Set(all.map((e) => e.meta.schema).filter(Boolean))].sort();
  const parsers = [...new Set(all.map((e) => e.meta.parser).filter(Boolean))].sort();
  const bar = h('div', { class: 'filterbar' }, seg,
    select('schema', 'Schema', [['', 'Any schema'], ...schemas.map((s) => [s, s])]),
    select('severity', 'Severity', [['', 'Any severity'], ...SEVERITIES.map((s) => [s, SEV_NAME[s]])]),
    select('parser', 'Source', [['', 'Any library parser'], ...parsers.map((p) => [p, parserName({ parser: p })])]),
    select('tested', 'Tested', [['', 'Any'], ['tenant', 'Ran in a tenant'], ['search', 'Search-tested'], ['offline', 'Offline checks only']]));
  const line = h('p', { class: 'resultline' });
  const sevOf = (e) => (e.meta.kind === 'case' ? collectedSeverities(e) : (e.rules || []).map((r) => r.severity));
  const test = (e) => (keep.kind === 'all' || e.meta.kind === keep.kind)
    && (!keep.schema || e.meta.schema === keep.schema)
    && (!keep.severity || sevOf(e).includes(keep.severity))
    && (!keep.parser || e.meta.parser === keep.parser)
    && (!keep.tested || testedState(e.meta).key === keep.tested);
  const summary = (list) => {
    const rules = list.reduce((k, e) => k + (e.rules ? e.rules.length : 0), 0);
    const ps = new Set(list.map((e) => e.meta.parser)).size;
    line.textContent = L.status !== 'ready' ? '' : `${list.length} ${list.length === 1 ? 'entry' : 'entries'} with ${rules} rule${rules === 1 ? '' : 's'}, for ${ps} library parser${ps === 1 ? '' : 's'}`;
  };
  searchList(root, { section: 'rules', entries: all, placeholder: 'Search source, title, schema, technique or author', label: 'Search the rules', text: (m, e) => ruleSearchText(m, e && e.rules), card: ruleCard, none: 'No rules yet.',
    filter: { el: h('div', {}, bar, line), test, subscribe: (fn) => listeners.push(fn), shown: summary } });
  root.append(h('div', { class: 'callout blue' }, pill('Scope', 'blue'), h('span', { text: 'Only sources that come in through a library parser, matched on that parser\'s sensor type. Sophos\'s own detectors cover its products and built-in integrations, and its IP Watchlist, Domain Watchlist and DGA detectors already run on custom-parsed addresses and domains, so there are no rules for those here.' })));
}

// The severities of the detection rules a case entry collects.
function collectedSeverities(e) {
  const d = ruleById(e.meta.links && e.meta.links.detection_rules);
  const names = new Set((e.case_rule && e.case_rule.collects) || []);
  return d ? (d.rules || []).filter((r) => names.has(r.name)).map((r) => r.severity) : [];
}

function ruleCard(e) {
  const m = e.meta;
  const a = h('a', { class: 'card', href: `#/rules/${e.id}` });
  a.append(h('span', { class: 'vendor', text: `${m.vendor} · ${m.product}` }), h('h2', { text: m.title }));
  const pills = h('span', { class: 'pills' }, popularSlot(`rules/${e.id}`), kindPill(m.kind));
  if (m.kind === 'detection') {
    if (m.schema) pills.append(pill(m.schema, 'blue'));
    for (const s of order([...new Set((e.rules || []).map((r) => r.severity))])) pills.append(sevPill(s));
  } else if (e.case_rule) {
    pills.append(pill(e.case_rule.state === 'TEST' ? 'Test state' : e.case_rule.state, 'amber'));
  }
  pills.append(pill('self-managed', 'grey'));
  a.append(pills);
  if (m.kind === 'detection') {
    const on = (e.rules || []).filter((r) => r.enabled_by_default).length;
    a.append(h('span', { class: 'sub', text: `${(e.rules || []).length} rule${(e.rules || []).length === 1 ? '' : 's'} (${on} on by default). Needs the ${parserName(m)} parser.` }));
    const first = (e.rules || [])[0];
    if (first) a.append(h('span', { class: 'query', text: first.query.replace(/\s+/g, ' ') }));
  } else {
    a.append(h('span', { class: 'sub', text: m.summary || '' }));
  }
  a.append(h('span', { class: 'foot2' }, h('span', { text: author(m) }), testedPill(m)));
  return h('div', { class: 'cardwrap' }, a, starSlot(`rules/${e.id}`, m.title));
}

// ---------------------------------------------------------------- an entry

export function renderRuleEntry(root, id) {
  const e = (state.library.rules || []).find((x) => x.id === id);
  root.append(h('div', { class: 'libhead' }, h('div', {}, h('a', { href: '#/rules', text: '← Rules' }))));
  if (!e) {
    root.append(h('p', { class: 'empty', text: state.library.status === 'ready' ? `No rule entry ${id}.` : 'Loading the library…' }));
    return;
  }
  const holder = h('div', {}, h('p', { class: 'empty', text: 'Loading the rules…' }));
  root.append(holder);
  loadRuleEntry(e)
    .then(() => { clear(holder); (e.meta.kind === 'case' ? drawCase : drawDetection)(holder, e); })
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

function testedText(m) {
  const t = m.tested || {};
  if (t.tenant && t.tenant.date) return `Ran live in a tenant in the ${t.tenant.region} region on ${t.tenant.date}${t.search ? `, and each query returned its sample lines in Data Lake Search on ${t.search}` : ''}.`;
  if (t.search) return `Offline checks passed. Each query returned its sample lines, and only them, in Data Lake Search on ${t.search}. Not yet run as a live rule.`;
  return m.kind === 'case' ? 'The case rule checks passed. Not yet installed in a tenant.' : 'Offline checks passed: the rules ran on the parser\'s samples in the emulator. Not yet run in a tenant.';
}

function head(e, extra = []) {
  const m = e.meta;
  return h('div', { class: 'libhead' }, h('div', {}, h('span', { class: 'sub', text: `${m.vendor} · ${m.product}` }), h('h1', { text: m.title })),
    h('div', { class: 'actions' }, kindPill(m.kind), ...extra, pill('self-managed', 'grey'), testedPill(m), starSlot(`rules/${e.id}`, m.title)));
}

function copyBox(label, text) {
  return h('div', { class: 'qbox' }, h('div', { class: 'editortools' }, h('span', { class: 'lbl', text: label }), h('span', { class: 'btnrow' }, h('button', { class: 'btn quiet small', onclick: () => copyText(text, 'Copied the query'), text: 'Copy' }))),
    h('pre', { class: 'code qcode', text }));
}

function overlapText(e) {
  const o = e.overlap;
  if (!o || !o.read) return null;
  if (o.named && o.named.length) return `Sophos's own rules name sensor types like ${o.named.join(', ')}. Check Sophos doesn't already detect this.`;
  if (o.techniques && o.techniques.length) return `Sophos rules on ${e.meta.schema} that match every sensor type share ${o.techniques.join(', ')}. Check Detector Explorer before you add the rules.`;
  return `None found: no Sophos rule names sensor type ${(e.meta.sensor_types || []).join(', ')}, and the ${o.any_sensor_rules} Sophos rules on ${e.meta.schema} that match every sensor type share no technique with these (snapshot of ${o.read}).`;
}

function drawDetection(root, e) {
  const m = e.meta;
  const rules = e.rules || [];
  const parser = parserOf(m);
  const caseRule = m.links && m.links.case_rule ? ruleById(m.links.case_rule) : null;
  const playbooks = (m.links && Array.isArray(m.links.playbooks) ? m.links.playbooks : []).map((p) => (state.library.playbooks || []).find((x) => `playbooks/${x.id}` === p)).filter(Boolean);
  root.append(head(e), readFirst('detection'));
  const grid = h('div', { class: 'grid g-entry' });
  root.append(grid);
  const on = rules.filter((r) => r.enabled_by_default).length;
  const left = h('section', { class: 'panel' }, h('h2', { text: 'About these rules' }), m.summary ? h('p', { class: 'lead', text: m.summary }) : null, kv([
    ['Needs', h('span', {}, parser ? h('a', { href: `#/${m.parser}`, text: parserName(m) }) : m.parser, ' parser, sensor type ', h('span', { class: 'mono', text: (m.sensor_types || []).join(', ') }))],
    ['Schema', m.schema],
    ['Rules', `${rules.length} (${on} on by default, ${rules.length - on} off)`],
    ['Volume', m.volume],
    ['MDR', m.mdr_note],
    ['Sophos overlap', overlapText(e)],
    ['Case rule', caseRule ? h('a', { href: `#/rules/${caseRule.id}`, text: caseRule.meta.title }) : null],
    ['Playbooks', playbooks.length ? h('span', {}, ...playbooks.flatMap((p, i) => [i ? ', ' : '', h('a', { href: `#/playbooks/${p.id}`, text: p.meta.title })])) : null],
    ['Tested', testedText(m)],
    ['Author', HANDLE.test(m.author || '') ? ext(`https://github.com/${m.author}`, `@${m.author}`) : 'unknown'],
    ['License', m.license],
    ['Docs', docsLinks(m)],
  ]));
  if (typeof m.notes === 'string' && m.notes.trim()) left.append(notesView(m.notes));
  left.append(h('p', { class: 'sub' }, ext(githubUrl(`/tree/main/rules/${e.id}`), 'View the files on GitHub')));
  const check = `FROM ${qlName(m.schema)} WHERE sensor_type = '${(m.sensor_types || [''])[0]}' EARLIEST=-7d`;
  const right = h('section', { class: 'panel' }, h('h2', { text: 'Add them to your tenant' }), h('ol', { class: 'steps-list' },
    h('li', {}, 'Add the ', parser ? h('a', { href: `#/${m.parser}`, text: parserName(m) }) : m.parser, ' parser and check events arrive with the search below.'),
    h('li', { text: 'Run each rule\'s query in Security Operations > Data Lake Search over 7 days and check the count fits the volume above.' }),
    h('li', { text: 'Go to Security Operations > Rules > Create Rule. Paste the rule criteria, then set the name, MITRE categories, description and severity shown for that rule. The rule turns on when you save it.' }),
    rules.some((r) => !r.enabled_by_default) ? h('li', { text: 'Leave the rules marked off by default out until you have checked their volume.' }) : null,
    caseRule ? h('li', {}, 'To group the detections into cases, add ', h('a', { href: `#/rules/${caseRule.id}`, text: 'the case rule' }), ' as well.') : null),
  copyBox('Check your data first', check),
  h('div', { class: 'callout blue' }, pill('No import', 'blue'), h('span', { text: 'Sophos Fusion has no export or import for custom detection rules, so each one is added by hand from the fields below.' })));
  grid.append(left, right);
  const tests = parseTests(e.texts['tests.json']);
  const lines = (name) => (tests && tests.triggers && Array.isArray(tests.triggers[name]) ? tests.triggers[name] : []);
  const list = h('div', { class: 'rules' });
  for (const r of rules) {
    const box = h('div', { class: `rule${r.enabled_by_default ? '' : ' off'}` },
      h('div', { class: 'rulehead' }, h('h3', { text: r.name }), h('span', { class: 'pills' }, sevPill(r.severity), r.enabled_by_default ? pill('on by default', 'green') : pill('off by default', 'grey'))),
      h('p', { class: 'sub', text: r.description }),
      copyBox('Rule criteria', r.query),
      kv([
        ['Severity', `${SEV_NAME[r.severity] || r.severity} (${SEVERITY_BANDS[r.severity] || ''})`],
        ['MITRE ATT&CK', r.mitre && r.mitre.length ? h('span', {}, ...r.mitre.flatMap((t, i) => [i ? ', ' : '', ext(`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`, t)])) : 'None set'],
        ['Triggers on', lines(r.name).length ? `Sample line${lines(r.name).length === 1 ? '' : 's'} ${lines(r.name).join(', ')}` : 'No sample line'],
      ]));
    list.append(box);
  }
  root.append(h('section', { class: 'panel rulespanel' }, h('h2', { text: 'Rules in this entry' }), list));
  const table = h('section', { class: 'panel rulespanel' }, h('h2', { text: 'Sample lines and what they trigger' }),
    h('p', { class: 'sub', text: 'From the parser entry\'s samples.log, parsed by the emulator. The checks run every rule on every line: each line must trigger the rule shown and nothing else, and the quiet lines must trigger nothing.' }));
  const body = h('div', {}, h('p', { class: 'empty', text: 'Loading the samples…' }));
  table.append(body);
  root.append(table);
  if (parser) {
    loadEntry(parser).then(() => { clear(body); body.append(samplesTable(parser, rules, tests)); })
      .catch((err) => { clear(body); body.append(h('p', { class: 'empty', text: `Couldn't load the samples: ${err.message}` })); });
  } else { clear(body); body.append(h('p', { class: 'empty', text: 'The parser entry is not in the library.' })); }
  if (e.texts['README.md']) root.append(h('section', { class: 'panel mdpanel' }, h('h2', { text: 'README' }), h('div', { class: 'mdview' }, renderMarkdown(e.texts['README.md'], { base: githubUrl(`/blob/main/rules/${e.id}/`) }))));
}

function parseTests(text) {
  try { return JSON.parse(text || 'null'); } catch { return null; }
}

// Each sample line with the event the parser made of it and the rule it triggers. The rules run on
// the records in expected.json, which the parser checks hold to the emulator's output.
function samplesTable(parser, rules, tests) {
  const results = (parser.expected || []).map((x) => ({ line: x.line, schema: x.schema, normalized: x.normalized }));
  const hits = ruleHits(compileRules(rules), results);
  const quiet = new Set(tests && Array.isArray(tests.quiet) ? tests.quiet : []);
  const t = h('table', { class: 'samples' }, h('thead', {}, h('tr', {}, h('th', { text: 'Line' }), h('th', { text: 'Event' }), h('th', { text: 'Triggers' }))));
  const tb = h('tbody');
  results.forEach((r, i) => {
    const n = r.normalized || {};
    const what = n.title || n.summary || (r.schema === 'scwx.generic' ? 'Kept generic' : r.schema);
    tb.append(h('tr', {}, h('td', { text: String(i + 1) }), h('td', { text: what }), h('td', { text: hits[i].length ? hits[i].join(', ') : quiet.has(i + 1) ? 'none: must not trigger' : 'none' })));
  });
  t.append(tb);
  return h('div', { class: 'tablewrap' }, t);
}

function drawCase(root, e) {
  const m = e.meta;
  const c = e.case_rule || {};
  const det = m.links && m.links.detection_rules ? ruleById(m.links.detection_rules) : null;
  root.append(head(e, [pill(c.state === 'TEST' ? 'Test state' : c.state || 'state unknown', 'amber')]), readFirst('case'));
  const grid = h('div', { class: 'grid g-entry' });
  root.append(grid);
  const left = h('section', { class: 'panel' }, h('h2', { text: 'About this case rule' }), m.summary ? h('p', { class: 'lead', text: m.summary }) : null, kv([
    ['Collects', det ? h('span', {}, h('a', { href: `#/rules/${det.id}`, text: det.meta.title }), `: ${(c.collects || []).join(', ')}`) : (c.collects || []).join(', ')],
    ['Groups by', (c.group_by || []).every((g) => /alertSourceIPs/.test(g)) && (c.group_by || []).length ? 'Source IP, with the rule\'s name added so other case rules can\'t add to these cases' : h('span', { class: 'mono', text: (c.group_by || []).join(', ') })],
    ['Case', c.template ? `${c.template.type === 'SECURITY_INVESTIGATION' ? 'Security Case' : c.template.type}, priority ${c.template.priority}, template ${c.template.name}, no assignee` : null],
    ['Ships as', 'Test state'],
    ['Scope', 'One tenant, or a partner for every child tenant'],
    ['MDR', m.mdr_note],
    ['Tested', testedText(m)],
    ['Author', HANDLE.test(m.author || '') ? ext(`https://github.com/${m.author}`, `@${m.author}`) : 'unknown'],
    ['License', m.license],
    ['Docs', docsLinks(m)],
  ]));
  if (typeof m.notes === 'string' && m.notes.trim()) left.append(notesView(m.notes));
  left.append(h('p', { class: 'sub' }, ext(githubUrl(`/tree/main/rules/${e.id}`), 'View the files on GitHub')));
  const tool = `node tools/case-rule-install.mjs rules/${e.id} --env-file <path> --install`;
  const right = h('section', { class: 'panel' }, h('h2', { text: 'Install it' }), h('ol', { class: 'steps-list' },
    h('li', {}, 'Add the ', det ? h('a', { href: `#/rules/${det.id}`, text: det.meta.title }) : 'detection', ' rules first.'),
    h('li', { text: 'Install the case rule with the library\'s install tool, from a clone of the repo and an API credential for the tenant. It imports case-rule.yaml, rule and template together, then saves the rule once more with updateCaseRule and no change. An imported rule stayed inactive in a lab tenant until that second save.' }),
    h('li', { text: 'Or import case-rule.yaml under Security Operations > Cases > Automatic Cases > + Import, then open the rule and save it. Whether that Save does what the tool\'s second save does is unchecked.' }),
    h('li', { text: 'Import puts the rule after your own case rules, so it moves none of them. Set the template\'s assignee if you want one.' }),
    h('li', { text: 'Leave it in Test for a day and read Rule Logs, then set it to Enabled.' })),
  copyBox('Install with the tool', tool),
  h('h3', { text: 'What the file doesn\'t carry' }),
  h('ul', { class: 'moves' }, h('li', { text: 'The assignee: user IDs differ in every tenant.' }), h('li', { text: 'Managed By: Sophos Fusion sets Self for cases from your own rules.' }), h('li', { text: 'The order: import puts the rule last.' }), h('li', { text: 'Rule Logs, audit history and the cases it opened.' })));
  grid.append(left, right);
  const text = e.texts['case-rule.yaml'] || '';
  const code = h('pre', { class: 'code codeview yamlview', tabindex: '0', 'aria-label': 'case-rule.yaml' });
  code.textContent = text;
  root.append(h('section', { class: 'panel yamlpanel', 'aria-label': 'case-rule.yaml' },
    h('div', { class: 'editortools' }, h('h2', { text: 'case-rule.yaml' }), h('span', { class: 'btnrow' },
      h('button', { class: 'btn quiet small', onclick: () => copyText(text, 'Copied case-rule.yaml'), text: 'Copy' }),
      h('button', { class: 'btn primary small', onclick: () => { download(`${e.id.replace('/', '-')}-case-rule.yaml`, text, 'application/yaml'); toast('Downloaded case-rule.yaml'); }, text: 'Download' }))),
    h('p', { class: 'sub', text: 'In the format Automatic Cases exports: the rule, then its case template.' }), code));
  if (e.texts['README.md']) root.append(h('section', { class: 'panel mdpanel' }, h('h2', { text: 'README' }), h('div', { class: 'mdview' }, renderMarkdown(e.texts['README.md'], { base: githubUrl(`/blob/main/rules/${e.id}/`) }))));
}

// ---------------------------------------------------------------- on a parser entry's page

export function rulesFor(parserId) {
  return (state.library.rules || []).filter((r) => r.meta.parser === `parsers/${parserId}`);
}

export function rulesPanel(parserEntry) {
  const list = rulesFor(parserEntry.id);
  if (!list.length) return null;
  const types = [...new Set(list.flatMap((r) => r.meta.sensor_types || []))];
  const links = h('div', { class: 'links' });
  for (const r of list) {
    const pills = h('span', { class: 'pills' }, kindPill(r.meta.kind));
    if (r.meta.kind === 'detection') for (const s of order([...new Set((r.rules || []).map((x) => x.severity))])) pills.append(sevPill(s));
    else pills.append(pill('Test state', 'amber'));
    pills.append(testedPill(r.meta));
    const n = (r.rules || []).length;
    const d = r.meta.kind === 'detection' ? `${n} detection rule${n === 1 ? '' : 's'}: ${(r.rules || []).map((x) => x.name).join('; ')}` : r.meta.summary;
    links.append(h('a', { class: 'linkrow', href: `#/rules/${r.id}` }, h('span', {}, h('span', { class: 't', text: r.meta.title }), h('span', { class: 'd', text: d })), pills));
  }
  return h('section', { class: 'panel rulespanel' }, h('div', { class: 'bridgehead' }, h('h2', { text: 'Rules for this source' }), pill(`${list.length} entr${list.length === 1 ? 'y' : 'ies'}`, 'blue')),
    h('p', { class: 'sub', text: `These rules match this parser's sensor type, ${types.join(', ')}. Add the parser first.` }), links);
}

// The rule hits for lines the tester ran: every library rule for this parser, on the emulator's
// records. Returns the panel, or null when no rule entry needs this parser.
export function ruleHitsPanel(parserId, results) {
  const entries = rulesFor(parserId).filter((r) => r.meta.kind === 'detection');
  if (!entries.length) return null;
  const compiled = entries.flatMap((r) => compileRules(r.rules || []).map((c) => ({ ...c, entry: r })));
  const hits = ruleHits(compiled, results);
  const byName = new Map(compiled.map((c) => [c.name, c]));
  const t = h('table', { class: 'samples' }, h('thead', {}, h('tr', {}, h('th', { text: 'Line' }), h('th', { text: 'Rule it triggers' }), h('th', { text: 'Severity' }))));
  const tb = h('tbody');
  results.forEach((r, i) => {
    const names = hits[i];
    const c = names.length ? byName.get(names[0]) : null;
    tb.append(h('tr', {}, h('td', { text: String(i + 1) }), h('td', {}, names.length ? names.flatMap((n, k) => [k ? ', ' : '', h('a', { href: `#/rules/${byName.get(n).entry.id}`, text: n })]) : 'none'), h('td', { text: c ? SEV_NAME[c.severity] || c.severity : '' })));
  });
  t.append(tb);
  const n = hits.filter((x) => x.length).length;
  return h('div', { class: 'rulehits' }, h('h3', { text: `Library rules: ${n} of ${results.length} line${results.length === 1 ? '' : 's'} trigger one` }), h('div', { class: 'tablewrap' }, t),
    h('p', { class: 'sub', text: 'The same check the repo runs, on the emulator\'s records. Sophos\'s rule engine is the authority: run each query in Data Lake Search before you add a rule.' }));
}

