#!/usr/bin/env node
// Builds the static site into _site/: the studio as is, the parsers/, rules/, playbooks/,
// connectors/ and bridges/ folders, and library-index.json, which lists every entry's metadata and
// files and every bridge's files. A rule entry is listed with its rules, read from rules.yaml, or its
// case rule's summary, and what the snapshot of Sophos's rules says about overlap. The page reads the index and the files next to it, so it needs nothing but this
// site. Each entry in the index carries the time it was added, from git history, when the checkout
// has its history (see tools/lib/added-dates.mjs). It also writes
// library-snapshot.json, the whole library and its bridges in one file. An entry with the legacy
// "collector" key is listed with it as "bridge". library-ids.json lists every entry as
// <section>/<vendor>/<name>, for the library API (library-api/) to check the ids it takes.
//
//   node tools/build-site.mjs [--out _site]

import { cp, lstat, mkdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { loadLibrary, loadBridges } from './lib/fs-library.mjs';
import { loadAutomation } from './lib/fs-automation.mjs';
import { loadRules, loadCoverage } from './lib/fs-rules.mjs';
import { parsedCaseRule, caseRuleTitles, sharedTechniques, coveragePatterns } from './lib/rules.mjs';
import { addedDates } from './lib/added-dates.mjs';
import { withBridgeKey } from '../studio/core/library.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const i = process.argv.indexOf('--out');
const OUT = path.resolve(ROOT, i === -1 ? '_site' : process.argv[i + 1]);

await rm(OUT, { recursive: true, force: true });
await mkdir(OUT, { recursive: true });
await cp(path.join(ROOT, 'studio'), OUT, { recursive: true });
// Plain files and folders only: a symlink is never published.
const plain = async (p) => { const s = await lstat(p); return s.isFile() || s.isDirectory(); };
for (const dir of ['parsers', 'rules', 'bridges', 'playbooks', 'connectors']) {
  if (existsSync(path.join(ROOT, dir))) await cp(path.join(ROOT, dir), path.join(OUT, dir), { recursive: true, filter: plain });
}

let sha = null;
try { sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a git checkout */ }
const generated = new Date().toISOString();
const library = await loadLibrary(ROOT);
const bridges = await loadBridges(ROOT);
const automation = await loadAutomation(ROOT);
const ruleEntries = await loadRules(ROOT);
const { coverage } = await loadCoverage(ROOT);
const added = addedDates(ROOT);
// A playbook or connector whose meta.json doesn't read as JSON is left out of the site.
const listed = (list, folder) => list.filter((e) => e.meta && typeof e.meta === 'object' && !Array.isArray(e.meta)).map((e) => ({ id: e.id, meta: e.meta, files: e.files.map((f) => f.path).sort(), added: added.get(`${folder}/${e.id}`) }));
// A rule entry as the page lists it. Detection entries carry their rules and the overlap the
// snapshot shows; case entries the rule's name, state, the rule names its filter takes and its template.
const { exact, patterns } = coveragePatterns(coverage);
function ruleListing(e) {
  const out = { id: e.id, meta: e.meta, files: e.files.map((f) => f.path).sort(), added: added.get(`rules/${e.id}`) };
  if (e.meta.kind === 'detection') {
    out.rules = (e.parsedRules || []).map((r) => ({ name: r.name, description: r.description, severity: r.severity, mitre: Array.isArray(r.mitre) ? r.mitre : [], enabled_by_default: r.enabled_by_default === true, query: r.query }));
    const types = Array.isArray(e.meta.sensor_types) ? e.meta.sensor_types : [];
    const s = coverage && coverage.schemas ? coverage.schemas[e.meta.schema] : null;
    out.overlap = {
      read: coverage ? coverage.read : null,
      schema_rules: s ? s.rules : null,
      any_sensor_rules: s ? s.any_sensor_rules : null,
      named: types.filter((t) => exact.has(String(t).toLowerCase()) || patterns.some((p) => p.schemaId === e.meta.schema && p.re.test(t))),
      techniques: [...new Set(out.rules.flatMap((r) => sharedTechniques(coverage, e.meta.schema, r.mitre)))],
    };
  } else {
    const c = parsedCaseRule(e);
    if (c) {
      out.case_rule = { name: c.rule.name, title: c.rule.title, state: c.rule.state, collects: caseRuleTitles(c.rule.filter), group_by: c.rule.group_by, template: { name: c.template.name, title: c.template.title, type: c.template.investigation && c.template.investigation.type, priority: c.template.investigation && c.template.investigation.priority } };
    }
  }
  return out;
}
const index = {
  generated,
  commit: sha,
  entries: library.map((e) => ({ id: e.id, meta: withBridgeKey(e.meta), files: e.files.map((f) => f.path), added: added.get(`parsers/${e.id}`) })),
  bridges: bridges.map((b) => ({ path: b.path, files: b.files })),
  rules: ruleEntries.filter((e) => e.meta && typeof e.meta === 'object' && !Array.isArray(e.meta) && ['detection', 'case'].includes(e.meta.kind)).map(ruleListing),
  playbooks: listed(automation.playbooks, 'playbooks'),
  connectors: listed(automation.connectors, 'connectors'),
};
const snapshot = {
  generated,
  commit: sha,
  entries: library.map((e) => ({ id: e.id, meta: withBridgeKey(e.meta), texts: e.texts, samples: e.samples, expected: e.expected, files: e.files.map((f) => f.path), vendor: e.meta.vendor, product: e.meta.product })),
  bridges,
};
await writeFile(path.join(OUT, 'library-index.json'), JSON.stringify(index));
await writeFile(path.join(OUT, 'library-snapshot.json'), JSON.stringify(snapshot));
const ids = [...index.entries.map((e) => `parsers/${e.id}`), ...index.rules.map((e) => `rules/${e.id}`), ...index.playbooks.map((e) => `playbooks/${e.id}`), ...index.connectors.map((e) => `connectors/${e.id}`)];
await writeFile(path.join(OUT, 'library-ids.json'), JSON.stringify({ generated, commit: sha, ids }));
await writeFile(path.join(OUT, '.nojekyll'), '');
const n = (k, one) => `${k} ${one}${k === 1 ? '' : 's'}`;
console.log(`built ${path.relative(ROOT, OUT)}: ${n(index.entries.length, 'library entry').replace('entrys', 'entries')}, ${n(index.rules.length, 'rule entry').replace('entrys', 'entries')}, ${n(index.playbooks.length, 'playbook')}, ${n(index.connectors.length, 'connector')}, ${n(bridges.length, 'bridge')}${sha ? ` at ${sha.slice(0, 7)}` : ''}`);
