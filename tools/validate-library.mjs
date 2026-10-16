#!/usr/bin/env node
// Validates library entries: for parsers, metadata, lint, the emulator against expected.json, the
// sample scan, and confirm-string overlap with the rest of the library; for playbooks and
// connectors, the checks in tools/lib/automation.mjs.
//
//   node tools/validate-library.mjs [--root <repo>] [--all | --changed-files <list.txt>]
//                                   [--base <base repo checkout>] [--author <github login>]
//                                   [--report <out.json>] [--markdown <out.md>]
//
// --all checks every entry. --changed-files checks the entries a pull request touches and
// decides whether it can merge without review. Exit code 1 when any checked entry fails.
// An entry's "bridge" must name a folder under bridges/ in --base when it is given (the base
// branch), otherwise in --root. The legacy "collector" key still works, with a warning. Connectors
// are checked against connectors/allowed-hosts.json from --base the same way, so a new host is
// reviewed and merged before a connector can call it. Playbooks and connectors never merge without
// a review.

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { loadLibrary, loadEntryFromDir, listBridges } from './lib/fs-library.mjs';
import { reviewReasons } from './lib/merge-rules.mjs';
import { validateEntry, vendorNames } from '../studio/core/library.js';
import { loadAutomation, loadAllowedHosts, connectorMap, ALLOWED_HOSTS } from './lib/fs-automation.mjs';
import { validateAutomation, checkAllowedHosts } from './lib/automation.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i === -1 ? null : args[i + 1]; };
const root = path.resolve(opt('--root') || '.');
const baseRoot = opt('--base') ? path.resolve(opt('--base')) : null;
const author = opt('--author');
const all = args.includes('--all');
const changedFile = opt('--changed-files');

const library = await loadLibrary(root);
const bridges = await listBridges(baseRoot || root);
// A sample may name a library vendor as a company, such as Microsoft Corporation. The names come
// from --base when it is given, so a pull request can't add to them.
const allowNames = vendorNames(baseRoot ? await loadLibrary(baseRoot) : library);
const report = { passed: true, eligible: false, reasons: [], outside: [], entries: [] };

const automation = await loadAutomation(root);
const allowedHosts = await loadAllowedHosts(baseRoot || root);
let autoTargets = [...automation.playbooks, ...automation.connectors];
let checkHosts = true;
let targets = library;
let changed = [];
if (changedFile) {
  // One path per line, kept exactly: trimming would read a top-level folder such as " parsers" as parsers/.
  changed = (await readFile(changedFile, 'utf8')).split(/\r?\n/).filter(Boolean);
  report.outside = changed.filter((f) => !f.startsWith('parsers/'));
  const ids = new Set();
  const deleted = new Set();
  for (const f of changed.filter((x) => x.startsWith('parsers/'))) {
    const parts = f.split('/');
    if (parts.length < 4) { report.reasons.push(`${f} is not inside parsers/<vendor>/<product>/`); report.passed = false; continue; }
    const id = `${parts[1]}/${parts[2]}`;
    if (existsSync(path.join(root, 'parsers', id))) ids.add(id); else deleted.add(id);
  }
  targets = library.filter((e) => ids.has(e.id));
  for (const id of deleted) report.entries.push({ id, status: 'deleted', ok: true, problems: [] });
  // Playbooks and connectors: <folder>/<vendor>/<name>/<file>, and the connector host allowlist.
  const autoIds = new Set();
  checkHosts = false;
  for (const f of changed.filter((x) => x.startsWith('playbooks/') || x.startsWith('connectors/'))) {
    if (f === ALLOWED_HOSTS) { checkHosts = true; continue; }
    const parts = f.split('/');
    if (parts.length < 4) { report.reasons.push(`${f} is not inside ${parts[0]}/<vendor>/<name>/`); report.passed = false; continue; }
    const id = `${parts[0]}/${parts[1]}/${parts[2]}`;
    if (existsSync(path.join(root, id))) autoIds.add(id);
    else if (!report.entries.some((e) => e.id === id)) report.entries.push({ id, status: 'deleted', ok: true, problems: [] });
  }
  // A changed connector checks again the playbooks that call it.
  for (const pb of automation.playbooks) if (pb.meta && typeof pb.meta.connector === 'string' && autoIds.has(pb.meta.connector)) autoIds.add(`playbooks/${pb.id}`);
  autoTargets = autoTargets.filter((e) => autoIds.has(`${e.folder}/${e.id}`));
} else if (!all) {
  console.error('pass --all or --changed-files <list>');
  process.exit(2);
}

for (const entry of targets) {
  let status = 'existing';
  let baseAuthor = null;
  if (baseRoot) {
    const baseDir = path.join(baseRoot, 'parsers', entry.id);
    if (existsSync(baseDir)) {
      const b = await loadEntryFromDir(baseDir, baseRoot);
      baseAuthor = b.meta && b.meta.author ? b.meta.author : null;
      status = 'changed';
    } else {
      status = 'new';
    }
  }
  const others = library.filter((e) => e.id !== entry.id);
  const v = entry.loadProblems.length ? { ok: false, problems: entry.loadProblems, results: [] } : validateEntry(entry, { library: others, bridges, allowNames });
  report.entries.push({
    id: entry.id, status, baseAuthor, author: entry.meta && entry.meta.author, ok: v.ok,
    problems: v.problems.map((p) => ({ level: p.level, code: p.code, file: p.file || null, line: p.line || null, message: p.message })),
    lines: v.results.length, normalized: v.results.filter((r) => r.normalized && r.schema !== 'scwx.generic').length,
  });
  if (!v.ok) report.passed = false;
}

if (checkHosts && existsSync(path.join(root, ALLOWED_HOSTS))) {
  let problems;
  try { problems = checkAllowedHosts(JSON.parse(await readFile(path.join(root, ALLOWED_HOSTS), 'utf8'))); } catch (e) { problems = [{ level: 'error', code: 'json', message: `${ALLOWED_HOSTS} is not valid JSON: ${e.message}`, file: 'allowed-hosts.json' }]; }
  report.entries.push({ id: ALLOWED_HOSTS, kind: 'allowlist', status: changedFile ? 'changed' : 'existing', ok: !problems.some((p) => p.level === 'error'), problems: problems.map((p) => ({ level: p.level, code: p.code, file: p.file || null, line: null, message: p.message })) });
  if (problems.some((p) => p.level === 'error')) report.passed = false;
}
if (allowedHosts.problem) { report.passed = false; report.reasons.push(allowedHosts.problem); }
const connectors = connectorMap(automation.connectors, allowedHosts.hosts);
for (const entry of autoTargets) {
  const full = `${entry.folder}/${entry.id}`;
  let status = 'existing';
  let baseAuthor = null;
  if (baseRoot) {
    const baseMeta = path.join(baseRoot, full, 'meta.json');
    if (existsSync(path.join(baseRoot, full))) {
      status = 'changed';
      try { baseAuthor = JSON.parse(await readFile(baseMeta, 'utf8')).author || null; } catch { baseAuthor = null; }
    } else {
      status = 'new';
    }
  }
  const v = validateAutomation(entry, { allowedHosts: allowedHosts.hosts, connectors, allowNames });
  report.entries.push({
    id: full, kind: entry.kind, status, baseAuthor, author: entry.meta && entry.meta.author, ok: v.ok,
    problems: v.problems.map((p) => ({ level: p.level, code: p.code, file: p.file || null, line: p.line || null, message: p.message })),
  });
  if (!v.ok) report.passed = false;
}

// Merge without review only when the PR touches nothing but library entries, every entry
// passes, and each changed entry already belongs to the PR author. Bridge code never merges
// without review.
if (changedFile) {
  const reasons = reviewReasons(changed);
  if (!report.entries.length) reasons.push('changes no library entries');
  for (const e of report.entries) {
    if (e.status === 'deleted') reasons.push(`deletes ${e.id}`);
    if (e.status === 'changed' && author && e.baseAuthor && e.baseAuthor.toLowerCase() !== author.toLowerCase()) reasons.push(`changes ${e.id}, which belongs to @${e.baseAuthor}`);
    if (e.status === 'changed' && author && e.author && e.baseAuthor && e.author.toLowerCase() !== e.baseAuthor.toLowerCase()) reasons.push(`changes the author of ${e.id}`);
    if (e.status === 'new' && author && e.author && e.author.toLowerCase() !== author.toLowerCase()) reasons.push(`${e.id} names @${e.author} as author but the pull request is from @${author}`);
  }
  if (!report.passed) reasons.push('checks failed');
  report.reasons.push(...reasons);
  report.eligible = report.passed && reasons.length === 0;
}

function markdown() {
  const lines = ['<!-- parser-studio-report -->', `### Library checks: ${report.passed ? 'passed' : 'failed'}`, ''];
  for (const e of report.entries) {
    const errors = e.problems.filter((p) => p.level === 'error');
    const warnings = e.problems.filter((p) => p.level === 'warning');
    lines.push(`**${e.id}** (${e.status}): ${e.ok ? 'passed' : 'failed'}${e.lines ? `, ${e.normalized} of ${e.lines} sample lines normalized` : ''}`);
    for (const p of errors) lines.push(`- Error${p.file ? ` in \`${p.file}\`` : ''}${p.line ? ` line ${p.line}` : ''}: ${p.message}`);
    for (const p of warnings.slice(0, 15)) lines.push(`- Warning${p.file ? ` in \`${p.file}\`` : ''}: ${p.message}`);
    if (warnings.length > 15) lines.push(`- ${warnings.length - 15} more warnings`);
    lines.push('');
  }
  if (changedFile) {
    lines.push(report.eligible ? 'This change only adds or updates its author\'s own library entries, and every library check passed, so it qualifies to merge without a review.' : `This change needs a maintainer review: ${report.reasons.join('; ') || 'see above'}.`);
  }
  lines.push('', report.entries.some((e) => e.kind === 'playbook' || e.kind === 'connector')
    ? 'Parser results come from the Parser Studio emulator, not from Sophos NG-SIEM. Playbook and connector checks are offline: validate a template in a tenant with playbookValidateDSLV2 before it ships.'
    : 'Results come from the Parser Studio emulator, not from Sophos NG-SIEM.');
  return lines.join('\n') + '\n';
}

if (opt('--report')) await writeFile(opt('--report'), JSON.stringify(report, null, 2) + '\n');
if (opt('--markdown')) await writeFile(opt('--markdown'), markdown());
process.stdout.write(markdown());
process.exit(report.passed ? 0 : 1);
