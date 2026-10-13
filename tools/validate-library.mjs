#!/usr/bin/env node
// Validates library entries: metadata, lint, the emulator against expected.json, the sample
// scan, and confirm-string overlap with the rest of the library.
//
//   node tools/validate-library.mjs [--root <repo>] [--all | --changed-files <list.txt>]
//                                   [--base <base repo checkout>] [--author <github login>]
//                                   [--report <out.json>] [--markdown <out.md>]
//
// --all checks every entry. --changed-files checks the entries a pull request touches and
// decides whether it can merge without review. Exit code 1 when any checked entry fails.
// An entry's "collector" must name a folder under collectors/ in --base when it is given (the
// base branch), otherwise in --root.

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { loadLibrary, loadEntryFromDir, listCollectors } from './lib/fs-library.mjs';
import { reviewReasons } from './lib/merge-rules.mjs';
import { validateEntry } from '../studio/core/library.js';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i === -1 ? null : args[i + 1]; };
const root = path.resolve(opt('--root') || '.');
const baseRoot = opt('--base') ? path.resolve(opt('--base')) : null;
const author = opt('--author');
const all = args.includes('--all');
const changedFile = opt('--changed-files');

const library = await loadLibrary(root);
const collectors = await listCollectors(baseRoot || root);
const report = { passed: true, eligible: false, reasons: [], outside: [], entries: [] };

let targets = library;
let changed = [];
if (changedFile) {
  changed = (await readFile(changedFile, 'utf8')).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
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
  const v = entry.loadProblems.length ? { ok: false, problems: entry.loadProblems, results: [] } : validateEntry(entry, { library: others, collectors });
  report.entries.push({
    id: entry.id, status, baseAuthor, author: entry.meta && entry.meta.author, ok: v.ok,
    problems: v.problems.map((p) => ({ level: p.level, code: p.code, file: p.file || null, line: p.line || null, message: p.message })),
    lines: v.results.length, normalized: v.results.filter((r) => r.normalized && r.schema !== 'scwx.generic').length,
  });
  if (!v.ok) report.passed = false;
}

// Merge without review only when the PR touches nothing but library entries, every entry
// passes, and each changed entry already belongs to the PR author. Collector code never
// merges without review.
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
  const lines = ['<!-- parser-studio-report -->', `### Parser library checks: ${report.passed ? 'passed' : 'failed'}`, ''];
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
  lines.push('', 'Results come from the Parser Studio emulator, not from Sophos NG-SIEM.');
  return lines.join('\n') + '\n';
}

if (opt('--report')) await writeFile(opt('--report'), JSON.stringify(report, null, 2) + '\n');
if (opt('--markdown')) await writeFile(opt('--markdown'), markdown());
process.stdout.write(markdown());
process.exit(report.passed ? 0 : 1);
