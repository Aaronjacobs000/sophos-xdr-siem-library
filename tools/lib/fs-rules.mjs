// Node helpers to read rule entries, and the snapshot of Sophos's own rule coverage, from disk.

import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { parsedRules, COVERAGE } from './rules.mjs';

async function exists(p) {
  try { await stat(p); return true; } catch { return false; }
}

// Reads rules/<vendor>/<name>. Only regular files are read; anything else is reported, and bad
// meta.json JSON is reported rather than thrown. Each entry carries its parsed rules, when it has
// a rules.yaml that reads, for the checks on other entries that link to it.
export async function loadRuleEntry(dir, root) {
  const abs = path.resolve(dir);
  const files = [];
  const loadProblems = [];
  for (const d of await readdir(abs, { withFileTypes: true })) {
    if (!d.isFile()) {
      loadProblems.push({ level: 'error', code: 'files', message: `${d.name} is not a regular file. Entries hold plain files only.`, file: d.name });
      continue;
    }
    files.push({ path: d.name, content: await readFile(path.join(abs, d.name), 'utf8') });
  }
  let meta = null;
  const m = files.find((f) => f.path === 'meta.json');
  if (m) {
    try { meta = JSON.parse(m.content); } catch (e) { loadProblems.push({ level: 'error', code: 'json', message: `meta.json is not valid JSON: ${e.message}`, file: 'meta.json' }); }
  }
  const id = path.relative(path.join(root, 'rules'), abs).split(path.sep).join('/');
  const entry = { id, dir: abs, files, meta, loadProblems };
  const list = parsedRules(entry);
  entry.parsedRules = list;
  entry.ruleNames = list ? list.map((r) => r.name).filter((n) => typeof n === 'string') : [];
  return entry;
}

export async function listRuleDirs(root) {
  const base = path.join(root, 'rules');
  if (!(await exists(base))) return [];
  const out = [];
  for (const v of await readdir(base, { withFileTypes: true })) {
    if (!v.isDirectory()) continue;
    for (const p of await readdir(path.join(base, v.name), { withFileTypes: true })) {
      if (p.isDirectory()) out.push(path.join(base, v.name, p.name));
    }
  }
  return out.sort();
}

export async function loadRules(root) {
  return Promise.all((await listRuleDirs(root)).map((d) => loadRuleEntry(d, root)));
}

// The coverage snapshot, or null with a problem when it is missing or isn't JSON.
export async function loadCoverage(root) {
  const p = path.join(root, COVERAGE);
  if (!(await exists(p))) return { coverage: null, problem: null };
  try {
    return { coverage: JSON.parse(await readFile(p, 'utf8')), problem: null };
  } catch (e) {
    return { coverage: null, problem: `${COVERAGE} is not valid JSON: ${e.message}` };
  }
}
