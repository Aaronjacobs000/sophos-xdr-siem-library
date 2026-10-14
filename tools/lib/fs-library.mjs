// Node helpers to read library entries from disk.

import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { parseSamples, bridgeScripts } from '../../studio/core/library.js';

async function exists(p) {
  try { await stat(p); return true; } catch { return false; }
}

// Reads parsers/<vendor>/<product>. Bad JSON is reported, not thrown, so CI can explain it.
export async function loadEntryFromDir(dir, root = null) {
  const abs = path.resolve(dir);
  const names = (await readdir(abs, { withFileTypes: true })).map((d) => (d.isDirectory() ? `${d.name}/` : d.name));
  const files = [];
  for (const n of names) {
    if (n.endsWith('/')) { files.push({ path: n, content: '' }); continue; }
    files.push({ path: n, content: await readFile(path.join(abs, n), 'utf8') });
  }
  const get = (n) => (files.find((f) => f.path === n) || {}).content;
  const loadProblems = [];
  let meta = null;
  try { meta = JSON.parse(get('meta.json') ?? 'null'); } catch (e) { loadProblems.push({ level: 'error', code: 'json', message: `meta.json is not valid JSON: ${e.message}`, file: 'meta.json' }); }
  let expected = [];
  try { expected = JSON.parse(get('expected.json') ?? '[]'); } catch (e) { loadProblems.push({ level: 'error', code: 'json', message: `expected.json is not valid JSON: ${e.message}`, file: 'expected.json' }); }
  const texts = {};
  for (const f of files) if (f.path.endsWith('.parser.txt')) texts[f.path.replace(/\.parser\.txt$/, '')] = f.content;
  const id = root ? path.relative(path.join(root, 'parsers'), abs).split(path.sep).join('/') : abs.split(path.sep).slice(-2).join('/');
  const samples = parseSamples(get('samples.log') ?? '');
  const parsers = meta && Array.isArray(meta.parsers)
    ? meta.parsers.map((p) => ({ name: p.name, text: texts[p.name] ?? '', parent: p.parent || undefined, role: p.role }))
    : [];
  return { id, dir: abs, meta: meta || {}, texts, samples, expected, files, parsers, loadProblems, vendor: meta && meta.vendor, product: meta && meta.product };
}

// Every entry directory: parsers/<vendor>/<product>.
export async function listEntryDirs(root) {
  const base = path.join(root, 'parsers');
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

export async function loadLibrary(root) {
  const dirs = await listEntryDirs(root);
  return Promise.all(dirs.map((d) => loadEntryFromDir(d, root)));
}

// Every bridge folder, bridges/<name>, with the names of the files directly in it.
export async function listBridges(root) {
  const base = path.join(root, 'bridges');
  if (!(await exists(base))) return [];
  const out = [];
  for (const d of await readdir(base, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    const files = (await readdir(path.join(base, d.name), { withFileTypes: true })).filter((f) => f.isFile()).map((f) => f.name).sort();
    out.push({ path: `bridges/${d.name}`, files });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

// Bridges with the text the studio shows: the README and the scripts, not the tests.
export async function loadBridges(root) {
  return Promise.all((await listBridges(root)).map(async (b) => {
    const dir = path.join(root, b.path);
    const readme = b.files.includes('README.md') ? await readFile(path.join(dir, 'README.md'), 'utf8') : '';
    const scripts = await Promise.all(bridgeScripts(b.files).map(async (name) => ({ name, text: await readFile(path.join(dir, name), 'utf8') })));
    return { ...b, readme, scripts };
  }));
}
