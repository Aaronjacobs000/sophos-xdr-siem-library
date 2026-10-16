#!/usr/bin/env node
// Builds the static site into _site/: the studio as is, the parsers/ and bridges/ folders, and
// library-index.json, which lists every entry's metadata and files and every bridge's files. The
// page reads the index and the files next to it, so it needs nothing but this site. It also writes
// library-snapshot.json, the whole library and its bridges in one file. An entry with the legacy
// "collector" key is listed with it as "bridge".
//
//   node tools/build-site.mjs [--out _site]

import { cp, lstat, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { loadLibrary, loadBridges } from './lib/fs-library.mjs';
import { withBridgeKey } from '../studio/core/library.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const i = process.argv.indexOf('--out');
const OUT = path.resolve(ROOT, i === -1 ? '_site' : process.argv[i + 1]);

await rm(OUT, { recursive: true, force: true });
await mkdir(OUT, { recursive: true });
await cp(path.join(ROOT, 'studio'), OUT, { recursive: true });
// Plain files and folders only: a symlink is never published.
const plain = async (p) => { const s = await lstat(p); return s.isFile() || s.isDirectory(); };
for (const dir of ['parsers', 'bridges']) await cp(path.join(ROOT, dir), path.join(OUT, dir), { recursive: true, filter: plain });

let sha = null;
try { sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a git checkout */ }
const generated = new Date().toISOString();
const library = await loadLibrary(ROOT);
const bridges = await loadBridges(ROOT);
const index = {
  generated,
  commit: sha,
  entries: library.map((e) => ({ id: e.id, meta: withBridgeKey(e.meta), files: e.files.map((f) => f.path) })),
  bridges: bridges.map((b) => ({ path: b.path, files: b.files })),
};
const snapshot = {
  generated,
  commit: sha,
  entries: library.map((e) => ({ id: e.id, meta: withBridgeKey(e.meta), texts: e.texts, samples: e.samples, expected: e.expected, files: e.files.map((f) => f.path), vendor: e.meta.vendor, product: e.meta.product })),
  bridges,
};
await writeFile(path.join(OUT, 'library-index.json'), JSON.stringify(index));
await writeFile(path.join(OUT, 'library-snapshot.json'), JSON.stringify(snapshot));
await writeFile(path.join(OUT, '.nojekyll'), '');
console.log(`built ${path.relative(ROOT, OUT)}: ${index.entries.length} library entries, ${bridges.length} bridge${bridges.length === 1 ? '' : 's'}${sha ? ` at ${sha.slice(0, 7)}` : ''}`);
