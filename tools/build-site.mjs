#!/usr/bin/env node
// Builds the static site into _site/: the studio as is, plus library-snapshot.json, a copy of
// the library and its bridges that the page falls back to when it can't reach GitHub. An entry
// with the legacy "collector" key is copied with it as "bridge".
//
//   node tools/build-site.mjs [--out _site]

import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
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

let sha = null;
try { sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a git checkout */ }
const library = await loadLibrary(ROOT);
const bridges = await loadBridges(ROOT);
const snapshot = {
  generated: new Date().toISOString(),
  commit: sha,
  entries: library.map((e) => ({ id: e.id, meta: withBridgeKey(e.meta), texts: e.texts, samples: e.samples, expected: e.expected, files: e.files.map((f) => f.path), vendor: e.meta.vendor, product: e.meta.product })),
  bridges,
};
await writeFile(path.join(OUT, 'library-snapshot.json'), JSON.stringify(snapshot));
await writeFile(path.join(OUT, '.nojekyll'), '');
console.log(`built ${path.relative(ROOT, OUT)}: ${snapshot.entries.length} library entries, ${bridges.length} bridge${bridges.length === 1 ? '' : 's'}${sha ? ` at ${sha.slice(0, 7)}` : ''}`);
