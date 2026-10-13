#!/usr/bin/env node
// Writes expected.json for library entries from the emulator's current output.
// Run it after you change a parser or its samples, then read the diff before you commit.
//
//   node tools/update-expected.mjs parsers/<vendor>/<product> [...]

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { loadEntryFromDir } from './lib/fs-library.mjs';
import { runParsers } from '../studio/core/engine.js';
import { expectedFrom } from '../studio/core/library.js';

const dirs = process.argv.slice(2);
if (!dirs.length) {
  console.error('usage: update-expected.mjs parsers/<vendor>/<product> [...]');
  process.exit(2);
}
for (const dir of dirs) {
  const e = await loadEntryFromDir(dir);
  const results = runParsers(e.parsers, e.samples, { now: e.meta.reference_time });
  await writeFile(path.join(dir, 'expected.json'), JSON.stringify(expectedFrom(results), null, 2) + '\n');
  const errors = results.filter((r) => r.error).length;
  console.log(`${dir}: ${results.length} lines, ${results.filter((r) => r.normalized).length} normalized, ${errors} errors`);
  for (const r of results) for (const n of r.notes) if (n.level !== 'info') console.log(`  line ${r.line} ${n.level}: ${n.message}`);
}
