#!/usr/bin/env node
// Run the emulator from the command line.
//
//   node tools/emulate.mjs [--now <ISO time>] [--lint] <samples.log> <TOP.parser.txt> [CHILD.parser.txt ...]
//   node tools/emulate.mjs [--now <ISO time>] [--lint] --entry parsers/<vendor>/<product>
//
// With parser files, the first file is the top-level parser and the rest are its children,
// unless a file sets !PARENT. Prints one JSON result per sample line.

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { runParsers } from '../studio/core/engine.js';
import { lintParsers } from '../studio/core/lint.js';
import { loadEntryFromDir } from './lib/fs-library.mjs';

const args = process.argv.slice(2);
let now;
let lint = false;
let entry = null;
const rest = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--now') now = args[++i];
  else if (args[i] === '--lint') lint = true;
  else if (args[i] === '--entry') entry = args[++i];
  else rest.push(args[i]);
}

let parsers;
let samples;
if (entry) {
  const e = await loadEntryFromDir(entry);
  parsers = e.parsers;
  samples = e.samples;
  now = now || e.meta.reference_time;
} else {
  if (rest.length < 2) {
    console.error('usage: emulate.mjs [--now ISO] [--lint] <samples.log> <TOP.parser.txt> [CHILD.parser.txt ...]');
    process.exit(2);
  }
  samples = (await readFile(rest[0], 'utf8')).split(/\r?\n/).filter((l) => l.trim());
  const files = rest.slice(1);
  const topName = path.basename(files[0]).replace(/\.parser\.txt$|\.txt$/, '');
  parsers = await Promise.all(files.map(async (f, i) => {
    const name = path.basename(f).replace(/\.parser\.txt$|\.txt$/, '');
    const text = await readFile(f, 'utf8');
    const parent = i === 0 || /^!PARENT=/m.test(text) ? undefined : topName;
    return { name, text, parent };
  }));
}

const results = runParsers(parsers, samples, { now });
if (lint) {
  const report = lintParsers(parsers, { samples, now });
  console.log(JSON.stringify({ lint: report, results }, null, 2));
} else {
  console.log(JSON.stringify(results, null, 2));
}
