#!/usr/bin/env node
// Turns an issue-form submission into library files, for the issue-submission workflow.
// The issue body is untrusted text: it is only parsed as JSON, and every file name is
// checked before anything is written.
//
//   node tools/issue-submission.mjs --body body.txt --author <login> --changed changed.txt [--root .]

import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { unpackBundle, entryFiles, slug, LIMITS } from '../studio/core/library.js';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i === -1 ? null : args[i + 1]; };
const root = path.resolve(opt('--root') || '.');
const author = (opt('--author') || '').trim();
const NAME = /^[A-Z0-9]+(?:_[A-Z0-9]+)+$/;

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

const body = await readFile(opt('--body'), 'utf8');
if (body.length > 65536) fail('The submission is too long for an issue. Use the pull request route instead.');
let entry;
try { entry = unpackBundle(body); } catch (e) { fail(`Couldn't read the submission: ${e.message}`); }

const meta = entry.meta;
if (!meta || typeof meta !== 'object') fail('The submission has no metadata.');
// The issue author is the author, whatever the bundle says.
meta.author = author;
const vendor = slug(meta.vendor);
const product = slug(meta.product);
if (!vendor || !product) fail('The submission needs a vendor and a product.');
if (!Array.isArray(meta.parsers) || !meta.parsers.length || meta.parsers.length > LIMITS.parsers) fail('The submission needs between 1 and 20 parsers.');
for (const p of meta.parsers) {
  if (!p || !NAME.test(String(p.name))) fail(`Parser name ${JSON.stringify(p && p.name)} must be UPPER_SNAKE_CASE.`);
  p.file = `${p.name}.parser.txt`;
  if (typeof entry.texts[p.name] !== 'string') fail(`The submission has no script for ${p.name}.`);
}
if (!Array.isArray(entry.samples) || !entry.samples.length) fail('The submission has no sample lines.');

const id = `${vendor}/${product}`;
const dir = path.join(root, 'parsers', vendor, product);
if (!dir.startsWith(path.join(root, 'parsers') + path.sep)) fail('Bad entry path.');
await rm(dir, { recursive: true, force: true });
await mkdir(dir, { recursive: true });
const files = entryFiles({ id: null, meta, texts: entry.texts, samples: entry.samples.map((l) => String(l).replace(/[\r\n]+/g, ' ')), expected: entry.expected });
const written = [];
for (const f of files) {
  if (f.path.includes('/') || f.path.includes('\\')) fail(`Bad file name ${f.path}.`);
  await writeFile(path.join(dir, f.path), f.content);
  written.push(`parsers/${id}/${f.path}`);
}
await writeFile(opt('--changed'), written.join('\n') + '\n');
console.log(`wrote ${written.length} files to parsers/${id}`);
console.log(`ENTRY_ID=${id}`);
