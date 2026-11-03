#!/usr/bin/env node
// Turns a playbook or connector issue-form submission into library files, for the
// automation-submission workflow. The issue body is untrusted text: it is only split into the
// form's fields, by the labels in this checkout's .github/ISSUE_TEMPLATE/<kind>-submission.yml.
// The folder is made of slugs, and only meta.json and the form's file fields are written.
//
//   node tools/automation-submission.mjs --kind playbook|connector --body body.txt --author <login> --changed changed.txt [--root .]

import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS } from './lib/yaml.mjs';
import { slug } from '../studio/core/library.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i === -1 ? null : args[i + 1]; };
const root = path.resolve(opt('--root') || '.');
const author = (opt('--author') || '').trim();
const kind = opt('--kind');

// What each form writes: the meta.json keys in the library's order, and the file each file field becomes.
const KINDS = {
  playbook: {
    folder: 'playbooks',
    name: (v) => v.title,
    meta: ['title', 'vendor', 'product', 'use_case', 'trigger', 'connections', 'requires', 'license', 'risk_tier', 'mdr_note', 'rollback', 'tested', 'connector', 'author', 'docs', 'summary', 'notes'],
    files: { yaml: 'template.yaml', setup: 'SETUP.md', readme: 'README.md' },
  },
  connector: {
    folder: 'connectors',
    name: (v) => v.product,
    meta: ['title', 'vendor', 'product', 'auth', 'functions', 'license', 'tested', 'author', 'docs', 'summary', 'notes'],
    files: { yaml: 'connector.yaml', readme: 'README.md' },
  },
};

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

if (!KINDS[kind]) fail('--kind must be playbook or connector');
const spec = KINDS[kind];

// The form's fields in order, as {id, label, render}.
const form = toJS(parseYaml(await readFile(path.join(REPO, '.github', 'ISSUE_TEMPLATE', `${kind}-submission.yml`), 'utf8')));
const fields = form.body.filter((b) => b.type !== 'markdown').map((b) => ({ id: b.id, label: b.attributes.label, render: b.attributes.render || null }));

const body = (await readFile(opt('--body'), 'utf8')).replace(/\r\n?/g, '\n');
if (body.length > 65536) fail('The submission is too long for an issue. Use the pull request route instead.');

// GitHub writes each field as "### <label>", a blank line, then the value. An empty optional field
// reads "_No response_", and a field with render is wrapped in a code fence.
const values = {};
let at = 0;
const text = `\n${body}`;
const starts = [];
for (const f of fields) {
  const head = `\n### ${f.label}\n`;
  const i = text.indexOf(head, at);
  if (i === -1) fail(`The issue has no "${f.label}" section. Open a new issue with the ${kind} form, or put the section back as the form wrote it.`);
  starts.push({ f, i, from: i + head.length });
  at = i + head.length;
}
starts.forEach((s, n) => {
  let v = text.slice(s.from, n + 1 < starts.length ? starts[n + 1].i : text.length).replace(/^\n+|\s+$/g, '');
  if (v === '_No response_') v = '';
  if (s.f.render && v.startsWith('```')) {
    const lines = v.split('\n');
    if (lines.length >= 2 && lines[lines.length - 1].trim() === '```') v = lines.slice(1, -1).join('\n').replace(/\s+$/, '');
  }
  values[s.f.id] = v;
});

const line = (v) => String(v || '').replace(/\s*\n\s*/g, ' ').trim();
const list = (v) => String(v || '').split('\n').map((l) => l.replace(/^\s*[-*]\s+/, '').trim()).filter(Boolean);

function tested() {
  const t = { validated: line(values.validated) || null, tenant: null };
  const run = line(values.tenant);
  if (run) {
    const m = /^(\d{4}-\d{2}-\d{2})[\s,]+([A-Za-z]{2}\d{2})$/.exec(run);
    if (!m) fail(`"Ran in a tenant on" must be a date and a data region, such as 2026-11-04 us01, or empty. It reads ${JSON.stringify(run.slice(0, 60))}.`);
    t.tenant = { date: m[1], region: m[2].toLowerCase() };
  }
  return t;
}

function functions() {
  const out = {};
  for (const l of list(values.functions)) {
    const m = /^([A-Za-z][A-Za-z0-9_]*)\s*:\s*(.+)$/.exec(l);
    if (!m) fail(`Each line under Functions must be a function name, a colon and a risk tier, such as "getDevice: lookup". This one isn't: ${JSON.stringify(l.slice(0, 80))}.`);
    out[m[1]] = m[2].trim();
  }
  return out;
}

const build = {
  title: () => line(values.title),
  vendor: () => line(values.vendor),
  product: () => line(values.product),
  use_case: () => line(values.use_case),
  trigger: () => line(values.trigger),
  connections: () => list(values.connections),
  requires: () => line(values.requires),
  license: () => line(values.license),
  risk_tier: () => line(values.risk_tier),
  mdr_note: () => line(values.mdr_note),
  rollback: () => line(values.rollback),
  tested,
  connector: () => line(values.connector).replace(/\/+$/, '') || null,
  author: () => author,
  docs: () => list(values.docs),
  summary: () => line(values.summary),
  notes: () => String(values.notes || '').split('\n').map((l) => l.replace(/\s+$/, '')).join('\n').trim(),
  auth: () => line(values.auth),
  functions,
};

const meta = {};
for (const k of spec.meta) meta[k] = build[k]();
if (!meta.notes) delete meta.notes;

const vendor = slug(meta.vendor);
const name = slug(spec.name(meta));
if (!vendor || !name) fail(`The submission needs a vendor and a ${kind === 'playbook' ? 'title' : 'product'} with letters or digits in them.`);

const id = `${spec.folder}/${vendor}/${name}`;
const dir = path.join(root, spec.folder, vendor, name);
if (!dir.startsWith(path.join(root, spec.folder) + path.sep)) fail('Bad entry path.');
const files = [{ path: 'meta.json', content: `${JSON.stringify(meta, null, 2)}\n` }];
for (const [field, file] of Object.entries(spec.files)) {
  if (values[field]) files.push({ path: file, content: `${values[field]}\n` });
}
await rm(dir, { recursive: true, force: true });
await mkdir(dir, { recursive: true });
const written = [];
for (const f of files) {
  await writeFile(path.join(dir, f.path), f.content);
  written.push(`${id}/${f.path}`);
}
await writeFile(opt('--changed'), written.join('\n') + '\n');
console.log(`wrote ${written.length} files to ${id}`);
console.log(`ENTRY_ID=${id}`);
