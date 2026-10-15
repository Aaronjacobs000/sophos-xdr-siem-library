// The issue-form workflow: the job that reads the issue holds no write token, and the job that
// writes takes only a library path and library file names from it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, mkdir, writeFile, readdir, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = await readFile(path.join(ROOT, '.github/workflows/issue-submission.yml'), 'utf8');
const LINES = WORKFLOW.split('\n');

// The lines of each job under jobs:, keyed by job name. The workflow uses two-space indents.
function jobs() {
  const start = LINES.indexOf('jobs:');
  const out = {};
  let name = null;
  for (const line of LINES.slice(start + 1)) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (m) { name = m[1]; out[name] = []; continue; }
    if (name && (line.startsWith('    ') || !line.trim())) out[name].push(line);
    else if (name && !line.startsWith('  #')) name = null;
  }
  return out;
}

// The scopes in the permissions: block that starts at the given indent, as [scope, access] pairs.
function permissions(lines, indent) {
  const at = lines.findIndex((l) => l === `${' '.repeat(indent)}permissions:`);
  if (at === -1) return null;
  const out = [];
  for (const l of lines.slice(at + 1)) {
    const m = new RegExp(`^ {${indent + 2}}([a-z-]+):\\s*(\\w+)\\s*$`).exec(l);
    if (!m) break;
    out.push([m[1], m[2]]);
  }
  return out;
}

const TOP = permissions(LINES.slice(0, LINES.indexOf('jobs:')), 0);
const effective = (lines) => permissions(lines, 4) ?? TOP;
const writes = (perms) => perms.filter(([, access]) => access === 'write');
const readsIssue = (lines) => lines.some((l) => /issue-submission\.mjs|validate-library\.mjs|github\.event\.issue\.body/.test(l));

test('issue workflow: the job that reads the issue has a read-only token and keeps no credentials', () => {
  assert.deepEqual(writes(TOP), [], 'the workflow-wide token is read-only');
  const all = jobs();
  const readers = Object.entries(all).filter(([, lines]) => readsIssue(lines));
  assert.ok(readers.length > 0);
  for (const [name, lines] of readers) {
    assert.deepEqual(writes(effective(lines)), [], `${name} reads the issue, so it can't write`);
    const checkouts = lines.filter((l) => /uses: actions\/checkout@/.test(l)).length;
    const noCredentials = lines.filter((l) => /^\s+persist-credentials: false\s*$/.test(l)).length;
    assert.equal(noCredentials, checkouts, `${name} keeps no credentials in its checkout`);
  }
  for (const [name, lines] of Object.entries(all)) {
    if (writes(effective(lines)).length) assert.ok(!readsIssue(lines), `${name} can write, so it doesn't read the issue`);
  }
});

// The publish job's guard: the part of "Open or update the pull request" before the branch is made.
function publishGuard() {
  const at = LINES.findIndex((l) => l.trim() === '- name: Open or update the pull request');
  const run = LINES.findIndex((l, i) => i > at && l.trim() === 'run: |');
  const indent = LINES[run].indexOf('run:') + 2;
  const body = [];
  for (const l of LINES.slice(run + 1)) {
    if (l.trim() && !l.startsWith(' '.repeat(indent))) break;
    body.push(l.slice(indent));
  }
  return body.join('\n').split('BRANCH="submission')[0];
}

async function guard(entry, extra) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-issue-'));
  const files = path.join(dir, 'sub', 'entry');
  await mkdir(files, { recursive: true });
  await mkdir(path.join(dir, 'ws', 'parsers'), { recursive: true });
  for (const f of ['meta.json', 'samples.log', 'expected.json', 'ACME_PULL_JSON_STANDALONE.parser.txt']) await writeFile(path.join(files, f), 'x\n');
  if (extra) await extra(files);
  const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', publishGuard()], {
    cwd: path.join(dir, 'ws'), encoding: 'utf8', env: { ...process.env, RUNNER_TEMP: dir, ENTRY: entry },
  });
  const written = r.status === 0 ? (await readdir(path.join(dir, 'ws', 'parsers', ...entry.split('/')))).sort() : null;
  await rm(dir, { recursive: true, force: true });
  return { status: r.status, out: r.stdout + r.stderr, written };
}

test('issue workflow: the publish job takes only a library path and library file names', { skip: process.platform === 'win32' }, async () => {
  const ok = await guard('acme/pull-api');
  assert.equal(ok.status, 0, ok.out);
  assert.deepEqual(ok.written, ['ACME_PULL_JSON_STANDALONE.parser.txt', 'expected.json', 'meta.json', 'samples.log']);
  for (const entry of ['../.github', 'acme/pull-api/x', '/tmp/x', 'Acme/pull-api', 'acme', '']) {
    const r = await guard(entry);
    assert.notEqual(r.status, 0, JSON.stringify(entry));
    assert.match(r.out, /not a library path/);
  }
  for (const [what, extra] of [
    ['a script', (d) => writeFile(path.join(d, 'run.sh'), 'echo hi\n')],
    ['a symlink', (d) => symlink('/etc/hosts', path.join(d, 'README.md'))],
    ['a folder', (d) => mkdir(path.join(d, 'nested'))],
  ]) {
    const r = await guard('acme/pull-api', extra);
    assert.notEqual(r.status, 0, what);
    assert.match(r.out, /a file a library entry can't have/, what);
  }
});
