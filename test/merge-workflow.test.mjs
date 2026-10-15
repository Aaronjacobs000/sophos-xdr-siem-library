// The gate workflow for pull requests: the job that reads the pull request's files holds no write
// token, and the job that merges runs only the default branch's code and merges the checked commit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = await readFile(path.join(ROOT, '.github/workflows/parser-merge.yml'), 'utf8');
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
// Fetching the pull request's files, listing them, or running the checks on them.
const readsPullRequest = (lines) => lines.some((l) => /refs\/pull\/|validate-library\.mjs|github-gate\.mjs changed/.test(l));

test('merge workflow: the job that checks the pull request has a read-only token and keeps no credentials', () => {
  assert.deepEqual(writes(TOP), [], 'the workflow-wide token is read-only');
  const all = jobs();
  const readers = Object.entries(all).filter(([, lines]) => readsPullRequest(lines));
  assert.ok(readers.length > 0);
  for (const [name, lines] of readers) {
    assert.deepEqual(writes(effective(lines)), [], `${name} reads the pull request, so it can't write`);
    const checkouts = lines.filter((l) => /uses: actions\/checkout@/.test(l)).length;
    const noCredentials = lines.filter((l) => /^\s+persist-credentials: false\s*$/.test(l)).length;
    assert.equal(noCredentials, checkouts, `${name} keeps no credentials in its checkout`);
  }
  for (const [name, lines] of Object.entries(all)) {
    if (writes(effective(lines)).length) assert.ok(!readsPullRequest(lines), `${name} can write, so it doesn't read the pull request`);
  }
});

test('merge workflow: the job that merges runs trusted code on the checked commit', () => {
  const mergers = Object.entries(jobs()).filter(([, lines]) => lines.some((l) => /github-gate\.mjs pr /.test(l)));
  assert.equal(mergers.length, 1);
  const [name, lines] = mergers[0];
  // Trusted code only: one checkout, of the default branch, and the gate is the only script it runs.
  assert.equal(lines.filter((l) => /uses: actions\/checkout@/.test(l)).length, 1, name);
  assert.ok(!lines.some((l) => /^\s+ref:/.test(l)), `${name} checks out the default branch`);
  assert.ok(lines.some((l) => /^\s+persist-credentials: false\s*$/.test(l)), `${name} keeps no credentials in its checkout`);
  const scripts = lines.filter((l) => /\bnode\s/.test(l));
  assert.ok(scripts.length > 0 && scripts.every((l) => /node base\/tools\/github-gate\.mjs (pr|merge) /.test(l)), scripts.join('\n'));
  // The pinned head commit: the merge names the commit the checks ran on, from the event, and the
  // pull request number is matched to that commit in this job rather than taken from another one.
  assert.ok(lines.some((l) => /^\s+HEAD_SHA: \$\{\{ github\.event\.workflow_run\.head_sha \}\}\s*$/.test(l)));
  assert.ok(lines.some((l) => /github-gate\.mjs pr --pr "\$PR" --sha "\$HEAD_SHA" /.test(l)));
  assert.ok(lines.some((l) => /\[ "\$SHA" != "\$HEAD_SHA" \]/.test(l)), `${name} matches the pull request to the commit itself`);
  assert.ok(!lines.some((l) => /needs\.[a-z-]+\.outputs\.(number|author)/.test(l)), `${name} takes no pull request number from another job`);
});
