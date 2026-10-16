// The workflow that takes the gate's "needs review" label off a pull request the owner merged: it
// runs no code from the pull request or the repo, can only change labels, and removes that one
// label, only when the gate added it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, mkdir, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = await readFile(path.join(ROOT, '.github/workflows/review-label.yml'), 'utf8');
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

// One step of a job, found by name: its env values and the body of its run: block.
function jobStep(lines, name) {
  const at = lines.findIndex((l) => l.trim() === `- name: ${name}`);
  assert.ok(at !== -1, `no step named ${name}`);
  const indent = lines[at].indexOf('-') + 2;
  const own = [];
  for (const l of lines.slice(at + 1)) {
    if (l.trim() && (l.length - l.trimStart().length < indent || l.trimStart().startsWith('- '))) break;
    own.push(l);
  }
  const env = {};
  const envAt = own.findIndex((l) => l.trim() === 'env:');
  for (const l of own.slice(envAt + 1)) {
    const m = /^\s+([A-Z0-9_]+):\s*(.*)$/.exec(l);
    if (!m) break;
    env[m[1]] = m[2];
  }
  const runAt = own.findIndex((l) => l.trim() === 'run: |');
  const runIndent = own[runAt].indexOf('run:') + 2;
  const body = [];
  for (const l of own.slice(runAt + 1)) {
    if (l.trim() && !l.startsWith(' '.repeat(runIndent))) break;
    body.push(l.slice(runIndent));
  }
  return { env, run: body.join('\n') };
}

// Runs the step's script with a stand-in for gh that logs its arguments. A read answers with
// GH_ANSWER, the logins the jq filter would print; the DELETE exits with GH_DELETE_EXIT after
// printing GH_DELETE_OUT.
async function runStep(script, env) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-review-label-'));
  try {
    const bin = path.join(dir, 'bin');
    await mkdir(bin);
    await writeFile(path.join(dir, 'calls.txt'), '');
    await writeFile(path.join(bin, 'gh'), `#!/bin/sh
echo "gh $*" >> "${dir}/calls.txt"
case " $* " in
  *" -X DELETE "*) printf '%s\\n' "$GH_DELETE_OUT" >&2; exit "\${GH_DELETE_EXIT:-0}";;
esac
printf '%b\\n' "$GH_ANSWER"
`);
    await chmod(path.join(bin, 'gh'), 0o755);
    const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
      cwd: dir, encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_REPOSITORY: 'o/r', GH_ANSWER: '', GH_DELETE_OUT: '', ...env },
    });
    const calls = (await readFile(path.join(dir, 'calls.txt'), 'utf8')).trim().split('\n').filter(Boolean);
    return { status: r.status, out: r.stdout + r.stderr, calls };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('review label workflow: runs only for a pull request the owner merged that has "needs review", and can only change labels', () => {
  const on = LINES.slice(0, LINES.indexOf('jobs:'));
  assert.ok(on.some((l) => /^ {2}pull_request_target:\s*$/.test(l)), on.join('\n'));
  assert.ok(on.some((l) => /^ {4}types: \[closed\]\s*$/.test(l)), on.join('\n'));
  assert.ok(on.includes('permissions: {}'), 'the workflow-wide token can do nothing');
  const all = jobs();
  assert.deepEqual(Object.keys(all), ['clear']);
  const lines = all.clear;
  const cond = lines.map((l) => /^ {4}if: (.*)$/.exec(l)).find(Boolean);
  assert.ok(cond, 'the job has a condition');
  for (const part of ['github.event.pull_request.merged == true', 'github.event.pull_request.merged_by.login == github.repository_owner', "contains(github.event.pull_request.labels.*.name, 'needs review')"]) {
    assert.ok(cond[1].split(' && ').includes(part), `${part} in: ${cond[1]}`);
  }
  const at = lines.indexOf('    permissions:');
  const perms = [];
  for (const l of lines.slice(at + 1)) { const m = /^ {6}([a-z-]+): (\w+)\s*$/.exec(l); if (!m) break; perms.push(`${m[1]}: ${m[2]}`); }
  assert.deepEqual(perms, ['issues: read', 'pull-requests: write']);
  // pull_request_target runs with a write token, so nothing from the pull request or the repo runs:
  // no checkout, no actions, and event values reach the script only through env.
  assert.ok(!lines.some((l) => /uses:|checkout|\bnode\b|npm /.test(l)), lines.join('\n'));
  const { env, run } = jobStep(lines, 'Take off the gate\'s "needs review" label');
  assert.ok(!run.includes('${{'), run);
  assert.equal(env.PR, '${{ github.event.pull_request.number }}');
  assert.equal(env.GH_TOKEN, '${{ github.token }}');
});

test('review label workflow: removes "needs review" when the gate added it, and nothing else', { skip: process.platform === 'win32' }, async () => {
  const { run } = jobStep(jobs().clear, 'Take off the gate\'s "needs review" label');
  const DELETE = 'gh api -X DELETE repos/o/r/issues/7/labels/needs%20review';
  // The gate added it last: only that label is removed.
  const gate = await runStep(run, { PR: '7', GH_ANSWER: 'Aaronjacobs000\\ngithub-actions[bot]' });
  assert.equal(gate.status, 0, gate.out);
  assert.match(gate.calls[0], /^gh api repos\/o\/r\/issues\/7\/events\?per_page=100 --paginate --jq /);
  assert.deepEqual(gate.calls.slice(1), [DELETE]);
  assert.match(gate.out, /Took off "needs review"\./);
  // Someone else added it last, or the events show no one: it stays.
  for (const answer of ['github-actions[bot]\\nAaronjacobs000', '']) {
    const kept = await runStep(run, { PR: '7', GH_ANSWER: answer });
    assert.equal(kept.status, 0, kept.out);
    assert.ok(!kept.calls.some((c) => c.includes('DELETE')), kept.calls.join('\n'));
    assert.match(kept.out, /not the gate, so it stays/);
  }
  // Already off by the time the job runs: fine. Any other failure fails the job.
  const gone = await runStep(run, { PR: '7', GH_ANSWER: 'github-actions[bot]', GH_DELETE_EXIT: '1', GH_DELETE_OUT: 'gh: Label does not exist (HTTP 404)' });
  assert.equal(gone.status, 0, gone.out);
  assert.match(gone.out, /already off/);
  const failed = await runStep(run, { PR: '7', GH_ANSWER: 'github-actions[bot]', GH_DELETE_EXIT: '1', GH_DELETE_OUT: 'gh: Resource not accessible by integration (HTTP 403)' });
  assert.notEqual(failed.status, 0, failed.out);
});
