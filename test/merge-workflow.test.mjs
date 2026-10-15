// The gate workflow for pull requests: the job that reads the pull request's files holds no write
// token, and the job that merges runs only the default branch's code and merges the checked commit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, mkdir, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = await readFile(path.join(ROOT, '.github/workflows/parser-merge.yml'), 'utf8');
const GATE_SCRIPT = await readFile(path.join(ROOT, 'tools/github-gate.mjs'), 'utf8');
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

test('merge workflow: the job that merges has time to wait for CI before it merges', () => {
  // github-gate.mjs waits up to 10 minutes for the other checks on the commit, so a job limit of 10
  // minutes or less would end the job before the gate could merge or report.
  const [, lines] = Object.entries(jobs()).find(([, l]) => l.some((x) => /github-gate\.mjs pr /.test(x)));
  const limit = lines.map((l) => /^ {4}timeout-minutes: (\d+)\s*$/.exec(l)).find(Boolean);
  assert.ok(limit && Number(limit[1]) > 10, limit ? limit[0] : 'no timeout-minutes');
  assert.match(GATE_SCRIPT, /for \(let i = 0; i < 40; i\+\+\)/);
  assert.match(GATE_SCRIPT, /GATE_POLL_MS \?\? 15000/);
});

// One step of a job, found by name: its env values, its if: condition, and the body of its run: block.
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
  if (envAt !== -1) {
    for (const l of own.slice(envAt + 1)) {
      const m = /^\s+([A-Z0-9_]+):\s*(.*)$/.exec(l);
      if (!m) break;
      env[m[1]] = m[2];
    }
  }
  const cond = own.map((l) => /^\s+if: (.*)$/.exec(l)).find(Boolean);
  const runAt = own.findIndex((l) => l.trim() === 'run: |');
  const runIndent = own[runAt].indexOf('run:') + 2;
  const body = [];
  for (const l of own.slice(runAt + 1)) {
    if (l.trim() && !l.startsWith(' '.repeat(runIndent))) break;
    body.push(l.slice(runIndent));
  }
  return { env, if: cond ? cond[1] : null, run: body.join('\n') };
}

// Runs a step's script with stand-ins for gh and node that log their arguments and answer from
// GH_ANSWER and NODE_EXIT. Returns the exit status, what the step wrote to GITHUB_OUTPUT, and the calls.
async function runStep(script, env, prNumber = '7') {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-merge-wf-'));
  try {
    const bin = path.join(dir, 'bin');
    await mkdir(bin);
    await mkdir(path.join(dir, 'artifact'));
    await writeFile(path.join(dir, 'artifact', 'pr-number.txt'), `${prNumber}\n`);
    await writeFile(path.join(dir, 'output.txt'), '');
    await writeFile(path.join(dir, 'calls.txt'), '');
    await writeFile(path.join(bin, 'gh'), `#!/bin/sh\necho "gh $*" >> "${dir}/calls.txt"\nprintf '%b\\n' "$GH_ANSWER"\n`);
    await writeFile(path.join(bin, 'node'), `#!/bin/sh\necho "node $*" >> "${dir}/calls.txt"\nexit "\${NODE_EXIT:-0}"\n`);
    await chmod(path.join(bin, 'gh'), 0o755);
    await chmod(path.join(bin, 'node'), 0o755);
    const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
      cwd: dir, encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_OUTPUT: path.join(dir, 'output.txt'), GITHUB_REPOSITORY: 'o/r', ...env },
    });
    const output = Object.fromEntries((await readFile(path.join(dir, 'output.txt'), 'utf8')).trim().split('\n').filter(Boolean).map((l) => l.split('=')));
    const calls = (await readFile(path.join(dir, 'calls.txt'), 'utf8')).trim().split('\n').filter(Boolean);
    return { status: r.status, out: r.stdout + r.stderr, output, calls };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const PARSER_CHECKS = '.github/workflows/parser-checks.yml';
const CI = '.github/workflows/ci.yml';

test('merge workflow: CI finishing on a pull request starts the gate too, for the same commit', () => {
  const on = LINES.slice(0, LINES.indexOf('jobs:'));
  assert.ok(on.some((l) => /^ {4}workflows: \[Parser checks, CI\]\s*$/.test(l)), on.join('\n'));
  assert.ok(on.some((l) => /^ {2}group: parser-merge-\$\{\{ github\.event\.workflow_run\.head_sha \}\}\s*$/.test(l)), 'one run at a time per commit, whichever workflow started it');
  for (const name of ['check', 'gate']) {
    const lines = jobs()[name];
    // The pull request number comes only from a Parser checks run, the one found for the commit.
    const downloads = lines.map((l, i) => [l, i]).filter(([l]) => /^\s+name: parser-checks\s*$/.test(l));
    assert.equal(downloads.length, 1, name);
    const block = lines.slice(downloads[0][1] - 3, downloads[0][1] + 5).join('\n');
    assert.match(block, /if: steps\.run\.outputs\.skip == 'false'/, name);
    assert.match(block, /run-id: \$\{\{ steps\.run\.outputs\.id \}\}/, name);
    assert.ok(!lines.some((l) => /run-id: \$\{\{ github\.event\.workflow_run\.id \}\}/.test(l)), name);
    assert.equal(jobStep(lines, 'Match the pull request to the checked commit').if, "steps.run.outputs.skip == 'false'", name);
  }
});

test('merge workflow: the run to take the pull request number from is the Parser checks run on the commit', { skip: process.platform === 'win32' }, async () => {
  for (const name of ['check', 'gate']) {
    const { env, run } = jobStep(jobs()[name], 'Find the Parser checks run for the commit');
    assert.equal(env.RUN_PATH, '${{ github.event.workflow_run.path }}', name);
    assert.ok(!run.includes('${{'), name);
    const base = { RUN_ID: '111', HEAD_SHA: 'abc123' };
    // Started by Parser checks: that run, and no lookup.
    const own = await runStep(run, { ...base, RUN_PATH: PARSER_CHECKS, GH_ANSWER: '999' });
    assert.equal(own.status, 0, own.out);
    assert.deepEqual(own.output, { id: '111', skip: 'false' }, name);
    assert.deepEqual(own.calls, []);
    // Started by CI: the newest finished Parser checks run on the same commit.
    const ci = await runStep(run, { ...base, RUN_PATH: CI, GH_ANSWER: '222' });
    assert.equal(ci.status, 0, ci.out);
    assert.deepEqual(ci.output, { id: '222', skip: 'false' }, name);
    assert.equal(ci.calls.length, 1);
    assert.match(ci.calls[0], /^gh api repos\/o\/r\/actions\/workflows\/parser-checks\.yml\/runs\?head_sha=abc123&status=completed&per_page=1 /);
    // None has finished yet: skip, since that run starts the gate when it finishes.
    const none = await runStep(run, { ...base, RUN_PATH: CI, GH_ANSWER: '' });
    assert.equal(none.status, 0, none.out);
    assert.deepEqual(none.output, { skip: 'true' }, name);
  }
});

test('merge workflow: a run CI started goes on only if the gate\'s report holds the commit for CI', { skip: process.platform === 'win32' }, async () => {
  const { env, run } = jobStep(jobs().check, 'Match the pull request to the checked commit');
  assert.equal(env.RUN_PATH, '${{ github.event.workflow_run.path }}');
  assert.equal(env.GITHUB_TOKEN, '${{ github.token }}');
  // CI's conclusion goes to the gate, which starts again after a failed check only when CI passed.
  assert.equal(env.CI_CONCLUSION, '${{ github.event.workflow_run.conclusion }}');
  const base = { HEAD_SHA: 'abc123', GH_ANSWER: 'abc123\\toctocat\\topen', CI_CONCLUSION: 'success' };
  // Started by CI, and the report holds the commit for CI: go on.
  const held = await runStep(run, { ...base, RUN_PATH: CI, NODE_EXIT: '0' });
  assert.equal(held.status, 0, held.out);
  assert.deepEqual(held.output, { number: '7', author: 'octocat', skip: 'false' });
  assert.ok(held.calls.includes('node base/tools/github-gate.mjs waiting --pr 7 --sha abc123 --ci success'), held.calls.join('\n'));
  const failed = await runStep(run, { ...base, RUN_PATH: CI, CI_CONCLUSION: 'failure', NODE_EXIT: '1' });
  assert.ok(failed.calls.includes('node base/tools/github-gate.mjs waiting --pr 7 --sha abc123 --ci failure'), failed.calls.join('\n'));
  assert.deepEqual(failed.output, { skip: 'true' });
  // Started by CI, and the report doesn't: skip.
  const not = await runStep(run, { ...base, RUN_PATH: CI, NODE_EXIT: '1' });
  assert.equal(not.status, 0, not.out);
  assert.deepEqual(not.output, { skip: 'true' });
  // Started by Parser checks: go on without asking.
  const checks = await runStep(run, { ...base, RUN_PATH: PARSER_CHECKS, NODE_EXIT: '1' });
  assert.deepEqual(checks.output, { number: '7', author: 'octocat', skip: 'false' });
  assert.ok(!checks.calls.some((c) => c.startsWith('node ')), checks.calls.join('\n'));
  // A pull request that moved on or closed is skipped before anything else, whichever started it.
  for (const answer of ['def456\\toctocat\\topen', 'abc123\\toctocat\\tclosed']) {
    const moved = await runStep(run, { ...base, GH_ANSWER: answer, RUN_PATH: CI, NODE_EXIT: '0' });
    assert.deepEqual(moved.output, { skip: 'true' }, answer);
    assert.ok(!moved.calls.some((c) => c.startsWith('node ')), answer);
  }
});
