// Bridges: the "bridge" metadata rule and its old "collector" name, the review rule for bridge
// code, the site build, and the README renderer the entry page uses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateMeta, bridgeScripts, hasBridge, bridgeOf, withBridgeKey } from '../studio/core/library.js';
import { bridgeFolders, bridgeFolder } from '../studio/app/library-client.js';
import { listBridges, loadBridges } from '../tools/lib/fs-library.mjs';
import { reviewReasons } from '../tools/lib/merge-rules.mjs';
import { parseMarkdown, parseInline, linkTarget } from '../studio/app/markdown.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILES = ['meta.json', 'ACME_PULL_JSON_STANDALONE.parser.txt', 'samples.log', 'expected.json'];
const META = { vendor: 'Acme', product: 'Pull API', versions: [], format: 'json', ship_method: 'http-ingest', author: 'octocat', license: 'MIT', sample_source: 'synthetic', reference_time: '2026-10-13T00:00:00Z', tested: { emulator: '0.1.0', tenant: null }, parsers: [{ name: 'ACME_PULL_JSON_STANDALONE', file: 'ACME_PULL_JSON_STANDALONE.parser.txt', role: 'standalone' }] };
const ON_MAIN = [{ path: 'bridges/acme-pull', files: ['README.md', 'acme_pull.py', 'test_acme_pull.py'] }];
const problems = (meta, bridges) => validateMeta(meta, FILES, bridges ? { bridges } : {}).filter((p) => p.code === 'bridge');

test('bridge: a folder under bridges/ that is on the main branch passes', () => {
  assert.deepEqual(problems({ ...META, bridge: 'bridges/acme-pull' }, ON_MAIN), []);
  assert.equal(hasBridge({ bridge: 'bridges/acme-pull' }), true);
  // Without the list of bridges (the page itself), only the form is checked.
  assert.deepEqual(problems({ ...META, bridge: 'bridges/not-listed' }), []);
});

test('bridge: the value must be a folder path under bridges/', () => {
  for (const bad of ['parsers/acme/pull-api', 'bridges/', 'bridges', 'bridges/acme-pull/', 'bridges/acme-pull/acme_pull.py', 'bridges/../parsers', '../bridges/acme-pull', '/bridges/acme-pull', './bridges/acme-pull', 'bridges/Acme_Pull', 'https://example.com/acme_pull.py', 42, true, ['bridges/acme-pull'], { path: 'bridges/acme-pull' }]) {
    const p = problems({ ...META, bridge: bad }, ON_MAIN);
    assert.equal(p.length, 1, JSON.stringify(bad));
    assert.equal(p[0].level, 'error');
    assert.match(p[0].message, /must be the path of a folder under bridges\//);
    assert.equal(hasBridge({ bridge: bad }), false);
  }
});

test('bridge: it must exist on the main branch with a README.md and a .py file', () => {
  const missing = problems({ ...META, bridge: 'bridges/acme-push' }, ON_MAIN);
  assert.equal(missing.length, 1);
  assert.equal(missing[0].level, 'error');
  assert.match(missing[0].message, /bridges\/acme-push is not on the main branch/);
  const noReadme = problems({ ...META, bridge: 'bridges/acme-pull' }, [{ path: 'bridges/acme-pull', files: ['acme_pull.py'] }]);
  assert.deepEqual(noReadme.map((p) => [p.level, p.message]), [['error', 'bridge bridges/acme-pull has no README.md']]);
  const noScript = problems({ ...META, bridge: 'bridges/acme-pull' }, [{ path: 'bridges/acme-pull', files: ['README.md', 'notes.txt'] }]);
  assert.deepEqual(noScript.map((p) => [p.level, p.message]), [['error', 'bridge bridges/acme-pull has no .py file']]);
  assert.equal(problems({ ...META, bridge: 'bridges/acme-pull' }, []).length, 1);
});

test('bridge: http-ingest without one is a warning, and older entries stay valid', () => {
  const w = problems({ ...META }, ON_MAIN);
  assert.equal(w.length, 1);
  assert.equal(w[0].level, 'warning');
  assert.match(w[0].message, /http-ingest but there is no bridge/);
  assert.deepEqual(problems({ ...META, bridge: null }, ON_MAIN).map((p) => p.level), ['warning']);
  for (const ship of ['syslog', 's3', 'azure', 'other']) assert.deepEqual(validateMeta({ ...META, ship_method: ship }, FILES, { bridges: ON_MAIN }), [], ship);
  assert.equal(validateMeta({ ...META }, FILES).some((p) => p.level === 'error'), false);
});

test('bridge: the old "collector" key still works, with a warning', () => {
  // An entry or a pull request from before the rename: collectors/<name> reads as bridges/<name>.
  const legacy = problems({ ...META, collector: 'collectors/acme-pull' }, ON_MAIN);
  assert.deepEqual(legacy.map((p) => p.level), ['warning']);
  assert.match(legacy[0].message, /^"collector" is the old name for "bridge"\. It still works/);
  assert.equal(bridgeOf({ collector: 'collectors/acme-pull' }), 'bridges/acme-pull');
  assert.equal(bridgeOf({ collector: 'bridges/acme-pull' }), 'bridges/acme-pull');
  assert.equal(hasBridge({ collector: 'collectors/acme-pull' }), true);
  // It is still checked against the bridges on the main branch, and for its form.
  const missing = problems({ ...META, collector: 'collectors/acme-push' }, ON_MAIN).filter((p) => p.level === 'error');
  assert.equal(missing.length, 1);
  assert.match(missing[0].message, /^bridge bridges\/acme-push is not on the main branch/);
  for (const bad of ['collectors/acme-pull/acme_pull.py', '../collectors/acme-pull', 'collectors/Acme_Pull', 42]) {
    assert.ok(problems({ ...META, collector: bad }, ON_MAIN).some((p) => p.level === 'error' && /must be the path of a folder under bridges\//.test(p.message)), JSON.stringify(bad));
    assert.equal(hasBridge({ collector: bad }), false);
  }
  // With both keys, "bridge" wins and "collector" gets a warning. "bridge" takes only the new path.
  const both = problems({ ...META, bridge: 'bridges/acme-pull', collector: 'collectors/acme-push' }, ON_MAIN);
  assert.deepEqual(both.map((p) => p.level), ['warning']);
  assert.match(both[0].message, /has both, so "collector" is ignored/);
  assert.equal(bridgeOf({ bridge: 'bridges/acme-pull', collector: 'collectors/acme-push' }), 'bridges/acme-pull');
  assert.equal(bridgeOf({ bridge: 'collectors/acme-pull' }), null);
  // The site's snapshot carries the old key as "bridge" and leaves current metadata alone.
  assert.deepEqual(withBridgeKey({ vendor: 'Acme', collector: 'collectors/acme-pull' }), { vendor: 'Acme', bridge: 'bridges/acme-pull' });
  assert.deepEqual(withBridgeKey({ vendor: 'Acme', bridge: 'bridges/acme-pull', collector: 'collectors/acme-push' }), { vendor: 'Acme', bridge: 'bridges/acme-pull' });
  const current = { vendor: 'Acme', bridge: 'bridges/acme-pull' };
  assert.equal(withBridgeKey(current), current);
});

test('the page lists bridge folders, and a fork from before the rename still shows its own', () => {
  const blob = (p) => ({ path: p, type: 'blob' });
  const tree = [blob('bridges/acme-pull/acme_pull.py'), blob('bridges/acme-pull/README.md'), { path: 'bridges/acme-pull', type: 'tree' }, blob('bridges/README.md'), blob('parsers/acme/pull-api/meta.json')];
  assert.deepEqual(bridgeFolders(tree), [{ path: 'bridges/acme-pull', files: ['README.md', 'acme_pull.py'] }]);
  // An older fork keeps collectors/<name>: it lists as bridges/<name>, read from its real folder.
  assert.deepEqual(bridgeFolders([blob('collectors/acme-pull/acme_pull.py')]), [{ path: 'bridges/acme-pull', dir: 'collectors/acme-pull', files: ['acme_pull.py'] }]);
  assert.deepEqual(bridgeFolders([blob('collectors/acme-pull/old.py'), blob('bridges/acme-pull/new.py')]), [{ path: 'bridges/acme-pull', files: ['new.py'] }]);
});

test('a bridge link points at the folder that holds the bridge, collectors/<name> in a fork made before the rename', () => {
  const blob = (p) => ({ path: p, type: 'blob' });
  const old = bridgeFolders([blob('collectors/acme-pull/acme_pull.py')]);
  assert.equal(bridgeFolder(old, { collector: 'collectors/acme-pull' }), 'collectors/acme-pull');
  assert.equal(bridgeFolder(old, { bridge: 'bridges/acme-pull' }), 'collectors/acme-pull');
  assert.equal(bridgeFolder(bridgeFolders([blob('bridges/acme-pull/acme_pull.py')]), { collector: 'collectors/acme-pull' }), 'bridges/acme-pull');
  // With no folder listed, the entry's own path.
  assert.equal(bridgeFolder([], { collector: 'collectors/acme-pull' }), 'collectors/acme-pull');
  assert.equal(bridgeFolder(undefined, { bridge: 'bridges/acme-pull' }), 'bridges/acme-pull');
});

test('the site build copies the bridges into the snapshot and every entry names its bridge with "bridge"', async () => {
  const out = await mkdtemp(path.join(tmpdir(), 'ps-site-'));
  execFileSync(process.execPath, [path.join(ROOT, 'tools/build-site.mjs'), '--out', out], { stdio: 'pipe' });
  const snap = JSON.parse(await readFile(path.join(out, 'library-snapshot.json'), 'utf8'));
  await rm(out, { recursive: true, force: true });
  assert.equal(snap.collectors, undefined);
  const relay = snap.bridges.find((b) => b.path === 'bridges/webhook-relay');
  assert.deepEqual(relay.scripts.map((s) => s.name), ['webhook_relay.py']);
  assert.equal(snap.entries.find((e) => e.id === 'huntress/huntress-webhooks').meta.bridge, 'bridges/webhook-relay');
  assert.deepEqual(snap.entries.filter((e) => 'collector' in e.meta).map((e) => e.id), []);
  for (const e of snap.entries.filter((x) => x.meta.bridge)) assert.ok(snap.bridges.some((b) => b.path === e.meta.bridge), e.id);
});

test('bridge scripts leave out tests, and the repo bridges load', async () => {
  assert.deepEqual(bridgeScripts(['README.md', 'test_acme_pull.py', 'acme_pull.py', 'acme_pull_test.py', 'helper.py']), ['acme_pull.py', 'helper.py']);
  assert.deepEqual(bridgeScripts(['README.md', 'test_only.py']), ['test_only.py']);
  assert.deepEqual(bridgeScripts(['README.md']), []);
  const listed = await listBridges(ROOT);
  const ai = listed.find((c) => c.path === 'bridges/ai-compliance-logs');
  assert.ok(ai && ai.files.includes('README.md') && ai.files.includes('ai_compliance_bridge.py'));
  const loaded = (await loadBridges(ROOT)).find((c) => c.path === 'bridges/ai-compliance-logs');
  assert.deepEqual(loaded.scripts.map((s) => s.name), ['ai_compliance_bridge.py']);
  assert.match(loaded.readme, /^# AI compliance log bridge/);
});

test('review rule: bridge code and other non-library files always need a review', () => {
  assert.deepEqual(reviewReasons(['parsers/acme/pull-api/meta.json', 'parsers/acme/pull-api/samples.log']), []);
  assert.match(reviewReasons(['parsers/acme/pull-api/meta.json', 'bridges/acme-pull/acme_pull.py']).join(), /changes bridge code, which a maintainer always reviews: bridges\/acme-pull\/acme_pull.py/);
  assert.match(reviewReasons(['bridges/acme-pull/README.md']).join(), /bridge code/);
  assert.match(reviewReasons(['.github/workflows/ci.yml']).join(), /outside parsers\//);
  // A branch from before the rename can still add code under the old collectors/ folder. It waits too.
  assert.match(reviewReasons(['parsers/acme/pull-api/meta.json', 'collectors/acme-pull/acme_pull.py']).join(), /changes files outside parsers\/: collectors\/acme-pull\/acme_pull.py/);
  // A top-level folder whose name only looks like parsers/, such as one that starts with a space, is outside it.
  for (const lookalike of [' parsers/acme/pull-api/notes.txt', '\u00a0parsers/acme/pull-api/notes.txt', '\tparsers/acme/pull-api/notes.txt']) {
    assert.match(reviewReasons(['parsers/acme/pull-api/meta.json', lookalike]).join(), /changes files outside parsers\//, JSON.stringify(lookalike));
  }
});

// Runs github-gate.mjs merge against a stand-in for the GitHub API, the way the two workflows
// call it, and reports what it said and which calls it made.
// checks, ciRuns and pulls are the answers GitHub gives in turn to each read of the commit's check
// runs, CI's workflow runs and the pull request; the last answer repeats. comments are the pull
// request's comments, and the result's comments are the report bodies the gate wrote.
const PASSED = [{ name: 'tests', status: 'completed', conclusion: 'success' }];
async function gateMerge(files, { command = 'merge', autoMerge = true, pull = {}, refSha = 'abc123', deleteStatus = 204, filesErrors = 0, mergeErrors = 0, mergeError = 'Base branch was modified. Review and try the merge again.', changedFiles = files.length, checks = [PASSED], ciRuns = [[{ status: 'completed', conclusion: 'success' }]], pulls = [{}], report = { passed: true, eligible: true }, comments = [] } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gate-'));
  const log = path.join(dir, 'calls.log');
  const written = path.join(dir, 'comments.json');
  const mock = path.join(dir, 'mock-fetch.mjs');
  const output = path.join(dir, 'github-output.txt');
  await writeFile(log, '');
  await writeFile(written, '');
  await writeFile(output, '');
  await writeFile(path.join(dir, 'report.json'), JSON.stringify(report));
  await writeFile(path.join(dir, 'report.md'), '### Parser library checks: passed\n');
  await writeFile(mock, `
import { appendFileSync } from 'node:fs';
const files = ${JSON.stringify(files.map((filename) => ({ filename })))};
let filesErrors = ${filesErrors}, mergeErrors = ${mergeErrors};
const answers = { checks: ${JSON.stringify(checks)}, ciRuns: ${JSON.stringify(ciRuns)}, pulls: ${JSON.stringify(pulls)} };
const next = (k) => (answers[k].length > 1 ? answers[k].shift() : answers[k][0]);
globalThis.fetch = async (url, init = {}) => {
  const method = init.method || 'GET';
  // Labels added are logged with their names.
  appendFileSync(${JSON.stringify(log)}, method + ' ' + url + (method === 'POST' && url.endsWith('/labels') && init.body ? ' ' + init.body : '') + '\\n');
  const u = new URL(url);
  // The report bodies the gate writes, one JSON string a line.
  if ((method === 'POST' || method === 'PATCH') && /\\/comments(\\/\\d+)?$/.test(u.pathname)) appendFileSync(${JSON.stringify(written)}, JSON.stringify(JSON.parse(init.body).body) + '\\n');
  let body = {};
  if (u.pathname === '/repos/o/r/pulls/7/files' && filesErrors > 0) { filesErrors--; return new Response('<html>Server Error</html>', { status: 500 }); }
  if (method === 'PUT' && u.pathname === '/repos/o/r/pulls/7/merge' && mergeErrors > 0) { mergeErrors--; return new Response(JSON.stringify({ message: ${JSON.stringify(mergeError)} }), { status: 405 }); }
  if (u.pathname === '/repos/o/r') body = { allow_auto_merge: true };
  else if (u.pathname === '/repos/o/r/pulls/7') { const now = next('pulls'); body = { state: 'open', draft: false, node_id: 'PR_7', changed_files: ${changedFiles}, ...${JSON.stringify(pull)}, ...now, head: { sha: 'abc123', ...${JSON.stringify(pull.head || {})}, ...(now.head || {}) } }; }
  // GitHub lists a pull request's files 100 to a page, and at most 3,000 of them.
  else if (u.pathname === '/repos/o/r/pulls/7/files') { const n = Number(u.searchParams.get('per_page') || 30), p = Number(u.searchParams.get('page') || 1); body = files.slice(0, 3000).slice((p - 1) * n, p * n); }
  // Without a branch rule, GitHub refuses native auto-merge and the gate merges the pull request itself.
  else if (u.pathname === '/graphql') body = ${autoMerge} ? { data: { enablePullRequestAutoMerge: { clientMutationId: null } } } : { errors: [{ message: 'Pull request is in clean status' }] };
  else if (u.pathname === '/repos/o/r/commits/abc123/check-runs') body = { check_runs: next('checks') };
  else if (u.pathname === '/repos/o/r/actions/workflows/ci.yml/runs' && u.searchParams.get('head_sha') === 'abc123') body = { workflow_runs: next('ciRuns') };
  else if (method === 'GET' && u.pathname === '/repos/o/r/issues/7/comments') body = ${JSON.stringify(comments)};
  else if (method === 'GET' && /\\/(labels|comments)$/.test(u.pathname)) body = [];
  else if (method === 'GET' && u.pathname.startsWith('/repos/o/r/git/ref/heads/')) body = { object: { sha: ${JSON.stringify(refSha)} } };
  else if (method === 'DELETE' && u.pathname.startsWith('/repos/o/r/git/refs/heads/')) return new Response(${deleteStatus} === 204 ? null : JSON.stringify({ message: 'Reference update failed' }), { status: ${deleteStatus} });
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
};
`);
  const args = command === 'pr' ? ['pr', '--pr', '7', '--sha', 'abc123', '--report', path.join(dir, 'report.json'), '--markdown', path.join(dir, 'report.md')]
    : command === 'changed' ? ['changed', '--pr', '7', '--out', path.join(dir, 'changed.txt')] : [command, '--pr', '7', '--sha', 'abc123'];
  const run = spawnSync(process.execPath, ['--import', pathToFileURL(mock).href, path.join(ROOT, 'tools/github-gate.mjs'), ...args], { env: { ...process.env, GITHUB_REPOSITORY: 'o/r', GITHUB_TOKEN: 'test', GITHUB_OUTPUT: output, GATE_RETRY_MS: '1', GATE_POLL_MS: '1' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  // waiting answers with its exit code; any other command that fails throws, as execFileSync would.
  if (run.status !== 0 && command !== 'waiting') throw Object.assign(new Error(`gate exited ${run.status}: ${run.stderr}`), { status: run.status });
  const calls = (await readFile(log, 'utf8')).trim().split('\n');
  const reports = (await readFile(written, 'utf8')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const stepOutput = await readFile(output, 'utf8');
  await rm(dir, { recursive: true, force: true });
  return { out: run.stdout.trim(), status: run.status, calls, comments: reports, stepOutput };
}

test('gate: the merge step refuses a pull request with bridge code, from either route', async () => {
  const held = await gateMerge(['parsers/acme/pull-api/meta.json', 'bridges/acme-pull/acme_pull.py']);
  assert.match(held.out, /^Not merged automatically: this pull request changes bridge code/);
  assert.ok(!held.calls.some((c) => /graphql|\/merge|^PUT/.test(c)), held.calls.join('\n'));
  // Code under the old collectors/ folder, from a branch made before the rename, is held too.
  for (const command of ['pr', 'merge']) {
    const legacy = await gateMerge(['parsers/acme/pull-api/meta.json', 'collectors/acme-pull/acme_pull.py'], { command, autoMerge: false });
    if (command === 'merge') assert.match(legacy.out, /^Not merged automatically: this pull request changes files outside parsers\/: collectors\/acme-pull\/acme_pull.py/);
    assert.ok(!legacy.calls.some((c) => /graphql|\/merge|^PUT/.test(c)), legacy.calls.join('\n'));
    assert.equal(legacy.stepOutput, '', command);
  }
  // Control: the same stand-in merges a library-only pull request.
  const ok = await gateMerge(['parsers/acme/pull-api/meta.json']);
  assert.equal(ok.out, 'Auto-merge is on for this pull request.');
  assert.ok(ok.calls.some((c) => c === 'POST https://api.github.com/graphql'));
});

test('gate: a pull request whose file list GitHub cuts short never merges on its own', async () => {
  // GitHub lists at most 3,000 files, and the gate reads 29 pages of 100, so a file past that
  // point would go unseen. The gate holds any pull request it can't list in full.
  const many = Array.from({ length: 2900 }, (_, i) => `parsers/acme/p${String(Math.floor(i / 5)).padStart(4, '0')}/f${i % 5}.parser.txt`);
  for (const command of ['pr', 'merge']) {
    const held = await gateMerge([...many, 'studio/app/main.js'], { command, autoMerge: false });
    if (command === 'merge') assert.match(held.out, /^Not merged automatically: GitHub listed 2900 of the 2901 changed files/);
    assert.ok(!held.calls.some((c) => /graphql|\/merge$/.test(c)), command);
    assert.equal(held.stepOutput, '', command);
  }
  // A count that doesn't match the list holds it too, and so does a missing count.
  assert.match((await gateMerge(['parsers/acme/pull-api/meta.json'], { changedFiles: 2 })).out, /^Not merged automatically: GitHub listed 1 of the 2 changed files/);
  assert.match((await gateMerge(['parsers/acme/pull-api/meta.json'], { changedFiles: 'null' })).out, /^Not merged automatically/);
  // The file list the checks read fails the same way, so the checks fail instead of passing on part of it.
  await assert.rejects(gateMerge([...many, 'studio/app/main.js'], { command: 'changed' }), /GitHub listed 2900 of the 2901 changed files/);
  assert.equal((await gateMerge(['parsers/acme/pull-api/meta.json', 'parsers/acme/pull-api/samples.log'], { command: 'changed' })).out, '2 changed files');
});

test('gate: a merge the gate makes tells the workflow to start the Pages build', async () => {
  // The repo has no branch rule, so the gate merges the pull request itself, from either route.
  for (const command of ['pr', 'merge']) {
    const merged = await gateMerge(['parsers/acme/pull-api/meta.json'], { command, autoMerge: false });
    assert.ok(merged.calls.includes('PUT https://api.github.com/repos/o/r/pulls/7/merge'), merged.calls.join('\n'));
    assert.equal(merged.stepOutput, 'merged=true\n', command);
  }
  // Native auto-merge merges later, and a held pull request doesn't merge, so neither says merged.
  assert.equal((await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr' })).stepOutput, '');
  const held = await gateMerge(['parsers/acme/pull-api/meta.json', 'bridges/acme-pull/acme_pull.py'], { command: 'pr', autoMerge: false });
  assert.ok(!held.calls.some((c) => /\/merge$/.test(c)), held.calls.join('\n'));
  assert.equal(held.stepOutput, '');
});

test('gate: after its own merge it deletes a same-repo head branch, never a fork\'s or main', async () => {
  const repo = { id: 1, full_name: 'o/r', default_branch: 'main' };
  const from = (ref, headRepo = repo) => ({ head: { ref, repo: headRepo }, base: { ref: 'main', repo } });
  const deletes = (r) => r.calls.filter((c) => c.startsWith('DELETE ') && c.includes('/git/refs/'));
  for (const command of ['pr', 'merge']) {
    const own = await gateMerge(['parsers/acme/pull-api/meta.json'], { command, autoMerge: false, pull: from('submission/issue-12') });
    assert.deepEqual(deletes(own), ['DELETE https://api.github.com/repos/o/r/git/refs/heads/submission/issue-12'], command);
    assert.ok(own.calls.indexOf('PUT https://api.github.com/repos/o/r/pulls/7/merge') < own.calls.indexOf(deletes(own)[0]));
    assert.equal(own.stepOutput, 'merged=true\n');
  }
  // A fork's branch, main, a missing head repo, and a branch that moved after the merge stay.
  const fork = await gateMerge(['parsers/acme/pull-api/meta.json'], { autoMerge: false, pull: from('main', { id: 2, full_name: 'someone/r' }) });
  assert.equal(fork.out, 'Merged.');
  assert.deepEqual(deletes(fork), []);
  assert.ok(!fork.calls.some((c) => c.includes('/git/ref')), fork.calls.join('\n'));
  for (const pull of [from('main'), from('library/acme', null), { head: { ref: 'library/acme' } }]) {
    assert.deepEqual(deletes(await gateMerge(['parsers/acme/pull-api/meta.json'], { autoMerge: false, pull })), [], JSON.stringify(pull));
  }
  assert.deepEqual(deletes(await gateMerge(['parsers/acme/pull-api/meta.json'], { autoMerge: false, pull: from('library/acme'), refSha: 'def456' })), []);
  // Nothing is deleted when the gate doesn't merge: native auto-merge merges later, and a held pull request waits.
  assert.deepEqual(deletes(await gateMerge(['parsers/acme/pull-api/meta.json'], { pull: from('library/acme') })), []);
  assert.deepEqual(deletes(await gateMerge(['parsers/acme/pull-api/meta.json', 'bridges/acme-pull/acme_pull.py'], { autoMerge: false, pull: from('library/acme') })), []);
  // A delete that fails leaves the merge reported as merged. gateMerge pipes the gate's stderr, so
  // the ::warning:: line it prints doesn't reach CI as an annotation.
  const failed = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', autoMerge: false, pull: from('library/acme'), deleteStatus: 403 });
  assert.equal(deletes(failed).length, 1);
  assert.equal(failed.stepOutput, 'merged=true\n');
});

test('gate: it retries a 500 while listing files and a 405 "Base branch was modified" on merge', async () => {
  const filesCalls = (r) => r.calls.filter((c) => c.startsWith('GET https://api.github.com/repos/o/r/pulls/7/files'));
  const puts = (r) => r.calls.filter((c) => c === 'PUT https://api.github.com/repos/o/r/pulls/7/merge');
  const listed = await gateMerge(['parsers/acme/pull-api/meta.json'], { filesErrors: 2 });
  assert.equal(listed.out, 'Auto-merge is on for this pull request.');
  // Two failures and a success, then one more read when the list is checked again after the wait for checks.
  assert.equal(filesCalls(listed).length, 4);
  for (const command of ['pr', 'merge']) {
    const merged = await gateMerge(['parsers/acme/pull-api/meta.json'], { command, autoMerge: false, mergeErrors: 2 });
    assert.equal(puts(merged).length, 3, command);
    assert.equal(merged.stepOutput, 'merged=true\n', command);
  }
  // Any other 405, such as a pull request that can't merge, isn't retried.
  const refused = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', autoMerge: false, mergeErrors: 1, mergeError: 'Pull Request is not mergeable' });
  assert.equal(puts(refused).length, 1);
  assert.equal(refused.stepOutput, '');
});

const MERGE_CALLS = /graphql|\/merge$/;
const firstMergeCall = (r) => r.calls.findIndex((c) => MERGE_CALLS.test(c));
const checkReads = (r) => r.calls.map((c, i) => [c, i]).filter(([c]) => c.startsWith('GET https://api.github.com/repos/o/r/commits/abc123/check-runs')).map(([, i]) => i);

test('gate: it merges only after every check on the checked commit has finished and passed', async () => {
  const running = [{ name: 'tests', status: 'in_progress', conclusion: null }, { name: 'validate', status: 'completed', conclusion: 'success' }];
  for (const autoMerge of [true, false]) {
    // CI is still running for two looks, then passes: nothing merges, and auto-merge isn't turned on, until it has.
    const waited = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', autoMerge, checks: [running, running, PASSED] });
    const reads = checkReads(waited);
    assert.equal(reads.length, 3, String(autoMerge));
    assert.ok(firstMergeCall(waited) > reads[2], waited.calls.join('\n'));
  }
  // A failed check, or one still running when the wait ends, stops it with no merge and a "needs review" label.
  for (const checks of [[[{ name: 'tests', status: 'completed', conclusion: 'failure' }]], [running]]) {
    for (const command of ['pr', 'merge']) {
      const held = await gateMerge(['parsers/acme/pull-api/meta.json'], { command, checks });
      assert.equal(firstMergeCall(held), -1, held.calls.join('\n'));
      assert.equal(held.stepOutput, '');
      if (command === 'merge') assert.match(held.out, /^Another check on this commit failed or is still running/);
      else assert.ok(held.calls.some((c) => c.endsWith('/issues/7/labels {"labels":["needs review"]}')), held.calls.join('\n'));
    }
  }
});

test('gate: on the pull request route it waits for CI to run on the commit, not just for the checks it can see', async () => {
  // GitHub hasn't created CI's run yet, so the commit shows only checks that passed. The gate waits for CI.
  const late = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', autoMerge: false, ciRuns: [[], [{ status: 'in_progress', conclusion: null }], [{ status: 'completed', conclusion: 'success' }]] });
  const ciReads = late.calls.map((c, i) => [c, i]).filter(([c]) => c.includes('/actions/workflows/ci.yml/runs?head_sha=abc123')).map(([, i]) => i);
  assert.equal(ciReads.length, 3);
  assert.ok(firstMergeCall(late) > ciReads[2]);
  assert.equal(late.stepOutput, 'merged=true\n');
  // A CI run that never comes, or fails, holds it.
  for (const ciRuns of [[[]], [[{ status: 'completed', conclusion: 'failure' }]]]) {
    const held = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', autoMerge: false, ciRuns });
    assert.equal(firstMergeCall(held), -1, JSON.stringify(ciRuns));
  }
  // The issue route's pull request starts no workflows, so there it doesn't look for CI and merges.
  const issue = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'merge', autoMerge: false, ciRuns: [[]], checks: [[]] });
  assert.equal(issue.out, 'Merged.');
  assert.ok(!issue.calls.some((c) => c.includes('/actions/workflows/')));
});

test('gate: a pull request that changed or closed while the gate waited for checks doesn\'t merge', async () => {
  const moved = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'merge', pulls: [{}, { head: { sha: 'def456' } }] });
  assert.equal(moved.out, 'The pull request changed after these checks ran; the next run decides.');
  assert.equal(firstMergeCall(moved), -1);
  // Already merged by a later run: no merge, and no "needs review" label on the merged pull request.
  const merged = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', pulls: [{}, { state: 'closed', merged: true, head: { sha: 'def456' } }] });
  assert.equal(firstMergeCall(merged), -1);
  assert.ok(!merged.calls.some((c) => c.startsWith('POST https://api.github.com/repos/o/r/issues/7/labels') && c.includes('needs review')), merged.calls.join('\n'));
});

test('gate: a merge clears the "needs review" label an earlier run added', async () => {
  const removeReview = 'DELETE https://api.github.com/repos/o/r/issues/7/labels/needs%20review';
  for (const autoMerge of [false, true]) {
    // With native auto-merge, GitHub merges the pull request a little after the gate turns it on.
    const r = await gateMerge(['parsers/acme/pull-api/meta.json'], { command: 'pr', autoMerge, pulls: autoMerge ? [{}, {}, { state: 'open' }, { state: 'closed', merged: true }] : [{}] });
    assert.equal(r.stepOutput, 'merged=true\n', String(autoMerge));
    const mergedAt = firstMergeCall(r);
    assert.ok(mergedAt >= 0);
    assert.ok(r.calls.lastIndexOf(removeReview) > mergedAt, r.calls.join('\n'));
    assert.ok(r.calls.some((c) => c.endsWith('/issues/7/labels {"labels":["auto-merge"]}')));
  }
});

test('gate: after native auto-merge merges, it deletes a same-repo head branch, never a fork\'s', async () => {
  const repo = { id: 1, full_name: 'o/r', default_branch: 'main' };
  const from = (ref, headRepo = repo) => ({ head: { ref, repo: headRepo }, base: { ref: 'main', repo } });
  const deletes = (r) => r.calls.filter((c) => c.startsWith('DELETE ') && c.includes('/git/refs/'));
  const later = [{}, {}, { state: 'open' }, { state: 'closed', merged: true }];
  for (const command of ['pr', 'merge']) {
    const own = await gateMerge(['parsers/acme/pull-api/meta.json'], { command, pull: from('library/acme'), pulls: later });
    assert.ok(own.calls.includes('POST https://api.github.com/graphql'), command);
    assert.deepEqual(deletes(own), ['DELETE https://api.github.com/repos/o/r/git/refs/heads/library/acme'], command);
    assert.equal(own.stepOutput, 'merged=true\n', command);
  }
  const fork = await gateMerge(['parsers/acme/pull-api/meta.json'], { pull: from('library/acme', { id: 2, full_name: 'someone/r' }), pulls: later });
  assert.equal(fork.out, 'Merged.');
  assert.deepEqual(deletes(fork), []);
  // A branch rule that keeps holding it: auto-merge stays on, and nothing is deleted or reported merged.
  const held = await gateMerge(['parsers/acme/pull-api/meta.json'], { pull: from('library/acme') });
  assert.equal(held.out, 'Auto-merge is on for this pull request.');
  assert.deepEqual(deletes(held), []);
  assert.equal(held.stepOutput, '');
});

test('gate: a run whose commit is no longer the head, or that ends after the pull request merged or closed, leaves the report alone', async () => {
  const entry = ['parsers/acme/pull-api/meta.json'];
  // The pull request moved on, or another run merged it, while this run waited for checks.
  for (const later of [{ head: { sha: 'def456' } }, { state: 'closed', merged: true, head: { sha: 'def456' } }, { state: 'closed', merged: true }]) {
    const r = await gateMerge(entry, { command: 'pr', pulls: [{}, later] });
    assert.equal(firstMergeCall(r), -1, JSON.stringify(later));
    assert.deepEqual(r.comments, [], JSON.stringify(later));
  }
  // A report that failed the checks, or one that needs a maintainer, from a run that is no longer current.
  for (const report of [{ passed: false, eligible: false }, { passed: true, eligible: false }]) {
    for (const now of [{ head: { sha: 'def456' } }, { state: 'closed', merged: true }, { state: 'closed' }]) {
      assert.deepEqual((await gateMerge(entry, { command: 'pr', report, pulls: [now] })).comments, [], JSON.stringify([report, now]));
    }
    // Control: a run that is still current writes it.
    assert.equal((await gateMerge(entry, { command: 'pr', report })).comments.length, 1, JSON.stringify(report));
  }
  // The run that merged the pull request writes its report, though the pull request is now closed.
  for (const autoMerge of [false, true]) {
    const own = await gateMerge(entry, { command: 'pr', autoMerge, pulls: autoMerge ? [{}, {}, { state: 'closed', merged: true }] : [{}] });
    assert.equal(own.stepOutput, 'merged=true\n', String(autoMerge));
    assert.equal(own.comments.length, 1, String(autoMerge));
    assert.match(own.comments[0], /Merged\.\n$/);
  }
});

const RUNNING = [{ name: 'tests', status: 'in_progress', conclusion: null }];
const WAITING_FOR = (sha) => `<!-- parser-studio-waiting-for-ci ${sha} -->`;

test('gate: CI still running when the wait ends: the report says the gate waits for CI, with no maintainer label', async () => {
  const entry = ['parsers/acme/pull-api/meta.json'];
  // CI is running, or GitHub hasn't created its run yet, and no check has failed.
  for (const [checks, ciRuns] of [[[RUNNING], [[{ status: 'in_progress', conclusion: null }]]], [[PASSED], [[]]]]) {
    const r = await gateMerge(entry, { command: 'pr', autoMerge: false, checks, ciRuns });
    assert.equal(firstMergeCall(r), -1);
    assert.equal(r.stepOutput, '');
    assert.ok(!r.calls.some((c) => c.endsWith('/issues/7/labels {"labels":["needs review"]}')), r.calls.join('\n'));
    assert.equal(r.comments.length, 1);
    assert.match(r.comments[0], /CI is still running on this commit after 10 minutes, so this waits\. When CI finishes, the gate runs again and merges this pull request if CI passed, with no maintainer needed\./);
    assert.ok(r.comments[0].trimEnd().endsWith(WAITING_FOR('abc123')), r.comments[0]);
  }
  // A check that has already failed, or a check other than CI's still running after CI finished,
  // holds it for a maintainer as before, with no marker.
  for (const [checks, ciRuns] of [
    [[[{ name: 'tests', status: 'completed', conclusion: 'failure' }, { name: 'secrets', status: 'in_progress', conclusion: null }]], [[{ status: 'in_progress', conclusion: null }]]],
    [[[{ name: 'other', status: 'in_progress', conclusion: null }]], [[{ status: 'completed', conclusion: 'success' }]]],
  ]) {
    const held = await gateMerge(entry, { command: 'pr', autoMerge: false, checks, ciRuns });
    assert.equal(firstMergeCall(held), -1);
    assert.ok(held.calls.some((c) => c.endsWith('/issues/7/labels {"labels":["needs review"]}')), held.calls.join('\n'));
    assert.match(held.comments[0], /Another check on this commit failed or is still running/);
    assert.ok(!held.comments[0].includes('waiting-for-ci'));
  }
  // The issue route has no CI to wait for, so a check still running there holds it for a maintainer.
  const issue = await gateMerge(entry, { command: 'merge', autoMerge: false, checks: [RUNNING], ciRuns: [[]] });
  assert.match(issue.out, /^Another check on this commit failed or is still running/);
});

test('gate: waiting is true only while the gate\'s own report holds this commit for CI', async () => {
  const report = (sha, extra = '') => `<!-- parser-studio-report -->\n### Parser library checks: passed\n\nCI is still running.\n\n${WAITING_FOR(sha)}\n${extra}`;
  const bot = { type: 'Bot' };
  const waiting = async (comments) => (await gateMerge([], { command: 'waiting', comments })).status;
  assert.equal(await waiting([{ id: 1, body: report('abc123'), user: bot }]), 0);
  // Another commit's marker, a report the gate has since replaced, a marker that isn't the report's
  // last line, or one in someone else's comment: no.
  assert.equal(await waiting([{ id: 1, body: report('def456'), user: bot }]), 1);
  assert.equal(await waiting([{ id: 1, body: '<!-- parser-studio-report -->\n### Parser library checks: passed\n\nMerged.\n', user: bot }]), 1);
  assert.equal(await waiting([{ id: 1, body: report('abc123', 'and more\n'), user: bot }]), 1);
  assert.equal(await waiting([{ id: 1, body: report('abc123'), user: { type: 'User' } }]), 1);
  assert.equal(await waiting([]), 1);
});

test('gate: the run CI starts merges a pull request held for CI once CI passed, and holds it if CI failed', async () => {
  // When CI finishes, the workflow runs the same gate for the commit: it checks the file list and
  // every check on the commit again, then merges, and the new report has no marker.
  const entry = ['parsers/acme/pull-api/meta.json'];
  const held = [{ id: 1, body: `<!-- parser-studio-report -->\nCI is still running.\n\n${WAITING_FOR('abc123')}\n`, user: { type: 'Bot' } }];
  const merged = await gateMerge(entry, { command: 'pr', autoMerge: false, comments: held });
  assert.equal(merged.stepOutput, 'merged=true\n');
  assert.ok(merged.calls.includes('PATCH https://api.github.com/repos/o/r/issues/comments/1'), merged.calls.join('\n'));
  assert.match(merged.comments[0], /Merged\.\n$/);
  assert.ok(!merged.comments[0].includes('waiting-for-ci'));
  const failed = await gateMerge(entry, { command: 'pr', autoMerge: false, comments: held, checks: [[{ name: 'tests', status: 'completed', conclusion: 'failure' }]], ciRuns: [[{ status: 'completed', conclusion: 'failure' }]] });
  assert.equal(firstMergeCall(failed), -1);
  assert.match(failed.comments[0], /Another check on this commit failed/);
  assert.ok(failed.calls.some((c) => c.endsWith('/issues/7/labels {"labels":["needs review"]}')));
  // Bridge code is still held, whatever started the run.
  const bridge = await gateMerge([...entry, 'bridges/acme-pull/acme_pull.py'], { command: 'pr', autoMerge: false, comments: held });
  assert.equal(firstMergeCall(bridge), -1);
  assert.match(bridge.comments[0], /changes bridge code/);
});

test('bridge READMEs: each service example restarts on failure after a delay, and says why', async () => {
  // A bridge started before the network is up stops when a host name doesn't resolve, since no run
  // has worked yet. The service manager starts it again, so each README's systemd unit restarts on
  // failure, after a delay, and the README says why.
  const names = (await readdir(path.join(ROOT, 'bridges'), { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name);
  assert.ok(names.includes('webhook-relay') && names.length >= 23, names.join());
  for (const name of names) {
    const readme = await readFile(path.join(ROOT, 'bridges', name, 'README.md'), 'utf8');
    const units = [...readme.matchAll(/```ini\n([\s\S]*?)```/g)].map((m) => m[1]).filter((u) => u.includes('[Service]'));
    assert.equal(units.length, 1, name);
    const [unit] = units;
    for (const line of [/^Restart=on-failure$/m, /^RestartSec=[1-9]\d*$/m, /^After=network-online\.target$/m, /^Wants=network-online\.target$/m]) {
      assert.match(unit, line, name);
    }
    assert.match(readme, /^`Restart=on-failure` starts the (bridge|relay) again .+ after it stops, for example when it started before /m, name);
    if (name === 'webhook-relay') continue;
    // A polling bridge runs with --interval, from a state directory that keeps its cursor.
    const exec = /^ExecStart=\/usr\/bin\/python3 \/opt\/([a-z0-9-]+)\/(\S+\.py) --interval \d+$/m.exec(unit);
    assert.ok(exec && exec[1] === name, name);
    assert.ok((await readdir(path.join(ROOT, 'bridges', name))).includes(exec[2]), name);
    assert.match(unit, new RegExp(`^StateDirectory=${name}\n`, 'm'), name);
    assert.match(unit, new RegExp(`^WorkingDirectory=/var/lib/${name}\n`, 'm'), name);
  }
});

test('README markdown: HTML stays text and only https links survive', () => {
  const blocks = parseMarkdown('# Title <img src=x onerror=alert(1)>\n\n<script>alert(1)</script>\n\nSee [docs](https://example.com/a) and [bad](javascript:alert) and https://example.org/b.\n');
  assert.deepEqual(blocks.map((b) => b.t), ['h', 'p', 'p']);
  assert.deepEqual(blocks[0].c, [{ t: 'text', v: 'Title <img src=x onerror=alert(1)>' }]);
  assert.deepEqual(blocks[1].c, [{ t: 'text', v: '<script>alert(1)</script>' }]);
  const links = blocks[2].c.filter((n) => n.t === 'a').map((n) => n.href);
  assert.deepEqual(links, ['https://example.com/a', 'javascript:alert', 'https://example.org/b']);
  assert.equal(linkTarget('javascript:alert(1)', 'https://github.com/o/r/blob/main/bridges/x/'), null);
  assert.equal(linkTarget('data:text/html,hi', 'https://github.com/o/r/blob/main/bridges/x/'), null);
  assert.equal(linkTarget('//evil.example.com/x', 'https://github.com/o/r/blob/main/bridges/x/'), null);
  assert.equal(linkTarget('../../README.md', 'https://github.com/o/r/blob/main/bridges/x/'), 'https://github.com/o/r/blob/main/README.md');
  assert.equal(linkTarget('README.md', null), null);
});

test('README markdown: the bridge README parses into tables, lists, code and quotes', async () => {
  const blocks = parseMarkdown(await readFile(path.join(ROOT, 'bridges/ai-compliance-logs/README.md'), 'utf8'));
  const kinds = new Set(blocks.map((b) => b.t));
  for (const k of ['h', 'p', 'quote', 'table', 'ul', 'code']) assert.ok(kinds.has(k), k);
  const env = blocks.find((b) => b.t === 'table' && b.head.some((c) => c[0] && c[0].v === 'Variable'));
  assert.ok(env.rows.length >= 15);
  assert.ok(env.rows.every((r) => r.length === 3));
  assert.deepEqual(parseInline('`a|b` **bold `x`**'), [{ t: 'code', v: 'a|b' }, { t: 'text', v: ' ' }, { t: 'b', c: [{ t: 'text', v: 'bold ' }, { t: 'code', v: 'x' }] }]);
});
