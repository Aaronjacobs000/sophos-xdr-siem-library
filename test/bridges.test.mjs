// Bridges: the "bridge" metadata rule and its old "collector" name, the review rule for bridge
// code, the site build, and the README renderer the entry page uses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateMeta, bridgeScripts, hasBridge, bridgeOf, withBridgeKey } from '../studio/core/library.js';
import { bridgeFolders } from '../studio/app/library-client.js';
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
});

// Runs github-gate.mjs merge against a stand-in for the GitHub API, the way the two workflows
// call it, and reports what it said and which calls it made.
async function gateMerge(files, { command = 'merge', autoMerge = true, pull = {}, refSha = 'abc123', deleteStatus = 204, filesErrors = 0, mergeErrors = 0, mergeError = 'Base branch was modified. Review and try the merge again.' } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gate-'));
  const log = path.join(dir, 'calls.log');
  const mock = path.join(dir, 'mock-fetch.mjs');
  const output = path.join(dir, 'github-output.txt');
  await writeFile(log, '');
  await writeFile(output, '');
  await writeFile(path.join(dir, 'report.json'), JSON.stringify({ passed: true, eligible: true }));
  await writeFile(path.join(dir, 'report.md'), '### Parser library checks: passed\n');
  await writeFile(mock, `
import { appendFileSync } from 'node:fs';
const files = ${JSON.stringify(files.map((filename) => ({ filename })))};
let filesErrors = ${filesErrors}, mergeErrors = ${mergeErrors};
globalThis.fetch = async (url, init = {}) => {
  const method = init.method || 'GET';
  appendFileSync(${JSON.stringify(log)}, method + ' ' + url + '\\n');
  const u = new URL(url);
  let body = {};
  if (u.pathname === '/repos/o/r/pulls/7/files' && filesErrors > 0) { filesErrors--; return new Response('<html>Server Error</html>', { status: 500 }); }
  if (method === 'PUT' && u.pathname === '/repos/o/r/pulls/7/merge' && mergeErrors > 0) { mergeErrors--; return new Response(JSON.stringify({ message: ${JSON.stringify(mergeError)} }), { status: 405 }); }
  if (u.pathname === '/repos/o/r') body = { allow_auto_merge: true };
  else if (u.pathname === '/repos/o/r/pulls/7') body = { draft: false, node_id: 'PR_7', ...${JSON.stringify(pull)}, head: { sha: 'abc123', ...${JSON.stringify(pull.head || {})} } };
  else if (u.pathname === '/repos/o/r/pulls/7/files') body = u.searchParams.get('page') === '1' ? files : [];
  // Without a branch rule, GitHub refuses native auto-merge and the gate merges the pull request itself.
  else if (u.pathname === '/graphql') body = ${autoMerge} ? { data: { enablePullRequestAutoMerge: { clientMutationId: null } } } : { errors: [{ message: 'Pull request is in clean status' }] };
  else if (u.pathname === '/repos/o/r/commits/abc123/check-runs') body = { check_runs: [{ name: 'tests', status: 'completed', conclusion: 'success' }] };
  else if (method === 'GET' && /\\/(labels|comments)$/.test(u.pathname)) body = [];
  else if (method === 'GET' && u.pathname.startsWith('/repos/o/r/git/ref/heads/')) body = { object: { sha: ${JSON.stringify(refSha)} } };
  else if (method === 'DELETE' && u.pathname.startsWith('/repos/o/r/git/refs/heads/')) return new Response(${deleteStatus} === 204 ? null : JSON.stringify({ message: 'Reference update failed' }), { status: ${deleteStatus} });
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
};
`);
  const args = command === 'pr' ? ['pr', '--pr', '7', '--sha', 'abc123', '--report', path.join(dir, 'report.json'), '--markdown', path.join(dir, 'report.md')] : ['merge', '--pr', '7', '--sha', 'abc123'];
  const out = execFileSync(process.execPath, ['--import', pathToFileURL(mock).href, path.join(ROOT, 'tools/github-gate.mjs'), ...args], { env: { ...process.env, GITHUB_REPOSITORY: 'o/r', GITHUB_TOKEN: 'test', GITHUB_OUTPUT: output, GATE_RETRY_MS: '1' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const calls = (await readFile(log, 'utf8')).trim().split('\n');
  const stepOutput = await readFile(output, 'utf8');
  await rm(dir, { recursive: true, force: true });
  return { out: out.trim(), calls, stepOutput };
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
  assert.equal(filesCalls(listed).length, 3);
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
