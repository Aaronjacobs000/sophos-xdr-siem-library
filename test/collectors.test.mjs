// Collectors: the "collector" metadata rule, the review rule for collector code, and the
// README renderer the entry page uses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateMeta, collectorScripts, hasCollector } from '../studio/core/library.js';
import { listCollectors, loadCollectors } from '../tools/lib/fs-library.mjs';
import { reviewReasons } from '../tools/lib/merge-rules.mjs';
import { parseMarkdown, parseInline, linkTarget } from '../studio/app/markdown.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILES = ['meta.json', 'ACME_PULL_JSON_STANDALONE.parser.txt', 'samples.log', 'expected.json'];
const META = { vendor: 'Acme', product: 'Pull API', versions: [], format: 'json', ship_method: 'http-ingest', author: 'octocat', license: 'MIT', sample_source: 'synthetic', reference_time: '2026-10-13T00:00:00Z', tested: { emulator: '0.1.0', tenant: null }, parsers: [{ name: 'ACME_PULL_JSON_STANDALONE', file: 'ACME_PULL_JSON_STANDALONE.parser.txt', role: 'standalone' }] };
const ON_MAIN = [{ path: 'collectors/acme-pull', files: ['README.md', 'acme_pull.py', 'test_acme_pull.py'] }];
const problems = (meta, collectors) => validateMeta(meta, FILES, collectors ? { collectors } : {}).filter((p) => p.code === 'collector');

test('collector: a folder under collectors/ that is on the main branch passes', () => {
  assert.deepEqual(problems({ ...META, collector: 'collectors/acme-pull' }, ON_MAIN), []);
  assert.equal(hasCollector({ collector: 'collectors/acme-pull' }), true);
  // Without the list of collectors (the page itself), only the form is checked.
  assert.deepEqual(problems({ ...META, collector: 'collectors/not-listed' }), []);
});

test('collector: the value must be a folder path under collectors/', () => {
  for (const bad of ['parsers/acme/pull-api', 'collectors/', 'collectors', 'collectors/acme-pull/', 'collectors/acme-pull/acme_pull.py', 'collectors/../parsers', '../collectors/acme-pull', '/collectors/acme-pull', './collectors/acme-pull', 'collectors/Acme_Pull', 'https://example.com/acme_pull.py', 42, true, ['collectors/acme-pull'], { path: 'collectors/acme-pull' }]) {
    const p = problems({ ...META, collector: bad }, ON_MAIN);
    assert.equal(p.length, 1, JSON.stringify(bad));
    assert.equal(p[0].level, 'error');
    assert.match(p[0].message, /must be the path of a folder under collectors\//);
    assert.equal(hasCollector({ collector: bad }), false);
  }
});

test('collector: it must exist on the main branch with a README.md and a .py file', () => {
  const missing = problems({ ...META, collector: 'collectors/acme-push' }, ON_MAIN);
  assert.equal(missing.length, 1);
  assert.equal(missing[0].level, 'error');
  assert.match(missing[0].message, /collectors\/acme-push is not on the main branch/);
  const noReadme = problems({ ...META, collector: 'collectors/acme-pull' }, [{ path: 'collectors/acme-pull', files: ['acme_pull.py'] }]);
  assert.deepEqual(noReadme.map((p) => [p.level, p.message]), [['error', 'collector collectors/acme-pull has no README.md']]);
  const noScript = problems({ ...META, collector: 'collectors/acme-pull' }, [{ path: 'collectors/acme-pull', files: ['README.md', 'notes.txt'] }]);
  assert.deepEqual(noScript.map((p) => [p.level, p.message]), [['error', 'collector collectors/acme-pull has no .py file']]);
  assert.equal(problems({ ...META, collector: 'collectors/acme-pull' }, []).length, 1);
});

test('collector: http-ingest without one is a warning, and older entries stay valid', () => {
  const w = problems({ ...META }, ON_MAIN);
  assert.equal(w.length, 1);
  assert.equal(w[0].level, 'warning');
  assert.match(w[0].message, /http-ingest but there is no collector/);
  assert.deepEqual(problems({ ...META, collector: null }, ON_MAIN).map((p) => p.level), ['warning']);
  for (const ship of ['syslog', 's3', 'azure', 'other']) assert.deepEqual(validateMeta({ ...META, ship_method: ship }, FILES, { collectors: ON_MAIN }), [], ship);
  assert.equal(validateMeta({ ...META }, FILES).some((p) => p.level === 'error'), false);
});

test('collector scripts leave out tests, and the repo collectors load', async () => {
  assert.deepEqual(collectorScripts(['README.md', 'test_acme_pull.py', 'acme_pull.py', 'acme_pull_test.py', 'helper.py']), ['acme_pull.py', 'helper.py']);
  assert.deepEqual(collectorScripts(['README.md', 'test_only.py']), ['test_only.py']);
  assert.deepEqual(collectorScripts(['README.md']), []);
  const listed = await listCollectors(ROOT);
  const ai = listed.find((c) => c.path === 'collectors/ai-compliance-logs');
  assert.ok(ai && ai.files.includes('README.md') && ai.files.includes('ai_compliance_collector.py'));
  const loaded = (await loadCollectors(ROOT)).find((c) => c.path === 'collectors/ai-compliance-logs');
  assert.deepEqual(loaded.scripts.map((s) => s.name), ['ai_compliance_collector.py']);
  assert.match(loaded.readme, /^# AI compliance log collector/);
});

test('review rule: collector code and other non-library files always need a review', () => {
  assert.deepEqual(reviewReasons(['parsers/acme/pull-api/meta.json', 'parsers/acme/pull-api/samples.log']), []);
  assert.match(reviewReasons(['parsers/acme/pull-api/meta.json', 'collectors/acme-pull/acme_pull.py']).join(), /changes collector code, which a maintainer always reviews: collectors\/acme-pull\/acme_pull.py/);
  assert.match(reviewReasons(['collectors/acme-pull/README.md']).join(), /collector code/);
  assert.match(reviewReasons(['.github/workflows/ci.yml']).join(), /outside parsers\//);
});

// Runs github-gate.mjs merge against a stand-in for the GitHub API, the way the two workflows
// call it, and reports what it said and which calls it made.
async function gateMerge(files) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gate-'));
  const log = path.join(dir, 'calls.log');
  const mock = path.join(dir, 'mock-fetch.mjs');
  await writeFile(log, '');
  await writeFile(mock, `
import { appendFileSync } from 'node:fs';
const files = ${JSON.stringify(files.map((filename) => ({ filename })))};
globalThis.fetch = async (url, init = {}) => {
  const method = init.method || 'GET';
  appendFileSync(${JSON.stringify(log)}, method + ' ' + url + '\\n');
  const u = new URL(url);
  let body = {};
  if (u.pathname === '/repos/o/r') body = { allow_auto_merge: true };
  else if (u.pathname === '/repos/o/r/pulls/7') body = { draft: false, head: { sha: 'abc123' }, node_id: 'PR_7' };
  else if (u.pathname === '/repos/o/r/pulls/7/files') body = u.searchParams.get('page') === '1' ? files : [];
  else if (u.pathname === '/graphql') body = { data: { enablePullRequestAutoMerge: { clientMutationId: null } } };
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
};
`);
  const out = execFileSync(process.execPath, ['--import', pathToFileURL(mock).href, path.join(ROOT, 'tools/github-gate.mjs'), 'merge', '--pr', '7', '--sha', 'abc123'], { env: { ...process.env, GITHUB_REPOSITORY: 'o/r', GITHUB_TOKEN: 'test' }, encoding: 'utf8' });
  const calls = (await readFile(log, 'utf8')).trim().split('\n');
  await rm(dir, { recursive: true, force: true });
  return { out: out.trim(), calls };
}

test('gate: the merge step refuses a pull request with collector code, from either route', async () => {
  const held = await gateMerge(['parsers/acme/pull-api/meta.json', 'collectors/acme-pull/acme_pull.py']);
  assert.match(held.out, /^Not merged automatically: this pull request changes collector code/);
  assert.ok(!held.calls.some((c) => /graphql|\/merge|^PUT/.test(c)), held.calls.join('\n'));
  // Control: the same stand-in merges a library-only pull request.
  const ok = await gateMerge(['parsers/acme/pull-api/meta.json']);
  assert.equal(ok.out, 'Auto-merge is on for this pull request.');
  assert.ok(ok.calls.some((c) => c === 'POST https://api.github.com/graphql'));
});

test('README markdown: HTML stays text and only https links survive', () => {
  const blocks = parseMarkdown('# Title <img src=x onerror=alert(1)>\n\n<script>alert(1)</script>\n\nSee [docs](https://example.com/a) and [bad](javascript:alert) and https://example.org/b.\n');
  assert.deepEqual(blocks.map((b) => b.t), ['h', 'p', 'p']);
  assert.deepEqual(blocks[0].c, [{ t: 'text', v: 'Title <img src=x onerror=alert(1)>' }]);
  assert.deepEqual(blocks[1].c, [{ t: 'text', v: '<script>alert(1)</script>' }]);
  const links = blocks[2].c.filter((n) => n.t === 'a').map((n) => n.href);
  assert.deepEqual(links, ['https://example.com/a', 'javascript:alert', 'https://example.org/b']);
  assert.equal(linkTarget('javascript:alert(1)', 'https://github.com/o/r/blob/main/collectors/x/'), null);
  assert.equal(linkTarget('data:text/html,hi', 'https://github.com/o/r/blob/main/collectors/x/'), null);
  assert.equal(linkTarget('//evil.example.com/x', 'https://github.com/o/r/blob/main/collectors/x/'), null);
  assert.equal(linkTarget('../../README.md', 'https://github.com/o/r/blob/main/collectors/x/'), 'https://github.com/o/r/blob/main/README.md');
  assert.equal(linkTarget('README.md', null), null);
});

test('README markdown: the collector README parses into tables, lists, code and quotes', async () => {
  const blocks = parseMarkdown(await readFile(path.join(ROOT, 'collectors/ai-compliance-logs/README.md'), 'utf8'));
  const kinds = new Set(blocks.map((b) => b.t));
  for (const k of ['h', 'p', 'quote', 'table', 'ul', 'code']) assert.ok(kinds.has(k), k);
  const env = blocks.find((b) => b.t === 'table' && b.head.some((c) => c[0] && c[0].v === 'Variable'));
  assert.ok(env.rows.length >= 15);
  assert.ok(env.rows.every((r) => r.length === 3));
  assert.deepEqual(parseInline('`a|b` **bold `x`**'), [{ t: 'code', v: 'a|b' }, { t: 'text', v: ' ' }, { t: 'b', c: [{ t: 'text', v: 'bold ' }, { t: 'code', v: 'x' }] }]);
});
