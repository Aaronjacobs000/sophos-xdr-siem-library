// Where the page reads the library from: the site itself, by paths relative to the page, so the
// site works whatever the repo is called and never calls GitHub.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadLibrary, loadEntry, loadBridge, loadAutomationEntry, siteUrl, githubUrl } from '../studio/app/library-client.js';
import { REPO } from '../studio/core/version.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SITE = new URL('../studio/', import.meta.url).href;

// Answers each fetch from a map of site paths and records the URLs asked for.
async function withSite(files, fn) {
  const realFetch = globalThis.fetch;
  const asked = [];
  globalThis.fetch = async (url) => {
    asked.push(String(url));
    const rel = String(url).startsWith(SITE) ? decodeURIComponent(String(url).slice(SITE.length)) : null;
    if (rel !== null && rel in files) return new Response(files[rel], { status: 200 });
    return new Response('not found', { status: 404, statusText: 'Not Found' });
  };
  try {
    return await fn(asked);
  } finally {
    globalThis.fetch = realFetch;
  }
}

const INDEX = {
  generated: '2026-10-16T00:00:00.000Z',
  commit: 'a'.repeat(40),
  entries: [{ id: 'acme/widget', meta: { vendor: 'Acme', product: 'Widget', parsers: [{ name: 'ACME_WIDGET_JSON_STANDALONE_AUTH', role: 'standalone' }] }, files: ['meta.json', 'samples.log'] }],
  bridges: [{ path: 'bridges/acme-pull', files: ['README.md', 'acme_pull.py', 'test_acme_pull.py'] }],
  playbooks: [{ id: 'acme/widget-lock', meta: { title: 'Widget lock', vendor: 'Acme' }, files: ['SETUP.md', 'meta.json', 'template.yaml'] }],
  connectors: [{ id: 'acme/widget', meta: { title: 'Widget', vendor: 'Acme' }, files: ['README.md', 'connector.yaml', 'meta.json'] }],
};

test('the library index comes from the site, by a path relative to the page', async () => {
  await withSite({ 'library-index.json': JSON.stringify(INDEX) }, async (asked) => {
    const lib = await loadLibrary();
    assert.equal(lib.source, 'site');
    assert.equal(lib.sha, INDEX.commit);
    assert.deepEqual(lib.entries.map((e) => [e.id, e.vendor, e.product, e.loaded]), [['acme/widget', 'Acme', 'Widget', false]]);
    assert.deepEqual(lib.bridges, INDEX.bridges);
    assert.deepEqual(asked, [`${SITE}library-index.json`]);
  });
});

test('an entry\'s files and a bridge\'s files come from the same site, and nothing comes from GitHub', async () => {
  const files = {
    'library-index.json': JSON.stringify(INDEX),
    'parsers/acme/widget/ACME_WIDGET_JSON_STANDALONE_AUTH.parser.txt': '# parser\n',
    'parsers/acme/widget/samples.log': '{"a":1}\n',
    'parsers/acme/widget/expected.json': '[]',
    'bridges/acme-pull/README.md': '# Acme bridge\n',
    'bridges/acme-pull/acme_pull.py': 'print("hi")\n',
  };
  await withSite(files, async (asked) => {
    const lib = await loadLibrary();
    const e = await loadEntry(lib.entries[0]);
    assert.equal(e.loaded, true);
    assert.equal(e.texts.ACME_WIDGET_JSON_STANDALONE_AUTH, '# parser\n');
    assert.deepEqual(e.samples, ['{"a":1}']);
    const b = await loadBridge(lib.bridges, 'bridges/acme-pull');
    assert.equal(b.readme, '# Acme bridge\n');
    assert.deepEqual(b.scripts, [{ name: 'acme_pull.py', text: 'print("hi")\n' }]);
    assert.ok(asked.length >= 6);
    for (const url of asked) {
      assert.ok(url.startsWith(SITE), url);
      assert.doesNotMatch(url, /github/i);
    }
  });
});

test('a bridge is read from its own path, whatever else its listing holds', async () => {
  const bridges = [{ path: 'bridges/acme-relay', dir: 'collectors/acme-relay', files: ['README.md', 'acme_relay.py'] }];
  const files = { 'bridges/acme-relay/README.md': '# Acme relay\n', 'bridges/acme-relay/acme_relay.py': 'pass\n' };
  await withSite(files, async (asked) => {
    const b = await loadBridge(bridges, 'bridges/acme-relay');
    assert.equal(b.readme, '# Acme relay\n');
    assert.equal(b.dir, undefined);
    for (const url of asked) assert.ok(url.startsWith(`${SITE}bridges/acme-relay/`), url);
  });
});

test('playbooks and connectors are listed from the index, and their files come from the same site', async () => {
  const files = {
    'library-index.json': JSON.stringify(INDEX),
    'playbooks/acme/widget-lock/template.yaml': 'kind: Playbook\n',
    'playbooks/acme/widget-lock/SETUP.md': '# Setup\n',
    'connectors/acme/widget/connector.yaml': 'kind: Connector\n',
    'connectors/acme/widget/README.md': '# Widget\n',
  };
  await withSite(files, async (asked) => {
    const lib = await loadLibrary();
    assert.deepEqual(lib.playbooks.map((e) => e.id), ['acme/widget-lock']);
    assert.deepEqual(lib.connectors.map((e) => e.id), ['acme/widget']);
    const pb = await loadAutomationEntry('playbooks', lib.playbooks[0]);
    assert.deepEqual(pb.texts, { 'SETUP.md': '# Setup\n', 'template.yaml': 'kind: Playbook\n' });
    const c = await loadAutomationEntry('connectors', lib.connectors[0]);
    assert.deepEqual(Object.keys(c.texts).sort(), ['README.md', 'connector.yaml']);
    for (const url of asked) assert.ok(url.startsWith(SITE) && !/github/i.test(url), url);
  });
});

test('when the index can\'t load, the library is empty and says why', async () => {
  await withSite({}, async () => {
    const lib = await loadLibrary();
    assert.equal(lib.source, 'none');
    assert.deepEqual(lib.entries, []);
    assert.match(lib.error, /404/);
  });
});

test('site paths are encoded, and links to the repo name it', () => {
  assert.equal(siteUrl('parsers/acme/a b/x.txt'), `${SITE}parsers/acme/a%20b/x.txt`);
  assert.equal(siteUrl('library-index.json'), `${SITE}library-index.json`);
  assert.equal(githubUrl('/issues'), `https://github.com/${REPO}/issues`);
  assert.equal(REPO, 'Aaronjacobs000/sophos-xdr-siem-library');
});

test('the page\'s content security policy lets it fetch from the site only', async () => {
  const html = await readFile(path.join(ROOT, 'studio/index.html'), 'utf8');
  const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  const connect = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('connect-src'));
  assert.equal(connect, "connect-src 'self'");
});
