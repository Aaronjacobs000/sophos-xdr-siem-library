// Where the page reads the library from: always this repo, whatever the address says, and a
// cached copy only when this repo wrote it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { REPO } from '../studio/core/version.js';
import { repo, loadLibrary } from '../studio/app/library-client.js';

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

test('the library always comes from this repo, whatever ?repo= says', () => {
  globalThis.location = { search: '?repo=example-owner/example-library', hash: '' };
  try {
    assert.equal(repo(), REPO);
  } finally {
    delete globalThis.location;
  }
});

test('offline, a cached library from another repo is not shown', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new TypeError('offline'); };
  try {
    const entry = { id: 'acme/widget', meta: { vendor: 'Acme', product: 'Widget', parsers: [] }, files: [] };
    store.set('parser-studio:library-cache:v3', JSON.stringify({ repo: 'example-owner/example-library', at: '2026-10-01T00:00:00Z', sha: 'a'.repeat(40), entries: [entry], bridges: [] }));
    const other = await loadLibrary();
    assert.equal(other.source, 'none');
    assert.deepEqual(other.entries, []);
    store.set('parser-studio:library-cache:v3', JSON.stringify({ repo: REPO, at: '2026-10-01T00:00:00Z', sha: 'a'.repeat(40), entries: [entry], bridges: [] }));
    const own = await loadLibrary();
    assert.deepEqual(own.entries.map((e) => e.id), ['acme/widget']);
  } finally {
    globalThis.fetch = realFetch;
    store.clear();
  }
});
