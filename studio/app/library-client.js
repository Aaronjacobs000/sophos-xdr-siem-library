// Loads the community library from the public GitHub repo at runtime, so the page shows
// newly merged parsers without a redeploy. Falls back to the copy bundled with the page when
// GitHub can't be reached (offline, or the unauthenticated API rate limit of 60 an hour).
// Only GET requests to api.github.com and raw.githubusercontent.com; nothing is sent.

import { REPO, BRANCH } from '../core/version.js';
import { parseSamples, entryId } from '../core/library.js';

const REPO_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const CACHE_KEY = 'parser-studio:library-cache:v1';

export function repo() {
  try {
    const q = new URLSearchParams(location.search).get('repo');
    if (q && REPO_RE.test(q)) return q;
  } catch { /* default */ }
  return REPO;
}

const raw = (path) => `https://raw.githubusercontent.com/${repo()}/${BRANCH}/${path.split('/').map(encodeURIComponent).join('/')}`;
export const githubUrl = (path = '') => `https://github.com/${repo()}${path}`;

function readCache() {
  try { return JSON.parse(localStorage.getItem(CACHE_KEY) || 'null'); } catch { return null; }
}
function writeCache(v) {
  try { localStorage.setItem(CACHE_KEY, JSON.stringify(v)); } catch { /* storage off */ }
}

async function fetchText(url, init) {
  const res = await fetch(url, { ...init, cache: 'no-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw Object.assign(new Error(`${res.status} ${res.statusText}`), { status: res.status });
  return res.text();
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

function fromSnapshot(snap) {
  return snap.entries.map((e) => ({ ...e, loaded: true }));
}

async function loadSnapshot() {
  const res = await fetch(new URL('../library-snapshot.json', import.meta.url), { cache: 'no-cache' });
  if (!res.ok) throw new Error('no bundled library copy');
  return res.json();
}

// Returns {entries, source: 'github'|'snapshot', at, sha?, error?}
export async function loadLibrary({ force = false } = {}) {
  const cache = readCache();
  const headers = { Accept: 'application/vnd.github+json' };
  if (cache && cache.repo === repo() && cache.etag && !force) headers['If-None-Match'] = cache.etag;
  try {
    const res = await fetch(`https://api.github.com/repos/${repo()}/git/trees/${BRANCH}?recursive=1`, { headers, cache: 'no-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (res.status === 304 && cache) {
      return { entries: cache.entries.map((e) => ({ ...e, loaded: false })), source: 'github', at: cache.at, sha: cache.sha };
    }
    if (!res.ok) throw Object.assign(new Error(res.status === 403 || res.status === 429 ? 'GitHub rate limit reached' : `GitHub said ${res.status}`), { status: res.status });
    const tree = await res.json();
    const metas = tree.tree.filter((t) => t.type === 'blob' && /^parsers\/[^/]+\/[^/]+\/meta\.json$/.test(t.path));
    const files = new Map();
    for (const t of tree.tree) {
      const m = /^parsers\/([^/]+\/[^/]+)\/([^/]+)$/.exec(t.path);
      if (m && t.type === 'blob') (files.get(m[1]) || files.set(m[1], []).get(m[1])).push(m[2]);
    }
    const entries = (await pool(metas, 6, async (t) => {
      const id = t.path.split('/').slice(1, 3).join('/');
      try {
        const meta = JSON.parse(await fetchText(raw(t.path)));
        return { id, meta, files: files.get(id) || [], vendor: meta.vendor, product: meta.product, loaded: false };
      } catch {
        return null;
      }
    })).filter(Boolean);
    const at = new Date().toISOString();
    writeCache({ repo: repo(), etag: res.headers.get('ETag'), at, sha: tree.sha, entries: entries.map(({ loaded, texts, samples, expected, ...rest }) => rest) });
    return { entries, source: 'github', at, sha: tree.sha };
  } catch (err) {
    try {
      const snap = await loadSnapshot();
      return { entries: fromSnapshot(snap), source: 'snapshot', at: snap.generated, error: err.message };
    } catch {
      if (cache && cache.entries) return { entries: cache.entries.map((e) => ({ ...e, loaded: false })), source: 'github', at: cache.at, error: err.message };
      return { entries: [], source: 'none', at: null, error: err.message };
    }
  }
}

// Fetch an entry's parser files, samples and expected output.
export async function loadEntry(entry) {
  if (entry.loaded) return entry;
  const base = `parsers/${entry.id}/`;
  const texts = {};
  await pool(entry.meta.parsers || [], 4, async (p) => { texts[p.name] = await fetchText(raw(`${base}${p.name}.parser.txt`)); });
  const samples = parseSamples(await fetchText(raw(`${base}samples.log`)));
  let expected = [];
  try { expected = JSON.parse(await fetchText(raw(`${base}expected.json`))); } catch { expected = []; }
  Object.assign(entry, { texts, samples, expected, loaded: true });
  return entry;
}

// Entries in the shape the lint's overlap check takes.
export function lintEntries(entries) {
  return entries.filter((e) => e.loaded).map((e) => ({ id: e.id, vendor: e.meta.vendor, product: e.meta.product, parsers: engineParsers(e), samples: e.samples }));
}

export function engineParsers(entry) {
  return (entry.meta.parsers || []).map((p) => ({ name: p.name, text: entry.texts[p.name] ?? '', parent: p.parent || undefined, role: p.role }));
}

export { entryId };
