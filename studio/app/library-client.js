// Loads the community library from the public GitHub repo at runtime, so the page shows
// newly merged parsers without a redeploy. Falls back to the copy bundled with the page when
// GitHub can't be reached (offline, or the unauthenticated API rate limit of 60 an hour).
// Only GET requests to api.github.com and raw.githubusercontent.com; nothing is sent.

import { REPO, BRANCH } from '../core/version.js';
import { parseSamples, entryId, BRIDGE_PATH, bridgeScripts } from '../core/library.js';

const REPO_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const CACHE_KEY = 'parser-studio:library-cache:v3';

export function repo() {
  try {
    const q = new URLSearchParams(location.search).get('repo');
    if (q && REPO_RE.test(q)) return q;
  } catch { /* default */ }
  return REPO;
}

// Files are read at a fixed commit, so a CDN copy of an older version can't mix in.
const raw = (path, ref = BRANCH) => `https://raw.githubusercontent.com/${repo()}/${ref}/${path.split('/').map(encodeURIComponent).join('/')}`;
export const githubUrl = (path = '') => `https://github.com/${repo()}${path}`;

// A cache written before bridges were listed is ignored, so the next load lists them.
function readCache() {
  try {
    const c = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
    return c && Array.isArray(c.bridges) ? c : null;
  } catch { return null; }
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

// Returns {entries, bridges, source: 'github'|'snapshot', at, sha?, error?}. bridges lists each
// bridges/<name> folder with its file names; snapshot copies also carry the text.
// Two API calls when the library changed (the head commit, then its tree) and one when it
// didn't; an unchanged head answers 304, which doesn't count against GitHub's rate limit.
export async function loadLibrary({ force = false } = {}) {
  const cache = readCache();
  const api = (path, headers = {}) => fetch(`https://api.github.com/repos/${repo()}${path}`, { headers: { Accept: 'application/vnd.github+json', ...headers }, cache: 'no-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
  const fail = (res) => Object.assign(new Error(res.status === 403 || res.status === 429 ? 'GitHub rate limit reached' : `GitHub said ${res.status}`), { status: res.status });
  try {
    const headHeaders = { Accept: 'application/vnd.github.sha' };
    if (cache && cache.repo === repo() && cache.headEtag && !force) headHeaders['If-None-Match'] = cache.headEtag;
    const head = await api(`/commits/${BRANCH}`, headHeaders);
    if (head.status === 304 && cache) return { entries: cache.entries.map((e) => ({ ...e, loaded: false })), bridges: cache.bridges, source: 'github', at: cache.at, sha: cache.sha };
    if (!head.ok) throw fail(head);
    const sha = (await head.text()).trim();
    if (cache && cache.repo === repo() && cache.sha === sha && !force) {
      writeCache({ ...cache, headEtag: head.headers.get('ETag') });
      return { entries: cache.entries.map((e) => ({ ...e, loaded: false })), bridges: cache.bridges, source: 'github', at: cache.at, sha };
    }
    const res = await api(`/git/trees/${sha}?recursive=1`);
    if (!res.ok) throw fail(res);
    const tree = await res.json();
    const metas = tree.tree.filter((t) => t.type === 'blob' && /^parsers\/[^/]+\/[^/]+\/meta\.json$/.test(t.path));
    const files = new Map();
    for (const t of tree.tree) {
      const m = /^parsers\/([^/]+\/[^/]+)\/([^/]+)$/.exec(t.path);
      if (m && t.type === 'blob') (files.get(m[1]) || files.set(m[1], []).get(m[1])).push(m[2]);
    }
    const bridges = bridgeFolders(tree.tree);
    const entries = (await pool(metas, 6, async (t) => {
      const id = t.path.split('/').slice(1, 3).join('/');
      try {
        const meta = JSON.parse(await fetchText(raw(t.path, sha)));
        return { id, ref: sha, meta, files: files.get(id) || [], vendor: meta.vendor, product: meta.product, loaded: false };
      } catch {
        return null;
      }
    })).filter(Boolean);
    const at = new Date().toISOString();
    writeCache({ repo: repo(), headEtag: head.headers.get('ETag'), at, sha, entries: entries.map(({ loaded, texts, samples, expected, ...rest }) => rest), bridges });
    return { entries, bridges, source: 'github', at, sha };
  } catch (err) {
    try {
      const snap = await loadSnapshot();
      return { entries: fromSnapshot(snap), bridges: (snap.bridges || []).map((b) => ({ ...b, loaded: true })), source: 'snapshot', at: snap.generated, error: err.message };
    } catch {
      if (cache && cache.entries) return { entries: cache.entries.map((e) => ({ ...e, loaded: false })), bridges: cache.bridges, source: 'github', at: cache.at, error: err.message };
      return { entries: [], bridges: [], source: 'none', at: null, error: err.message };
    }
  }
}

// Fetch an entry's parser files, samples and expected output.
export async function loadEntry(entry) {
  if (entry.loaded) return entry;
  const base = `parsers/${entry.id}/`;
  const texts = {};
  const ref = entry.ref || BRANCH;
  await pool(entry.meta.parsers || [], 4, async (p) => { texts[p.name] = await fetchText(raw(`${base}${p.name}.parser.txt`, ref)); });
  const samples = parseSamples(await fetchText(raw(`${base}samples.log`, ref)));
  let expected = [];
  try { expected = JSON.parse(await fetchText(raw(`${base}expected.json`, ref))); } catch { expected = []; }
  Object.assign(entry, { texts, samples, expected, loaded: true });
  return entry;
}

// Every bridge folder in a repo tree, with the names of the files directly in it. A fork made
// before bridges were renamed keeps them under collectors/<name>: each lists as bridges/<name>,
// the path its entries resolve to, with dir naming the folder that holds the files.
export function bridgeFolders(tree) {
  const dirs = new Map();
  for (const t of tree || []) {
    const m = t && t.type === 'blob' ? /^((?:bridges|collectors)\/[^/]+)\/([^/]+)$/.exec(t.path) : null;
    if (m) (dirs.get(m[1]) || dirs.set(m[1], []).get(m[1])).push(m[2]);
  }
  const out = [];
  for (const [dir, names] of dirs) {
    const path = dir.replace(/^collectors\//, 'bridges/');
    if (path === dir) out.push({ path, files: names.sort() });
    else if (!dirs.has(path)) out.push({ path, dir, files: names.sort() });
  }
  return out;
}

// A bridge's README and scripts, read at the same commit as the library. When GitHub can't
// serve them, the copy bundled with the page is used. Returns {path, dir?, files, readme,
// scripts: [{name, text}], fallback?}.
const bridgeCache = new Map();
export function loadBridge(bridges, path, ref = BRANCH) {
  if (typeof path !== 'string' || !BRIDGE_PATH.test(path)) return Promise.reject(new Error('not a bridge path'));
  const known = (bridges || []).find((b) => b.path === path);
  if (known && known.loaded) return Promise.resolve(known);
  const key = `${repo()}@${ref}:${path}`;
  if (!bridgeCache.has(key)) {
    bridgeCache.set(key, fetchBridge(known, path, ref).catch(async (err) => {
      bridgeCache.delete(key);
      let copy = null;
      try { copy = ((await loadSnapshot()).bridges || []).find((b) => b.path === path); } catch { /* no bundled copy */ }
      if (copy) return { ...copy, fallback: true, error: err.message };
      throw err;
    }));
  }
  return bridgeCache.get(key);
}

async function fetchBridge(known, path, ref) {
  if (!known) throw new Error(`${path} is not in the repo`);
  const dir = known.dir || path;
  const names = bridgeScripts(known.files);
  const readme = known.files.includes('README.md') ? await fetchText(raw(`${dir}/README.md`, ref)) : '';
  const texts = await pool(names, 3, (n) => fetchText(raw(`${dir}/${n}`, ref)));
  return { path, ...(known.dir ? { dir } : {}), files: known.files, readme, scripts: names.map((name, i) => ({ name, text: texts[i] })) };
}

// Entries in the shape the lint's overlap check takes.
export function lintEntries(entries) {
  return entries.filter((e) => e.loaded).map((e) => ({ id: e.id, vendor: e.meta.vendor, product: e.meta.product, parsers: engineParsers(e), samples: e.samples }));
}

export function engineParsers(entry) {
  return (entry.meta.parsers || []).map((p) => ({ name: p.name, text: entry.texts[p.name] ?? '', parent: p.parent || undefined, role: p.role }));
}

export { entryId };
