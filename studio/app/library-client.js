// Loads the library from the site itself. The site build writes library-index.json and copies the
// parsers/ and bridges/ folders next to the page, and Pages publishes it again after every merge,
// so every request is relative to the page and the site doesn't depend on the repo's name.
// Only GET requests to this site; nothing is sent.

import { REPO } from '../core/version.js';
import { parseSamples, entryId, BRIDGE_PATH, bridgeScripts, bridgeOf } from '../core/library.js';

// Links to the repo on GitHub, where people read the files, open issues and contribute.
export const githubUrl = (path = '') => `https://github.com/${REPO}${path}`;

// A file of the site, by its path from the site's root, which holds index.html and app/.
export const siteUrl = (path) => new URL(`../${path.split('/').map(encodeURIComponent).join('/')}`, import.meta.url).href;

async function fetchText(url) {
  const res = await fetch(url, { cache: 'no-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
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

// Returns {entries, bridges, playbooks, connectors, source: 'site'|'none', at, sha?, error?}.
// bridges lists each bridges/<name> folder with its file names, and playbooks and connectors each
// entry's metadata and file names. One request: the index the site build wrote.
export async function loadLibrary() {
  try {
    const index = JSON.parse(await fetchText(siteUrl('library-index.json')));
    const entries = (index.entries || []).filter((e) => e && e.meta && typeof e.id === 'string')
      .map((e) => ({ id: e.id, meta: e.meta, files: e.files || [], vendor: e.meta.vendor, product: e.meta.product, loaded: false }));
    const automation = (list) => (Array.isArray(list) ? list : []).filter((e) => e && e.meta && typeof e.id === 'string')
      .map((e) => ({ id: e.id, meta: e.meta, files: e.files || [], loaded: false }));
    return { entries, bridges: index.bridges || [], playbooks: automation(index.playbooks), connectors: automation(index.connectors), source: 'site', at: index.generated || null, sha: index.commit || null };
  } catch (err) {
    return { entries: [], bridges: [], playbooks: [], connectors: [], source: 'none', at: null, error: err.message };
  }
}

// Fetch the text files of a playbook or connector entry, as entry.texts by file name. folder is
// playbooks or connectors.
export async function loadAutomationEntry(folder, entry) {
  if (entry.loaded) return entry;
  const names = entry.files.filter((f) => /^(template\.yaml|connector\.yaml|SETUP\.md|README\.md)$/.test(f));
  const texts = {};
  await pool(names, 4, async (n) => { texts[n] = await fetchText(siteUrl(`${folder}/${entry.id}/${n}`)); });
  Object.assign(entry, { texts, loaded: true });
  return entry;
}

// Fetch an entry's parser files, samples and expected output.
export async function loadEntry(entry) {
  if (entry.loaded) return entry;
  const base = `parsers/${entry.id}/`;
  const texts = {};
  await pool(entry.meta.parsers || [], 4, async (p) => { texts[p.name] = await fetchText(siteUrl(`${base}${p.name}.parser.txt`)); });
  const samples = parseSamples(await fetchText(siteUrl(`${base}samples.log`)));
  let expected = [];
  try { expected = JSON.parse(await fetchText(siteUrl(`${base}expected.json`))); } catch { expected = []; }
  Object.assign(entry, { texts, samples, expected, loaded: true });
  return entry;
}

// The folder in the repo that holds an entry's bridge, for links: bridges/<name>. With no folder
// listed, an entry that still names collectors/<name> under the old "collector" key points there.
export function bridgeFolder(bridges, meta) {
  const path = bridgeOf(meta);
  const known = (bridges || []).find((b) => b && b.path === path);
  if (known) return known.path;
  const legacy = meta && (meta.bridge === undefined || meta.bridge === null) && typeof meta.collector === 'string' && /^collectors\//.test(meta.collector);
  return legacy ? meta.collector : path;
}

// A bridge's README and scripts, from the copy the site build put next to the page. Returns
// {path, files, readme, scripts: [{name, text}]}.
const bridgeCache = new Map();
export function loadBridge(bridges, path) {
  if (typeof path !== 'string' || !BRIDGE_PATH.test(path)) return Promise.reject(new Error('not a bridge path'));
  const known = (bridges || []).find((b) => b.path === path);
  if (known && known.loaded) return Promise.resolve(known);
  if (!bridgeCache.has(path)) {
    bridgeCache.set(path, fetchBridge(known, path).catch((err) => {
      bridgeCache.delete(path);
      throw err;
    }));
  }
  return bridgeCache.get(path);
}

async function fetchBridge(known, path) {
  if (!known) throw new Error(`${path} is not in the library`);
  const names = bridgeScripts(known.files);
  const readme = known.files.includes('README.md') ? await fetchText(siteUrl(`${path}/README.md`)) : '';
  const texts = await pool(names, 3, (n) => fetchText(siteUrl(`${path}/${n}`)));
  return { path, files: known.files, readme, scripts: names.map((name, i) => ({ name, text: texts[i] })) };
}

// Entries in the shape the lint's overlap check takes.
export function lintEntries(entries) {
  return entries.filter((e) => e.loaded).map((e) => ({ id: e.id, vendor: e.meta.vendor, product: e.meta.product, parsers: engineParsers(e), samples: e.samples }));
}

export function engineParsers(entry) {
  return (entry.meta.parsers || []).map((p) => ({ name: p.name, text: entry.texts[p.name] ?? '', parent: p.parent || undefined, role: p.role }));
}

export { entryId };
