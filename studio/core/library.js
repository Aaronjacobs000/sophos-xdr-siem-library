// Library entries: the folder layout, metadata rules, the single-text bundle used
// by the issue form, and the validation that both the studio and CI run.
//
// parsers/<vendor-slug>/<product-slug>/
//   meta.json            vendor, product, versions, format, ship method, author, license, parsers,
//                        and an optional bridge (bridges/<name>) for pull-only sources
//                        and webhooks that need a relay
//   <NAME>.parser.txt    one file per parser
//   samples.log          synthetic sample lines, one event per line
//   expected.json        the emulator result for each sample line

import { runParsers, expectedShape } from './engine.js';
import { lintParsers } from './lint.js';
import { scanText } from './scan.js';
import { gitleaksProblems } from './gitleaks.js';
import { SCHEMA_IDS } from './schemas.js';
import { TOOL_VERSION } from './version.js';

export const FORMATS = ['json', 'cef', 'leef', 'kv', 'syslog', 'csv', 'xml', 'other'];
export const SHIP_METHODS = ['syslog', 'http-ingest', 's3', 'azure', 'other'];
export const LICENSES = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'CC0-1.0'];
export const SAMPLE_SOURCES = ['synthetic', 'vendor-docs'];
export const ROLES = ['standalone', 'parent', 'child'];
export const ALLOWED_FILES = /^(meta\.json|samples\.log|expected\.json|README\.md|[A-Z0-9_]+\.parser\.txt)$/;
export const LIMITS = { samples: 200, lineBytes: 16384, parserBytes: 65536, parsers: 20 };
// An entry's optional "bridge": the repo path of a folder under bridges/ that pulls the
// source's logs from an API or relays its webhooks. Bridges are code, so they are reviewed and
// merged on their own.
export const BRIDGE_PATH = /^bridges\/[a-z0-9]+(?:-[a-z0-9]+)*$/;
// Bridges used to be called collectors and lived under collectors/. An entry from then has a
// "collector" key with a collectors/<name> path, which still works and reads as bridges/<name>.
const LEGACY_PATH = /^collectors\/([a-z0-9]+(?:-[a-z0-9]+)*)$/;
const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const NAME = /^[A-Z0-9]+(?:_[A-Z0-9]+)+$/;

export function slug(s) {
  return String(s || '').toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}

// The entry's bridge path, from "bridge" or the legacy "collector" key, or null when it names
// none or the value isn't a bridge folder path. "bridge" wins when both are set.
export function bridgeOf(meta) {
  if (!meta || typeof meta !== 'object') return null;
  const legacy = meta.bridge === undefined || meta.bridge === null;
  const value = legacy ? meta.collector : meta.bridge;
  if (typeof value !== 'string' || value.length > 80) return null;
  if (BRIDGE_PATH.test(value)) return value;
  const m = legacy ? LEGACY_PATH.exec(value) : null;
  return m ? `bridges/${m[1]}` : null;
}

export function hasBridge(meta) {
  return bridgeOf(meta) !== null;
}

// The metadata with a legacy "collector" key carried as "bridge", for copies of the library
// that the page reads, such as the snapshot.
export function withBridgeKey(meta) {
  if (!meta || typeof meta !== 'object' || !('collector' in meta)) return meta;
  const path = bridgeOf(meta);
  const out = { ...meta };
  delete out.collector;
  if (path) out.bridge = path;
  return out;
}

// The text the library search matches: vendor, product, author, format, parser names and schemas,
// and, for an entry that needs a bridge, "needs a bridge" and the bridge's path.
export function searchText(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  const bridge = bridgeOf(m);
  return JSON.stringify([m.vendor, m.product, m.author, m.format, (Array.isArray(m.parsers) ? m.parsers : []).map((p) => [p && p.name, p && p.schema]), bridge ? ['needs a bridge', bridge] : []]).toLowerCase();
}

// The scripts a bridge folder offers: its .py files, leaving out tests unless that's all.
export function bridgeScripts(fileNames) {
  const py = (fileNames || []).filter((f) => /^[A-Za-z0-9_.-]+\.py$/.test(f)).sort();
  const main = py.filter((f) => !/^test_|_test\.py$/.test(f));
  return main.length ? main : py;
}

export function entryId(meta) {
  return `${slug(meta.vendor)}/${slug(meta.product)}`;
}

export function blankMeta() {
  return {
    vendor: '', product: '', versions: [], format: 'json', ship_method: 'syslog', author: '', license: 'MIT',
    sample_source: 'synthetic', reference_time: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), tested: { emulator: TOOL_VERSION, tenant: null },
    docs: [], notes: '', parsers: [],
  };
}

// problems: [{level, code, message, file?}]
// opts.bridges: [{path, files}] for the bridges on the base branch. Without it, only the form of
// "bridge" is checked.
export function validateMeta(meta, fileNames = null, opts = {}) {
  const out = [];
  const err = (code, message) => out.push({ level: 'error', code, message, file: 'meta.json' });
  const warn = (code, message) => out.push({ level: 'warning', code, message, file: 'meta.json' });
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) { err('meta', 'meta.json must be a JSON object'); return out; }
  for (const k of ['vendor', 'product']) if (typeof meta[k] !== 'string' || !meta[k].trim() || meta[k].length > 80) err('meta', `${k} is required (up to 80 characters)`);
  if (!Array.isArray(meta.versions) || meta.versions.some((v) => typeof v !== 'string' || v.length > 40)) err('meta', 'versions must be a list of version strings, for example ["11.1"]; use [] when unknown');
  if (!FORMATS.includes(meta.format)) err('meta', `format must be one of ${FORMATS.join(', ')}`);
  if (!SHIP_METHODS.includes(meta.ship_method)) err('meta', `ship_method must be one of ${SHIP_METHODS.join(', ')}`);
  if (typeof meta.author !== 'string' || !HANDLE.test(meta.author)) err('meta', 'author must be a GitHub handle, without the @');
  if (!LICENSES.includes(meta.license)) err('meta', `license must be one of ${LICENSES.join(', ')}`);
  if (!SAMPLE_SOURCES.includes(meta.sample_source)) err('meta', `sample_source must be ${SAMPLE_SOURCES.join(' or ')}. Customer logs, even sanitized, are not accepted.`);
  if (typeof meta.reference_time !== 'string' || Number.isNaN(Date.parse(meta.reference_time))) err('meta', 'reference_time must be an ISO date and time, no earlier than the samples (the emulator uses it as the ingest time and for log times with no year)');
  if (!meta.tested || typeof meta.tested !== 'object') err('meta', 'tested must be an object like {"emulator": "0.1.0", "tenant": null}');
  else if (meta.tested.tenant !== null && meta.tested.tenant !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(meta.tested.tenant)) err('meta', 'tested.tenant must be null or the date (YYYY-MM-DD) the parsers passed Run Test in a tenant');
  if (meta.docs !== undefined && (!Array.isArray(meta.docs) || meta.docs.some((u) => typeof u !== 'string' || !/^https:\/\//.test(u)))) err('meta', 'docs must be a list of https links to the vendor\'s public log format docs');
  if (meta.notes !== undefined && (typeof meta.notes !== 'string' || meta.notes.length > 2500)) err('meta', 'notes must be text up to 2500 characters');
  const named = (k) => meta[k] !== undefined && meta[k] !== null;
  if (named('collector')) {
    warn('bridge', named('bridge')
      ? '"collector" is the old name for "bridge". This entry has both, so "collector" is ignored: remove it.'
      : '"collector" is the old name for "bridge". It still works, but rename it to "bridge", with a path under bridges/.');
  }
  if (named('bridge') || named('collector')) {
    const path = bridgeOf(meta);
    if (!path) err('bridge', 'bridge must be the path of a folder under bridges/, in lowercase with hyphens, for example "bridges/ai-compliance-logs"');
    else if (Array.isArray(opts.bridges)) {
      const b = opts.bridges.find((x) => x && x.path === path);
      if (!b) err('bridge', `bridge ${path} is not on the main branch. Bridges are code, so a maintainer reviews and merges each one before an entry can point at it.`);
      else {
        const files = Array.isArray(b.files) ? b.files : [];
        if (!files.includes('README.md')) err('bridge', `bridge ${path} has no README.md`);
        if (!files.some((f) => /\.py$/.test(f))) err('bridge', `bridge ${path} has no .py file`);
      }
    }
  } else if (meta.ship_method === 'http-ingest') {
    warn('bridge', 'ship_method is http-ingest but there is no bridge. A pull-only source, or a webhook that can\'t add the Authorization header, needs "bridge" set to its folder under bridges/; a source that sends to HTTP Ingest with the header itself needs none.');
  }
  if (!Array.isArray(meta.parsers) || !meta.parsers.length) { err('meta', 'parsers must list at least one parser'); return out; }
  if (meta.parsers.length > LIMITS.parsers) err('meta', `at most ${LIMITS.parsers} parsers per entry`);
  const names = new Set();
  for (const p of meta.parsers) {
    if (!p || typeof p.name !== 'string' || !NAME.test(p.name)) { err('meta', `parser name ${JSON.stringify(p && p.name)} must be UPPER_SNAKE_CASE, for example ACME_FW_CEF_PARENT`); continue; }
    if (names.has(p.name)) err('meta', `parser ${p.name} is listed twice`);
    names.add(p.name);
    if (p.file !== `${p.name}.parser.txt`) err('meta', `parser ${p.name}: file must be ${p.name}.parser.txt`);
    if (fileNames && !fileNames.includes(`${p.name}.parser.txt`)) err('meta', `parser ${p.name}: ${p.name}.parser.txt is missing`);
    if (!ROLES.includes(p.role)) err('meta', `parser ${p.name}: role must be ${ROLES.join(', ')}`);
    if (p.role === 'child' && !p.parent) err('meta', `parser ${p.name}: a child needs "parent"`);
    if (p.schema !== undefined && !SCHEMA_IDS.includes(p.schema)) err('meta', `parser ${p.name}: schema ${p.schema} is not one custom parsers can use`);
  }
  for (const p of meta.parsers) if (p && p.parent && !names.has(p.parent)) warn('meta', `parser ${p.name}: parent ${p.parent} is not in this entry, so it is treated as a global parser`);
  if (fileNames) {
    for (const f of fileNames) if (!ALLOWED_FILES.test(f)) err('files', `${f} is not allowed in a library entry (allowed: meta.json, samples.log, expected.json, README.md, NAME.parser.txt)`);
    for (const f of fileNames) if (/\.parser\.txt$/.test(f) && !names.has(f.replace(/\.parser\.txt$/, ''))) err('files', `${f} is not listed in meta.json parsers`);
    for (const f of ['samples.log', 'expected.json']) if (!fileNames.includes(f)) err('files', `${f} is missing`);
  }
  return out;
}

export function parseSamples(text) {
  return String(text || '').replace(/\r\n?/g, '\n').split('\n').filter((l) => l.trim() !== '');
}

// Deep equality that ignores key order.
export function same(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => same(x, b[i]));
  const ka = Object.keys(a), kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && same(a[k], b[k]));
}

export function diffRecords(got, want, prefix = '') {
  const out = [];
  const g = got || {}, w = want || {};
  for (const k of [...new Set([...Object.keys(g), ...Object.keys(w)])]) {
    if (!same(g[k], w[k])) out.push(`${prefix}${k}: emulator gives ${JSON.stringify(g[k] ?? null)}, expected.json has ${JSON.stringify(w[k] ?? null)}`);
  }
  return out;
}

export function compareExpected(results, expected) {
  const out = [];
  if (!Array.isArray(expected)) return ['expected.json must be a list with one result per sample line'];
  if (expected.length !== results.length) out.push(`expected.json has ${expected.length} results for ${results.length} sample lines`);
  results.forEach((r, i) => {
    const e = expected[i];
    if (i >= expected.length) return;
    if (!e || typeof e !== 'object' || Array.isArray(e)) { out.push(`line ${r.line}: expected.json has no result for this line`); return; }
    const got = expectedShape(r);
    const before = out.length;
    if (got.extractor_path !== e.extractor_path) out.push(`line ${r.line}: extractor path is ${JSON.stringify(got.extractor_path)}, expected ${JSON.stringify(e.extractor_path)}`);
    if (got.schema !== e.schema) out.push(`line ${r.line}: schema is ${got.schema}, expected ${e.schema}`);
    if (Boolean(got.error) !== Boolean(e.error)) out.push(`line ${r.line}: ${got.error ? `the emulator raised an error (${r.error})` : 'expected.json records an error, the emulator ran cleanly'}`);
    if (!same(got.normalized, e.normalized ?? null)) out.push(...diffRecords(got.normalized, e.normalized).map((d) => `line ${r.line}: ${d}`));
    // expected.json isn't scanned like the samples, because it should hold only what the emulator
    // writes. Anything more, or any other difference, fails.
    if (out.length === before && !same(got, e)) {
      const extra = Object.keys(e).filter((k) => !(k in got));
      out.push(extra.length ? `line ${r.line}: expected.json has fields the emulator doesn't write: ${extra.slice(0, 5).join(', ')}` : `line ${r.line}: expected.json doesn't match the emulator's output. Run tools/update-expected.mjs.`);
    }
  });
  return out;
}

export function toEngineParsers(meta, texts) {
  return meta.parsers.map((p) => ({ name: p.name, text: texts[p.name] ?? '', parent: p.parent || undefined, role: p.role }));
}

// The library's vendor names, which a sample may use as a company name, such as Microsoft
// Corporation (see scanText). The repo's checks take them from the main branch, and the studio from
// the library it loaded, which is the main branch too.
export function vendorNames(entries) {
  return [...new Set((entries || []).map((e) => e && e.meta && e.meta.vendor).filter((v) => typeof v === 'string' && v.trim()))];
}

// entry: {id, meta, texts: {NAME: text}, samples: [lines], expected, files: [{path, content}]}
// opts.library: other entries, for the overlap check. opts.bridges: see validateMeta.
// opts.allowNames: vendor names a sample may use as a company name (see scanText).
// Returns {ok, problems, results}.
export function validateEntry(entry, opts = {}) {
  const problems = [];
  const files = entry.files || entryFiles(entry);
  const fileNames = files.map((f) => f.path.split('/').pop());
  problems.push(...validateMeta(entry.meta, fileNames, { bridges: opts.bridges }));
  // Share to the library writes an entry to the folder its vendor and product make, so a folder
  // that doesn't match would split the entry in two.
  if (entry.meta && entry.meta.vendor && entry.meta.product && entry.id && entry.id !== entryId(entry.meta)) {
    problems.push({ level: 'error', code: 'folder', message: `the folder is parsers/${entry.id}, but vendor and product make it parsers/${entryId(entry.meta)}. Move the files there or change vendor and product.`, file: 'meta.json' });
  }
  if (!entry.samples.length) problems.push({ level: 'error', code: 'samples', message: 'samples.log has no lines', file: 'samples.log' });
  if (entry.samples.length > LIMITS.samples) problems.push({ level: 'error', code: 'samples', message: `samples.log has ${entry.samples.length} lines; the limit is ${LIMITS.samples}`, file: 'samples.log' });
  entry.samples.forEach((l, i) => { if (new TextEncoder().encode(l).length > LIMITS.lineBytes) problems.push({ level: 'error', code: 'samples', message: `line ${i + 1} is over ${LIMITS.lineBytes} bytes`, file: 'samples.log' }); });
  for (const [name, text] of Object.entries(entry.texts || {})) {
    if (new TextEncoder().encode(text).length > LIMITS.parserBytes) problems.push({ level: 'error', code: 'size', message: `${name}.parser.txt is over ${LIMITS.parserBytes} bytes`, file: `${name}.parser.txt` });
    if (!/emulator result, not run in Sophos NG-SIEM|Run Test/i.test(text.split('\n').slice(0, 12).join('\n'))) {
      problems.push({ level: 'warning', code: 'header', message: `${name}.parser.txt: start with the tool's header comment, which says whether it has passed Run Test in a tenant`, file: `${name}.parser.txt` });
    }
  }
  // CI's gitleaks scans every file as committed, at its path in the repo.
  const dir = entry.id || (entry.meta && entry.meta.vendor && entry.meta.product ? entryId(entry.meta) : '');
  for (const f of files) {
    const name = f.path.split('/').pop();
    for (const s of gitleaksProblems(f.content, dir ? `parsers/${dir}/${name}` : name, { source: name })) problems.push({ ...s, file: name });
    if (f.path.endsWith('expected.json')) continue;
    let content = f.content;
    // The docs links in meta.json point at real vendor sites on purpose; scan the rest.
    if (f.path.endsWith('meta.json')) {
      try { content = JSON.stringify({ ...JSON.parse(f.content), docs: undefined }, null, 2); } catch { /* scanned as is */ }
    }
    for (const s of scanText(content, { source: f.path.split('/').pop(), allowNames: opts.allowNames })) problems.push({ ...s, file: f.path.split('/').pop() });
  }
  let results = [];
  if (entry.meta && Array.isArray(entry.meta.parsers) && entry.meta.parsers.length) {
    const parsers = toEngineParsers(entry.meta, entry.texts || {});
    const lint = lintParsers(parsers, { samples: entry.samples, now: entry.meta.reference_time, library: opts.library || [], selfId: entry.id });
    results = lint.results || [];
    for (const p of lint.problems) {
      // Lines that stay generic on purpose are covered by the expected.json comparison.
      if (p.level === 'info' || p.code === 'unmatched') continue;
      problems.push({ level: p.level === 'inferred' ? 'info' : p.level, code: `lint:${p.code}`, message: `${p.parser ? `${p.parser}${p.line ? ` line ${p.line}` : ''}: ` : ''}${p.message}`, file: p.parser ? `${p.parser}.parser.txt` : null });
    }
    for (const d of compareExpected(results, entry.expected)) problems.push({ level: 'error', code: 'expected', message: d, file: 'expected.json' });
  }
  return { ok: !problems.some((p) => p.level === 'error'), problems, results };
}

export function expectedFrom(results) {
  return results.map(expectedShape);
}

export function entryFiles(entry) {
  const dir = entry.id ? `parsers/${entry.id}/` : '';
  const files = [{ path: `${dir}meta.json`, content: JSON.stringify(entry.meta, null, 2) + '\n' }];
  for (const p of entry.meta.parsers) files.push({ path: `${dir}${p.name}.parser.txt`, content: ensureNewline(entry.texts[p.name] ?? '') });
  files.push({ path: `${dir}samples.log`, content: entry.samples.join('\n') + '\n' });
  files.push({ path: `${dir}expected.json`, content: JSON.stringify(entry.expected, null, 2) + '\n' });
  return files;
}

const ensureNewline = (s) => (s.endsWith('\n') ? s : s + '\n');

// ---------------------------------------------------------------- bundle for the issue form

export const BUNDLE_TAG = 'parser-studio-bundle/v1';

export function packBundle(entry) {
  return JSON.stringify({
    bundle: BUNDLE_TAG,
    meta: entry.meta,
    parsers: entry.meta.parsers.map((p) => ({ name: p.name, text: entry.texts[p.name] ?? '' })),
    samples: entry.samples,
    expected: entry.expected,
  }, null, 1);
}

// Reads a bundle from free text, such as an issue body with the bundle in a code block.
export function unpackBundle(text) {
  const s = String(text || '');
  const at = s.indexOf(`"bundle"`);
  if (at === -1) throw new Error('no Parser Studio bundle found. Paste the text that "Share to the library" copied.');
  const start = s.lastIndexOf('{', at);
  let depth = 0, inStr = false, end = -1;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) { if (c === '\\') i++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end === -1) throw new Error('the bundle is cut off. Copy it again from the studio.');
  const b = JSON.parse(s.slice(start, end + 1));
  if (b.bundle !== BUNDLE_TAG) throw new Error(`unknown bundle version ${b.bundle}`);
  if (!b.meta || !Array.isArray(b.parsers) || !Array.isArray(b.samples)) throw new Error('the bundle is missing meta, parsers or samples');
  const texts = {};
  for (const p of b.parsers) if (p && typeof p.name === 'string') texts[p.name] = String(p.text ?? '');
  const meta = b.meta;
  return { id: entryId(meta), meta, texts, samples: b.samples.map(String), expected: b.expected ?? [] };
}
