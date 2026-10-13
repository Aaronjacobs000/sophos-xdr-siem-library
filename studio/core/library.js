// Community library entries: the folder layout, metadata rules, the single-text bundle used
// by the issue form, and the validation that both the studio and CI run.
//
// parsers/<vendor-slug>/<product-slug>/
//   meta.json            vendor, product, versions, format, ship method, author, license, parsers
//   <NAME>.parser.txt    one file per parser
//   samples.log          synthetic sample lines, one event per line
//   expected.json        the emulator result for each sample line

import { runParsers, expectedShape } from './engine.js';
import { lintParsers } from './lint.js';
import { scanText } from './scan.js';
import { SCHEMA_IDS } from './schemas.js';
import { TOOL_VERSION } from './version.js';

export const FORMATS = ['json', 'cef', 'leef', 'kv', 'syslog', 'csv', 'xml', 'other'];
export const SHIP_METHODS = ['syslog', 'http-ingest', 's3', 'azure', 'other'];
export const LICENSES = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'CC0-1.0'];
export const SAMPLE_SOURCES = ['synthetic', 'vendor-docs'];
export const ROLES = ['standalone', 'parent', 'child'];
export const ALLOWED_FILES = /^(meta\.json|samples\.log|expected\.json|README\.md|[A-Z0-9_]+\.parser\.txt)$/;
export const LIMITS = { samples: 200, lineBytes: 16384, parserBytes: 65536, parsers: 20 };
const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const NAME = /^[A-Z0-9]+(?:_[A-Z0-9]+)+$/;

export function slug(s) {
  return String(s || '').toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
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
export function validateMeta(meta, fileNames = null) {
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
  if (typeof meta.reference_time !== 'string' || Number.isNaN(Date.parse(meta.reference_time))) err('meta', 'reference_time must be an ISO date and time (the emulator uses it for log times with no year)');
  if (!meta.tested || typeof meta.tested !== 'object') err('meta', 'tested must be an object like {"emulator": "0.1.0", "tenant": null}');
  else if (meta.tested.tenant !== null && meta.tested.tenant !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(meta.tested.tenant)) err('meta', 'tested.tenant must be null or the date (YYYY-MM-DD) the parsers passed Run Test in a tenant');
  if (meta.docs !== undefined && (!Array.isArray(meta.docs) || meta.docs.some((u) => typeof u !== 'string' || !/^https:\/\//.test(u)))) err('meta', 'docs must be a list of https links to the vendor\'s public log format docs');
  if (meta.notes !== undefined && (typeof meta.notes !== 'string' || meta.notes.length > 2000)) err('meta', 'notes must be text up to 2000 characters');
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
    if (!e) return;
    const got = expectedShape(r);
    if (got.extractor_path !== e.extractor_path) out.push(`line ${r.line}: extractor path is ${JSON.stringify(got.extractor_path)}, expected ${JSON.stringify(e.extractor_path)}`);
    if (got.schema !== e.schema) out.push(`line ${r.line}: schema is ${got.schema}, expected ${e.schema}`);
    if (Boolean(got.error) !== Boolean(e.error)) out.push(`line ${r.line}: ${got.error ? `the emulator raised an error (${r.error})` : 'expected.json records an error, the emulator ran cleanly'}`);
    if (!same(got.normalized, e.normalized ?? null)) out.push(...diffRecords(got.normalized, e.normalized).map((d) => `line ${r.line}: ${d}`));
  });
  return out;
}

export function toEngineParsers(meta, texts) {
  return meta.parsers.map((p) => ({ name: p.name, text: texts[p.name] ?? '', parent: p.parent || undefined, role: p.role }));
}

// entry: {id, meta, texts: {NAME: text}, samples: [lines], expected, files: [{path, content}]}
// library: other entries, for the overlap check. Returns {ok, problems, results}.
export function validateEntry(entry, opts = {}) {
  const problems = [];
  const files = entry.files || entryFiles(entry);
  const fileNames = files.map((f) => f.path.split('/').pop());
  problems.push(...validateMeta(entry.meta, fileNames));
  if (entry.meta && entry.meta.vendor && entry.meta.product && entry.id && entry.id !== entryId(entry.meta)) {
    problems.push({ level: 'warning', code: 'folder', message: `the folder is ${entry.id}; from vendor and product it would be ${entryId(entry.meta)}`, file: 'meta.json' });
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
  for (const f of files) {
    if (f.path.endsWith('expected.json')) continue;
    let content = f.content;
    // The docs links in meta.json point at real vendor sites on purpose; scan the rest.
    if (f.path.endsWith('meta.json')) {
      try { content = JSON.stringify({ ...JSON.parse(f.content), docs: undefined }, null, 2); } catch { /* scanned as is */ }
    }
    for (const s of scanText(content, { source: f.path.split('/').pop() })) problems.push({ ...s, file: f.path.split('/').pop() });
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
