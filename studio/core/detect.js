// Looks at sample lines and works out the syslog header, the body format, the fields in each
// line, the key that splits event types, and a confirm string. Rules only.

import { splitSyslog, parseCef, parseLeef, splitNameValues, isIpv4, isIpv6 } from './formats.js';
import { goParse } from './gotime.js';
import { compileGo } from './goregex.js';

const TAG = /^([A-Za-z0-9_.\-/]+)(\[\d+\])?:\s/;

// ---------------------------------------------------------------- value shapes

// Go reads a fractional second after the seconds even when the layout has none, so the
// plain layouts cover values with and without fractions.
const TIME_LAYOUTS = [
  '2006-01-02T15:04:05Z07:00', '2006-01-02T15:04:05Z0700', '2006-01-02T15:04:05',
  '2006-01-02 15:04:05Z07:00', '2006-01-02 15:04:05', '2006/01/02 15:04:05', '02-Jan-2006 15:04:05', '02/Jan/2006:15:04:05 -0700', 'Jan 02 2006 15:04:05',
  'Jan _2 2006 15:04:05', 'Mon Jan _2 15:04:05 2006', 'Mon, 02 Jan 2006 15:04:05 -0700', 'Mon, 02 Jan 2006 15:04:05 MST',
  '01/02/2006 15:04:05', '01/02/2006 03:04:05 PM', 'Jan _2 15:04:05', '2006-01-02',
];

export function timeLayout(value) {
  const v = String(value).trim();
  if (!/\d/.test(v) || v.length < 8 || v.length > 40) return null;
  for (const layout of TIME_LAYOUTS) {
    try { goParse(layout, v, { handle2DigitYear: true }); return layout; } catch { /* try next */ }
  }
  return null;
}

export function shapeOf(key, value) {
  if (value === null || value === undefined || value === '') return 'empty';
  if (typeof value === 'boolean') return 'bool';
  if (typeof value === 'number') {
    if (/port/i.test(key) && Number.isInteger(value) && value >= 0 && value <= 65535) return 'port';
    if (/time|date|_ts$|^ts$|epoch|created|start|end/i.test(key) && Number.isInteger(value)) {
      const s = String(value);
      if (s.length === 10) return 'epoch-s';
      if (s.length === 13) return 'epoch-ms';
    }
    return Number.isInteger(value) ? 'int' : 'float';
  }
  if (typeof value !== 'string') return 'object';
  const v = value.trim();
  if (isIpv4(v) || isIpv6(v)) return 'ip';
  if (/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(v)) return 'mac';
  if (/^[0-9A-Fa-f]{32}$/.test(v)) return 'md5';
  if (/^[0-9A-Fa-f]{40}$/.test(v)) return 'sha1';
  if (/^[0-9A-Fa-f]{64}$/.test(v)) return 'sha256';
  if (/^[0-9A-Fa-f]{128}$/.test(v)) return 'sha512';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return 'uuid';
  if (/^(true|false)$/i.test(v)) return 'bool-string';
  if (/^\d+$/.test(v)) {
    if (/port/i.test(key) && Number(v) <= 65535) return 'port';
    if (/time|date|_ts$|^ts$|epoch/i.test(key) && (v.length === 10 || v.length === 13)) return v.length === 10 ? 'epoch-s' : 'epoch-ms';
    return 'int-string';
  }
  if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(v)) return /^file:/i.test(v) ? 'file-uri' : 'url';
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return 'email';
  if (/^[A-Za-z]:\\|^\\\\/.test(v)) return 'win-path';
  if (/^\/[^\s]*\//.test(v)) return 'unix-path';
  if (/^[A-Za-z0-9.-]+\\[^\\\s]+$/.test(v)) return 'domain-user';
  if (timeLayout(v)) return 'time';
  if (/^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return 'domain';
  return 'text';
}

// ---------------------------------------------------------------- per-line field extraction

const pathPart = (p) => (typeof p === 'number' ? `[${p}]` : /^[A-Za-z_][A-Za-z0-9_@-]*$/.test(p) ? `.${p}` : `["${p.replace(/"/g, '\\"')}"]`);
const keyPart = (p, i) => (typeof p === 'number' ? `[${p}]` : `${i ? '.' : ''}${p}`);

// Flattens nested objects to keys like alert.signature with JSONPath $.alert.signature.
// For a list of objects, the first item's fields come through as dns.queries[0].rrname.
function flattenJson(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    const parts = [...prefix, k];
    const key = parts.map(keyPart).join('');
    const path = '$' + parts.map(pathPart).join('');
    if (v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length && parts.length < 5) flattenJson(v, parts, out);
    else if (Array.isArray(v) && v.length && v[0] && typeof v[0] === 'object' && !Array.isArray(v[0]) && parts.length < 4) flattenJson(v[0], [...parts, 0], out);
    else out.push({ key, path, value: Array.isArray(v) ? JSON.stringify(v) : v, array: Array.isArray(v) });
  }
}

function findJson(body) {
  const start = body.indexOf('{');
  if (start === -1) return null;
  const tail = body.slice(start).trim();
  if (!tail.endsWith('}')) return null;
  try { return { json: JSON.parse(tail), prefix: body.slice(0, start) }; } catch { return null; }
}

const CEF_HEADER = ['cef_version', 'device_vendor', 'device_product', 'device_version', 'signature_id', 'name', 'severity'];
const LEEF_HEADER = ['leef_version', 'vendor', 'product', 'version', 'event_id', 'delimiter'];

function kvShape(body) {
  const candidates = [
    { delim: ' ', sep: '=', re: /(?:^|\s)[A-Za-z_][\w.-]*=/g },
    { delim: ',', sep: '=', re: /(?:^|,)\s*[A-Za-z_][\w.-]*=/g },
    { delim: ';', sep: '=', re: /(?:^|;)\s*[A-Za-z_][\w.-]*=/g },
    { delim: ',', sep: ':', re: /(?:^|,)\s*[A-Za-z_][\w. -]*:\s/g },
    { delim: '|', sep: '=', re: /(?:^|\|)[A-Za-z_][\w.-]*=/g },
  ];
  let best = null;
  for (const c of candidates) {
    const n = (body.match(c.re) || []).length;
    if (n >= 3 && (!best || n > best.n)) best = { ...c, n };
  }
  return best;
}

// Analyse one line. Returns {header, tag, body, format, fields: [{key, path?, index?, value}], json?, kv?}
export function analyseLine(line) {
  const header = splitSyslog(line);
  let body = header ? header.body : line;
  let tag = null;
  const t = TAG.exec(body);
  if (t && !/^(CEF|LEEF)$/.test(t[1])) { tag = { name: t[1], pid: Boolean(t[2]), text: t[0].trimEnd() }; }
  const afterTag = tag ? body.slice(tag.text.length).trimStart() : body;
  const out = { line, header, tag, body, format: 'text', fields: [] };
  if (/CEF:\d+\|/.test(line)) {
    const obj = parseCef(line);
    out.format = 'cef';
    obj.header.forEach((v, i) => { if (i > 0) out.fields.push({ key: CEF_HEADER[i], index: i, value: v, header: true }); });
    for (const [k, v] of obj.map) if (!/Label$/.test(k) && !obj.map.has(`${k}Label`)) out.fields.push({ key: k, value: v });
    for (const [k, v] of obj.map) if (obj.map.has(`${k}Label`)) out.fields.push({ key: obj.map.get(`${k}Label`), value: v, label: k });
    return out;
  }
  if (/LEEF:\d(\.\d)?\|/.test(line)) {
    const obj = parseLeef(line);
    out.format = 'leef';
    obj.header.forEach((v, i) => { if (i > 0 && i < 5) out.fields.push({ key: LEEF_HEADER[i], index: i, value: v, header: true }); });
    for (const [k, v] of obj.map) out.fields.push({ key: k, value: v });
    return out;
  }
  const j = findJson(afterTag) || findJson(body);
  if (j && Object.keys(j.json).length) {
    out.format = 'json';
    out.json = j.json;
    out.jsonAtEnd = Boolean(j.prefix.trim()) || Boolean(header) || Boolean(tag);
    flattenJson(j.json, [], out.fields);
    return out;
  }
  if (/^\s*<[A-Za-z?][^>]*>/.test(afterTag) && /<\/[A-Za-z][^>]*>\s*$/.test(afterTag)) {
    out.format = 'xml';
    return out;
  }
  const kv = kvShape(afterTag);
  if (kv) {
    const obj = splitNameValues(afterTag, kv.delim, kv.sep, '"');
    out.format = 'kv';
    out.kv = { delim: kv.delim, sep: kv.sep, quote: '"' };
    out.kvText = afterTag;
    for (const [k, v] of obj.map) out.fields.push({ key: k, value: v });
    return out;
  }
  for (const d of [',', '\t', '|', ';']) {
    const parts = afterTag.split(d);
    if (parts.length >= 4) {
      out.format = 'csv';
      out.csv = { delim: d };
      out.csvText = afterTag;
      parts.forEach((v, i) => out.fields.push({ key: `col${i}`, index: i, value: v.replace(/^"|"$/g, '') }));
      return out;
    }
  }
  return out;
}

// ---------------------------------------------------------------- plain text

const NAME_AFTER = { for: 'user', user: 'user', from: 'src', src: 'src', source: 'src', to: 'dst', dst: 'dst', port: 'port', is: 'answer', by: 'by', with: 'with', on: 'on', at: 'at' };

// A capture pattern for unstructured lines. Lines are grouped by shape (same number of
// tokens, at least half of them identical); the biggest group becomes the template. Tokens
// that are the same on every line of the group stay literal, the rest become named groups.
// With a single line, words stay literal and value-like tokens (numbers, addresses, paths,
// key=value) become groups.
const VALUE_TOKEN = /\d|[=@\\/:]|^".*"$/;

export function textTemplate(events, tagName = null, tagPid = false) {
  const bodies = events.map((e) => (e.tag ? e.body.slice(e.tag.text.length).trimStart() : e.body));
  const toks = bodies.map((b) => b.split(/\s+/).filter(Boolean)).filter((t) => t.length);
  if (!toks.length) return null;
  // Lines are alike when they have the same number of tokens and at least 80% of positions
  // hold the same kind of token (a word, or a value with digits or punctuation).
  const cls = (t) => t.map((w) => (VALUE_TOKEN.test(w) ? 'v' : 'w'));
  const clusters = [];
  for (const t of toks) {
    const c = clusters.find((x) => x.rep.length === t.length && cls(x.rep).filter((k, i) => k === cls(t)[i]).length >= 0.8 * t.length);
    if (c) c.lines.push(t); else clusters.push({ rep: t, lines: [t] });
  }
  // Biggest group first; on a tie, the one with more tokens shared by every line.
  const shared = (c) => c.rep.filter((w, i) => c.lines.every((t) => t[i] === w)).length;
  clusters.sort((a, b) => b.lines.length - a.lines.length || shared(b) - shared(a) || b.rep.length - a.rep.length);
  const group = clusters[0].lines;
  const n = group[0].length;
  const used = new Set();
  const parts = [];
  const literal = [];
  for (let j = 0; j < n; j++) {
    const vals = group.map((t) => t[j]);
    const same = vals.every((v) => v === vals[0]);
    literal[j] = same && (group.length > 1 || !VALUE_TOKEN.test(vals[0]));
    if (literal[j]) { parts.push(escapeRe(vals[0])); continue; }
    const prev = j > 0 && literal[j - 1] ? group[0][j - 1].toLowerCase().replace(/[^a-z0-9_]/g, '') : '';
    const shape = vals.every((v) => isIpv4(v) || isIpv6(v)) ? 'ip' : vals.every((v) => /^\d{9,10}\.\d+$/.test(v)) ? 'epoch' : vals.every((v) => /^\d+$/.test(v)) ? 'num' : vals.every((v) => /^[a-z][a-z0-9+.-]*:\/\//i.test(v)) ? 'url' : 'text';
    const name = NAME_AFTER[prev] || (prev && prev.length <= 16 && /^[a-z]/.test(prev) ? prev : shape === 'text' ? 'f' : shape);
    let k = name === 'f' ? `f${j + 1}` : name;
    let i = 2;
    while (used.has(k)) k = `${name}${i++}`;
    used.add(k);
    parts.push(`(?P<${k}>${shape === 'num' ? '\\d+' : '\\S+'})`);
  }
  const prefix = tagName ? `${escapeRe(tagName)}${tagPid ? '\\[\\d+\\]' : ''}:\\s+` : '';
  return prefix + parts.join('\\s+');
}

// Fields from a capture pattern's named groups, per line.
export function patternFields(line, pattern) {
  let re;
  try { re = compileGo(pattern); } catch { return null; }
  const m = re.exec(line);
  if (!m) return null;
  const names = [...pattern.matchAll(/\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>/g)].map((x) => x[1]);
  return names.map((name) => ({ key: name, value: m.groups ? m.groups[name] ?? '' : '', group: true }));
}

// ---------------------------------------------------------------- the whole sample

const SPLIT_KEYS = ['event_type', 'eventtype', 'event_category', 'eventcategory', 'log_type', 'logtype', 'type', 'subtype', 'category', 'cat',
  'event', 'eventname', 'event_name', 'eventid', 'event_id', 'action_type', 'operation', 'signature_id', 'name', 'devicevendor'];

function norm(k) { return String(k).toLowerCase().replace(/[^a-z0-9]/g, ''); }

function escapeRe(s) { return s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&'); }

function commonPrefix(list) {
  if (!list.length) return '';
  let p = list[0];
  for (const s of list) { let i = 0; while (i < p.length && i < s.length && p[i] === s[i]) i++; p = p.slice(0, i); }
  return p;
}

// Returns a summary used by the studio's first step.
export function analyseSample(lines) {
  const events = lines.map(analyseLine);
  const formats = count(events.map((e) => e.format));
  const format = Object.entries(formats).sort((a, b) => b[1] - a[1])[0]?.[0] || 'text';
  const headers = count(events.map((e) => (e.header ? e.header.kind : 'none')));
  const header = Object.entries(headers).sort((a, b) => b[1] - a[1])[0]?.[0] || 'none';
  const tags = count(events.map((e) => (e.tag ? e.tag.name : '')));
  const tagName = Object.keys(tags).length === 1 && Object.keys(tags)[0] ? Object.keys(tags)[0] : null;
  const tagPid = tagName ? events.every((e) => e.tag && e.tag.pid) : false;

  const tagName0 = (() => { const t = new Set(events.map((e) => (e.tag ? e.tag.name : ''))); return t.size === 1 ? [...t][0] || null : null; })();
  let template = null;
  if (format === 'text') {
    template = textTemplate(events, tagName0, tagName0 ? events.every((e) => e.tag && e.tag.pid) : false);
    if (template) for (const e of events) e.fields = patternFields(e.line, template) || [];
  }
  const keys = new Map();
  for (const e of events) {
    for (const f of e.fields) {
      if (!keys.has(f.key)) keys.set(f.key, { key: f.key, path: f.path, index: f.index, header: f.header, label: f.label, values: [], lines: 0 });
      const k = keys.get(f.key);
      k.values.push(f.value);
      k.lines++;
    }
  }
  for (const k of keys.values()) {
    const shapes = count(k.values.map((v) => shapeOf(k.key, v)).filter((s) => s !== 'empty'));
    k.shape = Object.entries(shapes).sort((a, b) => b[1] - a[1])[0]?.[0] || 'empty';
    k.distinct = new Set(k.values.map((v) => JSON.stringify(v))).size;
    if (k.shape === 'time') k.layout = timeLayout(String(k.values.find((v) => v !== '' && v !== null)));
  }

  // The key that splits event types: a known name, string values, 2 to 12 distinct values.
  let split = null;
  if (lines.length > 1 && format !== 'text') {
    const cands = [...keys.values()].filter((k) => k.lines === events.length && k.distinct >= 2 && k.distinct <= Math.min(12, lines.length) && k.values.every((v) => typeof v === 'string' && v.length <= 64));
    cands.sort((a, b) => rank(a) - rank(b));
    const best = cands[0];
    if (best && rank(best) < SPLIT_KEYS.length) split = best;
  }
  const types = split ? [...new Set(split.values)] : [];

  const vendor = format === 'cef' ? keys.get('device_vendor')?.values[0] : format === 'leef' ? keys.get('vendor')?.values[0] : null;
  const product = format === 'cef' ? keys.get('device_product')?.values[0] : format === 'leef' ? keys.get('product')?.values[0] : null;
  const confirm = suggestConfirm(events, { format, tagName, tagPid, vendor, product, keys });
  const notes = [];
  if (header !== 'none') notes.push(`The ${headerLabel(header)} header comes off before parsers see \`message\`; \`originalData$\` keeps the whole line.`);
  if (formats.json && events.some((e) => e.jsonAtEnd)) notes.push('The JSON object sits at the end of the line, so the parser cuts it off with a capture before JSON().');
  for (const k of keys.values()) {
    if (k.shape === 'time' && k.layout && !/Z07|-07|MST/.test(k.layout)) notes.push(`${k.key} has no time zone, so DATETIME() reads it as UTC. Check what the device sends.`);
  }
  if (Object.keys(formats).length > 1) notes.push(`The lines mix formats (${Object.entries(formats).map(([f, n]) => `${n} ${f}`).join(', ')}). One parser family per format works best.`);
  if (format === 'xml') notes.push('XML has no documented helper function, so it needs capture patterns.');
  if (format === 'text' && !template) notes.push('No structure found, so fields come from capture patterns you write in the parser.');
  if (keys.has('date') && keys.has('time')) notes.push('The date and time are in separate keys; the parser joins them before DATETIME().');
  if (template) notes.push('No key/value structure, so the page wrote a capture pattern with named groups from the most common line shape. Edit it on the map step; lines it doesn\'t match get no fields.');
  return {
    lines: lines.length, events, format, formats, header, tagName, tagPid, keys: [...keys.values()], split, types,
    vendor, product, confirm, notes, template,
    hintText: events.slice(0, 5).map((e) => e.body).join(' ').slice(0, 2000),
  };
}

function rank(k) {
  const i = SPLIT_KEYS.indexOf(norm(k.key.split('.').pop()));
  return i === -1 ? SPLIT_KEYS.length + k.distinct : i;
}

function count(list) {
  const out = {};
  for (const x of list) out[x] = (out[x] || 0) + 1;
  return out;
}

export function headerLabel(kind) {
  return { rfc3164: 'syslog (BSD, RFC 3164)', rfc5424: 'syslog (RFC 5424)', iso: 'syslog with an ISO time', 'pri-only': 'syslog priority', none: 'no syslog' }[kind] || kind;
}

function suggestConfirm(events, { format, tagName, tagPid, vendor, product, keys }) {
  const lines = events.map((e) => e.line);
  const tries = [];
  if (format === 'cef' && vendor && product) tries.push(`CEF:\\d+\\|${escapeRe(vendor)}\\|${escapeRe(product)}\\|`);
  if (format === 'leef' && vendor && product) tries.push(`LEEF:[\\d.]+\\|${escapeRe(vendor)}\\|${escapeRe(product)}\\|`);
  if (tagName) {
    const tag = `${escapeRe(tagName)}${tagPid ? '\\[\\d+\\]' : ''}:`;
    if (format === 'json') {
      const first = events.map((e) => (e.json ? Object.keys(e.json)[0] : null));
      if (first.every((k) => k && k === first[0])) tries.push(`${tag}\\s*\\{\\s*"${escapeRe(first[0])}"\\s*:`);
      tries.push(`${tag}\\s*\\{`);
    } else if (format === 'kv') {
      const firstKey = events.map((e) => (e.fields[0] ? e.fields[0].key : null));
      if (firstKey.every((k) => k && k === firstKey[0])) tries.push(`${tag}\\s+${escapeRe(firstKey[0])}=`);
      tries.push(tag);
    } else {
      tries.push(tag);
    }
  }
  if (format === 'json' && !tagName) {
    const common = [...keys.values()].filter((k) => k.lines === events.length && !k.path.includes('[') && k.path.split('.').length === 2);
    const pick = common.sort((a, b) => b.key.length - a.key.length).slice(0, 3);
    if (pick.length >= 2) return { kind: 'EXPRESSION', text: `VALIDATE_ALL_JSONPATHS_EXIST(originalData$, "${pick.map((k) => k.path).join(',')}")`, why: `every line has ${pick.map((k) => k.key).join(', ')}` };
  }
  const bodies = events.map((e) => e.body);
  const prefix = commonPrefix(bodies).replace(/[\s\S]*?(\S[\s\S]*)$/, '$1');
  const cut = prefix.replace(/[^A-Za-z]*$/, '').replace(/\s\S*$/, (m) => (prefix.length > 12 ? m : ''));
  if (cut.trim().length >= 6) tries.push(escapeRe(cut.trim()).replace(/\\\[\d+\\\]/g, '\\[\\d+\\]').replace(/(\d+)/g, (m) => (m.length > 2 ? '\\d+' : m)));
  if (format === 'kv') {
    const common = [...keys.values()].filter((k) => k.lines === events.length).slice(0, 3);
    if (common.length >= 2) tries.push(common.map((k) => `\\b${escapeRe(k.key)}=`).join('.*'));
  }
  for (const t of tries) {
    try {
      const re = compileGo(t);
      if (lines.every((l) => re.test(l))) return { kind: 'PATTERN', text: t, why: 'matches every sample line' };
    } catch { /* next */ }
  }
  return { kind: 'PATTERN', text: '', why: 'no stable text found; write one that names the vendor or product' };
}
