// Splitters and helpers behind CEF(), LEEF(), SPLIT_NAME_VALUES(), URL_PARSE() and the
// syslog header the root parser removes before custom parsers see `message`.

import { ObjValue } from './values.js';

// ---------------------------------------------------------------- syslog header

const MONTH = '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)';
const BSD = new RegExp(`^(<\\d{1,3}>)?(\\d\\s+)?(${MONTH}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s(.*)$`, 's');
const ISO = /^(<\d{1,3}>)?(\d\s+)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s(.*)$/s;

// Returns {kind, pri, version, timestamp, host, body} or null when the line has no header.
// INFERRED: the docs say the root parser separates the syslog header, and the docs' own
// examples show `message` starting right after the timestamp and host. App name, process ID
// and structured data stay in the body.
export function splitSyslog(line) {
  for (const [re, kind] of [[BSD, 'bsd'], [ISO, 'iso']]) {
    const m = re.exec(line);
    if (m) {
      return {
        kind: m[2] ? 'rfc5424' : kind === 'bsd' ? 'rfc3164' : 'iso',
        pri: m[1] ? Number(m[1].slice(1, -1)) : null,
        version: m[2] ? m[2].trim() : null,
        timestamp: m[3],
        host: m[4],
        body: m[5],
      };
    }
  }
  const pri = /^<(\d{1,3})>(.*)$/s.exec(line);
  if (pri) return { kind: 'pri-only', pri: Number(pri[1]), version: null, timestamp: null, host: null, body: pri[2] };
  return null;
}

// What the engine's root parser does before custom parsers run (checked in a lab tenant):
// it strips a leading BSD header "Mmm dd hh:mm:ss host " (twice for a relayed line) and
// nothing else. A <PRI> prefix, an RFC 5424 header or an ISO timestamp leaves the line whole.
const BSD_ONLY = /^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) /;

export function rootSplit(line) {
  let m = BSD_ONLY.exec(line);
  if (!m) return { message: line, host: null, time: null };
  let rest = line.slice(m[0].length);
  let time = m[1], host = m[2];
  const inner = BSD_ONLY.exec(rest);
  if (inner) { rest = rest.slice(inner[0].length); time = inner[1]; host = inner[2]; }
  return { message: rest, host, time };
}

// ---------------------------------------------------------------- CEF

// Splits on unescaped separators. The engine keeps the backslash in CEF and LEEF header fields.
function splitUnescaped(s, sep, limit) {
  const out = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length && (s[i + 1] === sep || s[i + 1] === '\\')) { cur += c + s[i + 1]; i++; continue; }
    if (c === sep && out.length < limit - 1) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

function unescapeCefValue(v) {
  return v.replace(/\\([=\\nr|])/g, (_, c) => ({ n: '\n', r: '\r' }[c] ?? c));
}

// Header fields by number ([0] is "CEF:<version>", [1] vendor, [2] product, ...), extension
// keys by name, and each csNLabel resolved so values["<label text>"] works (docs example).
export function parseCef(line) {
  if (line === null || line === undefined) return null;
  const s = String(line);
  const at = s.indexOf('CEF:');
  if (at === -1) return null;
  const parts = splitUnescaped(s.slice(at), '|', 8);
  const header = parts.slice(0, 7);
  const ext = parts.length > 7 ? parts[7] : '';
  const map = new Map();
  const keys = [];
  const keyRe = /(?:^|\s)([A-Za-z0-9_.\-[\]]+)=/g;
  let m;
  while ((m = keyRe.exec(ext))) {
    const eq = m.index + m[0].length - 1;
    if (eq > 0 && ext[eq - 1] === '\\') continue;
    keys.push({ key: m[1], start: m.index + m[0].length, from: m.index });
  }
  keys.forEach((k, n) => {
    const end = n + 1 < keys.length ? keys[n + 1].from : ext.length;
    map.set(k.key, unescapeCefValue(ext.slice(k.start, end).trim()));
  });
  for (const [k, v] of [...map]) {
    if (k.endsWith('Label')) {
      const base = k.slice(0, -5);
      if (map.has(base) && !map.has(v)) map.set(v, map.get(base));
    }
  }
  return new ObjValue(map, header);
}

// ---------------------------------------------------------------- LEEF

// The engine takes the delimiter field literally: a hex form such as x5E is not decoded.
function leefDelimiter(spec) {
  if (!spec) return '\t';
  return spec;
}

// LEEF:1.0 has five header fields then tab-separated attributes. LEEF:2.0 adds a sixth header
// field naming the attribute delimiter. delimiterOverride wins over both.
export function parseLeef(line, delimiterOverride = null) {
  if (line === null || line === undefined) return null;
  const s = String(line);
  const at = s.indexOf('LEEF:');
  if (at === -1) return null;
  const body = s.slice(at);
  const v2 = /^LEEF:2/.test(body);
  const parts = splitUnescaped(body, '|', v2 ? 7 : 6);
  const header = parts.slice(0, v2 ? 6 : 5);
  const attrs = parts.length > header.length ? parts[header.length] : '';
  const delim = delimiterOverride ? leefDelimiter(delimiterOverride) : v2 ? leefDelimiter(header[5]) : '\t';
  const map = new Map();
  for (const kv of attrs.split(delim)) {
    const eq = kv.indexOf('=');
    if (eq > 0) map.set(kv.slice(0, eq).trim(), kv.slice(eq + 1));
  }
  return new ObjValue(map, header);
}

// ---------------------------------------------------------------- name/value pairs

// SPLIT_NAME_VALUES(data, delimiter, separator, quoteChar). Keys and unquoted values are
// trimmed (docs example: "User: Unknown, InitiatorPackets: 2"). A backslash quote character,
// as in the docs examples, means values are not quoted.
export function splitNameValues(data, delimiter, separator, quoteChar) {
  if (data === null || data === undefined) return null;
  const s = String(data);
  const d = delimiter || ' ';
  const sep = separator || '=';
  const q = quoteChar && quoteChar !== '\\' ? quoteChar : null;
  const map = new Map();
  let i = 0;
  while (i < s.length) {
    while (i < s.length && (s.startsWith(d, i) || (d !== ' ' && /\s/.test(s[i])))) i += s.startsWith(d, i) ? d.length : 1;
    if (i >= s.length) break;
    const sepAt = s.indexOf(sep, i);
    const delimAt = s.indexOf(d, i);
    if (sepAt === -1) break;
    if (delimAt !== -1 && delimAt < sepAt) { i = delimAt + d.length; continue; }
    const key = s.slice(i, sepAt).trim();
    i = sepAt + sep.length;
    if (d !== ' ') while (i < s.length && s[i] === ' ') i++;
    let value;
    if (q && s.startsWith(q, i)) {
      const close = s.indexOf(q, i + q.length);
      if (close === -1) { value = s.slice(i + q.length); i = s.length; } else {
        value = s.slice(i + q.length, close);
        i = close + q.length;
        const nd = s.indexOf(d, i);
        i = nd === -1 ? s.length : nd + d.length;
      }
    } else {
      const end = s.indexOf(d, i);
      value = (end === -1 ? s.slice(i) : s.slice(i, end)).trim();
      i = end === -1 ? s.length : end + d.length;
    }
    if (key) map.set(key, value);
  }
  return new ObjValue(map);
}

// ---------------------------------------------------------------- URL_PARSE

function decodeOnce(s) {
  return s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function normPath(p) {
  const decoded = decodeOnce(p).replace(/\/{2,}/g, '/');
  const out = [];
  for (const seg of decoded.split('/')) {
    if (seg === '.') continue;
    if (seg === '..') { if (out.length > 1) out.pop(); continue; }
    out.push(seg);
  }
  let r = out.join('/');
  if (decoded.endsWith('/') && !r.endsWith('/')) r += '/';
  if (/\/\.\.?$/.test(decoded) && !r.endsWith('/')) r += '/';
  return r || (decoded.startsWith('/') ? '/' : '');
}

export function urlParse(url, silent = false) {
  const keys = ['scheme', 'user', 'password', 'host_raw', 'host', 'port', 'path_raw', 'path', 'query_raw', 'query', 'raw_query', 'fragment'];
  const empty = () => new ObjValue(new Map(keys.map((k) => [k, null])));
  if (url === null || url === undefined) return silent ? empty() : null;
  let s = String(url).trim();
  const out = new Map();
  let scheme = 'http';
  const sm = /^([A-Za-z][A-Za-z0-9+.-]*):(\/\/)?/.exec(s);
  if (sm && (sm[2] || !/^\d/.test(s.slice(sm[0].length)))) { scheme = sm[1].toLowerCase(); s = s.slice(sm[0].length); }
  let fragment = null;
  const h = s.indexOf('#');
  if (h !== -1) { fragment = s.slice(h + 1); s = s.slice(0, h); }
  let queryRaw = null;
  const qi = s.indexOf('?');
  if (qi !== -1) { queryRaw = s.slice(qi + 1); s = s.slice(0, qi); }
  const slash = s.indexOf('/');
  let authority = slash === -1 ? s : s.slice(0, slash);
  const pathRaw = slash === -1 ? '' : s.slice(slash);
  let user = null, password = null;
  const at = authority.lastIndexOf('@');
  if (at !== -1) {
    const ui = authority.slice(0, at);
    authority = authority.slice(at + 1);
    const c = ui.indexOf(':');
    user = c === -1 ? ui : ui.slice(0, c);
    password = c === -1 ? null : ui.slice(c + 1);
  }
  let host = authority, port = null;
  const pm = /^(.*):(\d+)$/.exec(authority);
  if (pm && !authority.startsWith('[')) { host = pm[1]; port = pm[2]; }
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority);
  if (v6) { host = v6[1]; port = v6[2] ?? null; }
  if (!host && !silent) return null;
  const query = queryRaw === null ? null : queryRaw.split('&').map((pair) => {
    try { return decodeURIComponent(pair.replace(/\+/g, '%2B')); } catch { return pair; }
  }).join('&');
  out.set('scheme', scheme);
  out.set('user', user);
  out.set('password', password);
  out.set('host_raw', authority || null);
  out.set('host', host ? host.toLowerCase() : null);
  out.set('port', port);
  out.set('path_raw', pathRaw || null);
  out.set('path', pathRaw ? normPath(pathRaw) : null);
  out.set('query_raw', queryRaw);
  out.set('query', query);
  out.set('raw_query', queryRaw);
  out.set('fragment', fragment);
  return new ObjValue(out);
}

// ---------------------------------------------------------------- domains and IPs

const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'id', 'asn', 'ltd', 'plc', 'sch', 'nhs', 'or', 'ne', 'go', 'gob', 'mil']);

// IDX_OF_TLD: index in the string where the registrable (top private) domain starts, or -1.
// INFERRED: the docs give three examples and no algorithm; this uses a small public-suffix
// heuristic (example.com, example.co.uk) on the host part.
export function idxOfTld(s) {
  if (s === null || s === undefined) return -1;
  const str = String(s);
  const m = /([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/.exec(str.replace(/^[a-z]+:\/\//i, (x) => ' '.repeat(x.length)));
  if (!m) return -1;
  const host = m[1];
  const labels = host.split('.');
  if (labels.length < 2) return -1;
  let keep = 2;
  if (labels.length >= 3 && labels[labels.length - 1].length === 2 && SECOND_LEVEL.has(labels[labels.length - 2].toLowerCase())) keep = 3;
  const start = labels.slice(0, labels.length - keep).join('.');
  const idx = start ? start.length + 1 : 0;
  // The docs examples return 0 for "aaa http://example.com" and "http://example.com".
  return idx;
}

// Go's net.ParseIP: dotted IPv4 without leading zeros, or IPv6 including IPv4-mapped forms.
export function isValidIp(s) {
  if (typeof s !== 'string') return false;
  return isIpv4(s) || isIpv6(s);
}

export function isIpv4(s) {
  const p = s.split('.');
  return p.length === 4 && p.every((x) => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255);
}

export function isIpv6(s) {
  if (!s.includes(':') || /[^0-9A-Fa-f:.]/.test(s)) return false;
  let tail = 0;
  let body = s;
  const v4 = /:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) { if (!isIpv4(v4[1])) return false; body = s.slice(0, -v4[1].length) + '0:0'; tail = 0; }
  const dbl = body.split('::');
  if (dbl.length > 2) return false;
  const groups = (x) => (x === '' ? [] : x.split(':'));
  const a = groups(dbl[0]), b = dbl.length === 2 ? groups(dbl[1]) : [];
  if (![...a, ...b].every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  const n = a.length + b.length + tail;
  return dbl.length === 2 ? n < 8 : n === 8;
}

export function ipv4ToInt(s) {
  return s.split('.').reduce((n, x) => n * 256 + Number(x), 0);
}

export function inCidr(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const mask = bits === '0' ? 0 : 2 ** 32 - 2 ** (32 - Number(bits));
  const a = ipv4ToInt(ip), b = ipv4ToInt(base);
  return (Math.floor(a / 2 ** (32 - Number(bits))) === Math.floor(b / 2 ** (32 - Number(bits)))) && mask >= 0;
}

export function isRfc1918(s) {
  return isIpv4(s) && ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some((c) => inCidr(s, c));
}
