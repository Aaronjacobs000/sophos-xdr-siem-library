// Splitters and helpers behind SPLIT(), CEF(), LEEF(), SPLIT_NAME_VALUES(), URL_PARSE() and the
// syslog header the root parser removes before custom parsers see `message`.

import { ObjValue, RuntimeError } from './values.js';

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

// What the engine's root parser does before custom parsers run (checked with Run Test in a lab
// tenant; ingest wasn't checked):
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

// ---------------------------------------------------------------- SPLIT

// SPLIT() reads its text the way Go's encoding/csv does with LazyQuotes on (checked in a lab
// tenant). The separator is the first character of the second argument, so "::" splits on ":"
// and ",;" on ",". A field that starts with a quote runs to the closing quote, separators and
// newlines included, and "" inside it is one quote; any other quote is kept. Each line is a
// record and the fields of every record come back in one list; an empty line is skipped, so ""
// gives []. Every record needs as many fields as the first, or the event fails. An empty
// separator, a quote or a newline as the separator fails the event too.
export function splitCsv(text, sep) {
  const comma = sep ? String.fromCodePoint(sep.codePointAt(0)) : '';
  if (!comma || /^["\r\n\0�]$/.test(comma) || /^[\uD800-\uDFFF]$/.test(comma)) throw new RuntimeError('csv: invalid field or comment delimiter. SPLIT needs a separator that isn\'t empty, a quote or a newline', 'split-separator');
  let pos = 0, lineNo = 0;
  const readLine = () => {
    if (pos >= text.length) return null;
    const nl = text.indexOf('\n', pos);
    let line = nl === -1 ? text.slice(pos) : text.slice(pos, nl + 1);
    pos = nl === -1 ? text.length : nl + 1;
    lineNo++;
    if (nl === -1 && line.endsWith('\r')) line = line.slice(0, -1);
    if (line.endsWith('\r\n')) line = `${line.slice(0, -2)}\n`;
    return line;
  };
  const nlLen = (l) => (l.endsWith('\n') ? 1 : 0);
  const out = [];
  let perRecord = null;
  for (;;) {
    let line = readLine();
    while (line !== null && line.length === nlLen(line)) line = readLine();
    if (line === null) return out;
    const recLine = lineNo;
    const fields = [];
    parse: for (;;) {
      if (!line.startsWith('"')) {
        const i = line.indexOf(comma);
        fields.push(i >= 0 ? line.slice(0, i) : line.slice(0, line.length - nlLen(line)));
        if (i < 0) break;
        line = line.slice(i + comma.length);
        continue;
      }
      line = line.slice(1);
      let field = '';
      for (;;) {
        const q = line.indexOf('"');
        if (q >= 0) {
          field += line.slice(0, q);
          line = line.slice(q + 1);
          if (line.startsWith('"')) { field += '"'; line = line.slice(1); }
          else if (line.startsWith(comma)) { line = line.slice(comma.length); fields.push(field); continue parse; }
          else if (line.length === nlLen(line)) { fields.push(field); break parse; }
          else field += '"';
        } else if (line.length) {
          field += line;
          line = readLine() ?? '';
        } else {
          fields.push(field);
          break parse;
        }
      }
    }
    if (perRecord === null) perRecord = fields.length;
    else if (fields.length !== perRecord) throw new RuntimeError(`record on line ${recLine}: wrong number of fields. SPLIT reads each line as a record, and every record needs as many fields as the first`, 'split-fields');
    out.push(...fields);
  }
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

// The engine unescapes \=, \\ and \" in extension values and leaves \n, \r, \t and \| as two
// characters (checked in a lab tenant).
function unescapeCefValue(v) {
  return v.replace(/\\([=\\"])/g, '$1');
}

// Index of the quote that closes a value opened with a quote at i, or -1.
function closingQuote(s, i) {
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === '\\') j++;
    else if (s[j] === '"') return j;
  }
  return -1;
}

function endsWithQuote(v) {
  if (v.length < 2 || !v.endsWith('"')) return false;
  let n = 0;
  for (let j = v.length - 2; j >= 0 && v[j] === '\\'; j--) n++;
  return n % 2 === 0;
}

// Extension keys whose <key>Label the engine resolves, so values["<label text>"] works (docs
// example). cfpN, c6aN, deviceCustomDateN, flexDateN and the long deviceCustom* names are not
// resolved (checked in a lab tenant).
const LABELLED = /^(?:cs|cn|flexString|flexNumber)\d+$/;

// Header fields by number ([0] is "CEF:<version>", [1] vendor, [2] product, ...), extension
// keys by name, and the labels in LABELLED resolved. A header with 6 or 7 fields, such as
// CEF:0|V|P|1|100|N, has no extension of its own, so the engine reads its last field as the
// extension. Fewer than 6 fields fails the event (checked in a lab tenant).
//
// A key is the text between a space and the next =, so it can hold |, a tab or a quote: an 8th
// field such as 6|a=b gives the key 6|a. The key can be empty too: =x gives the key "" the value
// x, and a=1 = 2 gives it " 2". Only a space ends a value, not a tab, and a value keeps its leading
// spaces: cs1= "a b" gives ' "a b"'. A value that is empty or only spaces and tabs, as in a= or
// a= b=c, isn't stored, while a="" stores "" (checked in a lab tenant).
//
// A value that starts with a quote runs at least to the next unescaped quote, so spaces and
// key= inside the quotes don't end it. When the value also ends with a quote, the engine drops
// its first and last quote: cs2="a b" gives a b and cs2="a b" c "d e" gives a b" c "d e, while
// cs3="a" b keeps its quotes. With no closing quote the value runs to the end (checked in a lab
// tenant).
//
// Text with no CEF: in it fails the event, "" included, with the engine's "message is not in
// LEEF format" (checked in a lab tenant).
export function parseCef(line) {
  if (line === null || line === undefined) return null;
  const s = String(line);
  const at = s.indexOf('CEF:');
  if (at === -1) throw new RuntimeError('message is not in LEEF format: CEF() found no "CEF:" in the text. Check the value holds the CEF part of the line.', 'cef-header');
  const parts = splitUnescaped(s.slice(at), '|', 8);
  if (parts.length < 3) throw new RuntimeError(`message is not in LEEF format: CEF() needs a header of at least 6 fields separated by |, as in CEF:0|Vendor|Product|1.0|100|Name, and this has ${parts.length}`, 'cef-header');
  if (parts.length < 6) throw new RuntimeError(`message isn't in CEF/LEEF format (header too short): CEF() needs at least 6 header fields separated by |, and this has ${parts.length}`, 'cef-header');
  const short = parts.length === 6 || parts.length === 7;
  const header = short ? parts.slice(0, -1) : parts.slice(0, 7);
  const ext = short ? parts[parts.length - 1] : parts.length > 7 ? parts[7] : '';
  const map = new Map();
  const keys = [];
  const keyRe = /(?:^| )([^ =]*)=/g;
  let m;
  while ((m = keyRe.exec(ext))) {
    const eq = m.index + m[0].length - 1;
    if (eq > 0 && ext[eq - 1] === '\\') continue;
    const start = m.index + m[0].length;
    const k = { key: m[1], start, from: m.index, quoted: ext[start] === '"' };
    keys.push(k);
    if (k.quoted) {
      const close = closingQuote(ext, start);
      k.closed = close !== -1;
      keyRe.lastIndex = k.closed ? close + 1 : ext.length;
    }
  }
  keys.forEach((k, n) => {
    const end = n + 1 < keys.length ? keys[n + 1].from : ext.length;
    let v = ext.slice(k.start, end).trimEnd();
    if (v === '') return;
    if (k.quoted && k.closed && endsWithQuote(v)) v = v.slice(1, -1);
    map.set(k.key, unescapeCefValue(v));
  });
  for (const [k, v] of [...map]) {
    if (k.endsWith('Label')) {
      const base = k.slice(0, -5);
      if (LABELLED.test(base) && map.has(base) && !map.has(v)) map.set(v, map.get(base));
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
//
// Text with no LEEF: in it fails the event, "" included, with or without a delimiter (checked in
// a lab tenant).
export function parseLeef(line, delimiterOverride = null) {
  if (line === null || line === undefined) return null;
  const s = String(line);
  const at = s.indexOf('LEEF:');
  if (at === -1) throw new RuntimeError('message is not in LEEF format: LEEF() found no "LEEF:" in the text. Check the value holds the LEEF part of the line.', 'leef-header');
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

// SPLIT_NAME_VALUES(data, delimiter, separator, quoteChar). Keys are trimmed, values are not:
// "a: 1;b: 2" with delimiter ";" and separator ":" gives " 1" and " 2", and so does the docs
// example "User: Unknown, InitiatorPackets: 2" (" Unknown"). A backslash quote character, as in
// the docs examples, means values are not quoted. The engine splits on the delimiter before it
// reads quotes, so each delimiter inside quotes comes back as a space: msg="x, y" with delimiter
// "," gives "x  y". A quote anywhere in a value protects a delimiter, but only a value that starts
// and ends with the quote character loses its quotes: a= "x;y" gives ' "x y"' and a=x"y;z"w gives
// 'x"y z"w' (checked in a lab tenant).
export function splitNameValues(data, delimiter, separator, quoteChar) {
  if (data === null || data === undefined) return null;
  const s = String(data);
  const d = delimiter || ' ';
  const sep = separator || '=';
  const q = quoteChar && quoteChar !== '\\' ? quoteChar : null;
  const items = [];
  let item = '';
  let quoted = false;
  for (let i = 0; i < s.length;) {
    if (q && s.startsWith(q, i)) { quoted = !quoted; item += q; i += q.length; continue; }
    if (s.startsWith(d, i)) {
      if (quoted) item += ' ';
      else { items.push(item); item = ''; }
      i += d.length;
      continue;
    }
    item += s[i++];
  }
  items.push(item);
  const map = new Map();
  for (const it of items) {
    const at = it.indexOf(sep);
    if (at === -1) continue;
    const key = it.slice(0, at).trim();
    let value = it.slice(at + sep.length);
    if (q && value.length >= 2 * q.length && value.startsWith(q) && value.endsWith(q)) value = value.slice(q.length, -q.length);
    if (key) map.set(key, value);
  }
  return new ObjValue(map);
}

// ---------------------------------------------------------------- URL_PARSE

// URL_PARSE() reads a URL the way Go's net/url Parse does, after three steps of its own (checked
// in a lab tenant). Each space becomes + and each * is dropped. A URL whose first / doesn't start
// a :// gets http:// in front, so mailto:a@b.com has the user mailto and the host b.com, and
// //host/x has no host and the path_raw //host/x, while " http://x" keeps its leading + and fails.
// When Go rejects a % escape, as in %zz, %2 or %20 in a host, every % is dropped and the URL read
// again, so /%zz%2Fq gives /zz2Fq.

class UrlError extends Error {
  constructor(message, escape = false) { super(message); this.escape = escape; }
}

const isHex = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);
const unhex = (b) => (b <= 0x39 ? b - 0x30 : (b | 0x20) - 0x57);

// ASCII a host can hold besides letters and digits; Go rejects any other.
const HOST_OK = new Set([..."!$&'()*+,;=:[]<>\"-_.~"].map((c) => c.charCodeAt(0)));
const isAlnum = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);

// Go's unescape: each %XX is a byte. In a host, %XX below %80 other than %25 is an error too.
function goUnescape(s, host = false) {
  const b = new TextEncoder().encode(s);
  const out = [];
  for (let i = 0; i < b.length;) {
    if (b[i] === 0x25) {
      if (i + 2 >= b.length || !isHex(b[i + 1]) || !isHex(b[i + 2])) throw new UrlError('invalid URL escape', true);
      if (host && unhex(b[i + 1]) < 8 && !(b[i + 1] === 0x32 && b[i + 2] === 0x35)) throw new UrlError('invalid URL escape', true);
      out.push(unhex(b[i + 1]) * 16 + unhex(b[i + 2]));
      i += 3;
      continue;
    }
    if (host && b[i] < 0x80 && !isAlnum(b[i]) && !HOST_OK.has(b[i])) throw new UrlError('invalid character in host name');
    out.push(b[i]);
    i++;
  }
  return Uint8Array.from(out);
}

// Bytes back to text. Bytes that aren't valid UTF-8 are dropped, so /%C3x gives /x (checked in a
// lab tenant).
function utf8Text(b) {
  let out = '';
  for (let i = 0; i < b.length;) {
    const c = b[i];
    if (c < 0x80) { out += String.fromCharCode(c); i++; continue; }
    const n = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
    const lo = c === 0xe0 ? 0xa0 : c === 0xf0 ? 0x90 : 0x80;
    const hi = c === 0xed ? 0x9f : c === 0xf4 ? 0x8f : 0xbf;
    let ok = n > 0 && i + n <= b.length && b[i + 1] >= lo && b[i + 1] <= hi;
    for (let k = 2; ok && k < n; k++) ok = b[i + k] >= 0x80 && b[i + k] <= 0xbf;
    if (!ok) { i++; continue; }
    let cp = c & (0xff >> (n + 1));
    for (let k = 1; k < n; k++) cp = (cp << 6) | (b[i + k] & 0x3f);
    out += String.fromCodePoint(cp);
    i += n;
  }
  return out;
}

const unescapeText = (s, host = false) => utf8Text(goUnescape(s, host));

// Go's escaping of a URL path: letters, digits and -_.~$&+,/:;=@ stay, every other byte is %XX.
function escapePath(bytes) {
  let out = '';
  for (const b of bytes) out += isAlnum(b) || '-_.~$&+,/:;=@'.includes(String.fromCharCode(b)) ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
  return out;
}

// A query decoded, with + as a space; as written when it holds a bad escape.
function queryText(q) {
  try { return unescapeText(q.replace(/\+/g, ' ')); } catch { return q; }
}

const validPort = (p) => p === '' || /^:\d*$/.test(p);

function goHost(host) {
  if (host.startsWith('[')) {
    const i = host.lastIndexOf(']');
    if (i === -1) throw new UrlError("missing ']' in host");
    if (!validPort(host.slice(i + 1))) throw new UrlError('invalid port after host');
  } else {
    const i = host.lastIndexOf(':');
    if (i !== -1 && !validPort(host.slice(i))) throw new UrlError('invalid port after host');
  }
  return unescapeText(host, true);
}

const USERINFO = /^[A-Za-z0-9\-._:~!$&'()*+,;=%@]*$/;

// Go's url.Parse, for the parts URL_PARSE() reports.
function goParse(raw) {
  const h = raw.indexOf('#');
  const u = h === -1 ? raw : raw.slice(0, h);
  if (/[\x00-\x1f\x7f]/.test(u)) throw new UrlError('invalid control character in URL');
  const url = { scheme: '', user: null, password: null, host: '', path: '', pathRaw: '', query: '', fragment: '' };
  let rest = u;
  for (let i = 0; i < u.length; i++) {
    const c = u[i];
    if (/[A-Za-z]/.test(c)) continue;
    if (/[0-9+\-.]/.test(c)) { if (i === 0) break; continue; }
    if (c === ':') {
      if (i === 0) throw new UrlError('missing protocol scheme');
      url.scheme = u.slice(0, i).toLowerCase();
      rest = u.slice(i + 1);
    }
    break;
  }
  if (rest.endsWith('?') && rest.indexOf('?') === rest.length - 1) rest = rest.slice(0, -1);
  else if (rest.includes('?')) { url.query = rest.slice(rest.indexOf('?') + 1); rest = rest.slice(0, rest.indexOf('?')); }
  let opaque = false;
  if (!rest.startsWith('/')) {
    if (url.scheme) opaque = true;
    else if (rest.split('/')[0].includes(':')) throw new UrlError('first path segment in URL cannot contain colon');
  }
  if (!opaque) {
    if ((url.scheme || !rest.startsWith('///')) && rest.startsWith('//')) {
      let authority = rest.slice(2);
      const slash = authority.indexOf('/');
      rest = slash === -1 ? '' : authority.slice(slash);
      if (slash !== -1) authority = authority.slice(0, slash);
      const at = authority.lastIndexOf('@');
      url.host = goHost(at === -1 ? authority : authority.slice(at + 1));
      if (at !== -1) {
        const ui = authority.slice(0, at);
        if (!USERINFO.test(ui)) throw new UrlError('invalid userinfo');
        const c = ui.indexOf(':');
        url.user = unescapeText(c === -1 ? ui : ui.slice(0, c));
        if (c !== -1) url.password = unescapeText(ui.slice(c + 1));
      }
    }
    // path_raw is the decoded path, unless escaping that again doesn't give back the path as
    // written, as with %2F, %7E or a lower-case %2f: then it is the path as written (Go's RawPath).
    const bytes = goUnescape(rest);
    url.path = utf8Text(bytes);
    url.pathRaw = escapePath(bytes) === rest ? url.path : rest;
  }
  if (h !== -1) url.fragment = unescapeText(raw.slice(h + 1));
  return url;
}

function normPath(decoded) {
  decoded = decoded.replace(/\/{2,}/g, '/');
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

// The engine's object has these keys, "" for a part the URL doesn't have, and password only when
// the URL has one, as in user:pass@ or user:@. raw is the text URL_PARSE was given. host is the
// host up to its first colon, so urn:isbn:123 gives the host urn and the port 123. An IPv6
// address in brackets comes out whole when it starts with a hex digit and has only hex digits and
// colons, as with [2001:db8::1]:8080, and then has no port key when the URL has no port. [::1]:80
// and [::ffff:192.0.2.1] give the host [. A URL Go can't read, such as foo:bar or
// javascript:alert(1) with their bad port, or one with a tab, gives every key "", password and
// scheme included (checked in a lab tenant).
const URL_KEYS = ['scheme', 'user', 'host_raw', 'host', 'port', 'path_raw', 'path', 'query_raw', 'query', 'fragment', 'raw'];

export function urlParse(url, silent = false) {
  const empty = () => new ObjValue(new Map(URL_KEYS.map((k) => [k, k === 'scheme' ? 'http' : ''])));
  if (url === null || url === undefined) return silent ? empty() : null;
  const raw = String(url);
  let s = raw.replace(/ /g, '+').replace(/\*/g, '');
  if (!/^[^/]*:\/\//.test(s)) s = `http://${s}`;
  let u;
  try {
    u = goParse(s);
  } catch (e) {
    try {
      if (!e.escape) throw e;
      u = goParse(s.replace(/%/g, ''));
    } catch {
      return new ObjValue(new Map([...URL_KEYS, 'password'].map((k) => [k, k === 'raw' ? raw : ''])));
    }
  }
  // The port is the digits after the last colon, as Go's Port() reads it.
  const colon = u.host.lastIndexOf(':');
  const port = colon !== -1 && validPort(u.host.slice(colon)) ? u.host.slice(colon + 1) : '';
  const out = new Map();
  out.set('scheme', u.scheme);
  out.set('user', u.user ?? '');
  if (u.password !== null) out.set('password', u.password);
  out.set('host_raw', u.host);
  const v6 = /^\[([0-9A-Fa-f]+:[0-9A-Fa-f:]*)\](:\d*)?$/.exec(u.host);
  out.set('host', (v6 ? v6[1] : u.host.split(':')[0]).toLowerCase());
  if (!v6 || v6[2] !== undefined) out.set('port', port);
  out.set('path_raw', u.pathRaw);
  out.set('path', u.path ? normPath(u.path) : '');
  out.set('query_raw', u.query);
  out.set('query', queryText(u.query));
  out.set('fragment', u.fragment);
  out.set('raw', raw);
  return new ObjValue(out);
}

// ---------------------------------------------------------------- domains and IPs

const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'id', 'asn', 'ltd', 'plc', 'sch', 'nhs', 'or', 'ne', 'go', 'gob', 'mil']);
// Reverse DNS names: the engine reads in-addr.arpa and ip6.arpa as suffixes, so
// 80.113.0.203.in-addr.arpa gives 9 (checked in a lab tenant).
const ARPA_SUFFIX = /\.(?:in-addr|ip6)\.arpa$/i;

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
  if (labels.length >= 3 && ARPA_SUFFIX.test(host)) keep = 3;
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
