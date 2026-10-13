// Checks text that is about to be published (samples, parser files, metadata) for things
// that must not go public: secrets, private or real IP addresses, real email addresses and
// hostnames, and company names. Samples in the library must be synthetic, using the
// documentation ranges and reserved domains below.

import { isIpv4, isIpv6, inCidr } from './formats.js';

const DOC_V4 = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'];
const SPECIAL_V4_OK = ['127.0.0.0/8', '0.0.0.0/32', '255.255.255.255/32', '224.0.0.0/4'];
const PRIVATE_V4 = [['10.0.0.0/8', 'private (RFC 1918)'], ['172.16.0.0/12', 'private (RFC 1918)'], ['192.168.0.0/16', 'private (RFC 1918)'], ['100.64.0.0/10', 'carrier-grade NAT'], ['169.254.0.0/16', 'link-local']];

export const RESERVED_DOMAIN = /(^|\.)(example\.(com|net|org)|example|test|invalid|localhost)$/i;
const INTERNAL_TLD = new Set(['local', 'lan', 'internal', 'corp', 'intranet', 'home', 'localdomain', 'ad', 'private', 'domain']);
const COMMON_CC = new Set(['au', 'uk', 'de', 'fr', 'nl', 'ca', 'jp', 'cn', 'in', 'br', 'nz', 'sg', 'ru', 'it', 'es', 'se', 'ch', 'be', 'at', 'dk', 'no', 'fi', 'pl', 'za', 'ie', 'mx', 'kr', 'hk', 'tw', 'us', 'my', 'ph', 'id', 'th', 'vn', 'ae', 'sa', 'il', 'tr', 'ar', 'cl', 'cz', 'pt', 'gr', 'hu', 'ro', 'ua']);
const SYSLOG_SELECTOR = /^(local[0-7]|kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp)\.(emerg|alert|crit|err|warning|notice|info|debug)$/i;
const COMMON_TLD = new Set(['com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'info', 'biz', 'me', 'app', 'dev', 'cloud', 'ai', 'xyz', 'online', 'site', 'tech', 'store', 'shop', 'live', 'pro', 'name', 'mobi', 'tv', 'cc', 'ly', 'gg', 'eu', 'asia']);
const FILE_EXT = new Set(['exe', 'dll', 'sys', 'com', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'js', 'jse', 'hta', 'msi', 'msp', 'cab', 'scr', 'lnk', 'jar', 'py', 'sh', 'pl', 'rb', 'php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'xml', 'json', 'yml', 'yaml', 'conf', 'cfg', 'ini', 'log', 'txt', 'csv', 'tsv', 'dat', 'tmp', 'bin', 'iso', 'img', 'zip', 'rar', 'gz', 'tgz', 'tar', 'bz2', 'xz', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pdf', 'rtf', 'odt', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'mp3', 'mp4', 'eml', 'msg', 'md', 'so', 'dylib', 'app', 'pkg', 'dmg', 'deb', 'rpm', 'apk', 'ipa', 'db', 'sql', 'bak', 'old', 'key', 'pem', 'crt', 'cer', 'pfx', 'p12']);
// Well-known public service domains that turn up in vendor logs and identify no one.
const PUBLIC_OK = /(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|office\.com|office365\.com|live\.com|azure\.com|windows\.net|google\.com|googleapis\.com|gstatic\.com|amazonaws\.com|aws\.amazon\.com|cloudflare\.com|akamai\.net|apple\.com|icloud\.com|github\.com|githubusercontent\.com|eset\.com|sophos\.com|mozilla\.org|ubuntu\.com|debian\.org|pool\.ntp\.org|digicert\.com|letsencrypt\.org|w3\.org|ietf\.org|iana\.org|opendns\.com|quad9\.net)$/i;
const FICTIONAL = /\b(acme|example|contoso|fabrikam|northwind|tailspin|woodgrove|litware|adventure works|wingtip|initech|globex|hooli|vandelay|wide world importers|proseware|fourth coffee)\b/i;
const COMPANY = /\b([A-Z][A-Za-z0-9&'.-]*(?:\s+[A-Z][A-Za-z0-9&'.-]*){0,3})\s+(Pty\.?\s+Ltd|Pty\.?\s+Limited|Ltd|Limited|Inc|Incorporated|LLC|L\.L\.C\.|GmbH|PLC|S\.A\.|S\.p\.A\.|B\.V\.|N\.V\.|Corp|Corporation|Holdings|AG|K\.K\.|Sdn\.?\s+Bhd)\b\.?/g;
const PLACEHOLDER = /^(\*+|x+|X+|redacted|<[^>]*>|\[redacted\]|example[\w-]*|placeholder|changeme|none|null|nil|n\/a|true|false|bearer|basic|ntlm|kerberos|negotiate|password|secret|token|\d{1,6})$/i;

const SECRET_PATTERNS = [
  [/\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b/, 'an AWS access key'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, 'a GitHub token'],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/, 'a Slack token'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, 'a Google API key'],
  [/\b[rs]k_(live|test)_[0-9A-Za-z]{16,}\b/, 'a Stripe key'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'a private key'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, 'a JSON Web Token'],
  [/AccountKey=[A-Za-z0-9+/=]{20,}/, 'an Azure storage key'],
  [/SharedAccessKey=[A-Za-z0-9+/=]{20,}/, 'an Azure shared access key'],
  [/\b(?:https?:\/\/)[^\s:@/]+:[^\s@/]+@/, 'a URL with a password in it'],
];
const SECRET_KEYS = /(?:^|[^A-Za-z0-9])["']?((?:client[_-]?)?secret|pass(?:word|wd)?|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?(?:id|token)|bearer|x-api-key|ingest[_-]?key|integration[_-]?key|token)["']?\s*[:=]\s*["']?([^"'\s,;&}<>]{6,})/gi;

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function classifyV4(ip) {
  if (DOC_V4.some((c) => inCidr(ip, c)) || SPECIAL_V4_OK.some((c) => inCidr(ip, c))) return null;
  const priv = PRIVATE_V4.find(([c]) => inCidr(ip, c));
  if (priv) return `${ip} is a ${priv[1]} address`;
  return `${ip} is a real public address`;
}

function classifyV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return null;
  if (/^2001:0?db8:/.test(lower)) return null;
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return `${ip} is a private (unique local) IPv6 address`;
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return `${ip} is a link-local IPv6 address`;
  if (/^::ffff:/.test(lower)) {
    const v4 = lower.slice(7);
    return isIpv4(v4) ? classifyV4(v4) : null;
  }
  return `${ip} is a real IPv6 address`;
}

function entropy(s) {
  const freq = new Map();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

// Returns [{level, code, message, line, text}]. source names the file in messages.
export function scanText(text, opts = {}) {
  const out = [];
  const seen = new Set();
  const add = (level, code, message, index, match) => {
    const key = `${code}:${match}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ level, code, message, line: lineOf(text, index), text: match, source: opts.source || null });
  };
  for (const [re, what] of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    for (const m of text.matchAll(g)) add('error', 'secret', `looks like ${what}. Remove it.`, m.index, m[0].slice(0, 12) + '...');
  }
  for (const m of text.matchAll(SECRET_KEYS)) {
    const value = m[2];
    if (PLACEHOLDER.test(value)) continue;
    if (/^[a-z]+$/i.test(value) && value.length < 12) continue;
    add('error', 'secret', `"${m[1]}" has a value that looks real. Replace it with REDACTED.`, m.index, `${m[1]}=...`);
  }
  for (const m of text.matchAll(/(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3})(?![\w.]*\d)/g)) {
    if (!isIpv4(m[1])) continue;
    const why = classifyV4(m[1]);
    if (why) add('error', 'ip', `${why}. Use 192.0.2.x, 198.51.100.x or 203.0.113.x (RFC 5737).`, m.index, m[1]);
  }
  for (const m of text.matchAll(/(?<![\w:])((?:[0-9A-Fa-f]{1,4}:){1,7}:?(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{1,4})*)(?![\w:])/g)) {
    const cand = m[1];
    if (!cand.includes('::') && cand.split(':').length < 8) continue;
    if (!isIpv6(cand)) continue;
    const why = classifyV6(cand);
    if (why) add('error', 'ip', `${why}. Use 2001:db8::/32 (RFC 3849).`, m.index, cand);
  }
  for (const m of text.matchAll(/[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g)) {
    const domain = m[1].toLowerCase();
    if (RESERVED_DOMAIN.test(domain)) continue;
    // user@<address>, as ESXi and other logs write a login, is not an email; the IP check covers the address.
    if (isIpv4(domain)) continue;
    add('error', 'email', `${m[0]} is a real-looking email address. Use a name at example.com.`, m.index, m[0]);
  }
  for (const m of text.matchAll(/(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.[a-z0-9])/gi)) {
    const host = m[1].toLowerCase();
    const tld = m[2].toLowerCase();
    if (RESERVED_DOMAIN.test(host) || PUBLIC_OK.test(host)) continue;
    if (text[m.index - 1] === '@') continue;
    if (INTERNAL_TLD.has(tld)) { add('error', 'hostname', `${m[1]} is an internal hostname. Use a name under example.com, such as host01.corp.example.com.`, m.index, m[1]); continue; }
    if (FILE_EXT.has(tld) && tld !== 'com') continue;
    if (!(COMMON_TLD.has(tld) || COMMON_CC.has(tld))) continue;
    if (SYSLOG_SELECTOR.test(host)) continue;
    if (/^\d/.test(host) && /^[\d.]+[a-z]{2}$/.test(host)) continue;
    add('error', 'hostname', `${m[1]} is a real-looking domain or hostname. Use example.com, example.net or example.org.`, m.index, m[1]);
  }
  for (const m of text.matchAll(COMPANY)) {
    if (FICTIONAL.test(m[0])) continue;
    if (opts.allowNames && opts.allowNames.some((n) => m[0].toLowerCase().includes(n.toLowerCase()))) continue;
    add('error', 'company', `"${m[0].trim()}" looks like a company name. Samples must not name customers; use Acme or Example Corp.`, m.index, m[0].trim());
  }
  for (const m of text.matchAll(/(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{32,}={0,2})(?![A-Za-z0-9+/=_-])/g)) {
    const s = m[1];
    if (/^[0-9a-fA-F]+$/.test(s)) continue;
    if ((s.match(/\//g) || []).length > 2 || /^[\w-]+$/.test(s) && /[a-z]{4,}[_-][a-z]{4,}/i.test(s)) continue;
    if (!/[A-Z]/.test(s) || !/[a-z]/.test(s) || !/\d/.test(s)) continue;
    if (entropy(s) < 4.2) continue;
    add('warning', 'entropy', `${s.slice(0, 10)}... looks like a key or token. Check it is not a real credential.`, m.index, s.slice(0, 10) + '...');
  }
  return out;
}

export function scanFiles(files, opts = {}) {
  return files.flatMap((f) => scanText(f.content, { ...opts, source: f.path }));
}
