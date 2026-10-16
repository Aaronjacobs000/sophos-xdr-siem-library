// The generic-api-key rule of gitleaks, the secret scan CI runs on every pull request, ported so
// the library check reports what that rule would flag before CI does. The rule, its allowlists and
// the global allowlist come from gitleaks' own config/gitleaks.toml, for the version CI installs, in
// gitleaks-rule.js, which tools/port-gitleaks.mjs writes. How a match becomes a finding follows
// detect/detect.go and config/allowlist.go of that version. The repo's own .gitleaks.toml
// allowlists for library entries apply too (REPO_ALLOWLISTS).
//
// Not ported: gitleaks' other 221 rules, and its decoding passes, which scan base64, hex and
// percent-encoded text again up to 5 levels deep. So CI can still flag something this lets through.
// With gitleaks on the PATH, as in CI, test/gitleaks.test.mjs checks that the whole library gives
// no finding this misses.
//
// How a match becomes a finding below follows gitleaks' code:
//   Copyright (c) 2019 Zachary Rice
//   Permission is hereby granted, free of charge, to any person obtaining a copy of this software
//   and associated documentation files (the "Software"), to deal in the Software without
//   restriction, including without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
//   Software is furnished to do so, subject to the following conditions:
//   The above copyright notice and this permission notice shall be included in all copies or
//   substantial portions of the Software.
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
//   BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import { GITLEAKS_VERSION, RULE, GLOBAL_ALLOWLISTS } from './gitleaks-rule.js';

export { GITLEAKS_VERSION };
export const RULE_ID = RULE.id;

// ---------------------------------------------------------------- Go regular expressions

// Go (RE2) regex syntax, as gitleaks writes it, translated to a JavaScript RegExp source. Node 22
// has no inline (?i) or (?-i:...), so a letter matched without case becomes a class of both cases,
// plus the letters Go folds in with them: the Kelvin sign with k and the long s with s. \s is Go's
// [\t\n\f\r ], . leaves out only \n, and \z is the end of the text. Anything else throws.
const PERL = { d: [[0x30, 0x39]], s: [[0x09, 0x0a], [0x0c, 0x0d], [0x20, 0x20]], w: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]] };
const ESCAPES = { t: 0x09, n: 0x0a, v: 0x0b, f: 0x0c, r: 0x0d, a: 0x07 };
const QUANT = /^\{\d+(?:,\d*)?\}/;

const unit = (cp) => (/^[A-Za-z0-9]$/.test(String.fromCodePoint(cp)) ? String.fromCodePoint(cp) : `\\u{${cp.toString(16)}}`);

function fold(ranges) {
  const out = [...ranges];
  const has = (lo, hi, cp) => lo <= cp && cp <= hi;
  for (const [lo, hi] of ranges) {
    for (const [a, b, d] of [[0x61, 0x7a, -32], [0x41, 0x5a, 32]]) {
      const l = Math.max(lo, a), h = Math.min(hi, b);
      if (l <= h) out.push([l + d, h + d]);
    }
    if (has(lo, hi, 0x6b) || has(lo, hi, 0x4b)) out.push([0x212a, 0x212a]);
    if (has(lo, hi, 0x73) || has(lo, hi, 0x53)) out.push([0x17f, 0x17f]);
    if (has(lo, hi, 0x212a)) out.push([0x4b, 0x4b], [0x6b, 0x6b]);
    if (has(lo, hi, 0x17f)) out.push([0x53, 0x53], [0x73, 0x73]);
  }
  return out;
}

const classOf = (ranges, ci, negate = false) => `[${negate ? '^' : ''}${(ci ? fold(ranges) : ranges).map(([lo, hi]) => (lo === hi ? unit(lo) : `${unit(lo)}-${unit(hi)}`)).join('')}]`;

// A single character: a class of its cases when it has more than one and ci is on.
const literal = (cp, ci) => (ci && fold([[cp, cp]]).length > 1 ? classOf([[cp, cp]], true) : unit(cp));

// A character escape at src[i] (a backslash): [code point, length].
function escapeChar(src, i) {
  const e = src[i + 1];
  if (e === undefined) throw new Error('trailing backslash');
  if (e in ESCAPES) return [ESCAPES[e], 2];
  if (e === 'x') {
    const m = /^\\x([0-9A-Fa-f]{2})/.exec(src.slice(i));
    if (!m) throw new Error(`unsupported escape ${src.slice(i, i + 4)}`);
    return [parseInt(m[1], 16), 4];
  }
  if (/[A-Za-z0-9]/.test(e)) throw new Error(`unsupported escape \\${e}`);
  return [src.codePointAt(i + 1), e.length + 1];
}

function parseClass(src, start, ci) {
  let i = start + 1;
  let negate = false;
  if (src[i] === '^') { negate = true; i++; }
  const ranges = [];
  const first = i;
  const char = () => {
    if (src[i] === '\\') { const [cp, n] = escapeChar(src, i); i += n; return cp; }
    const cp = src.codePointAt(i);
    i += cp > 0xffff ? 2 : 1;
    return cp;
  };
  while (i < src.length && (src[i] !== ']' || i === first)) {
    if (src.startsWith('[:', i)) throw new Error('POSIX classes are not supported');
    if (src[i] === '\\' && /[dsw]/.test(src[i + 1])) { ranges.push(...PERL[src[i + 1]]); i += 2; continue; }
    if (src[i] === '\\' && /[DSWpP]/.test(src[i + 1])) throw new Error(`unsupported class \\${src[i + 1]}`);
    const lo = char();
    if (src[i] === '-' && i + 1 < src.length && src[i + 1] !== ']') {
      i++;
      ranges.push([lo, char()]);
    } else ranges.push([lo, lo]);
  }
  if (src[i] !== ']') throw new Error('unterminated character class');
  return [classOf(ranges, ci, negate), i + 1 - start];
}

export function goRegexSource(src) {
  let out = '';
  let ci = false;
  const saved = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '(') {
      const flag = /^\(\?(-?)i([):])/.exec(src.slice(i, i + 5));
      if (flag && flag[2] === ')') { ci = !flag[1]; i += flag[0].length; continue; }
      saved.push(ci);
      if (flag) { ci = !flag[1]; out += '(?:'; i += flag[0].length; continue; }
      if (src.startsWith('(?:', i)) { out += '(?:'; i += 3; continue; }
      if (src[i + 1] === '?') throw new Error(`unsupported group ${src.slice(i, i + 4)}`);
      out += '('; i++;
      continue;
    }
    if (c === ')') { if (!saved.length) throw new Error('unbalanced )'); ci = saved.pop(); out += ')'; i++; continue; }
    if (c === '[') { const [cls, n] = parseClass(src, i, ci); out += cls; i += n; continue; }
    if (c === '\\') {
      const e = src[i + 1];
      if (e === 'z') { out += '$'; i += 2; continue; }
      if (e in PERL) { out += classOf(PERL[e], ci); i += 2; continue; }
      if (/[A-Za-z0-9]/.test(e) && !(e in ESCAPES) && e !== 'x') throw new Error(`unsupported escape \\${e}`);
      const [cp, n] = escapeChar(src, i);
      out += literal(cp, ci);
      i += n;
      continue;
    }
    if (c === '{') {
      const q = QUANT.exec(src.slice(i));
      if (q) { out += q[0]; i += q[0].length; continue; }
      out += '\\{'; i++;
      continue;
    }
    if (c === '}') { out += '\\}'; i++; continue; }
    if (c === '.') { out += '[^\\n]'; i++; continue; }
    if ('^$|*+?'.includes(c)) { out += c; i++; continue; }
    const cp = src.codePointAt(i);
    out += literal(cp, ci);
    i += cp > 0xffff ? 2 : 1;
  }
  if (saved.length) throw new Error('unbalanced (');
  return out;
}

// The u flag makes \u{...} escapes work, and leaves case alone: goRegexSource spells case out.
export const goRegex = (src, flags = '') => new RegExp(goRegexSource(src), `${flags}u`);

// ---------------------------------------------------------------- the rule

const RULE_REGEX = RULE.regex;
const ENTROPY = RULE.entropy;
const KEYWORDS = RULE.keywords;
const RULE_ALLOWLISTS = RULE.allowlists;
const ALLOW_SIGNATURE = 'gitleaks:allow';

// The [[allowlists]] in the repo's .gitleaks.toml that can apply to a library entry file, as
// written there. A test checks the two stay the same.
export const REPO_ALLOWLISTS = [
  {
    description: 'UUID record IDs under ...Id keys in synthetic library samples and parser files',
    targetRules: ['generic-api-key'],
    condition: 'AND',
    paths: [String.raw`^parsers/[^/]+/[^/]+/samples\.log$`, String.raw`^parsers/[^/]+/[^/]+/[A-Z0-9_]+\.parser\.txt$`],
    regexTarget: 'match',
    regexes: [String.raw`(?i)^[\w.-]*id["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?$`],
  },
  {
    description: 'The synthetic token ID the Atlassian entry\'s expected.json stores as access_key',
    targetRules: ['generic-api-key'],
    condition: 'AND',
    paths: [String.raw`^parsers/atlassian/atlassian-organization-audit-log/expected\.json$`],
    regexTarget: 'match',
    regexes: [String.raw`^access_key"\s*:\s*"c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f"$`],
  },
];

// ---------------------------------------------------------------- matching

// gitleaks joins an allowlist's regexes into one, (?:a|b|...), and its paths the same way, so a
// (?i) at the start of one also applies to those after it, as in the global allowlist.
const joined = (list) => (list && list.length ? goRegex(`(?:${list.join('|')})`) : null);
const compiled = new WeakMap();
function compile(a) {
  if (!compiled.has(a)) {
    compiled.set(a, {
      and: ['AND', '&&'].includes(String(a.condition || '').toUpperCase()),
      paths: joined(a.paths),
      regexes: joined(a.regexes),
      stopwords: (a.stopwords || []).map((w) => w.toLowerCase()),
      target: a.regexTarget === 'match' || a.regexTarget === 'line' ? a.regexTarget : 'secret',
    });
  }
  return compiled.get(a);
}

const pathAllowed = (c, path) => Boolean(path && c.paths && c.paths.test(path));
const regexAllowed = (c, s) => Boolean(s && c.regexes && c.regexes.test(s));
function hasStopword(c, s) {
  if (!s || !c.stopwords.length) return false;
  const lower = s.toLowerCase();
  return c.stopwords.some((w) => lower.includes(w));
}

// checkCommitOrPathAllowed in detect.go: an allowlist that skips the whole file for the rule.
function fileAllowed(allowlists, path) {
  return allowlists.map(compile).some((c) => (c.and ? !c.regexes && !c.stopwords.length && pathAllowed(c, path) : pathAllowed(c, path)));
}

// checkFindingAllowed in detect.go. finding: {secret, match, line}.
function findingAllowed(allowlists, finding, path) {
  return allowlists.map(compile).some((c) => {
    const re = regexAllowed(c, finding[c.target]);
    const stop = hasStopword(c, finding.secret);
    if (!c.and) return re || stop;
    const checks = [];
    if (c.paths) checks.push(pathAllowed(c, path));
    if (c.regexes) checks.push(re);
    if (c.stopwords.length) checks.push(stop);
    return checks.every(Boolean);
  });
}

// shannonEntropy in gitleaks: counts characters, but divides by the length in UTF-8 bytes.
function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  const inv = 1 / new TextEncoder().encode(s).length;
  let h = 0;
  for (const n of counts.values()) { const f = n * inv; h -= f * Math.log2(f); }
  return h;
}

// The line gitleaks reports a match on (location in detect/location.go), which the line
// allowlists and the gitleaks:allow comment are tested against. Like gitleaks, it starts at the
// newline before the match, and a match after the last newline reports the text from the start.
function lineText(raw, start, end) {
  if (!raw.includes('\n')) return raw;
  const nl = raw.indexOf('\n', start + 1);
  if (nl === -1) {
    let to = end;
    while (to < raw.length && raw[to] !== '\n' && raw[to] !== '\r') to++;
    return raw.slice(0, to);
  }
  const after = raw.indexOf('\n', end);
  return raw.slice(Math.max(0, raw.lastIndexOf('\n', start)), Math.max(after === -1 ? nl : after, end));
}

let rule = null;

// Every generic-api-key finding gitleaks 8.30.1 makes in raw, the content of the file at path
// (repo-relative, such as parsers/acme/gateway/samples.log), leaving out its decoding passes.
// opts.allowlists replaces REPO_ALLOWLISTS. Returns [{line, match, secret, key}]: line is 1-based,
// and key is the match before the secret, without the separator.
export function findGenericApiKeys(raw, path = '', opts = {}) {
  const text = String(raw ?? '');
  const allowlists = [...RULE_ALLOWLISTS, ...(opts.allowlists || REPO_ALLOWLISTS)];
  const out = [];
  // Go lowers U+0130 (capital I with a dot) to i, where JavaScript adds a combining dot.
  const lower = text.replace(/\u0130/g, 'i').toLowerCase();
  if (fileAllowed(GLOBAL_ALLOWLISTS, path) || !KEYWORDS.some((k) => lower.includes(k)) || fileAllowed(allowlists, path)) return out;
  rule ||= { all: goRegex(RULE_REGEX, 'g'), groups: goRegex(RULE_REGEX, 'd') };
  const all = new RegExp(rule.all);
  for (let m; (m = all.exec(text));) {
    const match = m[0].replace(/^\n+|\n+$/g, '');
    const line = lineText(text, m.index, m.index + match.length);
    if (line.includes(ALLOW_SIGNATURE)) continue;
    // The secret is the first group that isn't empty when the rule runs again on the match alone.
    let secret = match;
    let key = '';
    const g = rule.groups.exec(match);
    const i = g ? g.findIndex((s, n) => n > 0 && s) : -1;
    if (i > 0) {
      secret = g[i];
      key = match.slice(0, g.indices[i][0]).replace(/[\s'"`=>:|?,]+$/, '');
    }
    if (shannonEntropy(secret) <= ENTROPY) continue;
    const finding = { secret, match, line };
    if (findingAllowed(GLOBAL_ALLOWLISTS, finding, path) || findingAllowed(allowlists, finding, path)) continue;
    out.push({ line: text.slice(0, m.index).split('\n').length, match, secret, key });
  }
  return out;
}

// The findings as library check problems, one for each key and value. The message shows only the
// start of the value, so a real secret isn't copied into a public log.
export function gitleaksProblems(raw, path = '', opts = {}) {
  const seen = new Set();
  const out = [];
  for (const f of findGenericApiKeys(raw, path, opts)) {
    if (seen.has(`${f.key}\n${f.secret}`)) continue;
    seen.add(`${f.key}\n${f.secret}`);
    const shown = `${f.secret.slice(0, 4)}...`;
    out.push({
      level: 'error',
      code: 'gitleaks',
      message: `CI's secret scan (gitleaks ${RULE_ID}) would flag "${f.key}" with the value "${shown}"; change the key name or the value.`,
      line: f.line,
      text: `${f.key} ${shown}`,
      source: opts.source || null,
    });
  }
  return out;
}
