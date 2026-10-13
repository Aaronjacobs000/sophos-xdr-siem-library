// Go (RE2) regular expressions in a JavaScript engine.
// checkRe2() reports what Go's regexp package would reject. compileGo() translates the RE2
// syntax the docs use, such as (?P<name>...), \A, \z and POSIX classes, into a JS RegExp.

import { RuntimeError } from './values.js';

const POSIX = {
  alnum: '0-9A-Za-z', alpha: 'A-Za-z', ascii: '\\x00-\\x7F', blank: '\\t ', cntrl: '\\x00-\\x1F\\x7F',
  digit: '0-9', graph: '!-~', lower: 'a-z', print: ' -~', punct: '!-\\/:-@\\[-`{-~', space: '\\t\\n\\v\\f\\r ',
  upper: 'A-Z', word: '0-9A-Za-z_', xdigit: '0-9A-Fa-f',
};
const JS_SYNTAX = new Set('^$\\.*+?()[]{}|/'.split(''));
const CLASS_SPECIAL = new Set('\\]^-['.split(''));
const GO_SPACE = '\\t\\n\\f\\r ';

// Returns [{level: 'error'|'warning', message}] for constructs Go rejects or that are risky.
export function checkRe2(pattern) {
  const out = [];
  const err = (message) => out.push({ level: 'error', message });
  if (/\(\?<?[=!]/.test(pattern)) err('lookahead and lookbehind are not supported by Go (RE2)');
  if (/\(\?>/.test(pattern)) err('atomic groups (?>...) are not supported by Go (RE2)');
  if (/\(\?#/.test(pattern)) err('inline comments (?#...) are not supported by Go (RE2)');
  if (/\(\?\|/.test(pattern)) err('branch reset groups are not supported by Go (RE2)');
  if (/\(\?\(/.test(pattern)) err('conditionals are not supported by Go (RE2)');
  if (/\(\?R\)|\(\?\d+\)/.test(pattern)) err('recursion is not supported by Go (RE2)');
  // Scan escapes so an escaped backslash doesn't count as the start of a backreference.
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] !== '\\') continue;
    const c = pattern[i + 1];
    if (/[1-9]/.test(c)) err(`backreference \\${c} is not supported by Go (RE2)`);
    else if (c === 'k' && pattern[i + 2] === '<') err('named backreferences are not supported by Go (RE2)');
    else if (c === 'G' || c === 'Z' || c === 'K' || c === 'R' || c === 'X' || c === 'h' || c === 'H') err(`escape \\${c} is not supported by Go (RE2)`);
    i++;
  }
  if (/(?<!\\)(?:[*+?]|\})[+]/.test(stripClasses(pattern))) err('possessive quantifiers (*+, ++, ?+) are not supported by Go (RE2)');
  if (/(?<!\\)[*+]\*|(?<!\\)\*\+/.test(stripClasses(pattern))) err('a repetition of a repetition (for example **) is rejected by Go (RE2)');
  for (const m of stripClasses(pattern).matchAll(/\{(\d+)(?:,(\d*))?\}/g)) {
    if (Number(m[1]) > 1000 || (m[2] && Number(m[2]) > 1000)) err(`repeat count ${m[0]} is over Go's limit of 1000`);
  }
  if (/\(\?[imsU]*U[imsU]*[):]/.test(pattern)) out.push({ level: 'warning', message: 'the (?U) ungreedy flag works in Go, but the browser emulator cannot run it' });
  if (nestedQuantifier(pattern)) out.push({ level: 'warning', message: 'nested quantifiers such as (a+)+ are fine in Go (RE2 runs in linear time) but can be slow in this browser emulator' });
  try { compileGo(pattern); } catch (e) {
    if (!out.some((p) => p.level === 'error')) out.push({ level: 'error', message: `regex does not compile: ${e.message}` });
  }
  return out;
}

function stripClasses(p) {
  return p.replace(/\\./g, '__').replace(/\[(?:\\.|[^\]])*\]/g, '_');
}

function nestedQuantifier(p) {
  const s = stripClasses(p);
  // A group whose body has an unbounded quantifier, followed by another unbounded quantifier.
  const stack = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') stack.push({ start: i, inner: false });
    else if (s[i] === ')') {
      const g = stack.pop();
      if (!g) continue;
      const next = s[i + 1];
      if (g.inner && (next === '+' || next === '*' || (next === '{' && /^\{\d+,\d*\}/.test(s.slice(i + 1))))) return true;
      if (g.inner && stack.length) stack[stack.length - 1].inner = true;
    } else if ((s[i] === '+' || s[i] === '*') && stack.length) {
      stack[stack.length - 1].inner = true;
    }
  }
  return false;
}

const cache = new Map();

// Translate a Go regex to a JS RegExp. Throws RuntimeError when the pattern can't run here.
export function compileGo(pattern, extraFlags = '') {
  const key = pattern + '\u0000' + extraFlags;
  if (cache.has(key)) return cache.get(key);
  let flags = new Set(extraFlags.split('').filter(Boolean));
  let src = pattern;
  const lead = /^\(\?([imsU]+)\)/.exec(src);
  if (lead) {
    for (const f of lead[1]) {
      if (f === 'U') throw new RuntimeError('the emulator cannot run the (?U) flag');
      flags.add(f);
    }
    src = src.slice(lead[0].length);
  }
  let out = '';
  let inClass = false;
  let classStart = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      const n = src[i + 1];
      if (n === undefined) throw new RuntimeError('trailing backslash');
      i++;
      if (n === 'Q') {
        const end = src.indexOf('\\E', i + 1);
        const lit = end === -1 ? src.slice(i + 1) : src.slice(i + 1, end);
        out += inClass ? lit.replace(/[\\\]^\-[]/g, '\\$&') : lit.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
        i = end === -1 ? src.length : end + 1;
        continue;
      }
      if (n === 'A') { out += flags.has('m') ? '(?<![\\s\\S])' : '^'; continue; }
      if (n === 'z') { out += flags.has('m') ? '(?![\\s\\S])' : '$'; continue; }
      if (n === 'C') { out += '[\\s\\S]'; continue; }
      if (n === 'a') { out += '\\x07'; continue; }
      if (n === 's') { out += inClass ? GO_SPACE : `[${GO_SPACE}]`; continue; }
      if (n === 'S') { out += inClass ? '\\S' : `[^${GO_SPACE}]`; continue; }
      if (/[1-9]/.test(n)) throw new RuntimeError(`backreference \\${n} is not supported by Go (RE2)`);
      if (n === 'p' || n === 'P') {
        flags.add('u');
        if (src[i + 1] === '{') {
          const end = src.indexOf('}', i + 1);
          let name = src.slice(i + 2, end);
          const neg = name.startsWith('^');
          if (neg) name = name.slice(1);
          const prop = /^(L|Lu|Ll|Lt|Lm|Lo|M|Mn|Mc|Me|N|Nd|Nl|No|P|Pc|Pd|Ps|Pe|Pi|Pf|Po|S|Sm|Sc|Sk|So|Z|Zs|Zl|Zp|C|Cc|Cf|Co|Cs)$/.test(name) ? name : `Script=${name}`;
          out += `\\${neg ? (n === 'p' ? 'P' : 'p') : n}{${prop}}`;
          i = end;
        } else {
          out += `\\${n}{${src[i + 1]}}`;
          i++;
        }
        continue;
      }
      if (n === 'x' && src[i + 1] === '{') {
        const end = src.indexOf('}', i + 1);
        flags.add('u');
        out += `\\u{${src.slice(i + 2, end)}}`;
        i = end;
        continue;
      }
      if (/[A-Za-z0-9]/.test(n)) { out += '\\' + n; continue; }
      // Escaped punctuation is a literal in Go; JS only accepts some escapes in unicode mode.
      if (inClass) out += CLASS_SPECIAL.has(n) ? '\\' + n : n;
      else out += JS_SYNTAX.has(n) ? '\\' + n : (n === '-' ? '-' : n);
      continue;
    }
    if (inClass) {
      if (c === '[' && src[i + 1] === ':') {
        const end = src.indexOf(':]', i + 2);
        if (end !== -1) {
          let name = src.slice(i + 2, end);
          if (name.startsWith('^')) throw new RuntimeError(`the emulator cannot run negated POSIX class [:${name}:]`);
          if (!POSIX[name]) throw new RuntimeError(`unknown POSIX class [:${name}:]`);
          out += POSIX[name];
          i = end + 1;
          classStart = false;
          continue;
        }
      }
      if (c === ']' && !classStart) { inClass = false; out += c; continue; }
      if (c === '[') { out += '\\['; classStart = false; continue; }
      out += c;
      classStart = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      out += c;
      classStart = true;
      if (src[i + 1] === '^') { out += '^'; i++; }
      if (src[i + 1] === ']') { out += '\\]'; i++; classStart = false; }
      continue;
    }
    if (c === '(' && src[i + 1] === '?') {
      if (src[i + 2] === 'P' && src[i + 3] === '<') { out += '(?<'; i += 3; continue; }
      const inline = /^\(\?([imsU]*)(?:-([imsU]*))?\)/.exec(src.slice(i));
      if (inline) throw new RuntimeError('the emulator cannot run an inline flag group (?i) in the middle of a pattern; move it to the start');
    }
    if (c === '.') { out += flags.has('s') ? '[\\s\\S]' : '[^\\n]'; continue; }
    if (c === '{') {
      const q = /^\{\d+(?:,\d*)?\}/.exec(src.slice(i));
      if (q) { out += q[0]; i += q[0].length - 1; continue; }
      out += '\\{';
      continue;
    }
    if (c === '}') { out += '\\}'; continue; }
    if (c === '/') { out += '\\/'; continue; }
    out += c;
  }
  flags.delete('s');
  let re;
  try {
    re = new RegExp(out, [...flags].join(''));
  } catch (e) {
    throw new RuntimeError(`regex does not compile: ${e.message.replace(/^Invalid regular expression: /, '')}`);
  }
  cache.set(key, re);
  return re;
}

// Number of capture groups, counting named ones.
export function groupCount(pattern) {
  try {
    const re = compileGo(pattern);
    return new RegExp(re.source + '|', re.flags).exec('').length - 1;
  } catch {
    return null;
  }
}

export function groupNames(pattern) {
  return [...pattern.matchAll(/\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>/g)].map((m) => m[1]);
}

// Go's Regexp.ReplaceAllString template: $1, ${1}, $name, ${name}, $$ for a dollar.
export function goReplaceAll(input, pattern, template) {
  const re = compileGo(pattern, 'g');
  re.lastIndex = 0;
  return input.replace(re, (...args) => {
    const hasNamed = typeof args[args.length - 1] === 'object';
    const named = hasNamed ? args[args.length - 1] || {} : {};
    const groups = args.slice(0, hasNamed ? -3 : -2);
    return template.replace(/\$(\$|\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))/g, (_, all, braced, bare) => {
      if (all === '$') return '$';
      const name = braced ?? bare;
      if (/^\d+$/.test(name)) return groups[Number(name)] ?? '';
      return named[name] ?? '';
    });
  });
}
