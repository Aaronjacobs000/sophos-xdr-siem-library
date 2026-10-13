// Syntax colouring for parser scripts and sample lines, built as DOM nodes.

import { splitSyslog } from '../core/formats.js';

function span(cls, text) {
  const s = document.createElement('span');
  if (cls) s.className = cls;
  s.textContent = text;
  return s;
}

function tokens(out, text, rules) {
  let i = 0;
  while (i < text.length) {
    let hit = null;
    for (const [re, cls] of rules) {
      re.lastIndex = i;
      const m = re.exec(text);
      if (m && m.index === i && m[0].length) { hit = [m[0], typeof cls === 'function' ? cls(m, text) : cls]; break; }
    }
    if (hit) { out.append(span(hit[1], hit[0])); i += hit[0].length; } else {
      let j = i + 1;
      while (j < text.length && !/["'`\w$!#|]/.test(text[j])) j++;
      out.append(document.createTextNode(text.slice(i, j)));
      i = j;
    }
  }
}

const EXPR_RULES = [
  [/"(?:\\.|[^"\\])*"/y, 'tk-s'],
  [/'(?:\\.|[^'\\])*'/y, 'tk-s'],
  [/`[^`]*`/y, 'tk-s'],
  [/#.*/y, 'tk-c'],
  [/\b(?:IF|THEN|ELSE|AND|OR|TRUE|FALSE|NULL)\b/y, 'tk-kw'],
  [/[A-Z_][A-Z0-9_]*(?=\()/y, 'tk-f'],
  [/[A-Za-z_][A-Za-z0-9_]*\$/y, 'tk-v'],
  [/\b\d+(?:\.\d+)?\b/y, 'tk-n'],
  [/[A-Za-z_][A-Za-z0-9_]*/y, null],
];

export function highlightScriptLine(line) {
  const out = document.createDocumentFragment();
  const t = line.trimStart();
  if (t.startsWith('#')) { out.append(span('tk-c', line)); return out; }
  if (t.startsWith('!')) {
    const eq = line.indexOf('=');
    if (eq === -1) { out.append(span('tk-d', line)); return out; }
    const key = line.slice(0, eq + 1);
    const val = line.slice(eq + 1);
    out.append(span('tk-d', key));
    if (/!SAMPLE=/.test(key)) out.append(span('tk-c', val));
    else if (/!CONFIRMSTRING=/.test(key)) tokens(out, val, EXPR_RULES.slice(0, 1).concat([[/[^"]+/y, 'tk-r']]));
    else out.append(span('tk-s', val));
    return out;
  }
  const cap = /^(\s*[A-Za-z_][A-Za-z0-9_]*\$?\s*=\s*[A-Za-z_][A-Za-z0-9_]*\$?)\|(.*)$/.exec(line);
  if (cap) {
    tokens(out, cap[1], EXPR_RULES);
    out.append(span('tk-kw', '|'), span('tk-r', cap[2]));
    return out;
  }
  tokens(out, line, EXPR_RULES);
  return out;
}

export function highlightScript(text) {
  const out = document.createDocumentFragment();
  const lines = text.split('\n');
  lines.forEach((l, i) => {
    out.append(highlightScriptLine(l));
    if (i < lines.length - 1) out.append(document.createTextNode('\n'));
  });
  return out;
}

const BODY_RULES = [
  [/"(?:\\.|[^"\\])*"(?=\s*:)/y, 'tk-k'],
  [/"(?:\\.|[^"\\])*"/y, 'tk-s'],
  [/[A-Za-z_][\w.-]*(?==)/y, 'tk-k'],
  [/\b(?:true|false|null)\b/y, 'tk-n'],
  [/-?\b\d+(?:\.\d+)?\b/y, 'tk-n'],
  [/(?:CEF|LEEF):[\d.]+/y, 'tk-h'],
  [/[A-Za-z_][\w$]*/y, null],
];

export function highlightSample(line) {
  const out = document.createDocumentFragment();
  const hdr = splitSyslog(line);
  let body = line;
  if (hdr && hdr.body !== line) {
    const head = line.slice(0, line.length - hdr.body.length);
    out.append(span('tk-h', head));
    body = hdr.body;
  }
  const tag = /^([A-Za-z0-9_.\-/]+(?:\[\d+\])?:)(\s)/.exec(body);
  if (tag) { out.append(span('tk-h', tag[1]), document.createTextNode(tag[2])); body = body.slice(tag[0].length); }
  tokens(out, body, BODY_RULES);
  return out;
}
