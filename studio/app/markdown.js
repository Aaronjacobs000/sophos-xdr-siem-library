// A small markdown reader for collector READMEs. parseMarkdown turns the text into plain
// blocks; renderMarkdown builds DOM nodes from them with textContent only, so HTML in a README
// shows as text and never runs. It covers headings, paragraphs, lists, fenced code, tables,
// block quotes, inline code, bold and links. Links keep only https targets.

import { h, ext } from './dom.js';

const FENCE = /^\s*(```|~~~)/;
const HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const QUOTE = /^\s*>/;
const TABLE = /^\s*\|/;
const ITEM = /^\s*([-*+]|\d+[.)])\s+(.*)$/;
const RULE = /^:?-{2,}:?$/;
const INLINE = /`([^`]+)`|\*\*(.+?)\*\*|\[([^\]]+)\]\(([^)\s]+)\)|(https:\/\/[^\s<>()]*[^\s<>().,;:!?'"\]])/g;

const isBlockStart = (l) => FENCE.test(l) || HEADING.test(l) || QUOTE.test(l) || TABLE.test(l) || ITEM.test(l);

function cells(line) {
  const s = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  const out = [];
  let cur = '', tick = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && s[i + 1] === '|') { cur += '|'; i++; continue; }
    if (c === '`') tick = !tick;
    if (c === '|' && !tick) { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  out.push(cur.trim());
  return out;
}

// Inline nodes: {t: 'text', v} | {t: 'code', v} | {t: 'b', c: [nodes]} | {t: 'a', href, c: [nodes]}
export function parseInline(text, depth = 0) {
  const s = String(text || '');
  const out = [];
  let at = 0;
  for (const m of s.matchAll(INLINE)) {
    if (m.index > at) out.push({ t: 'text', v: s.slice(at, m.index) });
    if (m[1] !== undefined) out.push({ t: 'code', v: m[1] });
    else if (m[2] !== undefined) out.push(depth < 2 ? { t: 'b', c: parseInline(m[2], depth + 1) } : { t: 'text', v: m[2] });
    else if (m[3] !== undefined) out.push({ t: 'a', href: m[4], c: depth < 2 ? parseInline(m[3], depth + 1) : [{ t: 'text', v: m[3] }] });
    else out.push({ t: 'a', href: m[5], c: [{ t: 'text', v: m[5] }] });
    at = m.index + m[0].length;
  }
  if (at < s.length) out.push({ t: 'text', v: s.slice(at) });
  return out;
}

// Blocks: {t: 'h', level, c} | {t: 'p', c} | {t: 'code', v} | {t: 'ul'|'ol', items: [c]} |
// {t: 'table', head: [c], rows: [[c]]} | {t: 'quote', blocks}, where c is a list of inline nodes.
export function parseMarkdown(text, depth = 0) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    let m;
    if (!l.trim()) { i++; continue; }
    if ((m = FENCE.exec(l))) {
      const buf = [];
      for (i++; i < lines.length && !lines[i].trim().startsWith(m[1]); i++) buf.push(lines[i]);
      i++;
      out.push({ t: 'code', v: buf.join('\n') });
    } else if ((m = HEADING.exec(l))) {
      out.push({ t: 'h', level: m[1].length, c: parseInline(m[2]) });
      i++;
    } else if (QUOTE.test(l)) {
      const buf = [];
      while (i < lines.length && QUOTE.test(lines[i])) buf.push(lines[i++].replace(/^\s*>\s?/, ''));
      out.push(depth < 3 ? { t: 'quote', blocks: parseMarkdown(buf.join('\n'), depth + 1) } : { t: 'p', c: parseInline(buf.join(' ')) });
    } else if (TABLE.test(l)) {
      const rows = [];
      while (i < lines.length && TABLE.test(lines[i])) rows.push(cells(lines[i++]));
      const [head, ...body] = rows;
      out.push({ t: 'table', head: head.map((x) => parseInline(x)), rows: body.filter((r) => !r.every((x) => RULE.test(x))).map((r) => r.map((x) => parseInline(x))) });
    } else if ((m = ITEM.exec(l))) {
      const ordered = /\d/.test(m[1]);
      const items = [];
      while (i < lines.length) {
        const x = ITEM.exec(lines[i]);
        if (x && /\d/.test(x[1]) === ordered) { items.push(x[2]); i++; } else if (items.length && lines[i].trim() && /^\s+/.test(lines[i]) && !x) { items[items.length - 1] += ` ${lines[i].trim()}`; i++; } else break;
      }
      out.push({ t: ordered ? 'ol' : 'ul', items: items.map((x) => parseInline(x)) });
    } else {
      const buf = [l.trim()];
      for (i++; i < lines.length && lines[i].trim() && !isBlockStart(lines[i]); i++) buf.push(lines[i].trim());
      out.push({ t: 'p', c: parseInline(buf.join(' ')) });
    }
  }
  return out;
}

// https links stay; a relative link resolves against base (the folder on GitHub) when given.
export function linkTarget(href, base) {
  const s = String(href || '');
  if (/^https:\/\//i.test(s)) return s;
  if (!base || s.startsWith('#') || s.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(s)) return null;
  try {
    const u = new URL(s, base).href;
    return u.startsWith('https://github.com/') ? u : null;
  } catch { return null; }
}

function inline(nodes, base) {
  return nodes.map((n) => {
    if (n.t === 'code') return h('code', { text: n.v });
    if (n.t === 'b') return h('strong', {}, inline(n.c, base));
    if (n.t === 'a') {
      const href = linkTarget(n.href, base);
      return href ? ext(href, inline(n.c, base)) : h('span', {}, inline(n.c, base));
    }
    return n.v;
  });
}

function block(b, base) {
  if (b.t === 'h') return h(`h${Math.min(b.level + 3, 6)}`, {}, inline(b.c, base));
  if (b.t === 'code') return h('pre', { class: 'code', text: b.v });
  if (b.t === 'ul' || b.t === 'ol') return h(b.t, {}, b.items.map((c) => h('li', {}, inline(c, base))));
  if (b.t === 'quote') return h('blockquote', {}, b.blocks.map((x) => block(x, base)));
  if (b.t === 'table') {
    return h('div', { class: 'mdtable' }, h('table', {},
      h('thead', {}, h('tr', {}, b.head.map((c) => h('th', {}, inline(c, base))))),
      h('tbody', {}, b.rows.map((r) => h('tr', {}, r.map((c) => h('td', {}, inline(c, base))))))));
  }
  return h('p', {}, inline(b.c, base));
}

export function renderMarkdown(text, { base } = {}) {
  return h('div', { class: 'md' }, parseMarkdown(text).map((b) => block(b, base)));
}
