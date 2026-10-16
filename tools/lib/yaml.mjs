// A strict reader for the YAML that Sophos Fusion exports for playbook templates and connectors:
// block mappings and lists, plain, quoted and block scalars, and one-line flow collections. It
// refuses what library files never need rather than guess at it: anchors, aliases, tags, complex
// keys, more than one document, and tabs in indentation. Every node keeps its line, and a scalar
// keeps its style, because in a template a single-quoted value is text while a plain or
// double-quoted one is a CEL expression.
//
//   parseYaml(text) -> node, or throws YamlError (with .line)
//   node: {kind: 'map', line, entries: [{key, line, value}]}
//         {kind: 'seq', line, items: [node]}
//         {kind: 'scalar', line, style: 'plain'|'single'|'double'|'literal'|'folded', text, value}
//   toJS(node) -> plain values

export class YamlError extends Error {
  constructor(reason, line) {
    super(`line ${line}: ${reason}`);
    this.reason = reason;
    this.line = line;
  }
}

const scalar = (line, style, text, value = text) => ({ kind: 'scalar', line, style, text, value });

// YAML 1.2 core schema for plain scalars.
export function resolvePlain(text) {
  if (text === '' || text === '~' || /^(null|Null|NULL)$/.test(text)) return null;
  if (/^(true|True|TRUE)$/.test(text)) return true;
  if (/^(false|False|FALSE)$/.test(text)) return false;
  if (/^[-+]?[0-9]+$/.test(text)) return Number(text);
  if (/^0x[0-9a-fA-F]+$/.test(text)) return parseInt(text.slice(2), 16);
  if (/^0o[0-7]+$/.test(text)) return parseInt(text.slice(2), 8);
  if (/^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$/.test(text)) return Number(text);
  if (/^[-+]?\.(inf|Inf|INF)$/.test(text)) return text.startsWith('-') ? -Infinity : Infinity;
  if (/^\.(nan|NaN|NAN)$/.test(text)) return NaN;
  return text;
}

const DQ_ESCAPES = { 0: '\0', a: '\x07', b: '\b', t: '\t', '\t': '\t', n: '\n', v: '\v', f: '\f', r: '\r', e: '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\x85', _: '\xa0', L: ' ', P: ' ' };
const HEX_LEN = { x: 2, u: 4, U: 8 };

class Parser {
  constructor(text) {
    const split = text.split('\n');
    // A final line break ends the last line; it doesn't start an empty one.
    if (split.length > 1 && split[split.length - 1] === '') split.pop();
    this.lines = split.map((raw, i) => {
      const indent = /^ */.exec(raw)[0].length;
      return { no: i + 1, raw, indent, content: raw.slice(indent) };
    });
    this.i = 0;
  }

  // A line that holds something other than blanks or a comment.
  significant(l) {
    if (!l) return false;
    const c = l.content.replace(/[ \t]+$/, '');
    if (c === '' || c.startsWith('#')) return false;
    if (/^[ ]*\t/.test(l.raw) || (l.content.startsWith('\t'))) throw new YamlError('a tab in the indentation; use spaces', l.no);
    return true;
  }

  peek() {
    while (this.i < this.lines.length && !this.significant(this.lines[this.i])) this.i++;
    return this.lines[this.i] || null;
  }

  document() {
    let first = this.peek();
    if (first && first.indent === 0 && first.content.startsWith('%')) throw new YamlError('directives are not supported', first.no);
    if (first && first.indent === 0 && /^---\s*(#.*)?$/.test(first.content)) { this.i++; first = this.peek(); }
    if (!first) return scalar(1, 'plain', '', null);
    const node = this.node(-1);
    const rest = this.peek();
    if (rest) {
      if (rest.indent === 0 && /^(---|\.\.\.)(\s|$)/.test(rest.content)) throw new YamlError('only one YAML document is allowed', rest.no);
      throw new YamlError('this line is indented differently from the lines before it', rest.no);
    }
    return node;
  }

  // The node whose lines are indented more than parentIndent, or an empty scalar if there are none.
  node(parentIndent) {
    const l = this.peek();
    if (!l || l.indent <= parentIndent) return scalar(l ? l.no : this.lines.length, 'plain', '', null);
    if (isSeqLine(l.content)) return this.seq(l.indent);
    if (keyOf(l.content)) return this.map(l.indent);
    this.i++;
    return this.inline(l.content, l, parentIndent);
  }

  map(n) {
    const first = this.peek();
    const node = { kind: 'map', line: first.no, entries: [] };
    const seen = new Set();
    for (;;) {
      const l = this.peek();
      if (!l || l.indent < n || isMarker(l)) break;
      if (l.indent > n) throw new YamlError('this line is indented more than the key before it', l.no);
      if (isSeqLine(l.content)) throw new YamlError('a list item where a key was expected', l.no);
      const k = keyOf(l.content);
      if (!k) throw new YamlError('expected "key: value"', l.no);
      if (seen.has(k.key)) throw new YamlError(`the key "${k.key}" appears twice`, l.no);
      if (k.key === '__proto__') throw new YamlError('the key "__proto__" is not allowed', l.no);
      seen.add(k.key);
      this.i++;
      node.entries.push({ key: k.key, line: l.no, value: this.value(k.rest, l, n) });
    }
    return node;
  }

  // The value after "key:" on line l, whose key sits at indent n.
  value(rest, l, n) {
    const s = rest.replace(/^[ ]+/, '');
    if (s === '' || s.startsWith('#')) {
      const next = this.peek();
      if (next && next.indent === n && isSeqLine(next.content)) return this.seq(n);
      return this.node(n);
    }
    if (!/^[ ]/.test(rest)) throw new YamlError('a space must follow the colon', l.no);
    return this.inline(s, l, n);
  }

  seq(n) {
    const node = { kind: 'seq', line: this.peek().no, items: [] };
    for (;;) {
      const l = this.peek();
      if (!l || l.indent < n || isMarker(l)) break;
      if (l.indent > n) throw new YamlError('this line is indented more than the list item before it', l.no);
      if (!isSeqLine(l.content)) break;
      const after = l.content === '-' ? '' : l.content.slice(2);
      const pad = /^ */.exec(after)[0].length;
      const rest = after.slice(pad);
      if (rest === '' || rest.startsWith('#')) {
        this.i++;
        node.items.push(this.node(n));
      } else {
        // The item starts on the dash's line: read it as if that line began where the item does.
        this.lines[this.i] = { no: l.no, raw: l.raw, indent: n + 2 + pad, content: rest };
        node.items.push(this.node(n));
      }
    }
    return node;
  }

  // A value that starts on line l with text s: a block scalar, a flow collection, or a quoted or
  // plain scalar, which may go on over lines indented more than parentIndent.
  inline(s, l, parentIndent) {
    const c = s[0];
    if (c === '&' || c === '*') throw new YamlError('anchors and aliases are not supported', l.no);
    if (c === '!') throw new YamlError('tags are not supported', l.no);
    if (c === '?' && /^\?(\s|$)/.test(s)) throw new YamlError('complex keys are not supported', l.no);
    if (c === '@' || c === '`') throw new YamlError(`a value can't start with ${c}`, l.no);
    if (c === '|' || c === '>') return this.block(s, l, parentIndent);
    if (c === '[' || c === '{') {
      const f = new Flow(s, l.no);
      const node = f.node();
      f.end();
      return node;
    }
    if (c === '"' || c === "'") return this.quoted(s, l, parentIndent);
    return this.plain(s, l, parentIndent);
  }

  plain(s, l, parentIndent) {
    let text = stripComment(s);
    const parts = [text];
    // Continuation lines, folded: one line break is a space, each blank line a line break.
    let blanks = 0;
    while (this.i < this.lines.length) {
      const m = this.lines[this.i];
      const c = m.content.replace(/[ \t]+$/, '');
      if (c === '') { blanks++; this.i++; continue; }
      if (m.indent <= parentIndent || c.startsWith('#')) break;
      if (!this.significant(m)) break;
      this.i++;
      parts.push(blanks ? '\n'.repeat(blanks) : ' ', stripComment(m.content));
      blanks = 0;
    }
    text = parts.join('');
    if (/:(\s|$)/.test(text)) throw new YamlError('a plain value can\'t hold ": " (quote it)', l.no);
    if (/\s#/.test(text)) throw new YamlError('a plain value can\'t hold " #" (quote it)', l.no);
    return scalar(l.no, 'plain', text, resolvePlain(text));
  }

  quoted(s, l, parentIndent) {
    const q = s[0];
    let out = '';
    let text = s;
    let pos = 1;
    let lineNo = l.no;
    for (;;) {
      if (pos >= text.length) {
        // The value goes on to the next line: one line break is a space, each blank line a line
        // break, and a backslash at the end of a double-quoted line joins the lines.
        const joined = q === '"' && out.endsWith('\u0000');
        out = joined ? out.slice(0, -1) : out.replace(/[ \t]+$/, '');
        let breaks = 0;
        let next = this.lines[this.i];
        while (next && next.raw.trim() === '') { breaks++; this.i++; next = this.lines[this.i]; }
        if (!next) throw new YamlError(`the ${q === '"' ? 'double' : 'single'}-quoted value never ends`, l.no);
        if (next.indent <= parentIndent) throw new YamlError('the quoted value goes on at too small an indent', next.no);
        if (/^ *\t/.test(next.raw) && next.raw.indexOf('\t') < next.indent + 1) throw new YamlError('a tab in the indentation; use spaces', next.no);
        out += breaks ? '\n'.repeat(breaks) : joined ? '' : ' ';
        text = next.content.replace(/^[ \t]+/, '');
        pos = 0;
        lineNo = next.no;
        this.i++;
        continue;
      }
      const ch = text[pos];
      if (q === "'") {
        if (ch === "'") {
          if (text[pos + 1] === "'") { out += "'"; pos += 2; continue; }
          pos++;
          break;
        }
        out += ch;
        pos++;
        continue;
      }
      if (ch === '"') { pos++; break; }
      if (ch === '\\') {
        const e = text[pos + 1];
        if (e === undefined) { out += '\u0000'; pos++; continue; }
        if (HEX_LEN[e]) {
          const hex = text.slice(pos + 2, pos + 2 + HEX_LEN[e]);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== HEX_LEN[e]) throw new YamlError(`a bad \\${e} escape`, lineNo);
          out += String.fromCodePoint(parseInt(hex, 16));
          pos += 2 + HEX_LEN[e];
          continue;
        }
        if (!(e in DQ_ESCAPES)) throw new YamlError(`an unknown escape \\${e}`, lineNo);
        out += DQ_ESCAPES[e];
        pos += 2;
        continue;
      }
      out += ch;
      pos++;
    }
    // After the closing quote: nothing but a comment.
    const tail = text.slice(pos);
    if (tail.trim() !== '' && !/^\s+#/.test(tail)) throw new YamlError('text after the closing quote', lineNo);
    return scalar(l.no, q === '"' ? 'double' : 'single', out);
  }

  // A literal (|) or folded (>) block scalar, with an optional chomping indicator (+ or -) and
  // indentation digit. Its lines are the ones indented more than parentIndent.
  block(s, l, parentIndent) {
    const m = /^([|>])([+-]?)([1-9]?)([+-]?)(\s+#.*)?\s*$/.exec(s);
    if (!m || (m[2] && m[4])) throw new YamlError('a bad block scalar header', l.no);
    const literal = m[1] === '|';
    const chomp = { '-': 'strip', '+': 'keep' }[m[2] || m[4]] || 'clip';
    let indent = m[3] ? Math.max(parentIndent, 0) + Number(m[3]) : null;
    const lines = [];
    while (this.i < this.lines.length) {
      const x = this.lines[this.i];
      if (x.raw.trim() === '') { lines.push(''); this.i++; continue; }
      if (x.indent <= parentIndent) break;
      if (indent === null) indent = x.indent;
      if (x.indent < indent) throw new YamlError('this line is indented less than the first line of the block', x.no);
      lines.push(x.raw.slice(indent));
      this.i++;
    }
    let out = '';
    let empty = 0;
    let read = false;
    let moreIndented = false;
    for (const line of lines) {
      if (line === '') { empty++; continue; }
      if (literal) out += '\n'.repeat(read ? 1 + empty : empty);
      else if (/^[ \t]/.test(line)) { moreIndented = true; out += '\n'.repeat(read ? 1 + empty : empty); }
      else if (moreIndented) { moreIndented = false; out += '\n'.repeat(empty + 1); }
      else if (empty === 0) { if (read) out += ' '; }
      else out += '\n'.repeat(empty);
      out += line;
      read = true;
      empty = 0;
    }
    if (chomp === 'keep') out += '\n'.repeat(read ? 1 + empty : empty);
    else if (chomp === 'clip' && read) out += '\n';
    return scalar(l.no, literal ? 'literal' : 'folded', out);
  }
}

// A flow collection on one line: [a, b] or {k: v}.
class Flow {
  constructor(s, line) { this.s = s; this.p = 0; this.line = line; }
  ws() { while (this.p < this.s.length && /\s/.test(this.s[this.p])) this.p++; }
  err(msg) { return new YamlError(msg, this.line); }
  end() {
    this.ws();
    const tail = this.s.slice(this.p);
    if (tail !== '' && !tail.startsWith('#')) throw this.err('text after the closing bracket');
  }
  node() {
    this.ws();
    const c = this.s[this.p];
    if (c === '[') return this.seq();
    if (c === '{') return this.map();
    if (c === '"' || c === "'") return this.quoted();
    if (c === '&' || c === '*' || c === '!') throw this.err('anchors, aliases and tags are not supported');
    return this.plain();
  }
  seq() {
    const node = { kind: 'seq', line: this.line, items: [] };
    this.p++;
    for (;;) {
      this.ws();
      if (this.s[this.p] === ']') { this.p++; return node; }
      if (this.p >= this.s.length) throw this.err('a flow list without a closing ]');
      node.items.push(this.node());
      this.ws();
      if (this.s[this.p] === ',') { this.p++; continue; }
      if (this.s[this.p] === ']') { this.p++; return node; }
      throw this.err('expected , or ] in a flow list');
    }
  }
  map() {
    const node = { kind: 'map', line: this.line, entries: [] };
    const seen = new Set();
    this.p++;
    for (;;) {
      this.ws();
      if (this.s[this.p] === '}') { this.p++; return node; }
      if (this.p >= this.s.length) throw this.err('a flow mapping without a closing }');
      const k = this.node();
      if (k.kind !== 'scalar') throw this.err('a flow mapping key must be a scalar');
      const key = String(k.value === null ? '' : k.text);
      this.ws();
      if (this.s[this.p] !== ':') throw this.err('expected : in a flow mapping');
      this.p++;
      this.ws();
      const value = (this.s[this.p] === ',' || this.s[this.p] === '}') ? scalar(this.line, 'plain', '', null) : this.node();
      if (seen.has(key)) throw this.err(`the key "${key}" appears twice`);
      if (key === '__proto__') throw this.err('the key "__proto__" is not allowed');
      seen.add(key);
      node.entries.push({ key, line: this.line, value });
      this.ws();
      if (this.s[this.p] === ',') { this.p++; continue; }
      if (this.s[this.p] === '}') { this.p++; return node; }
      throw this.err('expected , or } in a flow mapping');
    }
  }
  quoted() {
    const q = this.s[this.p];
    let out = '';
    this.p++;
    for (;;) {
      if (this.p >= this.s.length) throw this.err('a quoted value in a flow collection never ends');
      const ch = this.s[this.p];
      if (q === "'" && ch === "'") {
        if (this.s[this.p + 1] === "'") { out += "'"; this.p += 2; continue; }
        this.p++;
        break;
      }
      if (q === '"' && ch === '"') { this.p++; break; }
      if (q === '"' && ch === '\\') {
        const e = this.s[this.p + 1];
        if (HEX_LEN[e]) {
          const hex = this.s.slice(this.p + 2, this.p + 2 + HEX_LEN[e]);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== HEX_LEN[e]) throw this.err(`a bad \\${e} escape`);
          out += String.fromCodePoint(parseInt(hex, 16));
          this.p += 2 + HEX_LEN[e];
          continue;
        }
        if (!(e in DQ_ESCAPES)) throw this.err(`an unknown escape \\${e}`);
        out += DQ_ESCAPES[e];
        this.p += 2;
        continue;
      }
      out += ch;
      this.p++;
    }
    return scalar(this.line, q === '"' ? 'double' : 'single', out);
  }
  plain() {
    const start = this.p;
    while (this.p < this.s.length) {
      const ch = this.s[this.p];
      if (ch === ',' || ch === ']' || ch === '}' || ch === '[' || ch === '{') break;
      if (ch === ':' && (this.p + 1 >= this.s.length || /[\s,\]}]/.test(this.s[this.p + 1]))) break;
      if (ch === '#' && /\s/.test(this.s[this.p - 1] || '')) break;
      this.p++;
    }
    const text = this.s.slice(start, this.p).trim();
    if (text === '' && !/[,\]}:]/.test(this.s[this.p] || '')) throw this.err('an empty value in a flow collection');
    return scalar(this.line, 'plain', text, resolvePlain(text));
  }
}

// A document marker (--- or ...) at the start of a line.
const isMarker = (l) => l.indent === 0 && /^(---|\.\.\.)(\s|$)/.test(l.content);

function isSeqLine(c) {
  return c === '-' || c.startsWith('- ') || c.startsWith('-\t');
}

// The key of a "key: value" line, with the text after the colon, or null when the line isn't one.
function keyOf(c) {
  if (c.startsWith('"') || c.startsWith("'")) {
    const q = c[0];
    let i = 1;
    let key = '';
    for (; i < c.length; i++) {
      if (c[i] === q) {
        if (q === "'" && c[i + 1] === "'") { key += "'"; i++; continue; }
        break;
      }
      if (q === '"' && c[i] === '\\') { key += c[i + 1]; i++; continue; }
      key += c[i];
    }
    if (i >= c.length) return null;
    const after = c.slice(i + 1);
    const m = /^\s*:(?=\s|$)/.exec(after);
    return m ? { key, rest: after.slice(m[0].length) } : null;
  }
  if (/^[[\]{},#&*!|>'"%@`]/.test(c) || /^\?(\s|$)/.test(c) || isSeqLine(c)) return null;
  const m = /:(?=\s|$)/.exec(c);
  if (!m) return null;
  const key = c.slice(0, m.index).replace(/\s+$/, '');
  if (/\s#/.test(key) || key === '') return null;
  return { key, rest: c.slice(m.index + 1) };
}

function stripComment(s) {
  const m = /(^|\s)#/.exec(s);
  return (m ? s.slice(0, m.index) : s).replace(/\s+$/, '');
}

export function parseYaml(text) {
  let src = String(text ?? '').replace(/\r\n?/g, '\n');
  if (src.charCodeAt(0) === 0xfeff) src = src.slice(1);
  return new Parser(src).document();
}

export function toJS(node) {
  if (!node) return null;
  if (node.kind === 'map') {
    const out = {};
    for (const e of node.entries) out[e.key] = toJS(e.value);
    return out;
  }
  if (node.kind === 'seq') return node.items.map(toJS);
  return node.value;
}

// The value at a key of a map node, or undefined.
export function get(node, key) {
  if (!node || node.kind !== 'map') return undefined;
  const e = node.entries.find((x) => x.key === key);
  return e ? e.value : undefined;
}
