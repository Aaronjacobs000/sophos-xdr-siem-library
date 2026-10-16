// A syntax checker for CEL, the Common Expression Language that Sophos Fusion playbooks and
// connectors use. It parses an expression into a tree and lists the names the expression reads
// from outside itself, so a check can tell a reference to a task from a typo or from text that was
// meant to be quoted. It doesn't evaluate anything or know which functions exist.
//
//   parseCel(text) -> ast, or throws CelError (with .offset)
//   freeNames(ast) -> Set of the outside names the expression reads
//   templateParts(text) -> [{expr, offset}] for each ${...} in a connector's template text

export class CelError extends Error {
  constructor(reason, offset) {
    super(`${reason} at character ${offset + 1}`);
    this.reason = reason;
    this.offset = offset;
  }
}

const PUNCT = ['&&', '||', '==', '!=', '<=', '>=', '(', ')', '[', ']', '{', '}', '.', ',', ':', '?', '!', '-', '+', '*', '/', '%', '<', '>'];
const ESC = { a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', '?': '?', '"': '"', "'": "'", '`': '`' };
const MAX_DEPTH = 250;

function lex(src) {
  const toks = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    const start = i;
    // Strings, with optional r (raw) and b (bytes) prefixes.
    const sm = /^([rRbB]{0,2})("""|'''|"|')/.exec(src.slice(i, i + 5));
    if (sm && (sm[1] === '' || /^(r|R|b|B|rb|rB|Rb|RB|br|bR|Br|BR)$/.test(sm[1]))) {
      const raw = /r/i.test(sm[1]);
      const q = sm[2];
      i += sm[0].length;
      let out = '';
      for (;;) {
        if (i >= src.length) throw new CelError('a string that never ends', start);
        if (src.startsWith(q, i)) { i += q.length; break; }
        const ch = src[i];
        if (ch === '\n' && q.length === 1) throw new CelError('a line break inside a string', i);
        if (ch === '\\' && !raw) {
          const e = src[i + 1];
          if (e in ESC) { out += ESC[e]; i += 2; continue; }
          const hex = { x: 2, u: 4, U: 8 }[e];
          if (hex) {
            const h = src.slice(i + 2, i + 2 + hex);
            if (!new RegExp(`^[0-9a-fA-F]{${hex}}$`).test(h)) throw new CelError(`a bad \\${e} escape`, i);
            out += String.fromCodePoint(parseInt(h, 16));
            i += 2 + hex;
            continue;
          }
          if (/^[0-3][0-7][0-7]$/.test(src.slice(i + 1, i + 4))) { out += String.fromCharCode(parseInt(src.slice(i + 1, i + 4), 8)); i += 4; continue; }
          throw new CelError(`an unknown escape \\${e ?? ''}`, i);
        }
        out += ch;
        i++;
      }
      toks.push({ t: 'str', v: out, pos: start });
      continue;
    }
    const nm = /^(?:0[xX][0-9a-fA-F]+[uU]?|[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?|[0-9]+[eE][+-]?[0-9]+|\.[0-9]+(?:[eE][+-]?[0-9]+)?|[0-9]+[uU]?)/.exec(src.slice(i));
    if (nm && !(c === '.' && toks.length && ['id', ')', ']', 'str'].includes(toks[toks.length - 1].t))) {
      const txt = nm[0];
      if (/^[0-9.]/.test(txt) && /[A-Za-z_]/.test(src[i + txt.length] || '') && !/[uU]$/.test(txt)) throw new CelError(`a bad number ${txt}${src[i + txt.length]}`, i);
      toks.push({ t: 'num', v: Number(txt.replace(/[uU]$/, '')), pos: start });
      i += txt.length;
      continue;
    }
    const im = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i));
    if (im) {
      const w = im[0];
      if (w === 'true' || w === 'false') toks.push({ t: 'lit', v: w === 'true', pos: start });
      else if (w === 'null') toks.push({ t: 'lit', v: null, pos: start });
      else if (w === 'in') toks.push({ t: 'in', pos: start });
      else toks.push({ t: 'id', v: w, pos: start });
      i += w.length;
      continue;
    }
    const p = PUNCT.find((x) => src.startsWith(x, i));
    if (!p) throw new CelError(`an unexpected character ${JSON.stringify(c)}`, i);
    toks.push({ t: p, pos: start });
    i += p.length;
  }
  toks.push({ t: 'eof', pos: src.length });
  return toks;
}

class P {
  constructor(src) { this.toks = lex(src); this.k = 0; this.depth = 0; }
  get cur() { return this.toks[this.k]; }
  is(t) { return this.cur.t === t; }
  eat(t) { if (this.is(t)) { this.k++; return true; } return false; }
  want(t, what) {
    if (!this.is(t)) throw new CelError(`expected ${what || t} but found ${this.cur.t === 'eof' ? 'the end' : this.describe(this.cur)}`, this.cur.pos);
    return this.toks[this.k++];
  }
  describe(tok) { return tok.t === 'id' ? `"${tok.v}"` : tok.t === 'str' ? 'a string' : tok.t === 'num' ? 'a number' : `"${tok.t}"`; }
  enter() { if (++this.depth > MAX_DEPTH) throw new CelError('the expression nests too deeply', this.cur.pos); }

  expr() {
    this.enter();
    const c = this.or();
    if (this.eat('?')) {
      const a = this.or();
      this.want(':', '":" of a ? : expression');
      const b = this.expr();
      this.depth--;
      return { t: 'cond', c, a, b };
    }
    this.depth--;
    return c;
  }
  or() { let l = this.and(); while (this.eat('||')) l = { t: 'bin', op: '||', l, r: this.and() }; return l; }
  and() { let l = this.rel(); while (this.eat('&&')) l = { t: 'bin', op: '&&', l, r: this.rel() }; return l; }
  rel() {
    let l = this.add();
    for (;;) {
      const op = ['<', '<=', '>', '>=', '==', '!=', 'in'].find((x) => this.is(x));
      if (!op) return l;
      this.k++;
      l = { t: 'bin', op, l, r: this.add() };
    }
  }
  add() {
    let l = this.mul();
    for (;;) {
      const op = ['+', '-'].find((x) => this.is(x));
      if (!op) return l;
      this.k++;
      l = { t: 'bin', op, l, r: this.mul() };
    }
  }
  mul() {
    let l = this.unary();
    for (;;) {
      const op = ['*', '/', '%'].find((x) => this.is(x));
      if (!op) return l;
      this.k++;
      l = { t: 'bin', op, l, r: this.unary() };
    }
  }
  unary() {
    if (this.is('!') || this.is('-')) {
      const op = this.cur.t;
      this.k++;
      this.enter();
      const x = this.unary();
      this.depth--;
      return { t: 'un', op, x };
    }
    return this.member();
  }
  member() {
    let x = this.primary();
    for (;;) {
      if (this.eat('.')) {
        const opt = this.eat('?');
        const name = this.want('id', 'a field name after "."').v;
        if (this.eat('(')) x = { t: 'call', fn: name, target: x, args: this.args(')') };
        else x = { t: 'sel', target: x, field: name, opt };
      } else if (this.eat('[')) {
        const opt = this.eat('?');
        const index = this.expr();
        this.want(']', '"]"');
        x = { t: 'idx', target: x, index, opt };
      } else {
        return x;
      }
    }
  }
  args(close) {
    const out = [];
    if (this.eat(close)) return out;
    for (;;) {
      out.push(this.expr());
      if (this.eat(close)) return out;
      this.want(',', `"," or "${close}"`);
    }
  }
  primary() {
    const tok = this.cur;
    if (this.eat('.')) {
      // A name from the root, such as .com.example.Message
      const id = this.want('id', 'a name after a leading "."');
      return this.named(id, true);
    }
    if (tok.t === 'id') { this.k++; return this.named(tok, false); }
    if (this.eat('(')) { const e = this.expr(); this.want(')', '")"'); return e; }
    if (this.eat('[')) {
      const items = [];
      if (!this.eat(']')) {
        for (;;) {
          this.eat('?');
          items.push(this.expr());
          if (this.eat(']')) break;
          this.want(',', '"," or "]"');
          if (this.eat(']')) break;
        }
      }
      return { t: 'list', items };
    }
    if (this.eat('{')) {
      const entries = [];
      if (!this.eat('}')) {
        for (;;) {
          this.eat('?');
          const k = this.expr();
          this.want(':', '":" in a map');
          entries.push({ k, v: this.expr() });
          if (this.eat('}')) break;
          this.want(',', '"," or "}"');
          if (this.eat('}')) break;
        }
      }
      return { t: 'map', entries };
    }
    if (tok.t === 'str' || tok.t === 'num' || tok.t === 'lit') { this.k++; return { t: 'lit', v: tok.v }; }
    throw new CelError(tok.t === 'eof' ? 'the expression ends too early' : `unexpected ${this.describe(tok)}`, tok.pos);
  }
  named(tok, root) {
    if (this.eat('(')) return { t: 'call', fn: tok.v, target: null, args: this.args(')'), pos: tok.pos };
    // A message: Name{field: value} or pkg.Name{...}
    let name = tok.v;
    const save = this.k;
    while (this.is('.') && this.toks[this.k + 1].t === 'id') { this.k++; name += `.${this.cur.v}`; this.k++; }
    if (this.is('{') && /^[A-Z]/.test(name.split('.').pop())) {
      this.k++;
      const fields = [];
      if (!this.eat('}')) {
        for (;;) {
          this.eat('?');
          const f = this.want('id', 'a field name').v;
          this.want(':', '":" after a field name');
          fields.push({ f, v: this.expr() });
          if (this.eat('}')) break;
          this.want(',', '"," or "}"');
          if (this.eat('}')) break;
        }
      }
      return { t: 'msg', name, fields };
    }
    this.k = save;
    return { t: 'id', name: tok.v, pos: tok.pos, root };
  }
}

export function parseCel(text) {
  const p = new P(String(text));
  if (p.is('eof')) throw new CelError('an empty expression', 0);
  const ast = p.expr();
  if (!p.is('eof')) throw new CelError(`unexpected ${p.describe(p.cur)}`, p.cur.pos);
  return ast;
}

// Macros that bind a variable for their other arguments: list.all(x, x > 0), and the two-variable
// forms such as map.all(k, v, ...).
const MACROS = new Set(['all', 'exists', 'exists_one', 'existsOne', 'map', 'filter', 'transformList', 'transformMap', 'transformMapEntry', 'sortBy']);
const TWO_VAR = new Set(['all', 'exists', 'existsOne', 'exists_one', 'transformList', 'transformMap', 'transformMapEntry']);

export function freeNames(ast) {
  const out = new Set();
  const walk = (n, bound) => {
    if (!n) return;
    switch (n.t) {
      case 'id': if (!bound.has(n.name)) out.add(n.name); return;
      case 'lit': return;
      case 'sel': walk(n.target, bound); return;
      case 'idx': walk(n.target, bound); walk(n.index, bound); return;
      case 'un': walk(n.x, bound); return;
      case 'bin': walk(n.l, bound); walk(n.r, bound); return;
      case 'cond': walk(n.c, bound); walk(n.a, bound); walk(n.b, bound); return;
      case 'list': for (const x of n.items) walk(x, bound); return;
      case 'map': for (const e of n.entries) { walk(e.k, bound); walk(e.v, bound); } return;
      case 'msg': for (const f of n.fields) walk(f.v, bound); return;
      case 'call': {
        // cel.bind(name, init, expr)
        if (n.fn === 'bind' && n.target && n.target.t === 'id' && n.target.name === 'cel' && n.args.length === 3 && n.args[0].t === 'id') {
          walk(n.args[1], bound);
          walk(n.args[2], new Set([...bound, n.args[0].name]));
          return;
        }
        if (n.target) walk(n.target, bound);
        if (n.target && MACROS.has(n.fn) && n.args.length >= 2 && n.args[0].t === 'id') {
          const names = [n.args[0].name];
          let from = 1;
          if (TWO_VAR.has(n.fn) && n.args.length === 3 && n.args[1].t === 'id') { names.push(n.args[1].name); from = 2; }
          const inner = new Set([...bound, ...names]);
          for (const a of n.args.slice(from)) walk(a, inner);
          return;
        }
        for (const a of n.args) walk(a, bound);
        return;
      }
      default: return;
    }
  };
  walk(ast, new Set());
  return out;
}

// The ${...} parts of a connector's template text, such as https://${config.host}/x/${inputs.id}.
// Braces inside quoted strings don't count. Throws CelError for one that never closes.
export function templateParts(text) {
  const s = String(text);
  const out = [];
  let i = 0;
  while ((i = s.indexOf('${', i)) !== -1) {
    const start = i + 2;
    let depth = 1;
    let j = start;
    let quote = null;
    for (; j < s.length && depth > 0; j++) {
      const ch = s[j];
      if (quote) {
        if (ch === '\\') { j++; continue; }
        if (s.startsWith(quote, j)) { j += quote.length - 1; quote = null; }
        continue;
      }
      if (s.startsWith('"""', j) || s.startsWith("'''", j)) { quote = s.slice(j, j + 3); j += 2; continue; }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    if (depth !== 0) throw new CelError('a ${ that never closes', i);
    out.push({ expr: s.slice(start, j - 1), offset: start });
    i = j;
  }
  return out;
}
