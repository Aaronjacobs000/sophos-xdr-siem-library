// Reads parser scripts: directives, capture statements, assignments, and expressions.
// Grammar from the Fusion "Custom parser syntax" page. Operators the page doesn't show
// (AND, OR, <, >, /) are accepted and flagged by the lint as inferred.

export const DIRECTIVES = ['SAMPLE', 'SCHEMA', 'CONFIRMWITH', 'CONFIRMSTRING', 'DISABLED', 'IMPORT', 'IMPORTONLY', 'TRIMALLOFF', 'SANITIZEALLOFF', 'PARENT'];
export const KEYWORDS = new Set(['IF', 'THEN', 'ELSE', 'TRUE', 'FALSE', 'NULL', 'AND', 'OR']);

export class SyntaxError2 extends Error {
  constructor(message, col = null) { super(message); this.col = col; }
}

const TOKEN = /(\s+)|(#.*)|("(?:\\.|[^"\\])*")|('(?:\\.|[^'\\])*')|(`[^`]*`)|(\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_]*\$?)|(==|!=|<=|>=|[-+*/%()[\],.<>])/y;

function unescape(s) {
  return s.replace(/\\(.)/g, (_, c) => ({ n: '\n', t: '\t', r: '\r' }[c] ?? c));
}

export function tokenize(src) {
  const out = [];
  TOKEN.lastIndex = 0;
  let i = 0;
  while (i < src.length) {
    TOKEN.lastIndex = i;
    const m = TOKEN.exec(src);
    if (!m) throw new SyntaxError2(`can't read "${src.slice(i, i + 20)}"`, i);
    const at = i;
    i = TOKEN.lastIndex;
    if (m[1]) continue;
    if (m[2]) break;
    if (m[3]) out.push({ k: 'str', v: unescape(m[3].slice(1, -1)), at, quote: '"' });
    else if (m[4]) out.push({ k: 'str', v: unescape(m[4].slice(1, -1)), at, quote: "'" });
    else if (m[5]) out.push({ k: 'str', v: m[5].slice(1, -1), at, quote: '`' });
    else if (m[6]) out.push({ k: 'num', v: m[6].includes('.') ? parseFloat(m[6]) : parseInt(m[6], 10), at });
    else if (m[7]) out.push({ k: KEYWORDS.has(m[7]) ? 'kw' : 'id', v: m[7], at });
    else out.push({ k: 'op', v: m[8], at });
  }
  out.push({ k: 'eof', v: null, at: src.length });
  return out;
}

// Expression AST nodes: {t:'lit',v} {t:'var',name} {t:'call',name,args} {t:'if',c,a,b}
// {t:'bin',op,l,r} {t:'neg',e} {t:'index',e,i} {t:'member',e,name} {t:'list',items}
class ExprParser {
  constructor(tokens) { this.t = tokens; this.i = 0; this.ops = new Set(); }
  peek(k, v) { const x = this.t[this.i]; return (k === undefined || x.k === k) && (v === undefined || x.v === v); }
  take(k, v) {
    if (!this.peek(k, v)) {
      const x = this.t[this.i];
      throw new SyntaxError2(`expected ${v ?? k}, found ${x.k === 'eof' ? 'end of line' : JSON.stringify(x.v)}`, x.at);
    }
    return this.t[this.i++];
  }
  parse() { const e = this.expr(); this.take('eof'); return e; }
  expr() {
    if (this.peek('kw', 'IF')) {
      this.take();
      const c = this.expr();
      this.take('kw', 'THEN');
      const a = this.expr();
      this.take('kw', 'ELSE');
      const b = this.expr();
      return { t: 'if', c, a, b };
    }
    return this.or();
  }
  or() {
    let e = this.and();
    while (this.peek('kw', 'OR')) { this.take(); this.ops.add('OR'); e = { t: 'bin', op: 'OR', l: e, r: this.and() }; }
    return e;
  }
  and() {
    let e = this.cmp();
    while (this.peek('kw', 'AND')) { this.take(); this.ops.add('AND'); e = { t: 'bin', op: 'AND', l: e, r: this.cmp() }; }
    return e;
  }
  cmp() {
    let e = this.add();
    for (const op of ['==', '!=', '<=', '>=', '<', '>']) {
      if (this.peek('op', op)) { this.take(); this.ops.add(op); return { t: 'bin', op, l: e, r: this.add() }; }
    }
    return e;
  }
  add() {
    let e = this.mul();
    while (this.peek('op', '+') || this.peek('op', '-')) { const op = this.take().v; this.ops.add(op); e = { t: 'bin', op, l: e, r: this.mul() }; }
    return e;
  }
  mul() {
    let e = this.unary();
    while (this.peek('op', '*') || this.peek('op', '/') || this.peek('op', '%')) { const op = this.take().v; this.ops.add(op); e = { t: 'bin', op, l: e, r: this.unary() }; }
    return e;
  }
  unary() {
    if (this.peek('op', '-')) { this.take(); return { t: 'neg', e: this.unary() }; }
    return this.postfix();
  }
  postfix() {
    let e = this.primary();
    for (;;) {
      if (this.peek('op', '[')) { this.take(); const i = this.expr(); this.take('op', ']'); e = { t: 'index', e, i }; }
      else if (this.peek('op', '.')) { this.take(); e = { t: 'member', e, name: this.take('id').v }; }
      else return e;
    }
  }
  primary() {
    const x = this.t[this.i];
    if (x.k === 'str' || x.k === 'num') { this.i++; return { t: 'lit', v: x.v, at: x.at }; }
    if (x.k === 'kw' && (x.v === 'TRUE' || x.v === 'FALSE' || x.v === 'NULL')) { this.i++; return { t: 'lit', v: { TRUE: true, FALSE: false, NULL: null }[x.v], at: x.at }; }
    if (x.k === 'kw' && x.v === 'IF') return this.expr();
    if (x.k === 'op' && x.v === '(') { this.take(); const e = this.expr(); this.take('op', ')'); return e; }
    if (x.k === 'op' && x.v === '[') {
      this.take();
      const items = [];
      while (!this.peek('op', ']')) { items.push(this.expr()); if (!this.peek('op', ']')) this.take('op', ','); }
      this.take('op', ']');
      return { t: 'list', items };
    }
    if (x.k === 'id') {
      this.i++;
      if (this.peek('op', '(')) {
        this.take();
        const args = [];
        while (!this.peek('op', ')')) { args.push(this.expr()); if (!this.peek('op', ')')) this.take('op', ','); }
        this.take('op', ')');
        return { t: 'call', name: x.v, args, at: x.at };
      }
      return { t: 'var', name: x.v, at: x.at };
    }
    throw new SyntaxError2(x.k === 'eof' ? 'expression ends too early' : `unexpected ${JSON.stringify(x.v)}`, x.at);
  }
}

export function parseExpression(src) {
  const p = new ExprParser(tokenize(src));
  const ast = p.parse();
  return { ast, ops: p.ops };
}

const IDENT = '[A-Za-z_][A-Za-z0-9_]*\\$?';
const CAPTURE = new RegExp(`^(${IDENT})\\s*=\\s*(${IDENT})\\|(.*)$`);
const ASSIGN = new RegExp(`^(${IDENT}(?:\\.${IDENT})*)\\s*=(?!=)\\s*(.*)$`);

// Parse one parser script. Returns {directives, flags, statements, problems, sample}.
// statements: {line, kind:'capture'|'assign'|'import', target, source?, pattern?, expr?, ops?}
export function parseScript(text) {
  const directives = {};
  const flags = new Set();
  const statements = [];
  const problems = [];
  const directiveLines = {};
  const lines = String(text ?? '').replace(/\r\n?/g, '\n').split('\n');
  lines.forEach((raw, n) => {
    const line = n + 1;
    const s = raw.trim();
    if (!s || s.startsWith('#')) return;
    if (s.startsWith('!')) {
      const eq = s.indexOf('=');
      const key = (eq === -1 ? s.slice(1) : s.slice(1, eq)).trim();
      const value = eq === -1 ? null : raw.slice(raw.indexOf('=') + 1);
      if (!DIRECTIVES.includes(key)) {
        problems.push({ level: 'error', code: 'unknown-directive', line, message: `!${key} is not a documented statement` });
        return;
      }
      if (key === 'IMPORT') { statements.push({ line, kind: 'import', target: (value ?? '').trim() }); return; }
      if (['DISABLED', 'IMPORTONLY', 'TRIMALLOFF', 'SANITIZEALLOFF'].includes(key)) { flags.add(key); directiveLines[key] = line; return; }
      if (key in directives && key !== 'SAMPLE') problems.push({ level: 'warning', code: 'duplicate-directive', line, message: `!${key} is set twice; the last one is used here` });
      if (key === 'SAMPLE') { (directives.SAMPLES ||= []).push(value ?? ''); }
      directives[key] = key === 'SAMPLE' || key === 'CONFIRMSTRING' ? (value ?? '') : (value ?? '').trim();
      directiveLines[key] = line;
      return;
    }
    let m = CAPTURE.exec(s);
    if (m) {
      statements.push({ line, kind: 'capture', target: m[1], source: m[2], pattern: m[3] });
      return;
    }
    m = ASSIGN.exec(s);
    if (!m) {
      problems.push({ level: 'error', code: 'syntax', line, message: `not a statement: ${s.slice(0, 70)}` });
      return;
    }
    try {
      const { ast, ops } = parseExpression(m[2]);
      statements.push({ line, kind: 'assign', target: m[1], expr: ast, ops, src: m[2] });
    } catch (e) {
      problems.push({ level: 'error', code: 'syntax', line, message: e.message });
    }
  });
  return { directives, flags, statements, problems, directiveLines };
}

// Walk an expression AST.
export function walk(node, fn) {
  if (!node || typeof node !== 'object') return;
  fn(node);
  switch (node.t) {
    case 'call': node.args.forEach((a) => walk(a, fn)); break;
    case 'if': walk(node.c, fn); walk(node.a, fn); walk(node.b, fn); break;
    case 'bin': walk(node.l, fn); walk(node.r, fn); break;
    case 'neg': walk(node.e, fn); break;
    case 'index': walk(node.e, fn); walk(node.i, fn); break;
    case 'member': walk(node.e, fn); break;
    case 'list': node.items.forEach((a) => walk(a, fn)); break;
    default:
  }
}
