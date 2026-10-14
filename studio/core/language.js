// Reads parser scripts: directives, capture statements, assignments, and expressions.
// Grammar from the Fusion "Custom parser syntax" page. Operators the page doesn't show
// (AND, OR, <, >, /) are accepted and flagged by the lint as inferred.

export const DIRECTIVES = ['SAMPLE', 'SCHEMA', 'CONFIRMWITH', 'CONFIRMSTRING', 'DISABLED', 'IMPORT', 'IMPORTONLY', 'TRIMALLOFF', 'SANITIZEALLOFF', 'PARENT'];
export const KEYWORDS = new Set(['IF', 'THEN', 'ELSE', 'TRUE', 'FALSE', 'NULL', 'AND', 'OR', 'NOT']);

export class SyntaxError2 extends Error {
  constructor(message, col = null) { super(message); this.col = col; }
}

// A minus sign right before a digit is part of the number, as in the engine's grammar: -5 is one
// token, so 3-1 and x -1 are two values side by side (checked in a lab tenant).
const TOKEN = /(\s+)|(#.*)|("(?:\\.|[^"\\])*")|('(?:\\.|[^'\\])*')|(`[^`]*`)|(-?\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_]*\$?)|(==|!=|<=|>=|[-+*/%()[\],.<>])/y;

// \n is a newline and \t a tab, but \r stays a backslash and an r, so SPLIT(x, "\r") splits on
// the backslash (checked in a lab tenant).
function unescape(s) {
  return s.replace(/\\(.)/g, (_, c) => (c === 'r' ? '\\r' : { n: '\n', t: '\t' }[c] ?? c));
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
    // The engine reads whole numbers only: 1.5 anywhere, in a list or not, makes it reject the
    // parser with a syntax error (checked in a lab tenant).
    else if (m[6] && m[6].includes('.')) throw new SyntaxError2(`${m[6]}: the engine reads whole numbers only, so it rejects the parser with a syntax error`, at);
    else if (m[6]) out.push({ k: 'num', v: parseInt(m[6], 10), at, text: m[6] });
    // TRUE, FALSE and NOT also work in lower case (checked in a lab tenant).
    else if (m[7] && /^(true|false|not)$/i.test(m[7])) out.push({ k: 'kw', v: m[7].toUpperCase(), at });
    else if (m[7]) out.push({ k: KEYWORDS.has(m[7]) ? 'kw' : 'id', v: m[7], at });
    else out.push({ k: 'op', v: m[8], at });
  }
  out.push({ k: 'eof', v: null, at: src.length });
  return out;
}

// Expression AST nodes: {t:'lit',v} {t:'var',name} {t:'call',name,args} {t:'if',c,a,b}
// {t:'bin',op,l,r} {t:'not',e} {t:'index',e,i} {t:'member',e,name} {t:'list',items}
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
    let e = this.not();
    for (const op of ['==', '!=', '<=', '>=', '<', '>']) {
      if (this.peek('op', op)) { this.take(); this.ops.add(op); return { t: 'bin', op, l: e, r: this.not() }; }
    }
    return e;
  }
  // NOT binds looser than + and * and tighter than comparisons, AND and OR: NOT 1 + 1 is
  // NOT (1 + 1), NOT 0 > 1 is (NOT 0) > 1 and NOT TRUE OR TRUE is (NOT TRUE) OR TRUE. It can
  // also start an operand, as in 5 + NOT TRUE (checked in a lab tenant).
  not() {
    if (this.peek('kw', 'NOT')) { this.take(); this.ops.add('NOT'); return { t: 'not', e: this.not() }; }
    return this.add();
  }
  add() {
    let e = this.mul();
    for (;;) {
      if (this.peek('op', '+') || this.peek('op', '-')) { const op = this.take().v; this.ops.add(op); e = { t: 'bin', op, l: e, r: this.mul() }; continue; }
      const x = this.t[this.i];
      if (x.k === 'num' && x.text.startsWith('-')) throw new SyntaxError2(`${x.text}: a minus sign right before a digit makes a negative number, so the engine reads two values side by side here and rejects the parser. Put a space after the minus, as in x - 1.`, x.at);
      return e;
    }
  }
  mul() {
    let e = this.unary();
    while (this.peek('op', '*') || this.peek('op', '/') || this.peek('op', '%')) { const op = this.take().v; this.ops.add(op); e = { t: 'bin', op, l: e, r: this.unary() }; }
    return e;
  }
  // The engine has no minus operator on its own: -5 is a number, but -x, -(3 / 2) and - 5 are
  // syntax errors (checked in a lab tenant).
  unary() {
    if (this.peek('op', '-')) {
      const x = this.t[this.i];
      throw new SyntaxError2('a minus sign only works as part of a number, such as -5, so the engine rejects the parser. Subtract from 0 instead, as in 0 - x.', x.at);
    }
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
    if (x.k === 'kw' && x.v === 'NOT') return this.not();
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
// The engine reads a line as a capture when the text between = and the first | outside [...] is
// either free of quotes and "(", or an opening quote with no closing quote before the |. So the
// source can be a variable, an index such as acct[2] or json["$.mail"], or an expression such
// as a + b, with or without a space before the pipe, but not a function call; a | inside [...]
// stays part of the expression; and x = "a|b" or r.value$ = 'a|b' becomes a capture whose
// source "a can't be read, which fails the parser (checked in a lab tenant).
const CAPTURE = new RegExp(`^(${IDENT}(?:\\.${IDENT})*)\\s*=\\s*((?:[^"'(|\\[]|\\[[^\\]]*\\])*?|["'][^"'|]*)\\s*\\|(.*)$`);
const PLAIN_SOURCE = new RegExp(`^${IDENT}$`);
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
  // The console saves test messages after a "*** Tests ***" line; the engine ignores them.
  const end = lines.findIndex((l) => /^\s*\*{3}\s*Tests\s*\*{3}/i.test(l));
  if (end !== -1) lines.length = end;
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
      const st = { line, kind: 'capture', target: m[1], source: m[2], pattern: m[3] };
      if (!PLAIN_SOURCE.test(m[2])) {
        try {
          st.sourceExpr = parseExpression(m[2]).ast;
          st.sourceText = m[2];
        } catch (e) {
          problems.push({ level: 'error', code: 'syntax', line, message: `the text before the first | is read as a capture source: ${e.message}` });
          return;
        }
      }
      statements.push(st);
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
    case 'not': walk(node.e, fn); break;
    case 'index': walk(node.e, fn); walk(node.i, fn); break;
    case 'member': walk(node.e, fn); break;
    case 'list': node.items.forEach((a) => walk(a, fn)); break;
    default:
  }
}
