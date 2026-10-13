// JSONPath for JSON() values. Covers the Goessner syntax the docs link to and that the
// engine's library (ohler55/ojg) reads: $.a.b, $['a.b'], $.a[0], $.a[-1], $.a[*], $.a.*,
// $..a, $.a[0,2], $.a[1:3], simple filters $.a[?(@.b == 'x')], and |preserve_structure.

import { RuntimeError, hasOwn } from './values.js';

function parsePath(path) {
  if (!path.startsWith('$')) throw new RuntimeError(`JSONPath must start with $: ${path}`);
  const steps = [];
  let i = 1;
  const nameRe = /^[^.[\]()\s|]+/;
  while (i < path.length) {
    const r = path.slice(i);
    if (r.startsWith('..')) {
      i += 2;
      if (path[i] === '[') { steps.push({ kind: 'descent' }); continue; }
      if (path[i] === '*') { steps.push({ kind: 'descent' }, { kind: 'wild' }); i++; continue; }
      const m = nameRe.exec(path.slice(i));
      if (!m) throw new RuntimeError(`bad JSONPath at "${r}"`);
      steps.push({ kind: 'descent' }, { kind: 'key', key: m[0] });
      i += m[0].length;
      continue;
    }
    if (r[0] === '.') {
      i++;
      if (path[i] === '*') { steps.push({ kind: 'wild' }); i++; continue; }
      const m = nameRe.exec(path.slice(i));
      if (!m) throw new RuntimeError(`bad JSONPath at "${r}"`);
      steps.push({ kind: 'key', key: m[0] });
      i += m[0].length;
      continue;
    }
    if (r[0] === '[') {
      const end = findClose(path, i);
      const body = path.slice(i + 1, end).trim();
      i = end + 1;
      if (body === '*') { steps.push({ kind: 'wild' }); continue; }
      if (body.startsWith('?')) { steps.push({ kind: 'filter', expr: body.replace(/^\?\s*\(?/, '').replace(/\)\s*$/, '') }); continue; }
      const parts = splitTop(body);
      if (parts.length === 1 && /^-?\d*:-?\d*(:-?\d+)?$/.test(body)) {
        const [a, b, c] = body.split(':');
        steps.push({ kind: 'slice', start: a === '' ? null : Number(a), end: b === '' ? null : Number(b), step: c ? Number(c) : 1 });
        continue;
      }
      const sel = parts.map((p) => {
        if (/^-?\d+$/.test(p)) return { idx: Number(p) };
        const q = /^(['"])((?:\\.|(?!\1).)*)\1$/.exec(p);
        if (q) return { key: q[2].replace(/\\(.)/g, '$1') };
        throw new RuntimeError(`bad JSONPath selector [${p}]`);
      });
      if (sel.length === 1) steps.push(sel[0].idx !== undefined ? { kind: 'idx', idx: sel[0].idx } : { kind: 'key', key: sel[0].key });
      else steps.push({ kind: 'union', sel });
      continue;
    }
    throw new RuntimeError(`bad JSONPath at "${r}"`);
  }
  return steps;
}

function findClose(s, i) {
  let q = null;
  for (let j = i + 1; j < s.length; j++) {
    const c = s[j];
    if (q) { if (c === '\\') j++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === ']') return j;
  }
  throw new RuntimeError(`unclosed [ in JSONPath ${s}`);
}

function splitTop(body) {
  const out = [];
  let cur = '', q = null;
  for (let j = 0; j < body.length; j++) {
    const c = body[j];
    if (q) { cur += c; if (c === '\\') { cur += body[++j]; } else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (c === ',') { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  out.push(cur.trim());
  return out;
}

const MISSING = Symbol('missing');

function children(node) {
  if (Array.isArray(node)) return node;
  if (node && typeof node === 'object') return Object.values(node);
  return [];
}

function descend(node, out) {
  out.push(node);
  for (const c of children(node)) if (c && typeof c === 'object') descend(c, out);
}

function filterValue(node, expr) {
  // Supports @.path, @.path op literal, joined with && or ||.
  const ors = expr.split('||');
  return ors.some((part) => part.split('&&').every((cond) => {
    const m = /^\s*@((?:\.[^\s=!<>~]+|\[[^\]]+\])*)\s*(?:(==|!=|<=|>=|<|>|=~)\s*(.+?))?\s*$/.exec(cond);
    if (!m) throw new RuntimeError(`unsupported JSONPath filter: ${cond}`);
    const got = m[1] ? query(node, '$' + m[1]) : node;
    if (!m[2]) return got !== null && got !== undefined;
    let lit = m[3].trim();
    let want;
    if (/^(['"]).*\1$/.test(lit)) want = lit.slice(1, -1);
    else if (lit === 'true' || lit === 'false') want = lit === 'true';
    else if (lit === 'null') want = null;
    else if (/^-?\d+(\.\d+)?$/.test(lit)) want = Number(lit);
    else if (m[2] === '=~') want = lit.replace(/^\/|\/[a-z]*$/g, '');
    else throw new RuntimeError(`unsupported JSONPath filter value: ${lit}`);
    switch (m[2]) {
      case '==': return got === want;
      case '!=': return got !== want;
      case '<': return got < want;
      case '>': return got > want;
      case '<=': return got <= want;
      case '>=': return got >= want;
      case '=~': return typeof got === 'string' && new RegExp(want).test(got);
      default: return false;
    }
  }));
}

// Returns the value, a list for multi-valued paths, or null when nothing matches.
export function query(root, rawPath) {
  const preserve = rawPath.endsWith('|preserve_structure');
  const path = preserve ? rawPath.slice(0, -'|preserve_structure'.length) : rawPath;
  const steps = parsePath(path.trim());
  let nodes = [root];
  let multi = false;
  for (const step of steps) {
    const next = [];
    for (const n of nodes) {
      if (n === MISSING) { if (preserve) next.push(MISSING); continue; }
      switch (step.kind) {
        case 'key':
          if (n && typeof n === 'object' && !Array.isArray(n) && hasOwn(n, step.key)) next.push(n[step.key]);
          else if (preserve) next.push(MISSING);
          break;
        case 'idx':
          if (Array.isArray(n)) {
            const k = step.idx < 0 ? n.length + step.idx : step.idx;
            if (k >= 0 && k < n.length) next.push(n[k]); else if (preserve) next.push(MISSING);
          } else if (preserve) next.push(MISSING);
          break;
        case 'wild':
          multi = true;
          next.push(...children(n));
          break;
        case 'descent':
          multi = true;
          descend(n, next);
          break;
        case 'union':
          multi = true;
          for (const s of step.sel) {
            if (s.idx !== undefined && Array.isArray(n)) {
              const k = s.idx < 0 ? n.length + s.idx : s.idx;
              if (k >= 0 && k < n.length) next.push(n[k]);
            } else if (s.key !== undefined && n && typeof n === 'object' && hasOwn(n, s.key)) next.push(n[s.key]);
          }
          break;
        case 'slice':
          multi = true;
          if (Array.isArray(n)) {
            const len = n.length;
            const norm = (x, d) => (x === null ? d : x < 0 ? Math.max(len + x, 0) : Math.min(x, len));
            const a = norm(step.start, 0), b = norm(step.end, len);
            for (let k = a; k < b; k += step.step) next.push(n[k]);
          }
          break;
        case 'filter':
          multi = true;
          for (const c of children(n)) if (filterValue(c, step.expr)) next.push(c);
          break;
        default:
      }
    }
    nodes = next;
  }
  if (preserve) {
    const vals = nodes.map((x) => (x === MISSING ? null : x));
    if (!multi) return vals.length ? vals[0] : null;
    return vals.length ? vals : null;
  }
  if (!nodes.length) return null;
  return multi ? nodes : nodes[0];
}

// True when the path can select more than one node, so the result is a list.
export function isMultiPath(rawPath) {
  try {
    const steps = parsePath(rawPath.replace(/\|preserve_structure$/, '').trim());
    return steps.some((s) => s.kind !== 'key' && s.kind !== 'idx');
  } catch {
    return false;
  }
}

export function validatePath(path) {
  try { parsePath(path.replace(/\|preserve_structure$/, '').trim()); return null; } catch (e) { return e.message; }
}
