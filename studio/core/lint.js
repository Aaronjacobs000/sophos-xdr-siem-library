// Static and runtime checks for a set of parsers.
// Levels: error (fix before you deploy), warning (likely wrong), inferred (works in the
// emulator, but the docs never show it, so confirm it on the first Parse Message), info.

import { compileParser, runParsers, evaluate, schemaList, rootVars } from './engine.js';
import { walk } from './language.js';
import { checkRe2, compileGo, groupCount, groupNames } from './goregex.js';
import { validatePath } from './jsonpath.js';
import { hasYear, hasZone, layoutChunks } from './gotime.js';
import { FUNCTION_NAMES, ARITY, DEPRECATED } from './functions.js';
import { schemaInfo, fieldsByParser, typeKind, enumMembers, enumNumbers, messageType, docMisspellings, GENERIC } from './schemas.js';
import { toStr, truthy, toBool } from './values.js';

const NAME_RE = /^[A-Z0-9]+(?:_[A-Z0-9]+)+$/;
// Set by the engine's root parser before custom parsers run.
const ROOT_VARS = new Set(['originalData$', 'message', 'sensorType$', 'sensorId$', 'eventTimeUsec$', 'eventTimeFidelity$']);
const LEVEL_ORDER = { error: 0, warning: 1, inferred: 2, info: 3 };
// Sophos Fusion refuses to save a parser whose code holds *= anywhere, in a comment or a regex
// too ("code contains restricted syntax: *="), though Run Test accepts it. +=, -=, /= and %=
// save, and so do single-quoted strings (checked in a lab tenant).
const RESTRICTED = ['*='];

function literalStrings(e) {
  // Values an expression can produce when it's a literal or an IF chain of them.
  // dynamic: false (only literals), 'var' (literals and variables), or true (anything else).
  if (!e) return { lits: [], dynamic: true, names: [] };
  if (e.t === 'lit') return { lits: e.v === null ? [] : [e.v], dynamic: false, names: [] };
  if (e.t === 'if') {
    const a = literalStrings(e.a), b = literalStrings(e.b);
    const dynamic = a.dynamic === true || b.dynamic === true ? true : a.dynamic || b.dynamic;
    return { lits: [...a.lits, ...b.lits], dynamic, names: [...a.names, ...b.names] };
  }
  if (e.t === 'var') return { lits: [], dynamic: 'var', names: [e.name] };
  return { lits: [], dynamic: true, names: [] };
}

function literalPatternChars(pattern) {
  return pattern.replace(/\\[dDwWsSbB]/g, '').replace(/\[[^\]]*\]/g, '').replace(/\\(.)/g, '$1').replace(/[()|.*+?^${}]/g, '').length;
}

// parsers: [{name, text, parent?, role?}]. opts: {samples, now, library: [{id, parsers, samples}], selfId}
export function lintParsers(parsers, opts = {}) {
  const problems = [];
  const add = (level, code, message, parser = null, line = null) => problems.push({ level, code, message, parser, line });
  const compiled = parsers.map(compileParser);
  const byName = new Map();
  for (const p of compiled) {
    if (byName.has(p.name)) add('error', 'duplicate-name', `two parsers are called ${p.name}`, p.name);
    byName.set(p.name, p);
  }
  const childrenOf = new Map();
  for (const p of compiled) if (p.parent && byName.has(p.parent)) (childrenOf.get(p.parent) || childrenOf.set(p.parent, []).get(p.parent)).push(p);

  const stats = { fieldsSet: 0, fieldsKnown: 0, enumsChecked: 0, enumsBad: 0, regexes: 0, regexBad: 0 };
  const inferredSeen = new Set();
  const inferred = (code, message, parser, line) => {
    if (inferredSeen.has(`${parser}:${code}`)) return;
    inferredSeen.add(`${parser}:${code}`);
    add('inferred', code, message, parser, line);
  };

  for (const p of compiled) {
    const d = p.script.directives;
    const dl = p.script.directiveLines;
    for (const pr of p.script.problems) add(pr.level, pr.code, pr.message, p.name, pr.line);
    const lines = String(p.text ?? '').split(/\r\n?|\n/);
    for (const r of RESTRICTED) {
      const at = lines.findIndex((l) => l.includes(r));
      if (at !== -1) add('error', 'restricted-syntax', `Sophos Fusion won't save a parser with ${r} anywhere in it, even in a comment or a regex, though Run Test accepts it. In a regex, write the = as [=], as in \\w*[=].`, p.name, at + 1);
    }
    const isLib = p.flags.has('IMPORTONLY');
    const isOff = p.flags.has('DISABLED');
    const parentP = p.parent ? byName.get(p.parent) : null;
    const role = p.role || (childrenOf.has(p.name) ? 'parent' : p.parent ? 'child' : 'standalone');

    if (!NAME_RE.test(p.name)) add('info', 'name', `${p.name}: Sophos suggests names like VENDOR_PRODUCT_FORMAT_PARENT or VENDOR_PRODUCT_FORMAT_CHILD_SCHEMA`, p.name);
    if (!isLib && !isOff) {
      if (!d.CONFIRMWITH) add('error', 'confirm-missing', 'set !CONFIRMWITH=PATTERN or !CONFIRMWITH=EXPRESSION', p.name);
      else if (d.CONFIRMWITH !== 'PATTERN' && d.CONFIRMWITH !== 'EXPRESSION') add('error', 'confirm-kind', `!CONFIRMWITH must be PATTERN or EXPRESSION, not ${d.CONFIRMWITH}`, p.name, dl.CONFIRMWITH);
      if (d.CONFIRMSTRING === undefined || !d.CONFIRMSTRING.trim()) add('error', 'confirm-missing', 'set !CONFIRMSTRING', p.name);
    }
    if (p.confirm && p.confirm.kind === 'PATTERN' && p.confirm.pattern) {
      stats.regexes++;
      const issues = checkRe2(p.confirm.pattern);
      for (const i of issues) { if (i.level === 'error') stats.regexBad++; add(i.level, 're2', `confirm string: ${i.message}`, p.name, dl.CONFIRMSTRING); }
      if (literalPatternChars(p.confirm.pattern) < 5) add('warning', 'confirm-broad', 'the confirm string has very little fixed text, so it may catch other sources. Include the vendor or product name.', p.name, dl.CONFIRMSTRING);
      if (/^\^/.test(p.confirm.pattern)) add('inferred', 'confirm-anchor', 'the confirm pattern starts with ^. The docs don\'t say whether it runs on the whole line or on the body after the syslog header, so an anchor is risky.', p.name, dl.CONFIRMSTRING);
    }
    if (p.confirm && p.confirm.kind === 'EXPRESSION') {
      if (p.confirm.error) add('error', 'syntax', `confirm expression: ${p.confirm.error}`, p.name, dl.CONFIRMSTRING);
      else {
        const parentVars = parentP ? assignedNames(parentP) : new Set();
        walk(p.confirm.ast, (n) => {
          if (n.t !== 'var') return;
          if (ROOT_VARS.has(n.name)) return;
          if (!parentP) add('warning', 'confirm-var', `the confirm expression reads ${n.name}, but a top-level parser only has originalData$ and message at that point`, p.name, dl.CONFIRMSTRING);
          else if (!parentVars.has(n.name)) add('warning', 'confirm-var', `the confirm expression reads ${n.name}, which ${parentP.name} never sets`, p.name, dl.CONFIRMSTRING);
        });
      }
    }

    let schema = d.SCHEMA || null;
    if (schema) {
      for (const id of schemaList(schema)) if (!schemaInfo(id)) add('error', 'schema', `!SCHEMA=${id} is not one of the schemas custom parsers can use${id === 'scwx.thirdparty' ? '; the Third Party Alerts schema is scwx.thirdpartyalert' : ''}`, p.name, dl.SCHEMA);
      if (schemaList(schema).length > 1) add('info', 'multi-schema', `!SCHEMA lists ${schemaList(schema).length} schemas, so the engine stores one event in each`, p.name, dl.SCHEMA);
      schema = schemaList(schema).find((x) => schemaInfo(x) && x !== GENERIC) || schemaList(schema)[0];
    }
    if (!schema && parentP) schema = parentP.schema ? schemaList(parentP.schema)[0] : null;
    if (!schema && !parentP && !isLib) {
      if (role === 'parent') add('info', 'schema', 'no !SCHEMA, so this parent uses the generic schema', p.name);
      else add('error', 'schema', 'set !SCHEMA to the destination schema, for example !SCHEMA=scwx.auth', p.name);
    }
    if (role === 'parent' && schema && schema !== GENERIC) add('warning', 'parent-schema', `parents should normally use !SCHEMA=scwx.generic and leave normalization to children (this one uses ${schema})`, p.name, dl.SCHEMA);
    if (parentP && parentP.parent && byName.has(parentP.parent)) add('error', 'generations', `${p.name} is a child of ${parentP.name}, which is itself a child. Parsers allow one generation of parent and child.`, p.name);
    if (role === 'child' && p.parent && !byName.has(p.parent)) add('info', 'global-parent', `parent ${p.parent} is not in this set; if it is a global parser, set it with !PARENT in Sophos Fusion`, p.name);
    if (role === 'parent' && !childrenOf.has(p.name) && (!schema || schema === GENERIC)) add('warning', 'no-children', 'a parent on the generic schema with no children only produces generic events', p.name);
    if (!isLib && !d.SAMPLE) add('info', 'sample', 'add a !SAMPLE= line so the console has a sample to test', p.name);

    const fields = schema && schemaInfo(schema) ? fieldsByParser(schema) : new Map();
    const known = new Set([...ROOT_VARS, ...(parentP ? assignedNames(parentP) : [])]);
    const captures = new Set();
    for (const st of p.script.statements) {
      if (st.kind === 'import') {
        if (!byName.has(st.target)) add('warning', 'import', `!IMPORT=${st.target}: not in this set, so the emulator can't run it`, p.name, st.line);
        else for (const n of assignedNames(byName.get(st.target))) known.add(n);
        continue;
      }
      if (st.kind === 'capture') {
        stats.regexes++;
        const sources = new Set();
        if (st.sourceExpr) walk(st.sourceExpr, (n) => { if (n.t === 'var') sources.add(n.name); });
        else sources.add(st.source);
        for (const v of sources) if (!known.has(v)) add('error', 'undefined-var', `${v} is read before it is set; the engine fails the event`, p.name, st.line);
        if (/\s#/.test(st.pattern)) add('warning', 'capture-comment', 'a capture pattern runs to the end of the line, so the comment here is part of the regex', p.name, st.line);
        for (const i of checkRe2(st.pattern)) { if (i.level === 'error') stats.regexBad++; add(i.level, 're2', i.message, p.name, st.line); }
        known.add(st.target);
        captures.add(st.target);
        continue;
      }
      // Assignment: functions, variables, literal arguments.
      const memberBases = new Set();
      const label = (n) => (n.t === 'var' ? n.name : n.t === 'member' ? `${label(n.e)}.${n.name}` : null);
      walk(st.expr, (n) => {
        if (n.t !== 'member') return;
        let b = n;
        while (b.t === 'member') b = b.e;
        if (b.t === 'var') memberBases.add(b);
        const full = label(n);
        if (full && !known.has(full) && !(b.t === 'var' && ROOT_VARS.has(b.name))) {
          const fix = full === 'eventMetadata$.record$' ? ' Set the list directly first, for example eventMetadata$.record$ = [r1, r2]; the docs\' append pattern only works once the list exists.' : '';
          add('error', 'undefined-var', `${full} is read before it is set, so the engine fails the event.${fix}`, p.name, st.line);
        }
      });
      walk(st.expr, (n) => {
        if (n.t === 'call') {
          if (!FUNCTION_NAMES.has(n.name)) add('error', 'unknown-function', `${n.name}() is not a documented function`, p.name, st.line);
          else {
            const [min, max] = ARITY[n.name];
            if (n.args.length < min || n.args.length > max) add('error', 'arity', `${n.name}() takes ${min === max ? min : `${min} to ${max}`} arguments, not ${n.args.length}`, p.name, st.line);
            if (DEPRECATED[n.name]) add('warning', 'deprecated', DEPRECATED[n.name], p.name, st.line);
          }
          if (n.name === 'DATETIME') checkDatetime(n, p, st, add, inferred);
          if (n.name === 'REPLACE_REGEX' && n.args[1] && n.args[1].t === 'lit' && typeof n.args[1].v === 'string') {
            stats.regexes++;
            for (const i of checkRe2(n.args[1].v)) { if (i.level === 'error') stats.regexBad++; add(i.level, 're2', `REPLACE_REGEX: ${i.message}`, p.name, st.line); }
          }
          if (n.name === 'TENANT_LOOKUP') add('info', 'tenant-lookup', 'TENANT_LOOKUP() needs a tenant directory; the emulator always takes the default', p.name, st.line);
          // Checked in a lab tenant: the records come out sorted by key, but starting at a random
          // key, so the order changes from one event to the next.
          if (n.name === 'FLATTEN') add('info', 'flatten-order', 'FLATTEN() records come out in a different order on each event in the engine: sorted by key, but starting at any key. The emulator lists them sorted, so don\'t rely on their order.', p.name, st.line);
        }
        if (n.t === 'var') {
          if (/^null$/i.test(n.name) && n.name !== 'NULL') add('warning', 'keyword-case', `${n.name} is read as a variable name; write NULL`, p.name, st.line);
          else if (!known.has(n.name) && !n.name.endsWith('$')) add('error', 'undefined-var', `${n.name} is read before it is set${parentP ? ` (here or in ${parentP.name})` : ''}; the engine fails the event`, p.name, st.line);
          else if (!known.has(n.name) && n.name.endsWith('$') && !memberBases.has(n)) add('error', 'undefined-var', `${n.name} is read before it is set${parentP ? ` (here or in ${parentP.name})` : ''}; the engine fails the event`, p.name, st.line);
        }
        if (n.t === 'bin' && ['==', '!=', '+'].includes(n.op)) {
          for (const side of [n.l, n.r]) {
            if (side.t === 'var' && captures.has(side.name)) add('error', 'regex-compare', `${side.name} is a capture; comparing or joining it fails in the engine ("cannot convert regex to string"). Use ${side.name}[1] != "" to test for a match.`, p.name, st.line);
          }
        }
        if (n.t === 'index' && n.i.t === 'lit') {
          if (typeof n.i.v === 'string' && n.i.v.startsWith('$')) {
            const bad = validatePath(n.i.v);
            if (bad) add('error', 'jsonpath', bad, p.name, st.line);
          }
          if (n.e.t === 'var') {
            const cap = p.script.statements.find((s) => s.kind === 'capture' && s.target === n.e.name && s.line < st.line);
            if (cap) {
              if (typeof n.i.v === 'number') {
                const g = groupCount(cap.pattern);
                if (g !== null && n.i.v > g) add('error', 'group-range', `${n.e.name}[${n.i.v}]: the pattern on line ${cap.line} has ${g} capture group${g === 1 ? '' : 's'}`, p.name, st.line);
              } else if (typeof n.i.v === 'string' && !groupNames(cap.pattern).includes(n.i.v)) {
                add('error', 'group-name', `${n.e.name}["${n.i.v}"]: the pattern on line ${cap.line} has no group named ${n.i.v}`, p.name, st.line);
              }
            }
          }
        }
      });
      for (const op of st.ops || []) {
        if (['<', '>', '<=', '>=', '/', '%'].includes(op)) inferred(`op-${op}`, `the ${op} operator isn't in the docs; the emulator supports it but confirm it in Sophos Fusion`, p.name, st.line);
      }
      checkTarget(st, p, fields, schema, add, inferred, stats, childrenOf);
      known.add(st.target.split('.')[0]);
      known.add(st.target);
    }
    if (schema === 'scwx.nids' || schema === 'scwx.netflow') {
      if (p.script.statements.some((s) => s.target === 'sourceAddress$' || s.target === 'destinationAddress$')) add('info', 'detectors', 'source or destination address is set, so the IP Watchlist detector can use these events', p.name);
    }
    if (schema === 'scwx.dnsquery' && p.script.statements.some((s) => s.target === 'queryName$')) add('info', 'detectors', 'queryName$ is set, so the Domain Generation Algorithms and Domain Watchlist detectors can use these events', p.name);
  }

  let results = null;
  if (opts.samples && opts.samples.length) {
    results = runParsers(parsers, opts.samples, { now: opts.now });
    // A syntax error rejects the whole parser, so every line fails the same way: one entry, next to
    // the syntax error it points at, rather than one per line.
    const rejected = results.filter((r) => r.rejected);
    if (rejected.length) problems.push({ level: 'error', code: 'rejected', message: 'Run Test rejects the whole parser over this syntax error, so no sample line gets a record.', parser: rejected[0].errorAt.parser, line: rejected[0].errorAt.line, lines: rejected.map((r) => r.line) });
    const seen = new Map();
    for (const r of results) {
      if (r.error && !r.rejected) add('error', 'runtime', `line ${r.line}: ${r.error}`, null);
      for (const n of r.notes) {
        const key = `${n.code}:${n.field || ''}:${n.message}`;
        if (seen.has(key)) { seen.get(key).lines.push(r.line); continue; }
        const entry = { level: n.level, code: n.code, message: n.message, parser: n.parser || null, line: n.line || null, lines: [r.line] };
        seen.set(key, entry);
        problems.push(entry);
      }
    }
    const unmatched = results.filter((r) => r.extractor_path === null && !r.error).map((r) => r.line);
    if (unmatched.length) add('warning', 'unmatched', `${unmatched.length} sample line${unmatched.length === 1 ? '' : 's'} (${unmatched.join(', ')}) matched no parser`, null);
  }

  if (opts.library && opts.library.length && opts.samples) {
    for (const o of overlaps(parsers, opts.samples, opts.library, opts.selfId)) add('error', 'overlap', o, null);
  }

  problems.sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level]);
  return { problems, results, stats, counts: count(problems) };
}

function count(problems) {
  const c = { error: 0, warning: 0, inferred: 0, info: 0 };
  for (const p of problems) c[p.level]++;
  return c;
}

function assignedNames(p) {
  const out = new Set();
  for (const s of p.script.statements) if (s.target) { out.add(s.target); out.add(s.target.split('.')[0]); }
  return out;
}

function checkDatetime(n, p, st, add, inferred) {
  const layout = n.args[1];
  if (!layout) return;
  if (layout.t !== 'lit' || typeof layout.v !== 'string') return;
  const chunks = layoutChunks(layout.v);
  if (!chunks.some((c) => c.std)) add('error', 'datetime-layout', `DATETIME layout "${layout.v}" has no Go reference fields. Write the reference time Mon Jan 2 15:04:05 MST 2006 in your format, for example "Jan 02 2006 15:04:05".`, p.name, st.line);
  const two = n.args[2];
  const twoOn = two && two.t === 'lit' && truthy(two.v);
  if (!hasYear(layout.v) && !twoOn) add('warning', 'datetime-year', `DATETIME layout "${layout.v}" has no year, so Go reads year 0 and the engine stores a huge number. Pass TRUE as the third argument so the engine picks the year.`, p.name, st.line);
  if (!hasZone(layout.v)) add('info', 'datetime-utc', `DATETIME layout "${layout.v}" has no zone, so the engine reads the time as UTC`, p.name, st.line);
}

function checkTarget(st, p, fields, schema, add, inferred, stats, childrenOf) {
  const parts = st.target.split('.');
  const head = parts[0];
  if (!head.endsWith('$')) return;
  if (head === 'originalData$') { add('warning', 'reserved', 'originalData$ holds the raw line; assigning to it is unusual', p.name, st.line); return; }
  if (!schema || schema === GENERIC) return;
  stats.fieldsSet++;
  const field = fields.get(head);
  const misspelt = docMisspellings(schema).get(head);
  if (!field && misspelt) { add('error', 'doc-misspelling', `${head} is how the ${schemaInfo(schema).name} schema page spells it, but the engine only accepts ${misspelt}`, p.name, st.line); return; }
  if (!field) {
    const usedByChild = (childrenOf.get(p.name) || []).some((c) => c.confirm && c.confirm.ast && JSON.stringify(c.confirm.ast).includes(`"${head}"`));
    if (!usedByChild) add('warning', 'not-a-field', `${head} isn't in the documented ${schemaInfo(schema).name} field table. The engine's schemas have more fields than the docs list, so check it with Run Test; a typo is dropped without an error.`, p.name, st.line);
    return;
  }
  stats.fieldsKnown++;
  if (parts.length > 1) {
    let type = field.type;
    for (const sub of parts.slice(1)) {
      const def = messageType(type);
      if (!def) { if (typeKind(type) !== 'opaque') add('error', 'sub-field', `${st.target}: ${type} has no sub-fields`, p.name, st.line); return; }
      const f = def.find((x) => x.parser === sub);
      if (!f) { add('error', 'sub-field', `${st.target}: ${sub} is not a field of ${type} (fields: ${def.map((x) => x.parser).join(', ')})`, p.name, st.line); return; }
      type = f.type;
    }
    return;
  }
  if (typeKind(field.type) === 'enum') {
    stats.enumsChecked++;
    const members = enumMembers(field.type);
    const numbers = enumNumbers(field.type);
    const { lits, dynamic, names } = literalStrings(st.expr);
    const others = names.filter((x) => x !== head);
    // The engine takes a name in any case, a number or a digit string; anything else fails the event.
    const ok = (v) => (typeof v === 'string' && (members.some((m) => m.toLowerCase() === v.trim().toLowerCase()) || numbers[v.trim()])) || (typeof v === 'number' && numbers[String(v)]);
    const bad = lits.filter((v) => !ok(v));
    if (bad.length) { stats.enumsBad++; add('error', 'enum', `${head}: ${bad.map((b) => JSON.stringify(b)).join(', ')} ${bad.length === 1 ? 'is not a' : 'are not'} ${field.type} name${bad.length === 1 ? '' : 's'}, so the engine fails the event. Use one of ${members.join(', ')}.`, p.name, st.line); }
    if (dynamic === true) add('warning', 'enum-raw', `${head} takes a value straight from the log. Any value that isn't a ${field.type} name or number fails the event; map the source values with IF ... THEN "NAME" ELSE ...`, p.name, st.line);
    if (dynamic === 'var' && others.length) add('info', 'enum-var', `${head} is set from ${others.join(', ')}; make sure ${others.length === 1 ? 'it holds' : 'they hold'} a ${field.type} name`, p.name, st.line);
  }
  if (typeKind(field.type) === 'message' && st.expr.t !== 'var' && st.expr.t !== 'call' && st.expr.t !== 'bin' && st.expr.t !== 'list' && st.expr.t !== 'if') {
    add('error', 'type', `${head} is a ${field.type}; set its sub-fields, for example ${head}.${(messageType(field.type)[0] || {}).parser || 'field$'} = ...`, p.name, st.line);
  }
}

// Confirm-string collisions between these parsers and the library, both ways.
export function overlaps(parsers, samples, library, selfId) {
  const out = [];
  const mine = parsers.map(compileParser).filter((p) => !p.parent && !p.flags.has('IMPORTONLY') && !p.flags.has('DISABLED'));
  for (const entry of library) {
    if (entry.id === selfId) continue;
    const label = entry.product && entry.vendor && !entry.product.toLowerCase().startsWith(entry.vendor.toLowerCase()) ? `${entry.vendor} ${entry.product}` : entry.product || entry.vendor || entry.id;
    const theirs = entry.parsers.map(compileParser).filter((p) => !p.parent && !p.flags.has('IMPORTONLY') && !p.flags.has('DISABLED'));
    for (const p of mine) {
      const hits = (entry.samples || []).filter((s) => topConfirms(p, s));
      if (hits.length) out.push(`${p.name} also matches ${hits.length} sample line${hits.length === 1 ? '' : 's'} of the library entry ${entry.id} (${label}). Make the confirm string more specific.`);
    }
    for (const p of theirs) {
      const hits = samples.filter((s) => topConfirms(p, s));
      if (hits.length) out.push(`the library parser ${p.name} (${entry.id}) also matches ${hits.length} of your sample line${hits.length === 1 ? '' : 's'}`);
    }
  }
  return out;
}

export function topConfirms(p, sample) {
  if (!p.confirm || p.confirm.error) return false;
  try {
    if (p.confirm.kind === 'PATTERN') return compileGo(p.confirm.pattern).test(sample);
    const vars = new Map(rootVars(sample));
    const ctx = { vars, now: undefined, get: (n) => (vars.has(n) ? vars.get(n) : null), note() {}, sink: [] };
    return toBool(evaluate(ctx, p.confirm.ast));
  } catch {
    return false;
  }
}

export { toStr };
