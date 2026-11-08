// Which library entries a tenant ingests, for ql-check --discover. Two signals, as the 08/11/2026
// lab runs used them:
// - Parser paths. One search across every schema the library writes to counts the tenant's records
//   by normalizer_revision. A path that names a library parser means the tenant runs that entry.
// - Raw lines. For each other parser path, a sample of records is read and every entry's parsers
//   run on their original_data in the emulator. An entry that claims lines there is a source the
//   tenant receives, parsed by a built-in or the tenant's own parser.
// The report holds parser names, paths and counts, never a raw line or a field value.

import { runParsers } from '../../studio/core/engine.js';
import { entrySchemas, qlSchema, qlTime } from './ql-compare.mjs';
import { searchRows, qlString, SearchFailedError, MAX_PAGE } from './fusion-search.mjs';

export const DEFAULT_SAMPLE = 100;

// Every schema the library's parsers write to, as QL names.
export function librarySchemas(lib) {
  const out = new Set();
  for (const e of lib) for (const s of entrySchemas(e)) out.add(qlSchema(s));
  return [...out].sort();
}

// Each library parser name and the entry it belongs to.
export function parserOwners(lib) {
  const out = new Map();
  for (const e of lib) for (const p of e.meta.parsers || []) if (p.name && !out.has(p.name)) out.set(p.name, e.id);
  return out;
}

export function aggregateQuery(schemas, window = {}) {
  return `from ${schemas.join(', ')}${qlTime(window)} | aggregate count by normalizer_revision`;
}

export function sampleQuery(schema, path, n, window = {}) {
  return `from ${schema} where normalizer_revision = ${qlString(path)}${qlTime(window)} | head ${n}`;
}

// Aggregate rows as {schema, path, count}, by schema and then the most records first.
export function pathGroups(rows) {
  return rows
    .map((r) => ({ schema: String(r.schema_type || ''), path: String(r.normalizer_revision || ''), count: Number(r.row_count) || 0 }))
    .sort((a, b) => a.schema.localeCompare(b.schema) || b.count - a.count || a.path.localeCompare(b.path));
}

// library: paths that name a library parser, one item per entry. other: paths of other parsers.
// unparsed: records with no parser path, which come from Sophos and native integrations.
export function classify(groups, owners) {
  const library = [], other = [], unparsed = [];
  for (const g of groups) {
    if (!g.path) { unparsed.push(g); continue; }
    const names = g.path.split(/\s*->\s*/).map((s) => s.trim()).filter((n) => owners.has(n));
    if (!names.length) { other.push(g); continue; }
    for (const id of new Set(names.map((n) => owners.get(n)))) library.push({ ...g, id, parsers: names.filter((n) => owners.get(n) === id) });
  }
  return { library, other, unparsed };
}

// The entries whose parsers claim any of the lines in the emulator, with the parser paths they used.
export function claimLines(lib, lines, now = new Date().toISOString()) {
  const out = [];
  for (const e of lib) {
    const paths = new Map();
    for (const r of runParsers(e.parsers, lines, { now })) if (r.extractor_path) paths.set(r.extractor_path, (paths.get(r.extractor_path) || 0) + 1);
    const claimed = [...paths.values()].reduce((a, b) => a + b, 0);
    if (claimed) out.push({ id: e.id, claimed, of: lines.length, paths: [...paths].sort((a, b) => b[1] - a[1]) });
  }
  return out;
}

// A GraphQL or search failure on one query is reported and the rest go on; a sign-in or network
// failure stops the run.
const searchProblem = (e) => e instanceof SearchFailedError || Array.isArray(e.graphql);

export async function discover(client, lib, { earliest = '-7d', latest = null, reuse = false, sample = DEFAULT_SAMPLE, emulator = true, log = () => {}, pollMs, maxWaitMs } = {}) {
  const window = { earliest, latest };
  const schemas = librarySchemas(lib);
  const run = (text, max) => searchRows(client, text, { reuse, max, log, pollMs, maxWaitMs });
  const failed = [];
  const partial = [];
  let rows = [];
  try {
    const res = await run(aggregateQuery(schemas, window));
    rows = res.rows;
    if (res.partial) partial.push(...(res.partitionErrors.length ? res.partitionErrors : ['no error given']));
  } catch (e) {
    if (!searchProblem(e)) throw e;
    log(`The search across every schema failed (${e.message}), so each schema is searched on its own.`);
    for (const s of schemas) {
      try {
        const res = await run(aggregateQuery([s], window));
        rows.push(...res.rows);
        if (res.partial) partial.push(`${s}: ${res.partitionErrors.join('; ') || 'no error given'}`);
      } catch (err) {
        if (!searchProblem(err)) throw err;
        failed.push({ schema: s, error: err.message });
      }
    }
  }
  const groups = pathGroups(rows);
  const { library, other, unparsed } = classify(groups, parserOwners(lib));
  const claimed = [];
  const n = Math.min(Math.max(0, sample), MAX_PAGE);
  if (emulator && n > 0) {
    for (const g of other) {
      try {
        const res = await run(sampleQuery(g.schema, g.path, n, window), n);
        const lines = res.rows.map((r) => r.original_data).filter((v) => typeof v === 'string' && v);
        g.sampled = lines.length;
        if (lines.length) for (const c of claimLines(lib, lines)) claimed.push({ ...c, group: g });
      } catch (e) {
        if (!searchProblem(e)) throw e;
        g.error = e.message;
      }
    }
  }
  return { schemas, window, groups, library, other, unparsed, claimed, failed, partial, sample: n, emulator };
}

const plural = (k, one, many = `${one}s`) => `${k.toLocaleString('en-US')} ${k === 1 ? one : many}`;

export function formatDiscovery(r) {
  const time = qlTime(r.window).trim();
  const args = time.replace(/(^| )(earliest|latest)=/g, '$1--$2 ');
  const out = [`Searched ${plural(r.schemas.length, 'schema')} (${r.schemas.join(', ')}) ${time}: ${plural(r.groups.length, 'parser path')}.`];
  if (r.partial.length) out.push(`PARTIAL: some search partitions failed, so parser paths may be missing: ${r.partial.join('; ')}`);
  for (const f of r.failed) out.push(`The search failed for ${f.schema}: ${f.error}`);

  const ids = [...new Set(r.library.map((g) => g.id))];
  out.push('', `Ingested with library parsers (${plural(ids.length, 'entry', 'entries')}):`);
  for (const id of ids) {
    for (const g of r.library.filter((x) => x.id === id)) out.push(`  parsers/${id}: ${g.path} in ${g.schema}, ${plural(g.count, 'record')}`);
    out.push(`    Check it: node tools/ql-check.mjs parsers/${id} ${args}`);
  }
  if (!ids.length) out.push('  none');

  out.push('');
  if (!r.emulator || !r.sample) {
    out.push('Raw lines were not sampled (--no-emulator or --sample 0).');
  } else {
    out.push(`Raw lines a library entry claims, from other parsers (up to ${r.sample} lines a parser path):`);
    for (const c of r.claimed) {
      const g = c.group;
      out.push(`  parsers/${c.id} claims ${c.claimed} of ${c.of} sampled lines from ${g.path} in ${g.schema} (${plural(g.count, 'record')}), as ${c.paths.map(([p, k]) => `${p} (${k})`).join(', ')}`);
      out.push(`    Check it: node tools/ql-check.mjs parsers/${c.id} --where "normalizer_revision = ${qlString(g.path)}" ${args}`);
    }
    if (!r.claimed.length) out.push('  none');
    const claimedGroups = new Set(r.claimed.map((c) => c.group));
    const quiet = r.other.filter((g) => !g.error && !claimedGroups.has(g));
    const noRaw = quiet.filter((g) => !g.sampled).length;
    if (quiet.length) out.push(`${plural(quiet.length, 'other parser path')} ${quiet.length === 1 ? 'was' : 'were'} sampled and no entry claimed a line${noRaw ? `; ${quiet.length === 1 ? 'it' : `${noRaw} of them`} had no raw lines` : ''}.`);
    for (const g of r.other.filter((x) => x.error)) out.push(`Sampling failed for ${g.path} in ${g.schema}: ${g.error}`);
  }
  if (r.unparsed.length) {
    const total = r.unparsed.reduce((a, g) => a + g.count, 0);
    out.push(`${plural(total, 'record')} in ${plural(new Set(r.unparsed.map((g) => g.schema)).size, 'schema')} came with no parser path (Sophos and native integrations) and were not sampled.`);
  }
  return out.join('\n');
}
