#!/usr/bin/env node
// Checks a library entry against real records in a Sophos NG-SIEM tenant. A maintenance tool: it
// needs an API credential and a tenant that ingests the entry's source with its parsers.
//
//   node tools/ql-check.mjs parsers/<vendor>/<product> [--env-file <path>] [--tenant <id>]
//     [--earliest -7d] [--latest <time>] [--max 1000] [--where '<QL condition>'] [--reuse]
//     [--show-values] [--no-emulator]
//
// It runs one QL search through the Sophos Fusion Search GraphQL API for the records the entry's
// parsers made (by parser path, normalizer_revision), compares their fields with expected.json, and
// runs the entry's parsers through the emulator on each record's raw line (original_data) to compare
// the values. It only searches: it sends createSearch or getOrCreateSearch, search and searchResults,
// nothing else.
//
// Credentials: SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET (and SOPHOS_TENANT_ID for a partner or
// organization credential) from the environment, or from the env file --env-file names. Keep that
// file outside the repo. The report prints field names and counts; --show-values adds the first
// differing value of each field, which is tenant data, so don't paste that output anywhere public.

import { pathToFileURL } from 'node:url';
import { loadEntryFromDir } from './lib/fs-library.mjs';
import { loadCredentials, SearchClient, searchRows, MAX_PAGE, ROW_CAP } from './lib/fusion-search.mjs';
import { buildQuery, parserNames, groupRows, expectedRecords, compareFields, compareValues, formatFieldReport, formatValueReport, qlSchema } from './lib/ql-compare.mjs';

const USAGE = 'usage: ql-check.mjs parsers/<vendor>/<product> [--env-file <path>] [--tenant <id>] [--earliest -7d] [--latest <time>] [--max 1000] [--where \'<QL condition>\'] [--reuse] [--show-values] [--no-emulator]';

export function parseArgs(argv) {
  const o = { dir: null, envFile: null, tenant: null, earliest: '-7d', latest: null, max: MAX_PAGE, where: null, reuse: false, showValues: false, emulator: true };
  const need = (i) => { if (i >= argv.length) throw new Error(`${argv[i - 1]} needs a value`); return argv[i]; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--env-file') o.envFile = need(++i);
    else if (a === '--tenant') o.tenant = need(++i);
    else if (a === '--earliest') o.earliest = need(++i);
    else if (a === '--latest') o.latest = need(++i);
    else if (a === '--max') o.max = Number(need(++i));
    else if (a === '--where') o.where = need(++i);
    else if (a === '--reuse') o.reuse = true;
    else if (a === '--show-values') o.showValues = true;
    else if (a === '--no-emulator') o.emulator = false;
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}`);
    else if (!o.dir) o.dir = a;
    else throw new Error(`one entry at a time: ${a}`);
  }
  if (!o.dir) throw new Error('name an entry folder');
  if (!Number.isInteger(o.max) || o.max < 1 || o.max > ROW_CAP) throw new Error(`--max must be a whole number from 1 to ${ROW_CAP}`);
  return o;
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`${e.message}\n${USAGE}`);
    process.exit(2);
  }
  const entry = await loadEntryFromDir(opts.dir);
  if (!entry.meta.parsers || !entry.meta.parsers.length) {
    console.error(`${opts.dir} has no parsers in meta.json`);
    process.exit(2);
  }
  const log = (m) => console.error(`  ${m}`);
  const creds = await loadCredentials({ envFile: opts.envFile });
  if (opts.tenant) creds.tenantId = opts.tenant;
  const client = new SearchClient(creds, { log });
  const query = buildQuery(entry, opts);
  console.log(`${entry.id}: ${query}`);

  const res = await searchRows(client, query, { reuse: opts.reuse, max: opts.max, log });
  if (res.partial) console.log(`PARTIAL: some search partitions failed, so this is not every record${res.partitionErrors.length ? `: ${res.partitionErrors.join('; ')}` : ''}`);
  if (res.capped) console.log(`The search hit its ${ROW_CAP}-row cap, so it read the newest ones only.`);
  console.log(`${res.rows.length} record${res.rows.length === 1 ? '' : 's'} read${res.total !== null && res.total > res.rows.length ? ` of ${res.total}` : ''}`);

  const names = parserNames(entry);
  const { groups, other } = groupRows(res.rows, names, { anyParser: Boolean(opts.where) });
  if (other) console.log(`${other} record${other === 1 ? '' : 's'} from a parser whose name only contains an entry parser's name, left out`);
  if (!groups.length) {
    console.log('No records from these parsers in that time range. Check the tenant ingests the source with these parser names, or widen --earliest (a search covers at most 31 days).');
    return;
  }
  let differ = 0, noRecord = 0, compared = 0;
  for (const g of groups) {
    console.log('');
    const fields = compareFields(expectedRecords(entry.expected, g.schema, g.entryParser ? g.parser : null), g.rows, g.schema);
    console.log(formatFieldReport(fields, g.parser, { entryParser: g.entryParser }));
    if (opts.emulator) {
      const values = compareValues(entry, g.rows, g.schema);
      console.log(formatValueReport(values, { showValues: opts.showValues, entryParser: g.entryParser }));
      for (const [, f] of values.fields) differ += f.differ + f.emulatorOnly + f.realOnly;
      if (g.entryParser) differ += values.pathDiffer;
      noRecord += values.noRecord;
      compared += values.records - values.noRecord;
    }
  }
  const schemas = new Set(groups.map((g) => qlSchema(g.schema)));
  console.log(`\n${groups.length} parser and schema pair${groups.length === 1 ? '' : 's'} checked across ${[...schemas].join(', ')}.`);
  if (opts.emulator) {
    if (noRecord) console.log(`The emulator put ${noRecord} raw line${noRecord === 1 ? '' : 's'} in another schema than the real record, so ${noRecord === 1 ? 'it was' : 'they were'} not compared.`);
    if (differ) console.log(`The emulator and the real records differ in ${differ} field value${differ === 1 ? '' : 's'} or parser path${differ === 1 ? '' : 's'}; see above.`);
    else if (!compared && !noRecord) console.log('No real record had a raw line the emulator could compare.');
    else if (!noRecord) console.log('The emulator matched every real record.');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(`ql-check: ${e.message}`);
    process.exit(1);
  });
}
