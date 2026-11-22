// Search-tests a detection rule entry against real records, for tools/ql-check.mjs: each rule's
// query runs in Data Lake Search, and so does one search for every record of the entry's sensor
// types. The rules then run offline on those same records, as the library's checks run them on
// the emulator's records, and the two have to agree. Records whose raw line is a line of the
// parser entry's samples.log are matched to tests.json as well. No network here.

import { parseQuery, matches, qlName } from '../../studio/core/ql.js';
import { qlString } from './fusion-search.mjs';
import { qlTime } from './ql-compare.mjs';

// {universe, rules: [{name, text}]}: the queries ql-check sends. where narrows every search, such as
// to one test batch, and wraps the rule's own condition so its ANDs and ORs keep their meaning.
export function ruleQueries(meta, rules, { earliest = '-7d', latest = null, where = null } = {}) {
  const time = qlTime({ earliest, latest });
  const extra = where ? ` and (${where})` : '';
  const types = (meta.sensor_types || []).map(qlString).join(', ');
  const universe = `from ${qlName(meta.schema)} where sensor_type in (${types})${extra}${time}`;
  return {
    universe,
    rules: rules.map((r) => {
      const p = parseQuery(r.query);
      return { name: r.name, text: `from ${p.schemas[0]} where (${p.whereText})${extra}${time}` };
    }),
  };
}

// A record's identity across searches.
export const rowKey = (row) => (row && row.resource_id ? `id:${row.resource_id}` : JSON.stringify([row && row.original_data, row && row.event_time_usec]));

// Compares, for each rule, the records its search returned with the records of the universe search
// the rule matches offline. samples: the parser entry's sample lines; tests: tests.json.
// Returns {rules: [{name, search, offline, onlySearch, onlyOffline, lines, want}], sampleRows, records}.
export function compareRuleSearches(rules, universeRows, ruleRows, { samples = [], tests = null } = {}) {
  const lineOf = new Map(samples.map((l, i) => [l, i + 1]));
  const sampleRows = universeRows.filter((r) => lineOf.has(r.original_data)).length;
  const out = [];
  for (const r of rules) {
    const parsed = parseQuery(r.query);
    const offline = new Set(universeRows.filter((row) => matches(parsed.where, row)).map(rowKey));
    const found = new Set((ruleRows.get(r.name) || []).map(rowKey));
    const lines = [...new Set((ruleRows.get(r.name) || []).map((row) => lineOf.get(row.original_data)).filter(Boolean))].sort((a, b) => a - b);
    const want = tests && tests.triggers && Array.isArray(tests.triggers[r.name]) ? [...tests.triggers[r.name]].sort((a, b) => a - b) : null;
    out.push({
      name: r.name,
      search: found.size,
      offline: offline.size,
      onlySearch: [...found].filter((k) => !offline.has(k)).length,
      onlyOffline: [...offline].filter((k) => !found.has(k)).length,
      lines,
      want,
    });
  }
  return { rules: out, sampleRows, records: universeRows.length };
}

export function formatRuleReport(report) {
  const lines = [`${report.records} record${report.records === 1 ? '' : 's'} of the entry's sensor types, ${report.sampleRows} of them lines of the parser's samples.log.`];
  let agree = true;
  for (const r of report.rules) {
    const same = r.onlySearch === 0 && r.onlyOffline === 0;
    if (!same) agree = false;
    lines.push(`- ${r.name}: Data Lake Search returned ${r.search}, the offline check predicts ${r.offline}${same ? ', the same records' : `; ${r.onlySearch} only in the search, ${r.onlyOffline} only offline`}.`);
    if (report.sampleRows && r.want) {
      const ok = r.lines.length === r.want.length && r.lines.every((x, i) => x === r.want[i]);
      if (!ok) agree = false;
      lines.push(`  Sample lines it returned: ${r.lines.join(', ') || 'none'}${ok ? ', as tests.json lists' : `; tests.json lists ${r.want.join(', ')}`}.`);
    }
  }
  lines.push(agree ? 'Every rule\'s search agrees with the offline check.' : 'The search and the offline check differ; see above.');
  return { text: lines.join('\n'), agree };
}
