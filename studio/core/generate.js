// Writes parser scripts from the studio's plan: a standalone parser, or a parent plus one
// child per event type. Every script starts with a header that says it is an emulator
// result and has not been run in Sophos NG-SIEM.

import { TOOL_NAME, TOOL_VERSION, REPO } from './version.js';
import { schemaInfo, fieldsByParser, hasEventMetadata, GENERIC } from './schemas.js';
import { hasYear } from './gotime.js';
import { LEEF_PIPES } from './formats.js';

export function upperSlug(s) {
  return String(s || '').toUpperCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

export function baseName(vendor, product, format) {
  const v = upperSlug(vendor);
  let p = upperSlug(product);
  if (v && p.startsWith(`${v}_`)) p = p.slice(v.length + 1);
  if (p === v) p = '';
  return [v || 'VENDOR', p || null, upperSlug(format || 'LOG')].filter(Boolean).join('_');
}

const FORMAT_NAME = { json: 'JSON', cef: 'CEF', leef: 'LEEF', kv: 'key=value', csv: 'delimited text', xml: 'XML', text: 'plain text', syslog: 'plain text' };

export function headerComment(plan, extra = []) {
  const vendor = plan.vendor && plan.product && plan.product.toLowerCase().startsWith(plan.vendor.toLowerCase()) ? '' : plan.vendor;
  const src = [vendor, plan.product, plan.version].filter(Boolean).join(' ');
  return [
    `# ${TOOL_NAME} ${TOOL_VERSION}: https://github.com/${REPO}`,
    '# Emulator result, not run in Sophos NG-SIEM. Test with Parse Message and Run Test before you turn it on.',
    src ? `# Source: ${src}, ${FORMAT_NAME[plan.format] || plan.format || 'unknown format'} over ${shipLabel(plan.shipMethod)}.` : null,
    ...extra.map((x) => `# ${x}`),
  ].filter(Boolean);
}

export function shipLabel(m) {
  return { syslog: 'syslog to the data collector', 'http-ingest': 'HTTP Ingest', s3: 'Amazon S3', azure: 'Azure Event Hubs', other: 'another transport' }[m] || 'an unknown transport';
}

const q = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function escapeRe(s) { return String(s).replace(/[\\^$.*+?()[\]{}|]/g, '\\$&'); }

// The syslog header (an optional <PRI>, then a version, a BSD or ISO time and the host) and the
// program tag the studio takes off a line before reading its columns, as a Go pattern.
const SYSLOG_CUT = '^(?:<\\d{1,3}>)?(?:(?:\\d\\s+)?(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}|\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?)\\s+\\S+\\s)?(?:[A-Za-z0-9_./-]+(?:\\[\\d+\\])?:\\s+)?';

// Lines that split the message, and how to read one field from the result.
export function extraction(plan) {
  const x = plan.extract || {};
  switch (plan.format) {
    case 'json':
      return {
        lines: x.jsonAtEnd
          ? [
            '# Cut the JSON object off the end of the line, then parse it. JSON() of a capture that',
            '# didn\'t match fails the event, so a line with no JSON object at its end gets no fields.',
            'jsonMatch = originalData$|(\\{.*})$',
            'json = IF jsonMatch[1] != "" THEN JSON(jsonMatch[1]) ELSE NULL',
          ]
          : ['json = JSON(originalData$)'],
        read: (m) => `json[${q(m.path || `$.${m.key}`)}]`,
      };
    case 'cef': {
      // A key named by a label CEF() doesn't resolve is read from the key that has that label,
      // checked on each line, since the label can sit on another key in another line.
      const labelled = new Map((plan.keys || []).filter((k) => k.labels && k.labels.length).map((k) => [k.key, k.labels]));
      const read = (m) => {
        if (m.index !== undefined && m.index !== null) return `values[${m.index}]`;
        let out = `values[${q(m.key)}]`;
        for (const b of [...(labelled.get(m.key) || [])].reverse()) out = `(IF STRING(values[${q(`${b}Label`)}]) == ${q(m.key)} THEN values[${q(b)}] ELSE ${out})`;
        return out;
      };
      return { lines: ['values = CEF(originalData$)'], read };
    }
    case 'leef': {
      const read = (m) => (m.index !== undefined && m.index !== null ? `values[${m.index}]` : `values[${q(m.key)}]`);
      if (!x.leefPipes) return { lines: ['values = LEEF(originalData$)'], read };
      return {
        lines: [
          '# Some lines put | between their pairs. LEEF() reads the first pair of such a line as its',
          '# delimiter field, so those lines are read with | as the delimiter. Their first pair stays values[5].',
          `leefPipes = originalData$|${LEEF_PIPES}`,
          'values = IF leefPipes[0] != "" THEN LEEF(originalData$, "|") ELSE LEEF(originalData$)',
        ],
        read,
      };
    }
    case 'kv': {
      const delim = x.delim ?? ' ';
      const sep = x.sep ?? '=';
      // The sample's lines start their pairs at one of these keys.
      const first = x.firstKey ? [x.firstKey] : x.firstKeys || [];
      const start = first.length ? `(${first.length > 1 ? `(?:${first.map(escapeRe).join('|')})` : escapeRe(first[0])}${escapeRe(sep)}.*)$` : '(.*)$';
      return {
        lines: [
          `# Everything from the first ${first.length === 1 ? first[0] : 'key'}${sep} on is ${delim === ' ' ? 'space' : JSON.stringify(delim)}-separated key${sep}value pairs.`,
          `body = originalData$|${start}`,
          `vals = SPLIT_NAME_VALUES(body[1], ${q(delim)}, ${q(sep)}, "\\"")`,
        ],
        read: (m) => `vals[${q(m.key)}]`,
      };
    }
    case 'csv': {
      const delim = x.delim ?? ',';
      return {
        lines: [
          '# Delimited fields, read by position. SPLIT() reads CSV quotes, so a quoted value keeps the delimiters inside it.',
          x.syslogCut ? '# The columns start after the syslog header and program tag, so both come off the line first.' : null,
          x.syslogCut ? `body = originalData$|${SYSLOG_CUT}(.*)$` : x.prefix ? `body = originalData$|${escapeRe(x.prefix)}(.*)$` : null,
          `parts = SPLIT(${x.syslogCut || x.prefix ? 'body[1]' : 'message'}, ${q(delim)})`,
        ].filter(Boolean),
        read: (m) => `parts[${m.index}]`,
      };
    }
    default:
      if (x.pattern) {
        return {
          lines: ['# No key/value structure, so one capture pattern with named groups reads the line.', '# A capture runs to the end of the line, so keep comments off it.', `m = originalData$|${x.pattern}`],
          read: (m) => `m[${q(m.key)}]`,
        };
      }
      return {
        lines: ['# No structure was found. Write capture patterns, for example:', '# m = originalData$|user=(?P<user>\\S+) from (?P<src>\\S+)'],
        read: () => 'NULL',
      };
  }
}

function varName(key, used) {
  let v = 'md_' + String(key).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 30);
  while (used.has(v)) v += '_';
  used.add(v);
  return v;
}

// INT() fails the event on anything but a whole number, "" and "N/A" included, so the value goes
// through a capture that only matches one, and anything else gives NULL (checked in a lab tenant).
// A capture can't read a function call, so STRING() goes in a variable first.
function intLines(field, src, scale = '') {
  const v = field.replace(/\$/g, '').replace(/[^A-Za-z0-9_]/g, '_');
  return [
    `${v}Text = STRING(${src})`,
    `${v}Num = ${v}Text|^\\s*(?P<n>[-+]?\\d{1,18})\\s*$`,
    `${field} = IF ${v}Num["n"] != "" THEN INT(${v}Num["n"], 10)${scale} ELSE NULL`,
  ];
}

// One mapping -> statements.
export function mappingLines(m, read, sampleValues = []) {
  const src = read(m);
  const t = m.transform || { kind: 'none' };
  const field = m.field;
  switch (t.kind) {
    case 'int': return intLines(field, src);
    // LOWERCASE() and UPPERCASE() fail the event on a number, TRUE or FALSE, so the value goes
    // through STRING() first, which gives "" for a missing value (checked in a lab tenant).
    case 'lower': return [`${field} = LOWERCASE(STRING(${src}))`];
    case 'upper': return [`${field} = UPPERCASE(STRING(${src}))`];
    case 'string': return [`${field} = STRING(${src})`];
    case 'replace': return [`${field} = REPLACE(${src}, ${q(t.from ?? '')}, ${q(t.to ?? '')})`];
    case 'bool': return [`${field} = LOWERCASE(STRING(${src})) == "true"`];
    case 'epoch-s': return [`# ${m.key} is epoch seconds; the field takes microseconds.`, ...intLines(field, src, ' * 1000000')];
    case 'epoch-ms': return [`# ${m.key} is epoch milliseconds; the field takes microseconds.`, ...intLines(field, src, ' * 1000')];
    case 'datetime': {
      const layout = t.layout || '2006-01-02T15:04:05Z07:00';
      const value = t.join ? `${src} + " " + ${read({ key: t.join, path: `$.${t.join}` })}` : src;
      const twoDigit = hasYear(layout) ? '' : ', TRUE';
      // A time before 1970, such as the zero date 0001-01-01T00:00:00Z some sources send for "not
      // set", wraps the unsigned field to a huge number, so it gives NULL and the event keeps the
      // ingest time. A DATETIME value compares with a number as its microseconds, and NULL > 0 is
      // false (checked in a lab tenant).
      const v = `${field.replace(/\$/g, '').replace(/[^A-Za-z0-9_]/g, '_')}Time`;
      return [
        `# A time before 1970, such as the zero date 0001-01-01T00:00:00Z, would wrap ${field}, so it gives NULL.`,
        `${v} = DATETIME(${value}, ${q(layout)}${twoDigit})`,
        `${field} = IF ${v} > 0 THEN ${v} ELSE NULL`,
      ];
    }
    case 'dns-type': return [
      '# query_type takes the DNS type number; the log sends the name.',
      `qtype = UPPERCASE(STRING(${src}))`,
      `${field} = NULL`,
      ...[['A', 1], ['NS', 2], ['CNAME', 5], ['SOA', 6], ['PTR', 12], ['MX', 15], ['TXT', 16], ['AAAA', 28], ['SRV', 33], ['HTTPS', 65], ['ANY', 255]].map(([n, v]) => `${field} = IF qtype == "${n}" THEN ${v} ELSE ${field}`),
    ];
    case 'dns-rcode': return [
      '# response_code takes the DNS RCODE number; the log sends the name.',
      `rcode = UPPERCASE(STRING(${src}))`,
      `${field} = NULL`,
      ...[['NOERROR', 0], ['FORMERR', 1], ['SERVFAIL', 2], ['NXDOMAIN', 3], ['NOTIMP', 4], ['REFUSED', 5]].map(([n, v]) => `${field} = IF rcode == "${n}" THEN ${v} ELSE ${field}`),
    ];
    case 'protocol': {
      const numeric = sampleValues.length && sampleValues.every((v) => /^\d+$/.test(String(v)));
      if (numeric) return intLines(field, src);
      return [
        '# The field takes the IANA protocol number; the log sends a name.',
        `proto = UPPERCASE(STRING(${src}))`,
        `${field} = IF proto == "TCP" THEN 6 ELSE 0`,
        `${field} = IF proto == "UDP" THEN 17 ELSE ${field}`,
        `${field} = IF proto == "ICMP" THEN 1 ELSE ${field}`,
      ];
    }
    case 'enum': {
      const v = `${field.replace(/\$$/, '').replace(/\./g, '_')}Raw`;
      const lines = [
        `# ${field} takes a ${t.type} name. Values not listed fall to ${t.default}.`,
        `${v} = LOWERCASE(STRING(${src}))`,
        `${field} = ${q(t.default)}`,
      ];
      for (const r of t.map || []) {
        if (!r.member || r.match === undefined || r.match === '') continue;
        const cond = r.kind === 'equals' ? `${v} == ${q(String(r.match).toLowerCase())}` : `CONTAINS(${v}, ${q(String(r.match).toLowerCase())})`;
        lines.push(`${field} = IF ${cond} THEN ${q(r.member)} ELSE ${field}`);
      }
      return lines;
    }
    case 'const': return [`${field} = ${q(t.value ?? '')}`];
    default: return [`${field} = ${src}`];
  }
}

function sampleFor(unit, lines) {
  const i = (unit.lines && unit.lines.length) ? unit.lines[0] : 0;
  return lines[i] ?? lines[0] ?? '';
}

function unitBody(plan, unit, read, keysByName) {
  const out = [];
  for (const m of unit.mappings || []) {
    if (!m.field) continue;
    const k = keysByName.get(m.key);
    out.push(...mappingLines(m, read, k ? k.values : []));
  }
  if (unit.metadata && hasEventMetadata(unit.schema)) {
    const mapped = new Set((unit.mappings || []).filter((m) => m.field).map((m) => m.key));
    const extra = (unit.keys || []).filter((k) => !mapped.has(k.key) && k.key !== (plan.split && plan.split.key) && !k.header).slice(0, 25);
    if (extra.length) {
      const used = new Set();
      out.push('', '# Keys with no field of their own go to event_metadata as key/value records.');
      const names = [];
      for (const k of extra) {
        const v = varName(k.key, used);
        names.push(v);
        out.push(`${v}.key$ = ${q(k.key)}`, `${v}.value$ = STRING(${read(k)})`);
      }
      out.push(`eventMetadata$.record$ = [${names.join(', ')}]`);
    }
  }
  return out;
}

// plan: {vendor, product, version, format, shipMethod, sensorType, baseName, confirm, extract,
//   split: {key, path, index} | null, units: [{name, eventType, schema, mappings, metadata, keys, lines}]}
// sampleLines: all sample lines. Returns [{name, role, parent, schema, text}].
export function generateParsers(plan, sampleLines) {
  const ex = extraction(plan);
  const keysByName = new Map((plan.keys || []).map((k) => [k.key, k]));
  const json = plan.format === 'json';
  const confirmLines = (c) => [`!CONFIRMWITH=${c.kind || 'PATTERN'}`, `!CONFIRMSTRING=${c.text || ''}`];
  const sensor = plan.sensorType ? [`sensorType$ = ${q(plan.sensorType)}`] : [];
  if (!plan.split || (plan.units || []).length <= 1 && !plan.forceParent) {
    const unit = plan.units[0];
    const lines = [
      `!SAMPLE=${sampleFor(unit, sampleLines)}`,
      ...confirmLines(plan.confirm || {}),
      `!SCHEMA=${unit.schema}`,
      ...(json ? ['!TRIMALLOFF'] : []),
      '',
      ...headerComment(plan, [`Standalone parser for the ${schemaInfo(unit.schema)?.name || unit.schema} schema.`]),
      '',
      ...ex.lines,
      '',
      ...sensor,
      ...unitBody(plan, unit, ex.read, keysByName),
    ];
    return [{ name: unit.name, role: 'standalone', schema: unit.schema, text: lines.join('\n') + '\n' }];
  }
  const parentName = plan.parentName || `${plan.baseName}_PARENT`;
  const splitRead = ex.read(plan.split);
  const parent = [
    `!SAMPLE=${sampleLines[0] ?? ''}`,
    ...confirmLines(plan.confirm || {}),
    `!SCHEMA=${GENERIC}`,
    ...(json ? ['!TRIMALLOFF'] : []),
    '',
    ...headerComment(plan, ['Parent: recognizes every message from this source and hands the parsed fields to its children.', ...(json ? ['!TRIMALLOFF stops TRIM_ALL() stripping braces from JSON values.'] : [])]),
    '',
    ...ex.lines,
    '',
    '# Variables and $ fields set here are visible to every child.',
    `eventType$ = ${splitRead}`,
    ...sensor,
  ];
  const out = [{ name: parentName, role: 'parent', schema: GENERIC, text: parent.join('\n') + '\n' }];
  for (const unit of plan.units) {
    if (!unit.schema || unit.schema === GENERIC) continue;
    const lines = [
      `!SAMPLE=${sampleFor(unit, sampleLines)}`,
      '!CONFIRMWITH=EXPRESSION',
      `!CONFIRMSTRING=eventType$==${q(unit.eventType)}`,
      `!SCHEMA=${unit.schema}`,
      ...(json ? ['!TRIMALLOFF'] : []),
      '',
      ...headerComment(plan, [`Child of ${parentName}: ${unit.eventType} to the ${schemaInfo(unit.schema)?.name || unit.schema} schema.`, `${plan.format === 'json' ? 'json' : plan.format === 'kv' ? 'vals' : plan.format === 'csv' ? 'parts' : 'values'}, eventType$ and sensorType$ come from the parent.`]),
      '',
      ...unitBody(plan, unit, ex.read, keysByName),
    ];
    out.push({ name: unit.name, role: 'child', parent: parentName, schema: unit.schema, text: lines.join('\n') + '\n' });
  }
  return out;
}

export function childName(base, schemaId, eventType, taken) {
  const s = upperSlug((schemaInfo(schemaId) || {}).name || 'GENERIC');
  let name = `${base}_CHILD_${s}`;
  if (taken.has(name)) name = `${base}_CHILD_${upperSlug(eventType).slice(0, 24) || s}`;
  while (taken.has(name)) name += '_2';
  taken.add(name);
  return name;
}

export function fieldExists(schemaId, field) {
  return fieldsByParser(schemaId).has(String(field).split('.')[0]);
}
