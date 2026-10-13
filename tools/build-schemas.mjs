#!/usr/bin/env node
// Rebuilds studio/core/schema-data.js from the public schema pages.
// It keeps field names, types, parser field names and enum member names only.
// Descriptions are left out on purpose: the page links to each schema page instead.
//
// Usage: node tools/build-schemas.mjs [--from <dir of saved .html pages>]

import { writeFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'studio/core/schema-data.js');

const SOPHOS = 'https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/Schemas/';
const TYPES = 'https://docs.taegis.secureworks.com/integration/customParsers/schema_types/';
const OS = 'https://docs.taegis.secureworks.com/integration/customParsers/schema_os/';

// Page slug, schema name used in the docs, and the !SCHEMA identifier.
// "documented" means the identifier appears in the Sophos docs; the rest follow the
// scwx.<data lake schema> pattern and are marked inferred in the lint.
const SCHEMAS = [
  ['AntivirusSchema', 'Antivirus', 'scwx.antivirus', false],
  ['APIcallSchema', 'APIcall', 'scwx.apicall', false],
  ['AuthSchema', 'Auth', 'scwx.auth', true],
  ['CloudAuditSchema', 'CloudAudit', 'scwx.cloudaudit', false],
  ['DHCPSchema', 'DHCP', 'scwx.dhcp', false],
  ['DNSSchema', 'DNS', 'scwx.dnsquery', true],
  ['EmailSchema', 'Email', 'scwx.email', false],
  ['EncryptSchema', 'Encrypt', 'scwx.encrypt', false],
  ['FilemodSchema', 'FileMod', 'scwx.filemod', false],
  ['HTTPSchema', 'HTTP', 'scwx.http', false],
  ['ManagementEventSchema', 'ManagementEvent', 'scwx.managementevent', false],
  ['NetflowSchema', 'Netflow', 'scwx.netflow', true],
  ['NIDSSchema', 'NIDS', 'scwx.nids', true],
  ['ProcessSchema', 'Process', 'scwx.process', false],
  ['RegistrySchema', 'Registry', 'scwx.registry', false],
  ['ThirdpartySchema', 'Thirdparty', 'scwx.thirdpartyalert', false],
];

const args = process.argv.slice(2);
const fromDir = args[0] === '--from' ? args[1] : null;

async function load(url, file) {
  if (fromDir) return readFile(path.join(fromDir, file), 'utf8');
  const res = await fetch(url, { headers: { 'user-agent': 'sophos-ngsiem-parser-studio schema builder' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

const text = (html) => html
  .replace(/<a [^>]*class="?headerlink[^>]*>.*?<\/a>/g, '')
  .replace(/<[^>]+>/g, '')
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/ /g, ' ')
  .trim();

// Returns [{heading, columns, rows}] for every table, with the nearest h2/h3 heading before it.
function tables(html) {
  const out = [];
  const re = /<(h[23])[^>]*>([\s\S]*?)<\/\1>|<table>([\s\S]*?)<\/table>/g;
  let heading = '';
  for (const m of html.matchAll(re)) {
    if (m[1]) { heading = text(m[2]); continue; }
    const body = m[3];
    const columns = [...body.matchAll(/<th[^>]*>([\s\S]*?)<\/th>/g)].map((x) => text(x[1]));
    const rows = [...body.matchAll(/<tr>([\s\S]*?)<\/tr>/g)]
      .map((r) => [...r[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((x) => text(x[1])))
      .filter((r) => r.length);
    out.push({ heading, columns, rows });
  }
  return out;
}

const camel = (snake) => snake.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase()) + '$';

// A field row: [name, type, parser field, ...]. The docs sometimes put "repeated" in the
// type ("repeated string") and sometimes in the parser field column, or leave it empty.
function fieldRow(row) {
  const [name, rawType, rawParser] = row;
  let type = rawType.trim().replace(/\(.*\)$/, '').trim();
  let repeated = false;
  if (/^repeated\s+/.test(type)) { repeated = true; type = type.replace(/^repeated\s+/, ''); }
  let parser = (rawParser || '').trim();
  let derived = false;
  let subPath;
  if (parser === 'repeated') { repeated = true; parser = ''; }
  // A few rows give a nested path such as os$.os$; the top-level parser field is the first part.
  if (parser.includes('.')) { subPath = parser; parser = parser.split('.')[0]; }
  if (!parser || !parser.endsWith('$')) derived = true;
  // The parser field is the camelCase of the normalized name plus $, as the docs describe. A
  // handful of rows in the docs' parser-field column don't follow that rule (typos such as
  // extraUserpricipalname$), and the engine uses the rule name, so the rule wins.
  const rule = name.includes('.') ? parser : camel(name);
  const f = { name, type, parser: rule };
  if (repeated) f.repeated = true;
  if (derived) f.derived = true;
  if (!derived && parser !== rule) f.docParser = parser;
  if (subPath) f.docPath = subPath;
  return f;
}

function collect(html, into) {
  for (const t of tables(html)) {
    const cols = t.columns.map((c) => c.toLowerCase().replace(/\s+/g, ''));
    if (cols[0] === 'name' && cols[1] === 'number') {
      into.enums[t.heading] = t.rows.map((r) => r[0]);
      into.enumNumbers[t.heading] = Object.fromEntries(t.rows.filter((r) => /^\d+$/.test(r[1])).map((r) => [r[1], r[0]]));
    } else if ((cols[0] === 'normalizedfield' || cols[0] === 'field') && cols[2] === 'parserfield') {
      // A page can split one heading's fields over two tables; keep them together.
      into.messages[t.heading] = [...(into.messages[t.heading] || []), ...t.rows.map(fieldRow)];
    }
  }
}

const data = { generated: new Date().toISOString().slice(0, 10), sources: { sophos: SOPHOS, types: TYPES }, schemas: {}, types: { enums: {}, enumNumbers: {}, messages: {} } };

for (const [slug, name, id, documented] of SCHEMAS) {
  const html = await load(`${SOPHOS}${slug}/`, `${slug}.html`);
  const found = { enums: {}, enumNumbers: {}, messages: {} };
  collect(html, found);
  const fields = found.messages['Schema fields'];
  if (!fields) throw new Error(`${slug}: no Schema fields table`);
  // Rows such as vendor_alert_details.is_custom_alert describe a sub-field. Fold them into a
  // message type so vendorAlertDetails$.isCustomAlert$ checks like any other nested field.
  for (const f of fields.filter((x) => x.name.includes('.'))) {
    const [top, sub] = f.name.split('.');
    const typeName = `${name}.${top.replace(/(^|_)([a-z])/g, (_, __, c) => c.toUpperCase())}`;
    const subParser = (f.docPath || '').split('.')[1] || camel(sub);
    (found.messages[typeName] ||= []).push({ name: sub, type: f.type, parser: subParser });
    if (!fields.some((x) => x.name === top)) fields.push({ name: top, type: typeName, parser: f.parser });
  }
  for (let i = fields.length - 1; i >= 0; i--) if (fields[i].name.includes('.')) fields.splice(i, 1);
  delete found.messages['Schema fields'];
  delete found.messages['Schema summary'];
  data.schemas[id] = { name, page: `${SOPHOS}${slug}/`, documentedId: documented, fields };
  Object.assign(data.types.enums, found.enums);
  Object.assign(data.types.enumNumbers, found.enumNumbers);
  Object.assign(data.types.messages, found.messages);
}

for (const [url, file] of [[TYPES, 'schema_types.html'], [OS, 'schema_os.html']]) {
  const found = { enums: {}, enumNumbers: {}, messages: {} };
  collect(await load(url, file), found);
  for (const [k, v] of Object.entries(found.enums)) if (!data.types.enums[k]) data.types.enums[k] = v;
  for (const [k, v] of Object.entries(found.enumNumbers)) if (!data.types.enumNumbers[k]) data.types.enumNumbers[k] = v;
  for (const [k, v] of Object.entries(found.messages)) if (!data.types.messages[k]) data.types.messages[k] = v;
}

const banner = `// Generated by tools/build-schemas.mjs from the public schema pages. Do not edit by hand.
// Field names, types, parser fields and enum names only. Read each schema page for descriptions.
`;
await writeFile(OUT, `${banner}export default ${JSON.stringify(data, null, 1)};\n`);
const nFields = Object.values(data.schemas).reduce((n, s) => n + s.fields.length, 0);
console.log(`wrote ${path.relative(ROOT, OUT)}: ${Object.keys(data.schemas).length} schemas, ${nFields} fields, ${Object.keys(data.types.enums).length} enums, ${Object.keys(data.types.messages).length} message types`);
