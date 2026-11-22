#!/usr/bin/env node
// Installs a library case rule, with its case template, in a Sophos Fusion tenant through the
// Cases GraphQL API. Without --install it only reads the tenant and says what it would do.
//
//   node tools/case-rule-install.mjs rules/<vendor>/<name> [--env-file <path>] [--tenant <id>]
//     [--method import|create] [--install]
//
// --method import (the default) sends case-rule.yaml, rule and template together, to the import
// that Automatic Cases uses, then saves the rule once more with updateCaseRule and no change. In a
// lab tenant an imported rule opened no case until that second save. Import puts the rule after
// the tenant's own rules, so it moves none of them.
// --method create imports the template alone, then makes the rule with createCaseRule, at the
// order after the tenant's last rule, so it moves none of them either.
//
// Either way the rule keeps the state in the file, Test for a library entry, so it only writes Rule
// Logs until you turn it on. The tool refuses when the tenant already has a case rule or template
// with the entry's names. It never deletes anything and never touches a case.
//
// Credentials: SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET (and SOPHOS_TENANT_ID for a partner or
// organization credential) from the environment, or from the env file --env-file names. Keep that
// file outside the repo.

import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { loadCredentials } from './lib/fusion-search.mjs';
import { casesClient, importYaml, allCaseRules, readUntil, createInput, resaveInput } from './lib/fusion-cases.mjs';
import { readCaseRuleYaml } from './lib/rules.mjs';

const USAGE = 'usage: case-rule-install.mjs rules/<vendor>/<name> [--env-file <path>] [--tenant <id>] [--method import|create] [--install]';

export function parseArgs(argv) {
  const o = { dir: null, envFile: null, tenant: null, method: 'import', install: false };
  const need = (i) => { if (i >= argv.length) throw new Error(`${argv[i - 1]} needs a value`); return argv[i]; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--env-file') o.envFile = need(++i);
    else if (a === '--tenant') o.tenant = need(++i);
    else if (a === '--method') o.method = need(++i);
    else if (a === '--install') o.install = true;
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}`);
    else if (!o.dir) o.dir = a;
    else throw new Error(`one entry at a time: ${a}`);
  }
  if (!o.dir) throw new Error('name a case rule entry folder');
  if (!['import', 'create'].includes(o.method)) throw new Error('--method is import or create');
  return o;
}

// The template document of a case-rule.yaml, on its own, for --method create.
export function templateText(yaml) {
  const parts = String(yaml).replace(/\r\n?/g, '\n').split(/^---\s*$/m);
  return parts[parts.length - 1].replace(/^\n/, '');
}

// Reads the entry and returns {yaml, rule, template}, or throws with what is wrong.
export async function readEntry(dir) {
  const meta = JSON.parse(await readFile(path.join(dir, 'meta.json'), 'utf8'));
  if (meta.kind !== 'case') throw new Error(`${dir} is a ${meta.kind} entry. Only a case rule installs this way; add detection rules by hand.`);
  const yaml = await readFile(path.join(dir, 'case-rule.yaml'), 'utf8');
  const doc = readCaseRuleYaml(yaml);
  if (!doc) throw new Error('case-rule.yaml doesn\'t read as a rule and its template. Run npm run validate.');
  return { yaml, rule: doc.rule, template: doc.template };
}

const same = (a, b) => a.order === b.order && a.state === b.state && a.updatedAt === b.updatedAt;

// Installs the entry and returns a report. log gets one line per step.
export async function install(client, { yaml, rule, template }, { method = 'import', write = false, log = () => {}, wait = {} } = {}) {
  const before = await allCaseRules(client);
  const clash = before.find((r) => r.name === rule.name);
  if (clash) throw new Error(`the tenant already has a case rule named ${rule.name} (order ${clash.order}, ${clash.state}). Delete it first or leave it.`);
  const existing = await client.request('caseTemplate', { a: { name: template.name } }).catch(() => null);
  if (existing && existing.id) throw new Error(`the tenant already has a case template named ${template.name}. Delete it first or leave it.`);
  const last = before.reduce((m, r) => Math.max(m, r.order || 0), 0);
  log(`The tenant has ${before.length} case rule${before.length === 1 ? '' : 's'}; the new rule goes after them, at order ${last + 1}.`);
  if (!write) {
    log(method === 'import'
      ? `Would import case-rule.yaml (rule ${rule.name} in ${rule.state}, template ${template.name}), then save the rule once more with updateCaseRule. Add --install to do it.`
      : `Would import the template ${template.name}, then create the rule ${rule.name} in ${rule.state} with createCaseRule. Add --install to do it.`);
    return { installed: false };
  }
  let made;
  if (method === 'import') {
    await importYaml(client, yaml);
    log('Imported case-rule.yaml.');
    const read = await readUntil(() => client.request('caseRule', { a: { name: rule.name } }), (v) => v && v.id, wait);
    if (!read || !read.id) throw new Error(`the import answered, but no case rule named ${rule.name} reads back`);
    made = await client.request('updateCaseRule', { i: resaveInput(read) });
    log(`Saved ${rule.name} once more with updateCaseRule, with no change.`);
  } else {
    await importYaml(client, templateText(yaml), { fileName: 'case-template.yaml' });
    const t = await readUntil(() => client.request('caseTemplate', { a: { name: template.name } }), (v) => v && v.id, wait);
    if (!t || !t.id) throw new Error(`the import answered, but no case template named ${template.name} reads back`);
    log(`Imported the template ${template.name}.`);
    made = await client.request('createCaseRule', { i: createInput(rule, t.id, last + 1) });
    log(`Created ${rule.name} with createCaseRule at order ${last + 1}.`);
  }
  const back = await readUntil(() => client.request('caseRule', { a: { id: made.id } }), (v) => v && v.id === made.id && v.template && v.template.name === template.name, wait);
  const after = await allCaseRules(client);
  const moved = before.filter((b) => { const a = after.find((x) => x.id === b.id); return !a || !same(a, b); }).map((b) => b.name);
  const report = { installed: true, id: back && back.id, order: back && back.order, state: back && back.state, template: back && back.template ? back.template.name : null, moved };
  log(`Read back: ${rule.name}, order ${report.order}, ${report.state}, template ${report.template}.`);
  log(moved.length ? `CHECK: these case rules changed while it installed: ${moved.join(', ')}` : 'None of the tenant\'s other case rules changed.');
  if (report.state !== rule.state) log(`CHECK: the rule reads back ${report.state}, not ${rule.state} as in the file.`);
  return report;
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\n${USAGE}`); process.exit(2); }
  const entry = await readEntry(opts.dir);
  const creds = await loadCredentials({ envFile: opts.envFile });
  if (opts.tenant) creds.tenantId = opts.tenant;
  const client = casesClient(creds, { log: (m) => console.error(`  ${m}`) });
  const report = await install(client, entry, { method: opts.method, write: opts.install, log: (m) => console.log(m) });
  if (report.installed) console.log('Installed in Test state. Read its Rule Logs under Security Operations > Cases > Automatic Cases before you set it to Enabled.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(`case-rule-install: ${e.message}`);
    process.exit(1);
  });
}
