// The two Ransomware containment chain templates: the version without Microsoft 365 must be the
// full chain less its user step, so a fix to one can't miss the other. Approval before acting must
// know every action the chain holds for approval.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS } from '../tools/lib/yaml.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (rel) => toJS(parseYaml(readFileSync(path.join(ROOT, rel), 'utf8')));
const FULL = load('playbooks/sophos/ransomware-containment-chain/template.yaml');
const LITE = load('playbooks/sophos/ransomware-containment-chain-without-microsoft-365/template.yaml');
const EXECUTOR = load('playbooks/microsoft/approval-before-acting/template.yaml');
const USER_TASKS = ['user_names', 'user_parse', 'user_gate', 'user_go', 'user_loop'];
const USER_INPUTS = ['approval', 'approval_hours', 'bridge_name', 'domains', 'excluded_users', 'force_password_change', 'max_users', 'revoke_sessions'];

test('ransomware chain without Microsoft 365: the full chain\'s tasks less the user step, and a people task with nothing in it', () => {
  const full = FULL.dsl.tasks.filter((t) => !USER_TASKS.includes(t.name));
  assert.deepEqual(LITE.dsl.tasks.map((t) => t.name), full.map((t) => t.name));
  for (const [i, t] of LITE.dsl.tasks.entries()) {
    if (t.name === 'people') assert.deepEqual(t.let, { steps: '[]', held: '[]' });
    else assert.deepEqual(t, full[i], `task ${t.name} differs from the full chain`);
  }
  assert.deepEqual(USER_TASKS.filter((n) => FULL.dsl.tasks.some((t) => t.name === n)), USER_TASKS);
  assert.deepEqual(LITE.dsl.outputs, FULL.dsl.outputs);
});

test('ransomware chain without Microsoft 365: no Microsoft Graph API connector or user inputs, everything else the same', () => {
  assert.deepEqual(LITE.connectors, FULL.connectors.filter((c) => !c.startsWith('Taegis.MicrosoftGraphAPI:')));
  assert.equal(JSON.stringify(LITE).includes('MicrosoftGraphAPI'), false);
  assert.deepEqual(LITE.interfaces, FULL.interfaces);
  assert.deepEqual(LITE.playbooks, FULL.playbooks);
  assert.equal(LITE.triggerHints[0].config.filter, FULL.triggerHints[0].config.filter);
  const full = FULL.inputs.properties.configuration.properties;
  const lite = LITE.inputs.properties.configuration.properties;
  assert.deepEqual(Object.keys(lite), Object.keys(full).filter((k) => !USER_INPUTS.includes(k)));
  for (const k of Object.keys(lite)) assert.deepEqual(lite[k], full[k], k);
  assert.ok(LITE.name !== FULL.name && LITE.dsl.name === LITE.name);
});

test('ransomware chain: Approval before acting runs every action the chain holds, by default', () => {
  const kinds = [...JSON.stringify(FULL.dsl.tasks).matchAll(/'((?:endpoint|entra)\.[a-z_]+); /g)].map((m) => m[1]);
  assert.deepEqual([...new Set(kinds)].sort(), ['endpoint.isolate', 'entra.require_password_change', 'entra.revoke_sessions']);
  const allowed = EXECUTOR.inputs.properties.configuration.properties.allowed_actions.default;
  for (const k of kinds) assert.ok(allowed.includes(k), k);
  assert.ok(EXECUTOR.connectors.some((c) => c.startsWith('Taegis.SophosEndpoint:')));
  const known = EXECUTOR.dsl.tasks.find((t) => t.name === 'run').for.find((t) => t.name === 'check_action').let.known;
  for (const k of kinds) assert.ok(known.includes(`'${k}'`), k);
});
