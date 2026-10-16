// Playbooks and connectors: the YAML and CEL readers, the checks, and the CI script. Every entry
// acts on a tenant, so none merges on its own; the checks catch what review shouldn't have to.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS, YamlError } from '../tools/lib/yaml.mjs';
import { parseCel, freeNames, templateParts, CelError } from '../tools/lib/cel.mjs';
import { validateAutomation, checkAllowedHosts, connectorInfo, TIERS } from '../tools/lib/automation.mjs';
import { loadAutomation, loadAllowedHosts, connectorMap } from '../tools/lib/fs-automation.mjs';
import { vendorNames } from '../studio/core/library.js';
import { loadLibrary } from '../tools/lib/fs-library.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------- YAML

test('YAML: block maps, lists, scalars and their styles, the way Sophos Fusion exports them', () => {
  const src = [
    'apiVersion: v0.0.1',
    'name: Acme_Test',
    'version: 1.0.0',
    'tags:',
    '    - Type:Response',
    'empty: []',
    'flow: {a: 1, b: [x, "y"]}',
    'dsl:',
    '    tasks:',
    '        # a comment',
    '        - name: setup',
    '          let:',
    "            text: 'started'",
    '            expr: started',
    '            quoted: "a == \'b\'"',
    '        - name: next',
    '          condition: >-',
    '              a &&',
    '              b',
    'doc: |',
    '    # Title',
    '      indented',
    '',
    '    last',
    'n: 3',
    'b: true',
    'z: ~',
  ].join('\n');
  const node = parseYaml(src);
  const js = toJS(node);
  assert.equal(js.version, '1.0.0');
  assert.deepEqual(js.tags, ['Type:Response']);
  assert.deepEqual(js.empty, []);
  assert.deepEqual(js.flow, { a: 1, b: ['x', 'y'] });
  assert.deepEqual(js.dsl.tasks[0].let, { text: 'started', expr: 'started', quoted: "a == 'b'" });
  assert.equal(js.dsl.tasks[1].condition, 'a && b');
  assert.equal(js.doc, '# Title\n  indented\n\nlast\n');
  assert.deepEqual([js.n, js.b, js.z], [3, true, null]);
  const let_ = node.entries.find((e) => e.key === 'dsl').value.entries[0].value.items[0].entries[1].value;
  assert.deepEqual(let_.entries.map((e) => e.value.style), ['single', 'plain', 'double']);
  assert.equal(let_.entries[1].value.line, 14);
});

test('YAML: a list at the same indent as its key, folded quotes, and chomping', () => {
  const js = toJS(parseYaml('a:\n- 1\n- two\nb: "x\n  y"\nc: |-\n  keep\nd: >+\n  one\n  two\n\n'));
  assert.deepEqual(js, { a: [1, 'two'], b: 'x y', c: 'keep', d: 'one two\n\n' });
});

test('YAML: what library files never need is refused, with the line', () => {
  const bad = {
    'a: &x 1\nb: *x\n': /anchors/,
    'a: !!str 1\n': /tags/,
    'a: 1\n---\nb: 2\n': /one YAML document/,
    'a:\n\tb: 1\n': /tab/,
    'a: 1\na: 2\n': /appears twice/,
    'a: x: y\n': /": "/,
    "a: 'never ends\n": /never ends/,
    'a:\n  b: 1\n c: 2\n': /indented/,
    '? complex\n': /complex keys|key: value/,
  };
  for (const [src, why] of Object.entries(bad)) {
    assert.throws(() => parseYaml(src), (e) => e instanceof YamlError && why.test(e.message) && e.line >= 1, JSON.stringify(src));
  }
});

// ---------------------------------------------------------------- CEL

test('CEL: Sophos Fusion expressions parse, and the names they read are found', () => {
  const names = (s) => [...freeNames(parseCel(s))].sort();
  assert.deepEqual(names("has(inputs, 'configuration.userId') && size(inputs.configuration.userId) > 1"), ['inputs']);
  assert.deepEqual(names("send.?outputs.orValue([]).collect('outputs.success').exists(s, toString(s) == 'true') ? 'success' : 'failure'"), ['send']);
  assert.deepEqual(names("inputs.recipients.split(',').map(r, r.trim()).filter(r, r != '').map(r, {'email': r})"), ['inputs']);
  assert.deepEqual(names('cel.bind(x, inputs.a, x + other)'), ['inputs', 'other']);
  assert.deepEqual(names("[1, 2.5, .6, 0x1F, 3u, -1, r'raw\\d', b'bytes', '''tri\nple''', null, true][?0]"), []);
  assert.deepEqual(names('started'), ['started']);
  for (const bad of ['a ? b :', "'x' +", 'a.(b)', '(a', "'open", 'a $ b', '']) {
    assert.throws(() => parseCel(bad), CelError, JSON.stringify(bad));
  }
});

test('CEL: the ${...} parts of a connector template, with braces inside strings left alone', () => {
  assert.deepEqual(templateParts("https://${config.host}/x/${inputs.id.trim()}?q=${has(inputs, 'p') ? '}' : '1'}").map((p) => p.expr),
    ['config.host', 'inputs.id.trim()', "has(inputs, 'p') ? '}' : '1'"]);
  assert.deepEqual(templateParts('no templates'), []);
  assert.throws(() => templateParts('https://${config.host/x'), CelError);
});

// ---------------------------------------------------------------- fixtures

const HOSTS = { acme: { api: ['api.example.com', 'auth.example.com'], docs: ['docs.example.com'], sources: ['https://docs.example.com/api'] } };

const CONNECTOR = `apiVersion: v0.0.1
kind: Connector
name: Acme_Widget
tags: []
categories:
    - Generic
title: Acme Widget
description: Reads and locks Acme widgets. Docs at https://docs.example.com/api
documentation: |
    # Overview
    See https://docs.example.com/api
method: http
version: 1.2.0
vendorName: Acme
vendorProduct: Widget
parameters:
    properties:
        host:
            enum:
                - api.example.com
            required: true
            title: API host
            type: string
    type: object
actions:
    - name: validate
      config:
        method: GET
        url: https://\${config.host}/v1/widgets?limit=1
        headers:
            - name: X-Acme-Account
              value: \${config.account}
    - name: getWidget
      inputs:
        properties:
            id:
                type: string
        type: object
      config:
        method: GET
        url: https://\${config.host}/v1/widgets/\${inputs.id.trim()}
        outputs: \${body}
    - name: lockWidget
      config:
        body:
            ids: \${inputs.ids}
        method: POST
        error: '\${has(status.code) && status.code == 201 ? '''' : ''failed''}'
        url: https://\${config.host}/v1/widgets/lock
authTypes:
    - OAuthClientCreds
authDefaults:
    url: https://auth.example.com/oauth/token
    clientCredentialsAuth:
        clientId: <Client-ID>
        scopes:
            - widgets
`;

const CONNECTOR_META = {
  title: 'Acme Widget', vendor: 'Acme', product: 'Acme Widget', auth: 'OAuth client credentials',
  functions: { validate: 'lookup', getWidget: 'lookup', lockWidget: 'reversible action' },
  license: 'MIT', tested: { validated: '2026-10-16', tenant: null }, author: 'octocat', docs: ['https://docs.example.com/api'],
};

const TEMPLATE = `apiVersion: v0.0.1
kind: Playbook
name: Acme_Widget_Lock
version: 1.0.0
title: Acme widget lock
description: Locks an Acme widget.
documentation: |
    # Overview
    Locks a widget. https://docs.example.com/api
connectors:
    - Acme_Widget:1.2.0
    - Taegis.Case:1.0.5
triggerHints:
    - type: actions
      config:
        category: response
        context: Host
      celHints:
        - name: Tagged
          expr: '''tag'' in assetTags(inputs)'
inputs:
    properties:
        configuration:
            properties:
                dry_run:
                    default: true
                    type: boolean
            type: object
    type: object
dsl:
    name: Acme_Widget_Lock
    outcomeStatus: finish.variables.status
    outputs:
        status: finish.variables.status
    tasks:
        - name: setup
          let:
            dry_run: "inputs.?configuration.dry_run.orValue(true)"
            state: 'started'
            ids: "entityValue(inputs, 'host_id')"
        - name: read
          range: setup.variables.ids
          for:
            - name: get_one
              action: Acme_Widget.getWidget
              optional: true
              retry: 2
              inputs:
                id: read.value
        - name: lock
          condition: "!setup.variables.dry_run"
          action: Acme_Widget.lockWidget
          inputs:
            ids: setup.variables.ids
        - name: wait
          sleep: '15s'
        - name: finish
          let:
            status: "has(lock, 'outputs') ? 'SUCCESS' : 'FAIL'"
        - name: comment
          condition: "caseId(inputs) != '' && tenant.id != ''"
          action: Taegis.Case.addComment
          optional: true
          inputs:
            caseId: caseId(inputs)
            comment: "'Acme: ' + finish.variables.status"
            title: "Widget \${finish.variables.status}"
`;

const PLAYBOOK_META = {
  title: 'Acme widget lock', vendor: 'Acme', product: 'Acme Widget', use_case: 'Lock a widget.', trigger: 'User Initiated on Host',
  connections: ['Acme_Widget'], requires: 'Acme Widget', license: 'MIT', risk_tier: 'reversible action', mdr_note: 'Tell MDR.',
  rollback: 'Unlock it in the Acme console.', tested: { validated: '2026-10-16', tenant: null }, connector: 'connectors/acme/acme-widget',
  author: 'octocat', docs: ['https://docs.example.com/api'],
};

const SETUP = '# Setup\n\n1. Import it.\n2. Leave it off.\n';

const file = (p, content) => ({ path: p, content: typeof content === 'string' ? content : JSON.stringify(content, null, 2) });
const connectorEntry = (over = {}) => ({ kind: 'connector', folder: 'connectors', id: 'acme/acme-widget', meta: { ...CONNECTOR_META, ...(over.meta || {}) }, loadProblems: [],
  files: [file('connector.yaml', over.yaml ?? CONNECTOR), file('meta.json', { ...CONNECTOR_META, ...(over.meta || {}) }), file('README.md', over.readme ?? '# Acme Widget\n\nCalls the Acme API.\n')] });
const playbookEntry = (over = {}) => ({ kind: 'playbook', folder: 'playbooks', id: 'acme/acme-widget-lock', meta: { ...PLAYBOOK_META, ...(over.meta || {}) }, loadProblems: [],
  files: [file('template.yaml', over.yaml ?? TEMPLATE), file('meta.json', { ...PLAYBOOK_META, ...(over.meta || {}) }), file('SETUP.md', over.setup ?? SETUP)] });

function check(entry, connector = connectorEntry()) {
  const connectors = new Map([[connector.id, connectorInfo(connector, { allowedHosts: HOSTS })]]);
  return validateAutomation(entry, { allowedHosts: HOSTS, connectors });
}
const errors = (r) => r.problems.filter((p) => p.level === 'error');
const codes = (r) => errors(r).map((p) => p.code);
const has = (r, code, re) => errors(r).some((p) => p.code === code && (!re || re.test(p.message)));

// ---------------------------------------------------------------- checks

test('checks: a clean connector and the playbook that uses it pass', () => {
  const c = check(connectorEntry());
  assert.deepEqual(errors(c), []);
  const p = check(playbookEntry());
  assert.deepEqual(errors(p), []);
  assert.deepEqual(TIERS, ['lookup', 'notify', 'reversible action', 'destructive']);
});

test('checks: tenant IDs, icons, credentials, webhook URLs, object IDs and personal data are refused', () => {
  assert.ok(has(check(playbookEntry({ yaml: `tenantId: "346249"\n${TEMPLATE}` })), 'tenant'));
  assert.ok(has(check(playbookEntry({ yaml: `${TEMPLATE}icon: iVBORw0KGgo=\n` })), 'icon'));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('clientId: <Client-ID>', 'clientId: <Client-ID>\n        clientSecret: s3cr3tValue99') })), 'secret'));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('name: X-Acme-Account\n              value: ${config.account}', 'name: Authorization\n              value: Bearer abc123') })), 'secret'));
  assert.ok(has(check(playbookEntry({ setup: `${SETUP}\nPost to https://hooks.slack.com/services/T0/B0/xyz\n` })), 'webhook'));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("state: 'started'", "state: 'started'\n            group: '3fa85f64-5717-4562-b3fc-2c963f66afa6'") })), 'id'));
  // A placeholder made of one repeated digit is fine.
  assert.ok(!has(check(playbookEntry({ setup: `${SETUP}\nSuch as 00000000-0000-0000-0000-000000000000.\n` })), 'id'));
  assert.ok(has(check(playbookEntry({ setup: `${SETUP}\nAsk bob@realcorp.com.au or 8.8.4.4.\n` })), 'email'));
  assert.ok(has(check(playbookEntry({ setup: `${SETUP}\nAsk bob@realcorp.com.au or 8.8.4.4.\n` })), 'ip'));
});

test('checks: a connector calls only allowlisted https hosts, never one set at run time', () => {
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('- api.example.com\n', '- api.example.com\n                - api.example.net\n') })), 'host', /api\.example\.net/));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('url: https://${config.host}/v1/widgets/lock', 'url: https://${inputs.host}/v1/widgets/lock') })), 'host', /isn't a setting with a fixed list/));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('url: https://${config.host}/v1/widgets/lock', 'url: http://api.example.com/v1/widgets/lock') })), 'host', /https/));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('url: https://auth.example.com/oauth/token', 'url: https://login.example.org/token') })), 'host', /grant URL/));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('See https://docs.example.com/api', 'See https://elsewhere.example.org/x') })), 'host', /documentation links/));
  // A template holds no addresses at all.
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("comment: \"'Acme: ' + finish.variables.status\"", "comment: \"'https://api.example.com/x'\"") })), 'host', /holds the address/));
});

test('checks: wipe-type actions are refused, and only the http method and credential sign-in are taken', () => {
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('- name: lockWidget', '- name: wipeWidget'), meta: { functions: { validate: 'lookup', getWidget: 'lookup', wipeWidget: 'destructive' } } })), 'wipe'));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('/v1/widgets/lock', '/v1/widgets/factory-reset') })), 'wipe'));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('method: http', 'method: central') })), 'field', /method must be http/));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('- OAuthClientCreds', '- Platform') })), 'auth'));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('name: Acme_Widget\n', 'name: Taegis.AcmeWidget\n') })), 'field', /Taegis/));
  // Every function has a tier in meta.json, and only those functions.
  assert.ok(has(check(connectorEntry({ meta: { functions: { validate: 'lookup', getWidget: 'lookup' } } })), 'tier', /lockWidget has no risk tier/));
});

test('checks: the risk tier can\'t be less than what the template calls, and destructive needs a tenant run', () => {
  assert.ok(has(check(playbookEntry({ meta: { risk_tier: 'notify' } })), 'tier', /Acme_Widget\.lockWidget \(reversible action\)/));
  const viaInterface = TEMPLATE.replace('connectors:\n', 'interfaces:\n    - Taegis.IsolateHost:1.1.0\nconnectors:\n').replace("        - name: wait\n", "        - name: isolate\n          call: Taegis.IsolateHost\n        - name: wait\n");
  assert.ok(has(check(playbookEntry({ yaml: viaInterface, meta: { risk_tier: 'reversible action' } })), 'tier') === false);
  assert.ok(has(check(playbookEntry({ yaml: viaInterface.replace('action: Acme_Widget.lockWidget', 'action: Acme_Widget.getWidget'), meta: { risk_tier: 'lookup' } })), 'tier', /Taegis\.IsolateHost/));
  assert.ok(has(check(playbookEntry({ meta: { risk_tier: 'destructive' } })), 'tier', /tested\.tenant/));
  assert.ok(!has(check(playbookEntry({ meta: { risk_tier: 'destructive', tested: { validated: '2026-10-16', tenant: { date: '2026-10-16', region: 'us01' } } } })), 'tier'));
  // Generic webhook connectors send data anywhere: a warning for review.
  const webhook = check(playbookEntry({ yaml: TEMPLATE.replace('    - Taegis.Case:1.0.5\n', '    - Taegis.Case:1.0.5\n    - Taegis.Webhook:1.1.4\n').replace('action: Taegis.Case.addComment', 'action: Taegis.Webhook.post') }));
  assert.ok(webhook.problems.some((p) => p.level === 'warning' && p.code === 'review'));
});

test('checks: dependencies match the entry\'s own connector, its functions and the lists the template declares', () => {
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('    - Acme_Widget:1.2.0\n', '    - Acme_Widget:1.1.0\n') })), 'connector', /version 1\.2\.0/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('    - Taegis.Case:1.0.5\n', '') })), 'dependency', /Taegis\.Case isn't in connectors/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('Acme_Widget.getWidget', 'Acme_Widget.getGadget') })), 'dependency', /no function getGadget/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('    - Taegis.Case:1.0.5\n', '    - Taegis.Case:1.0.5\n    - Other_Thing:1.0.0\n') })), 'connector', /Other_Thing/));
  assert.ok(has(check(playbookEntry({ meta: { connector: 'connectors/acme/missing' } })), 'connector', /isn't in the library/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('        - name: wait\n', '        - name: other\n          exec: Taegis.CaseWorkNote\n        - name: wait\n') })), 'dependency', /isn't in playbooks/));
});

test('checks: expressions parse and read only tasks, inputs, TDR and tenant; a bare word must be quoted to be text', () => {
  const plain = check(playbookEntry({ yaml: TEMPLATE.replace("state: 'started'", 'state: started') }));
  assert.ok(has(plain, 'reference', /started is not a task.*single-quote it: 'started'/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("!setup.variables.dry_run", "!setupp.variables.dry_run") })), 'reference', /setupp/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("has(lock, 'outputs') ? 'SUCCESS' : 'FAIL'", "has(lock, 'outputs') ? 'SUCCESS' :") })), 'cel'));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('Widget ${finish.variables.status}', 'Widget ${finish.variables.status') })), 'cel'));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("expr: '''tag'' in assetTags(inputs)'", "expr: '''tag'' in assetTags(input)'") })), 'reference', /input is not inputs/));
  assert.ok(has(check(connectorEntry({ yaml: CONNECTOR.replace('outputs: ${body}', 'outputs: ${body.}') })), 'cel'));
});

test('checks: task names, retry, sleep and the YAML itself', () => {
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("        - name: finish\n          let:", "        - name: finish\n          retry: 2\n          let:") })), 'task', /retry only works/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace("- name: wait\n          sleep: '15s'", "- name: wait\n          sleep: 'soon'") })), 'task', /sleep/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('- name: finish', '- name: setup') })), 'task', /two tasks/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('- name: finish', '- name: Finish') })), 'task', /lowercase/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('dsl:\n    name', 'dsl:\n\tname') })), 'yaml', /tab/));
  assert.ok(has(check(playbookEntry({ yaml: TEMPLATE.replace('kind: Playbook\n', 'kind: Playbook\nisPlatformGlobal: true\n') })), 'platform'));
});

test('checks: meta.json fields, the folder name and the allowed files', () => {
  assert.ok(has(check(playbookEntry({ meta: { risk_tier: 'harmless' } })), 'meta', /risk_tier/));
  assert.ok(has(check(playbookEntry({ meta: { title: 'Something else' } })), 'folder'));
  assert.ok(has(check(playbookEntry({ meta: { tested: { validated: 'yesterday', tenant: null } } })), 'meta', /tested\.validated/));
  const extra = playbookEntry();
  extra.files.push(file('run.sh', 'echo hi\n'));
  assert.ok(has(check(extra), 'files', /run\.sh/));
  const missing = playbookEntry();
  missing.files = missing.files.filter((f) => f.path !== 'SETUP.md');
  assert.ok(has(check(missing), 'files', /SETUP\.md is missing/));
});

test('checks: the host allowlist itself must be well formed', () => {
  assert.deepEqual(checkAllowedHosts(HOSTS), []);
  assert.ok(checkAllowedHosts({ Acme: { api: ['https://api.example.com'], docs: [], sources: [] } }).length >= 3);
});

test('every playbook and connector in the library passes the checks', async () => {
  const automation = await loadAutomation(ROOT);
  const hosts = await loadAllowedHosts(ROOT);
  assert.equal(hosts.problem, null);
  assert.deepEqual(checkAllowedHosts(hosts.hosts), []);
  const connectors = connectorMap(automation.connectors, hosts.hosts);
  const allowNames = vendorNames(await loadLibrary(ROOT));
  for (const e of [...automation.playbooks, ...automation.connectors]) {
    const r = validateAutomation(e, { allowedHosts: hosts.hosts, connectors, allowNames });
    assert.deepEqual(errors(r), [], `${e.folder}/${e.id}`);
  }
});

// ---------------------------------------------------------------- the CI script

// A base checkout with the allowlist, and a pull request that adds what change() writes.
async function ciRun(change, author = 'octocat') {
  const dir = await mkdtemp(path.join(tmpdir(), 'xsl-auto-ci-'));
  const base = path.join(dir, 'base');
  const pr = path.join(dir, 'pr');
  for (const d of [base, pr]) {
    await mkdir(path.join(d, 'connectors'), { recursive: true });
    await writeFile(path.join(d, 'connectors/allowed-hosts.json'), JSON.stringify(HOSTS));
  }
  const changed = await change(pr, base);
  await writeFile(path.join(dir, 'changed.txt'), changed.join('\n'));
  let code = 0;
  try {
    execFileSync(process.execPath, [path.join(ROOT, 'tools/validate-library.mjs'), '--root', pr, '--base', base, '--changed-files', path.join(dir, 'changed.txt'), '--author', author, '--report', path.join(dir, 'report.json'), '--markdown', path.join(dir, 'report.md')], { stdio: 'pipe' });
  } catch (e) { code = e.status; }
  const report = JSON.parse(await readFile(path.join(dir, 'report.json'), 'utf8'));
  const md = await readFile(path.join(dir, 'report.md'), 'utf8');
  await rm(dir, { recursive: true, force: true });
  return { code, report, md };
}

async function writeEntry(root, entry) {
  const dir = path.join(root, entry.folder, entry.id);
  await mkdir(dir, { recursive: true });
  for (const f of entry.files) await writeFile(path.join(dir, f.path), f.content);
  return entry.files.map((f) => `${entry.folder}/${entry.id}/${f.path}`);
}

test('CI: a pull request that adds a playbook and its connector is checked, passes, and never qualifies to merge on its own', async () => {
  const { code, report, md } = await ciRun(async (pr) => [...await writeEntry(pr, connectorEntry()), ...await writeEntry(pr, playbookEntry())]);
  assert.equal(code, 0, JSON.stringify(report.entries, null, 1));
  assert.equal(report.passed, true);
  assert.equal(report.eligible, false);
  assert.deepEqual(report.entries.map((e) => [e.id, e.kind, e.status, e.ok]).sort(), [['connectors/acme/acme-widget', 'connector', 'new', true], ['playbooks/acme/acme-widget-lock', 'playbook', 'new', true]]);
  assert.match(report.reasons.join('; '), /changes playbooks or connectors, which act on tenants, so the owner always reviews them/);
  assert.match(md, /needs a maintainer review/);
});

test('CI: a broken playbook fails the checks, and a changed connector checks again the playbooks that call it', async () => {
  const broken = await ciRun(async (pr) => writeEntry(pr, playbookEntry({ yaml: TEMPLATE.replace("state: 'started'", 'state: started') })));
  assert.equal(broken.code, 1);
  assert.equal(broken.report.passed, false);
  assert.match(JSON.stringify(broken.report.entries), /single-quote it/);
  // The playbook is on the base branch; the pull request drops the function it calls.
  const dropped = await ciRun(async (pr, base) => {
    for (const root of [pr, base]) { await writeEntry(root, playbookEntry()); await writeEntry(root, connectorEntry()); }
    const yaml = CONNECTOR.replace(/    - name: getWidget[\s\S]*?(?=    - name: lockWidget)/, '');
    return writeEntry(pr, connectorEntry({ yaml, meta: { functions: { validate: 'lookup', lockWidget: 'reversible action' } } }));
  });
  assert.equal(dropped.report.passed, false);
  const pb = dropped.report.entries.find((e) => e.id === 'playbooks/acme/acme-widget-lock');
  assert.ok(pb && !pb.ok && pb.problems.some((p) => /no function getWidget/.test(p.message)), JSON.stringify(dropped.report.entries, null, 1));
});

test('CI: a connector can only call hosts that are on the base branch\'s allowlist', async () => {
  const { report } = await ciRun(async (pr) => {
    await writeFile(path.join(pr, 'connectors/allowed-hosts.json'), JSON.stringify({ acme: { ...HOSTS.acme, api: [...HOSTS.acme.api, 'api.example.net'] } }));
    const yaml = CONNECTOR.replace('- api.example.com\n', '- api.example.com\n                - api.example.net\n');
    return ['connectors/allowed-hosts.json', ...await writeEntry(pr, connectorEntry({ yaml }))];
  });
  assert.equal(report.passed, false);
  assert.match(JSON.stringify(report.entries), /api\.example\.net, which isn't on the allowlist/);
  assert.ok(report.entries.some((e) => e.id === 'connectors/allowed-hosts.json' && e.ok));
});

test('CI: a file directly under playbooks/ or connectors/ is refused, and a deleted entry needs review', async () => {
  const loose = await ciRun(async (pr) => {
    await mkdir(path.join(pr, 'playbooks'), { recursive: true });
    await writeFile(path.join(pr, 'playbooks/notes.md'), 'hi\n');
    return ['playbooks/notes.md'];
  });
  assert.equal(loose.report.passed, false);
  assert.match(loose.report.reasons.join('; '), /playbooks\/notes\.md is not inside playbooks\/<vendor>\/<name>\//);
  const gone = await ciRun(async (pr, base) => { await writeEntry(base, playbookEntry()); return ['playbooks/acme/acme-widget-lock/template.yaml']; });
  assert.ok(gone.report.entries.some((e) => e.id === 'playbooks/acme/acme-widget-lock' && e.status === 'deleted'));
  assert.match(gone.report.reasons.join('; '), /deletes playbooks\/acme\/acme-widget-lock/);
  assert.equal(gone.report.eligible, false);
});

test('CI: the repo\'s own allowlist and entries are in place for the checks', () => {
  assert.ok(existsSync(path.join(ROOT, 'connectors/allowed-hosts.json')));
});
