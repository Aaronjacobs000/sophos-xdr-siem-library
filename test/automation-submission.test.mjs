// The playbook and connector issue forms and their workflow: the job that reads the issue holds no
// write token, the job that writes takes only a library path and library file names, and the tool
// turns a filled-in form back into the exact files of every playbook and connector in the library.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, mkdir, writeFile, readdir, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS } from '../tools/lib/yaml.mjs';
import { loadAutomation } from '../tools/lib/fs-automation.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = await readFile(path.join(ROOT, '.github/workflows/automation-submission.yml'), 'utf8');
const LINES = WORKFLOW.split('\n');
const TOOL = path.join(ROOT, 'tools/automation-submission.mjs');

// The lines of each job under jobs:, keyed by job name. The workflow uses two-space indents.
function jobs() {
  const start = LINES.indexOf('jobs:');
  const out = {};
  let name = null;
  for (const line of LINES.slice(start + 1)) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (m) { name = m[1]; out[name] = []; continue; }
    if (name && (line.startsWith('    ') || !line.trim())) out[name].push(line);
    else if (name && !line.startsWith('  #')) name = null;
  }
  return out;
}

function permissions(lines, indent) {
  const at = lines.findIndex((l) => l === `${' '.repeat(indent)}permissions:`);
  if (at === -1) return null;
  const out = [];
  for (const l of lines.slice(at + 1)) {
    const m = new RegExp(`^ {${indent + 2}}([a-z-]+):\\s*(\\w+)\\s*$`).exec(l);
    if (!m) break;
    out.push([m[1], m[2]]);
  }
  return out;
}

const TOP = permissions(LINES.slice(0, LINES.indexOf('jobs:')), 0);
const effective = (lines) => permissions(lines, 4) ?? TOP;
const writes = (perms) => perms.filter(([, access]) => access === 'write');
const readsIssue = (lines) => lines.some((l) => /automation-submission\.mjs|validate-library\.mjs|github\.event\.issue\.body/.test(l));

test('automation submission workflow: the job that reads the issue has a read-only token and keeps no credentials', () => {
  assert.deepEqual(writes(TOP), [], 'the workflow-wide token is read-only');
  const all = jobs();
  const readers = Object.entries(all).filter(([, lines]) => readsIssue(lines));
  assert.ok(readers.length > 0);
  for (const [name, lines] of readers) {
    assert.deepEqual(writes(effective(lines)), [], `${name} reads the issue, so it can't write`);
    const checkouts = lines.filter((l) => /uses: actions\/checkout@/.test(l)).length;
    const noCredentials = lines.filter((l) => /^\s+persist-credentials: false\s*$/.test(l)).length;
    assert.equal(noCredentials, checkouts, `${name} keeps no credentials in its checkout`);
  }
  for (const [name, lines] of Object.entries(all)) {
    if (writes(effective(lines)).length) assert.ok(!readsIssue(lines), `${name} can write, so it doesn't read the issue`);
  }
});

test('automation submission workflow: it never merges', () => {
  assert.doesNotMatch(WORKFLOW, /github-gate\.mjs merge|gh pr merge|--auto\b/);
  assert.match(WORKFLOW, /--add-label "needs review"/);
});

// The run script of a workflow step, by the step's name.
function stepScript(name) {
  const at = LINES.findIndex((l) => l.trim() === `- name: ${name}`);
  const run = LINES.findIndex((l, i) => i > at && l.trim() === 'run: |');
  const indent = LINES[run].indexOf('run:') + 2;
  const body = [];
  for (const l of LINES.slice(run + 1)) {
    if (l.trim() && !l.startsWith(' '.repeat(indent))) break;
    body.push(l.slice(indent));
  }
  return body.join('\n');
}

// The publish job's guard: the part of "Open or update the pull request" before the branch is made.
const publishGuard = () => stepScript('Open or update the pull request').split('FOLDER="')[0];

// seed(ws) writes what main already holds; inspect(entryDir) looks at the result before cleanup.
async function guard(entry, extra, names = ['meta.json', 'template.yaml', 'SETUP.md'], { seed, inspect } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-auto-'));
  const files = path.join(dir, 'sub', 'entry');
  await mkdir(files, { recursive: true });
  await mkdir(path.join(dir, 'ws'), { recursive: true });
  for (const f of names) await writeFile(path.join(files, f), 'x\n');
  if (extra) await extra(files);
  if (seed) await seed(path.join(dir, 'ws'));
  const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', publishGuard()], {
    cwd: path.join(dir, 'ws'), encoding: 'utf8', env: { ...process.env, RUNNER_TEMP: dir, ENTRY: entry },
  });
  const entryDir = path.join(dir, 'ws', ...entry.split('/'));
  const written = r.status === 0 ? (await readdir(entryDir)).sort() : null;
  if (r.status === 0 && inspect) await inspect(entryDir);
  await rm(dir, { recursive: true, force: true });
  return { status: r.status, out: r.stdout + r.stderr, written };
}

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

test('automation submission workflow: the publish job takes only a playbook or connector path and their file names', { skip: process.platform === 'win32' }, async () => {
  const ok = await guard('playbooks/acme/block-url');
  assert.equal(ok.status, 0, ok.out);
  assert.deepEqual(ok.written, ['SETUP.md', 'meta.json', 'template.yaml']);
  const conn = await guard('connectors/acme/gateway', null, ['meta.json', 'connector.yaml', 'README.md']);
  assert.equal(conn.status, 0, conn.out);
  for (const entry of ['parsers/acme/pull-api', 'bridges/acme/x', '../.github', 'playbooks/acme/block-url/x', 'playbooks/../x/y', '/tmp/x', 'playbooks/Acme/block-url', 'playbooks/acme', '']) {
    const r = await guard(entry);
    assert.notEqual(r.status, 0, JSON.stringify(entry));
    assert.match(r.out, /not a library path/);
  }
  for (const [what, extra] of [
    ['a script', (d) => writeFile(path.join(d, 'run.sh'), 'echo hi\n')],
    ['a parser file', (d) => writeFile(path.join(d, 'ACME_STANDALONE.parser.txt'), 'x\n')],
    ['a symlink', (d) => symlink('/etc/hosts', path.join(d, 'README.md'))],
    ['a folder', (d) => mkdir(path.join(d, 'nested'))],
  ]) {
    const r = await guard('playbooks/acme/block-url', extra);
    assert.notEqual(r.status, 0, what);
    assert.match(r.out, /a file a library entry can't have/, what);
  }
});

test('automation submission workflow: a resubmission keeps the example.png main has and replaces the rest', { skip: process.platform === 'win32' }, async () => {
  const seed = async (ws) => {
    const d = path.join(ws, 'playbooks', 'acme', 'block-url');
    await mkdir(path.join(d, 'nested'), { recursive: true });
    for (const f of ['meta.json', 'template.yaml', 'SETUP.md', 'README.md', 'stale.txt']) await writeFile(path.join(d, f), 'old\n');
    await writeFile(path.join(d, 'example.png'), PNG);
  };
  let png = null;
  let meta = null;
  const r = await guard('playbooks/acme/block-url', null, undefined, { seed, inspect: async (d) => { png = await readFile(path.join(d, 'example.png')); meta = await readFile(path.join(d, 'meta.json'), 'utf8'); } });
  assert.equal(r.status, 0, r.out);
  // README.md, left out of this submission, goes; so do files and folders an entry can't have.
  assert.deepEqual(r.written, ['SETUP.md', 'example.png', 'meta.json', 'template.yaml']);
  assert.deepEqual(png, PNG);
  assert.equal(meta, 'x\n');
  // A symlink named example.png isn't kept, and the submission still can't bring its own.
  const link = await guard('playbooks/acme/block-url', null, undefined, { seed: async (ws) => {
    const d = path.join(ws, 'playbooks', 'acme', 'block-url');
    await mkdir(d, { recursive: true });
    await symlink('/etc/hosts', path.join(d, 'example.png'));
  } });
  assert.equal(link.status, 0, link.out);
  assert.deepEqual(link.written, ['SETUP.md', 'meta.json', 'template.yaml']);
  const own = await guard('playbooks/acme/block-url', (d) => writeFile(path.join(d, 'example.png'), PNG));
  assert.notEqual(own.status, 0);
  assert.match(own.out, /a file a library entry can't have/);
});

test('automation submission workflow: the check job hands over only the files the form wrote', { skip: process.platform === 'win32' }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-auto-hand-'));
  const entry = 'playbooks/acme/block-url';
  const d = path.join(dir, 'ws', ...entry.split('/'));
  await mkdir(d, { recursive: true });
  await mkdir(path.join(dir, 'sub'), { recursive: true });
  for (const f of ['meta.json', 'template.yaml', 'SETUP.md']) await writeFile(path.join(d, f), 'x\n');
  await writeFile(path.join(d, 'example.png'), PNG);
  await writeFile(path.join(dir, 'sub', 'changed.txt'), ['meta.json', 'template.yaml', 'SETUP.md'].map((f) => `${entry}/${f}`).join('\n') + '\n');
  await writeFile(path.join(dir, 'sub', 'report.md'), 'report\n');
  const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript('Hand the entry and the report to the publish job')], {
    cwd: path.join(dir, 'ws'), encoding: 'utf8', env: { ...process.env, RUNNER_TEMP: dir, ENTRY: entry },
  });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual((await readdir(path.join(dir, 'out', 'entry'))).sort(), ['SETUP.md', 'meta.json', 'template.yaml']);
  assert.deepEqual((await readdir(path.join(dir, 'out'))).sort(), ['entry', 'report.md']);
  await rm(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------- the tool

const form = async (kind) => toJS(parseYaml(await readFile(path.join(ROOT, `.github/ISSUE_TEMPLATE/${kind}-submission.yml`), 'utf8')));

// An issue body as GitHub writes it from the form, with values by field id.
async function issueBody(kind, values) {
  const parts = [];
  for (const b of (await form(kind)).body) {
    if (b.type === 'markdown') continue;
    let v = values[b.id];
    if (b.type === 'checkboxes') v = b.attributes.options.map((o) => `- [X] ${o.label}`).join('\n');
    else if (!v) v = '_No response_';
    else if (b.attributes.render) v = `\`\`\`${b.attributes.render}\n${v}\n\`\`\``;
    parts.push(`### ${b.attributes.label}\n\n${v}`);
  }
  return parts.join('\n\n');
}

// The form values that describe an entry already in the library.
function valuesOf(entry) {
  const m = entry.meta;
  const file = (name) => { const f = entry.files.find((x) => x.path === name); return f ? f.content.replace(/\n$/, '') : ''; };
  const t = m.tested || {};
  return {
    title: m.title, vendor: m.vendor, product: m.product, use_case: m.use_case, trigger: m.trigger,
    connections: (m.connections || []).join('\n'), requires: m.requires, risk_tier: m.risk_tier,
    rollback: m.rollback, mdr_note: m.mdr_note, connector: m.connector || '',
    validated: t.validated || '', tenant: t.tenant ? `${t.tenant.date} ${t.tenant.region}` : '',
    docs: (m.docs || []).join('\n'), license: m.license, summary: m.summary, notes: m.notes || '',
    auth: m.auth, functions: Object.entries(m.functions || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
    yaml: file(entry.kind === 'playbook' ? 'template.yaml' : 'connector.yaml'), setup: file('SETUP.md'), readme: file('README.md'),
  };
}

// seed(root) writes what the checkout already holds before the tool runs.
async function submit(kind, body, author = 'octocat', seed = null) {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-auto-tool-'));
  await writeFile(path.join(dir, 'body.txt'), body);
  if (seed) await seed(path.join(dir, 'out'));
  const r = spawnSync(process.execPath, [TOOL, '--kind', kind, '--body', path.join(dir, 'body.txt'), '--author', author, '--changed', path.join(dir, 'changed.txt'), '--root', path.join(dir, 'out')], { encoding: 'utf8' });
  const out = { status: r.status, out: r.stdout + r.stderr, id: (/ENTRY_ID=(\S+)/.exec(r.stdout) || [])[1], files: {} };
  if (r.status === 0) {
    out.changed = (await readFile(path.join(dir, 'changed.txt'), 'utf8')).trim().split('\n');
    for (const f of await readdir(path.join(dir, 'out', out.id))) out.files[f] = await readFile(path.join(dir, 'out', out.id, f), f === 'example.png' ? null : 'utf8');
  }
  await rm(dir, { recursive: true, force: true });
  return out;
}

const library = await loadAutomation(ROOT);

test('automation submission tool: every playbook and connector in the library comes back byte for byte from its form', async () => {
  const entries = [...library.playbooks, ...library.connectors];
  assert.ok(library.playbooks.length > 0 && library.connectors.length > 0);
  for (const e of entries) {
    for (const eol of ['\n', '\r\n']) {
      const body = (await issueBody(e.kind, valuesOf(e))).replace(/\n/g, eol);
      const r = await submit(e.kind, body, e.meta.author);
      assert.equal(r.status, 0, `${e.folder}/${e.id}: ${r.out}`);
      assert.equal(r.id, `${e.folder}/${e.id}`);
      // example.png can't come through an issue form; a pull request adds it.
      const want = Object.fromEntries(e.files.filter((f) => f.path !== 'example.png').map((f) => [f.path, f.content]));
      assert.deepEqual(Object.keys(r.files).sort(), Object.keys(want).sort(), `${e.id} files`);
      for (const [name, content] of Object.entries(want)) assert.equal(r.files[name], content, `${e.folder}/${e.id}/${name}`);
      assert.deepEqual(r.changed.sort(), Object.keys(want).map((f) => `${e.folder}/${e.id}/${f}`).sort());
    }
  }
});

test('automation submission tool: the issue author is the author, and the folder comes from slugs', async () => {
  const e = library.playbooks.find((x) => x.meta.connector === null);
  const values = { ...valuesOf(e), vendor: '../../Acme Corp', title: 'Block a URL / now!' };
  const r = await submit('playbook', await issueBody('playbook', values), 'someone-else');
  assert.equal(r.status, 0, r.out);
  assert.equal(r.id, 'playbooks/acme-corp/block-a-url-now');
  assert.equal(JSON.parse(r.files['meta.json']).author, 'someone-else');
  const none = await submit('playbook', await issueBody('playbook', { ...values, title: '!!!' }));
  assert.notEqual(none.status, 0);
  assert.match(none.out, /needs a vendor and a title/);
});

test('automation submission tool: a body without the form\'s sections, a bad tenant run or a bad function line is refused', async () => {
  const pb = valuesOf(library.playbooks[0]);
  const missing = await submit('playbook', 'just some text');
  assert.notEqual(missing.status, 0);
  assert.match(missing.out, /has no "Title" section/);
  const tenant = await submit('playbook', await issueBody('playbook', { ...pb, tenant: 'yesterday' }));
  assert.notEqual(tenant.status, 0);
  assert.match(tenant.out, /Ran in a tenant on/);
  const cn = valuesOf(library.connectors[0]);
  const fn = await submit('connector', await issueBody('connector', { ...cn, functions: 'lock reversible action' }));
  assert.notEqual(fn.status, 0);
  assert.match(fn.out, /function name, a colon and a risk tier/);
  const wrong = await submit('parser', await issueBody('playbook', pb));
  assert.notEqual(wrong.status, 0);
});

test('automation submission tool: empty optional fields leave notes and README.md out, and bullets come off list lines', async () => {
  const pb = valuesOf(library.playbooks[0]);
  const r = await submit('playbook', await issueBody('playbook', { ...pb, notes: '', readme: '', connector: '', validated: '', tenant: '', docs: '- https://example.com/a\n\n* https://example.com/b' }));
  assert.equal(r.status, 0, r.out);
  const meta = JSON.parse(r.files['meta.json']);
  assert.equal('notes' in meta, false);
  assert.equal(r.files['README.md'], undefined);
  assert.equal(meta.connector, null);
  assert.deepEqual(meta.tested, { validated: null, tenant: null });
  assert.deepEqual(meta.docs, ['https://example.com/a', 'https://example.com/b']);
});

test('automation submission tool: a resubmission keeps the entry\'s example.png, and an emptied field removes its file', async () => {
  const e = library.playbooks.find((x) => x.files.some((f) => f.path === 'README.md')) || library.playbooks[0];
  const at = (root) => path.join(root, e.folder, ...e.id.split('/'));
  const seed = async (root) => {
    await mkdir(path.join(at(root), 'nested'), { recursive: true });
    for (const f of ['meta.json', 'template.yaml', 'SETUP.md', 'README.md', 'stale.txt']) await writeFile(path.join(at(root), f), 'old\n');
    await writeFile(path.join(at(root), 'example.png'), PNG);
  };
  const r = await submit('playbook', await issueBody('playbook', { ...valuesOf(e), readme: '' }), e.meta.author, seed);
  assert.equal(r.status, 0, r.out);
  assert.deepEqual(Object.keys(r.files).sort(), ['SETUP.md', 'example.png', 'meta.json', 'template.yaml']);
  assert.deepEqual(r.files['example.png'], PNG);
  assert.notEqual(r.files['template.yaml'], 'old\n');
  // example.png wasn't written, so it isn't in the changed files the checks look at.
  assert.deepEqual(r.changed.sort(), ['SETUP.md', 'meta.json', 'template.yaml'].map((f) => `${e.folder}/${e.id}/${f}`));
  // A connector entry can't hold example.png, so a resubmission doesn't keep one.
  const c = library.connectors[0];
  const cr = await submit('connector', await issueBody('connector', valuesOf(c)), c.meta.author, async (root) => {
    const d = path.join(root, c.folder, ...c.id.split('/'));
    await mkdir(d, { recursive: true });
    await writeFile(path.join(d, 'example.png'), PNG);
  });
  assert.equal(cr.status, 0, cr.out);
  assert.equal(cr.files['example.png'], undefined);
});
