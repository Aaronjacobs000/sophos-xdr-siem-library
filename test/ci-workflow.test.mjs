// The CI workflow's secret scan: gitleaks comes from its release, pinned by version and checked
// against its SHA-256, and it scans the commits a pull request adds, or a push brings in, with
// --redact so a secret it finds stays out of the public log.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, mkdir, writeFile, chmod, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = await readFile(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
const LINES = WORKFLOW.split('\n');

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

// A step's env values and the body of its run: block, found by the step's name.
function step(name) {
  const at = LINES.findIndex((l) => l.trim() === `- name: ${name}`);
  assert.ok(at !== -1, `no step named ${name}`);
  const indent = LINES[at].indexOf('-') + 2;
  const own = [];
  for (const l of LINES.slice(at + 1)) {
    if (l.trim() && (l.length - l.trimStart().length < indent || l.trimStart().startsWith('- '))) break;
    own.push(l);
  }
  const env = {};
  const envAt = own.findIndex((l) => l.trim() === 'env:');
  if (envAt !== -1) {
    for (const l of own.slice(envAt + 1)) {
      const m = /^\s+([A-Z0-9_]+):\s*(.*)$/.exec(l);
      if (!m) break;
      env[m[1]] = m[2];
    }
  }
  const runAt = own.findIndex((l) => l.trim() === 'run: |');
  const runIndent = own[runAt].indexOf('run:') + 2;
  const body = [];
  for (const l of own.slice(runAt + 1)) {
    if (l.trim() && !l.startsWith(' '.repeat(runIndent))) break;
    body.push(l.slice(runIndent));
  }
  return { env, run: body.join('\n'), lines: own };
}

const bash = (script, cwd, env) => spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], { cwd, encoding: 'utf8', env: { ...process.env, ...env } });
const exists = (p) => access(p).then(() => true, () => false);

test('CI workflow: the secret scan job is read-only and runs only trusted, pinned steps', () => {
  const all = jobs();
  assert.ok(all.secrets, 'there is a secrets job');
  const lines = all.secrets;
  assert.ok(!lines.some((l) => /^\s+permissions:/.test(l)), 'it keeps the workflow-wide read-only token');
  assert.match(WORKFLOW, /^permissions:\n {2}contents: read\n/m);
  const uses = lines.filter((l) => /^\s+- uses: /.test(l));
  assert.ok(uses.length > 0 && uses.every((l) => /- uses: actions\/[a-z-]+@[0-9a-f]{40} # v/.test(l)), uses.join('\n'));
  assert.ok(lines.some((l) => /^\s+fetch-depth: 0\s*$/.test(l)), 'the whole history is fetched, so the base commit is there');
  assert.ok(lines.some((l) => /^\s+persist-credentials: false\s*$/.test(l)));
  // Values from the event reach the scripts only through env.
  for (const name of ['Install gitleaks', 'Scan the new commits']) assert.ok(!step(name).run.includes('${{'), name);
  const { env } = step('Install gitleaks');
  assert.match(env.GITLEAKS_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(env.GITLEAKS_SHA256, /^[0-9a-f]{64}$/);
  assert.match(step('Scan the new commits').run, /gitleaks" git .*--redact/);
});

test('CI workflow: gitleaks is installed only when the download matches the pinned SHA-256', { skip: process.platform === 'win32' }, async () => {
  const { env, run } = step('Install gitleaks');
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gitleaks-'));
  try {
    const temp = path.join(dir, 'runner');
    const bin = path.join(dir, 'bin');
    const pkg = path.join(dir, 'pkg');
    await mkdir(temp);
    await mkdir(bin);
    await mkdir(pkg);
    // A stand-in release: a gitleaks that prints a version, packed the way the release is.
    await writeFile(path.join(pkg, 'gitleaks'), '#!/bin/sh\necho "fake gitleaks"\n');
    await chmod(path.join(pkg, 'gitleaks'), 0o755);
    await writeFile(path.join(pkg, 'README.md'), 'not extracted\n');
    const tarball = path.join(dir, 'release.tar.gz');
    execFileSync('tar', ['-czf', tarball, '-C', pkg, 'gitleaks', 'README.md']);
    const good = createHash('sha256').update(await readFile(tarball)).digest('hex');
    // curl writes the stand-in release, and records the URL it was asked for.
    await writeFile(path.join(bin, 'curl'), `#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -*) shift;; *) echo "$1" > "${dir}/url.txt"; shift;; esac; done\ncp "${tarball}" "$out"\n`);
    await chmod(path.join(bin, 'curl'), 0o755);
    const PATH = `${bin}:${process.env.PATH}`;

    // The pinned hash doesn't match the stand-in, so nothing is extracted and the step fails.
    const refused = bash(run, temp, { ...env, RUNNER_TEMP: temp, PATH });
    assert.notEqual(refused.status, 0, refused.stdout + refused.stderr);
    assert.equal(await exists(path.join(temp, 'gitleaks')), false);
    assert.equal((await readFile(path.join(dir, 'url.txt'), 'utf8')).trim(),
      `https://github.com/gitleaks/gitleaks/releases/download/v${env.GITLEAKS_VERSION}/gitleaks_${env.GITLEAKS_VERSION}_linux_x64.tar.gz`);

    // With a matching hash it installs the binary alone and runs it.
    const installed = bash(run, temp, { ...env, GITLEAKS_SHA256: good, RUNNER_TEMP: temp, PATH });
    assert.equal(installed.status, 0, installed.stdout + installed.stderr);
    assert.match(installed.stdout, /fake gitleaks/);
    assert.equal(await exists(path.join(temp, 'README.md')), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CI workflow: the scan covers a pull request\'s own commits, or the commits a push brings in', { skip: process.platform === 'win32' }, async () => {
  const { run } = step('Scan the new commits');
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-scan-'));
  try {
    const repo = path.join(dir, 'repo');
    const temp = path.join(dir, 'runner');
    await mkdir(repo);
    await mkdir(temp);
    // gitleaks records its arguments.
    await writeFile(path.join(temp, 'gitleaks'), `#!/bin/sh\nprintf '%s\\n' "$@" > "${dir}/args.txt"\n`);
    await chmod(path.join(temp, 'gitleaks'), 0o755);
    const git = (...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...a], { cwd: repo, encoding: 'utf8' }).trim();
    git('init', '-q');
    const commit = async (n) => { await writeFile(path.join(repo, `f${n}.txt`), `${n}\n`); git('add', '.'); git('commit', '-qm', `c${n}`); return git('rev-parse', 'HEAD'); };
    const base = await commit(1);
    await commit(2);
    const head = await commit(3);
    const scan = async (env) => {
      const r = bash(run, repo, { RUNNER_TEMP: temp, EVENT: '', BASE_SHA: '', HEAD_SHA: '', BEFORE: '', AFTER: '', ...env });
      assert.equal(r.status, 0, r.stdout + r.stderr);
      const args = (await readFile(path.join(dir, 'args.txt'), 'utf8')).trim().split('\n');
      assert.ok(args.includes('--redact'), args.join(' '));
      assert.equal(args[0], 'git');
      return { range: args.find((a) => a.startsWith('--log-opts=')).slice('--log-opts='.length), out: r.stdout };
    };
    const pr = await scan({ EVENT: 'pull_request', BASE_SHA: base, HEAD_SHA: head });
    assert.equal(pr.range, `${base}..${head}`);
    assert.match(pr.out, /Scanning 2 commits/);
    assert.equal((await scan({ EVENT: 'push', BEFORE: base, AFTER: head })).range, `${base}..${head}`);
    // A push with no earlier commit, or one this clone doesn't have, scans the whole history.
    for (const before of ['0000000000000000000000000000000000000000', '', 'f'.repeat(40)]) {
      const all = await scan({ EVENT: 'push', BEFORE: before, AFTER: head });
      assert.equal(all.range, head, before);
      assert.match(all.out, /Scanning 3 commits/);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CI workflow: every bridge test server notices shutdown within 0.05 s, so the tests job stays well inside its limit', async () => {
  // serve_forever looks for a shutdown request every poll_interval, 0.5 s by default, and the bridge
  // suites start and stop a server in nearly every test. At the default, the shutdowns alone took
  // most of the tests job's 10 minutes.
  const { readdir } = await import('node:fs/promises');
  const limit = Number(/^ {4}timeout-minutes: (\d+)$/m.exec(jobs().tests.join('\n'))[1]);
  assert.ok(limit <= 10, `tests job limit ${limit}`);
  let servers = 0;
  for (const dir of (await readdir(path.join(ROOT, 'bridges'), { withFileTypes: true })).filter((d) => d.isDirectory())) {
    for (const file of (await readdir(path.join(ROOT, 'bridges', dir.name))).filter((f) => /^test_.*\.py$/.test(f))) {
      const src = await readFile(path.join(ROOT, 'bridges', dir.name, file), 'utf8');
      for (const line of src.split('\n').filter((l) => l.includes('serve_forever'))) {
        servers++;
        const m = /serve_forever, args=\((\d*\.?\d+),\)/.exec(line);
        assert.ok(m && Number(m[1]) <= 0.05, `${dir.name}/${file}: ${line.trim()}`);
      }
    }
  }
  assert.ok(servers >= 100, `found ${servers} test servers`);
});

test('CI workflow: the tests job installs the secrets job\'s gitleaks before the unit tests, and puts only it on the PATH', { skip: process.platform === 'win32' }, async () => {
  const lines = jobs().tests;
  const names = lines.map((l) => /^\s+- name: (.*)$/.exec(l)).filter(Boolean).map((m) => m[1]);
  assert.ok(names.indexOf('Install gitleaks for the port tests') !== -1 && names.indexOf('Install gitleaks for the port tests') < names.indexOf('Unit tests'), names.join(', '));
  const own = step('Install gitleaks for the port tests');
  const scan = step('Install gitleaks');
  assert.deepEqual(own.env, scan.env, 'the same version and checksum as the secrets job');
  assert.ok(!own.run.includes('${{'));
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gitleaks-path-'));
  try {
    const temp = path.join(dir, 'runner');
    const bin = path.join(dir, 'bin');
    const pkg = path.join(dir, 'pkg');
    await mkdir(temp);
    await mkdir(bin);
    await mkdir(pkg);
    await writeFile(path.join(pkg, 'gitleaks'), '#!/bin/sh\necho "fake gitleaks"\n');
    await chmod(path.join(pkg, 'gitleaks'), 0o755);
    await writeFile(path.join(pkg, 'README.md'), 'not extracted\n');
    const tarball = path.join(dir, 'release.tar.gz');
    execFileSync('tar', ['-czf', tarball, '-C', pkg, 'gitleaks', 'README.md']);
    const good = createHash('sha256').update(await readFile(tarball)).digest('hex');
    await writeFile(path.join(bin, 'curl'), `#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -*) shift;; *) shift;; esac; done\ncp "${tarball}" "$out"\n`);
    await chmod(path.join(bin, 'curl'), 0o755);
    const ghPath = path.join(dir, 'github-path.txt');
    await writeFile(ghPath, '');
    const env = { ...own.env, RUNNER_TEMP: temp, PATH: `${bin}:${process.env.PATH}`, GITHUB_PATH: ghPath };
    // The pinned hash doesn't match the stand-in: nothing is installed or added to the PATH.
    assert.notEqual(bash(own.run, temp, env).status, 0);
    assert.equal(await readFile(ghPath, 'utf8'), '');
    const r = bash(own.run, temp, { ...env, GITLEAKS_SHA256: good });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const added = (await readFile(ghPath, 'utf8')).trim();
    assert.equal(added, path.join(temp, 'gitleaks-bin'));
    const { readdir } = await import('node:fs/promises');
    assert.deepEqual(await readdir(added), ['gitleaks']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
