// The port of gitleaks' generic-api-key rule (studio/core/gitleaks.js): it flags what CI's gitleaks
// flags, the library check reports it, and its copies of the repo's .gitleaks.toml allowlists and
// the gitleaks version match the repo's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { goRegex, findGenericApiKeys, gitleaksProblems, REPO_ALLOWLISTS, GITLEAKS_VERSION } from '../studio/core/gitleaks.js';
import { RULE, GLOBAL_ALLOWLISTS } from '../studio/core/gitleaks-rule.js';
import { portFromConfig, renderModule, setCiVersion, setAttributionVersion, tarballSha256 } from '../tools/lib/gitleaks-port.mjs';
import { readToml as readTomlLib } from '../tools/lib/toml.mjs';
import { validateEntry } from '../studio/core/library.js';
import { loadEntryFromDir } from '../tools/lib/fs-library.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// A synthetic NEC UNIVERGE IX filter line: gitleaks reads the ACL name access1 as a key and the
// interface as its value.
const NEC = '<190>Oct 14 09:20:11 ix01 FLT.001: permit tcp 192.0.2.10.51522 > 198.51.100.20.443, match access1, GigaEthernet0.1 in';

// The tables and keys of .gitleaks.toml: enough TOML for that file (tables, arrays of tables,
// strings, booleans and arrays).
function readToml(text) {
  const doc = {};
  let table = doc;
  let i = 0;
  const skip = () => {
    for (;;) {
      while (i < text.length && /\s/.test(text[i])) i++;
      if (text[i] !== '#') return;
      while (i < text.length && text[i] !== '\n') i++;
    }
  };
  const value = () => {
    skip();
    if (text.startsWith("'''", i)) {
      const end = text.indexOf("'''", i + 3);
      const s = text.slice(i + 3, end).replace(/^\n/, '');
      i = end + 3;
      return s;
    }
    if (text[i] === "'") { const end = text.indexOf("'", i + 1); const s = text.slice(i + 1, end); i = end + 1; return s; }
    if (text[i] === '"') {
      let s = '';
      for (i++; text[i] !== '"'; i++) {
        if (text[i] !== '\\') { s += text[i]; continue; }
        const e = text[++i];
        assert.ok(e in { n: 1, t: 1, '"': 1, '\\': 1 }, `escape \\${e} in .gitleaks.toml`);
        s += { n: '\n', t: '\t', '"': '"', '\\': '\\' }[e];
      }
      i++;
      return s;
    }
    if (text[i] === '[') {
      const list = [];
      for (i++; ;) {
        skip();
        if (text[i] === ']') { i++; return list; }
        list.push(value());
        skip();
        if (text[i] === ',') i++;
      }
    }
    const m = /^(?:true|false)\b/.exec(text.slice(i));
    assert.ok(m, `unexpected ${JSON.stringify(text.slice(i, i + 20))} in .gitleaks.toml`);
    i += m[0].length;
    return m[0] === 'true';
  };
  for (;;) {
    skip();
    if (i >= text.length) return doc;
    if (text.startsWith('[[', i)) {
      const end = text.indexOf(']]', i);
      (doc[text.slice(i + 2, end).trim()] ||= []).push(table = {});
      i = end + 2;
    } else if (text[i] === '[') {
      const end = text.indexOf(']', i);
      table = doc[text.slice(i + 1, end).trim()] = {};
      i = end + 1;
    } else {
      const m = /^([A-Za-z0-9_-]+)\s*=/.exec(text.slice(i));
      assert.ok(m, `unexpected ${JSON.stringify(text.slice(i, i + 20))} in .gitleaks.toml`);
      i += m[0].length;
      table[m[1]] = value();
    }
  }
}

test('gitleaks regexes: Go syntax translates exactly, case folding and all', () => {
  // (?-i:...) keeps its part case-sensitive inside (?i).
  const api = goRegex('(?i)x(?:(?-i:[Aa]pi|API)|key)y');
  for (const s of ['xApiy', 'XapiY', 'xAPIy', 'xKEYy']) assert.ok(api.test(s), s);
  assert.equal(api.test('xaPIy'), false);
  // Go folds the Kelvin sign into k and the long s into s, in literals, ranges and \w.
  assert.ok(goRegex('(?i)^key$').test('\u212Aey'));
  assert.ok(goRegex('(?i)^secret$').test('\u017Fecret'));
  assert.ok(goRegex('(?i)^[a-z]+$').test('\u017F\u212A'));
  assert.ok(goRegex('(?i)^\\w$').test('\u212A'));
  assert.equal(goRegex('^\\w$').test('\u212A'), false);
  // \s is [\t\n\f\r ], . leaves out only \n, and \z is the end of the text.
  assert.ok(goRegex('^a\\sb$').test('a\fb'));
  for (const s of ['a\vb', 'a\u00a0b']) assert.equal(goRegex('^a\\sb$').test(s), false);
  assert.ok(goRegex('^a.b$').test('a\rb'));
  assert.equal(goRegex('^a.b$').test('a\nb'), false);
  assert.ok(goRegex('x(?:\\n|\\z)').test('x'));
  // A brace that isn't a repeat is a literal, and a (?i) lasts to the end of its group.
  assert.ok(goRegex('^\\{\\d{0,2}}$').test('{12}'));
  assert.ok(goRegex('^\\${(?:[A-Z_]+|[a-z_]+)}$').test('${HOME}'));
  assert.ok(goRegex('(?:(?i)^true|false|null$)').test('NULL'));
  assert.equal(goRegex('(?:(?i)a)b').test('AB'), false);
  for (const src of ['\\bkey', '(?s)a', '[[:alpha:]]', '\\pL', '(?P<n>a)']) assert.throws(() => goRegex(src), src);
});

test('gitleaks port: flags the generic-api-key findings CI flagged on an NEC UNIVERGE IX entry', () => {
  const samples = `${NEC}\n<190>Oct 14 09:20:12 ix01 FLT.001: permit tcp 192.0.2.10.51523 > 198.51.100.20.443, match acl1, GigaEthernet0.1 in\n`;
  const found = findGenericApiKeys(samples, 'parsers/nec/univerge-ix/samples.log');
  assert.deepEqual(found.map((f) => `${f.line} ${f.key} ${f.secret}`), ['1 access1 GigaEthernet0.1']);
  assert.equal(findGenericApiKeys(`!SAMPLE=${NEC}\n# comment\n`, 'parsers/nec/univerge-ix/NEC_IX_SYSLOG_PARENT.parser.txt').length, 1);
  const [p] = gitleaksProblems(samples, 'parsers/nec/univerge-ix/samples.log');
  assert.equal(p.level, 'error');
  assert.equal(p.message, 'CI\'s secret scan (gitleaks generic-api-key) would flag "access1" with the value "Giga..."; change the key name or the value.');
  assert.ok(!p.message.includes('GigaEthernet0.1') && !p.text.includes('GigaEthernet0.1'));
});

test('gitleaks port: lets through what the rule and its allowlists let through', () => {
  const none = (text, file = 'parsers/acme/gateway/samples.log') => assert.deepEqual(findGenericApiKeys(text, file), [], text);
  none('match acl1, GigaEthernet0.1 in');
  // Entropy at or under 3.5, a stopword in the value, a key the rule allowlist names, and a value
  // of letters only.
  none('password=Hunter2xyz9');
  none('"auth_method":"saml2-redirect-binding-9"');
  none('"access_id":"q7Wd2Rk9Xz4Lp8Vn"');
  none('password=WqZxRtYpLkMnBv');
  // A line with gitleaks:allow on it.
  none('"auth_token":"q7Wd2Rk9Xz4Lp8Vn" # gitleaks:allow');
});

test('validateEntry reports what CI\'s gitleaks would flag in any entry file, at its repo path', async () => {
  const e = await loadEntryFromDir(path.join(ROOT, 'parsers/h3c/comware-h3c-and-hpe'), ROOT);
  const flagged = (v) => v.problems.filter((p) => p.code === 'gitleaks').map((p) => `${p.file}:${p.line}`);
  assert.deepEqual(flagged(validateEntry(e, {})), []);
  // gitleaks scans expected.json and README.md too, which the sample scan leaves out. The UUID
  // record ID passes in samples.log, where the repo's .gitleaks.toml allows it, and not elsewhere.
  const uuid = '{"claims_token_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6"}';
  const add = { 'expected.json': NEC, 'samples.log': uuid };
  const files = e.files.map((f) => (add[f.path] ? { ...f, content: `${f.content}${add[f.path]}\n` } : f));
  files.push({ path: 'README.md', content: `# Notes\n\n${NEC}\n${uuid}\n` });
  const v = validateEntry({ ...e, files }, {});
  const at = e.files.find((f) => f.path === 'expected.json').content.split('\n').length;
  assert.deepEqual(flagged(v), [`expected.json:${at}`, 'README.md:3', 'README.md:4']);
  assert.equal(v.ok, false);
});

test('the port\'s copies of the .gitleaks.toml allowlists and gitleaks version match the repo\'s', async () => {
  const toml = readToml(await readFile(path.join(ROOT, '.gitleaks.toml'), 'utf8'));
  assert.deepEqual(toml.extend, { useDefault: true });
  // Allowlists scoped to library entries are ported; the rest are scoped to files outside parsers/.
  const ported = [];
  for (const a of toml.allowlists) {
    assert.ok(Array.isArray(a.paths) && a.paths.length, `${a.description}: an allowlist without paths applies to library entries, so port it`);
    const inLibrary = a.paths.map((p) => p.startsWith('^parsers/'));
    assert.ok(inLibrary.every((x) => x === inLibrary[0]), `${a.description}: paths both in and out of parsers/`);
    if (inLibrary[0]) ported.push(a);
    else for (const p of a.paths) assert.match(p, /^\^[a-z.]/, `${a.description}: ${p} must be anchored to a folder outside parsers/`);
  }
  assert.deepEqual(REPO_ALLOWLISTS, ported);
  for (const a of REPO_ALLOWLISTS) for (const r of [...a.paths, ...a.regexes]) assert.doesNotThrow(() => goRegex(r), r);
  // Both CI jobs that install gitleaks, the unit tests' and the secret scan's, take the version the
  // port came from, with one checksum.
  const ci = await readFile(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const versions = [...ci.matchAll(/GITLEAKS_VERSION: (\S+)/g)].map((m) => m[1]);
  assert.equal(versions.length, 2, 'the tests and secrets jobs each install gitleaks');
  for (const v of versions) assert.equal(v, GITLEAKS_VERSION, `CI installs gitleaks ${v} and the port came from ${GITLEAKS_VERSION}: run node tools/port-gitleaks.mjs ${v}`);
  assert.equal(new Set([...ci.matchAll(/GITLEAKS_SHA256: (\S+)/g)].map((m) => m[1])).size, 1, 'the two jobs install gitleaks with different checksums');
});

// The Appgate SDP shape CI flagged in parser files: a UUID record ID under a key ending in id, in a
// !SAMPLE line.
const APPGATE = 'parsers/appgate/sdp/APPGATE_SDP_JSON_PARENT.parser.txt';
const appgate = (value) => `!SAMPLE={"version":2,"log":{"claims_token_id":"${value}","client_ip":"203.0.113.45"}}\n!SCHEMA=scwx.generic\n`;
const UUID = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
// The UUID allowlist as it was, for samples.log only.
const SAMPLES_ONLY = [{ ...REPO_ALLOWLISTS[0], paths: [String.raw`^parsers/[^/]+/[^/]+/samples\.log$`] }];

test('a UUID record ID under a key ending in id passes in a library parser file, and nothing else does', () => {
  assert.equal(findGenericApiKeys(appgate(UUID), APPGATE, { allowlists: SAMPLES_ONLY }).length, 1);
  assert.deepEqual(findGenericApiKeys(appgate(UUID), APPGATE), []);
  // Another value under the key, the UUID under a key that doesn't end in id, and the UUID in any
  // other file are still flagged.
  assert.equal(findGenericApiKeys(appgate('Synthetic7Qv2Lm9Rt4'), APPGATE).length, 1);
  assert.equal(findGenericApiKeys(appgate(UUID).replace('_id"', '"'), APPGATE).length, 1);
  for (const file of ['parsers/appgate/sdp/README.md', 'parsers/appgate/sdp/expected.json', 'parsers/appgate/APPGATE_SDP_JSON_PARENT.parser.txt', 'test/APPGATE_SDP_JSON_PARENT.parser.txt']) {
    assert.equal(findGenericApiKeys(appgate(UUID), file).length, 1, file);
  }
});

const installed = spawnSync('gitleaks', ['version'], { encoding: 'utf8' });
const realGitleaks = installed.status === 0 && installed.stdout.trim() === GITLEAKS_VERSION;

// A gitleaks config that extends the default with these allowlists, as .gitleaks.toml writes them.
const configOf = (allowlists) => ['[extend]', 'useDefault = true', ...allowlists.flatMap((a) => [
  '', '[[allowlists]]', `description = ${JSON.stringify(a.description)}`, `targetRules = ${JSON.stringify(a.targetRules)}`, `condition = "${a.condition}"`,
  `paths = [${a.paths.map((x) => `'''${x}'''`).join(', ')}]`, `regexTarget = "${a.regexTarget}"`, `regexes = [${a.regexes.map((x) => `'''${x}'''`).join(', ')}]`,
])].join('\n') + '\n';

test('gitleaks itself flags what the port flags, before and after the parser file allowlist', { skip: !realGitleaks && `needs gitleaks ${GITLEAKS_VERSION} on the PATH` }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gitleaks-'));
  try {
    const files = {
      [APPGATE]: appgate(UUID),
      'parsers/appgate/sdp/APPGATE_SDP_JSON_CHILD_NETFLOW.parser.txt': appgate('Synthetic7Qv2Lm9Rt4'),
      'parsers/nec/univerge-ix/samples.log': `${NEC}\n`,
    };
    for (const [file, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(dir, 'src', file)), { recursive: true });
      await writeFile(path.join(dir, 'src', file), content);
    }
    await writeFile(path.join(dir, 'old.toml'), configOf(SAMPLES_ONLY));
    const flagged = async (config) => {
      const report = path.join(dir, 'report.json');
      const r = spawnSync('gitleaks', ['dir', '--no-banner', '--config', config, '--report-format', 'json', '--report-path', report, '--exit-code', '0', '.'], { cwd: path.join(dir, 'src'), encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
      return JSON.parse(await readFile(report, 'utf8')).map((f) => `${f.File}:${f.StartLine} ${f.Secret}`).sort();
    };
    const ported = (allowlists) => Object.entries(files).flatMap(([file, content]) => findGenericApiKeys(content, file, { allowlists }).map((f) => `${file}:${f.line} ${f.secret}`)).sort();
    const before = await flagged(path.join(dir, 'old.toml'));
    const after = await flagged(path.join(ROOT, '.gitleaks.toml'));
    const others = ['parsers/appgate/sdp/APPGATE_SDP_JSON_CHILD_NETFLOW.parser.txt:1 Synthetic7Qv2Lm9Rt4', 'parsers/nec/univerge-ix/samples.log:1 GigaEthernet0.1'];
    assert.deepEqual(before, [...others, `${APPGATE}:1 ${UUID}`].sort());
    assert.deepEqual(after, others);
    assert.deepEqual(ported(SAMPLES_ONLY), before);
    assert.deepEqual(ported(REPO_ALLOWLISTS), after);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// A config in the shape of gitleaks' config/gitleaks.toml: the global allowlist, another rule, and
// generic-api-key with allowlists of each kind.
const CONFIG = `title = "gitleaks config"
minVersion = "v8.25.0"

# TODO: change to [[allowlists]]
[allowlist]
description = "global allow lists"
paths = [
    '''gitleaks\\.toml''',
    '''(?:^|/)node_modules(?:/.*)?$''',
]
regexes = [
    '''(?i)^true|false|null$''',
]
stopwords = [
    "abcdefghijklmnopqrstuvwxyz",
]

[[rules]]
id = "github-app-token"
description = "Identified a GitHub App Token."
regex = '''(?:ghu|ghs)_[0-9a-zA-Z]{36}'''
entropy = 3
keywords = [
    "ghu_","ghs_",
]
[[rules.allowlists]]
paths = [
    '''(?:^|/)@octokit/auth-token/README\\.md$''',
]

[[rules]]
id = "generic-api-key"
description = "Detected a Generic API Key."
regex = '''(?i)[\\w.-]{0,50}?(?:key|token)[\\s'"]{0,3}(?:=|:)([\\w.=-]{10,150})'''
entropy = 3.5
keywords = [
    "key",
    "token",
]
[[rules.allowlists]]
regexes = [
    '''^[a-zA-Z_.-]+$''',
]
[[rules.allowlists]]
description = "Allowlist for Generic API Keys"
regexTarget = "match"
regexes = [
    '''(?i)(?:access(?:ibility|or)|author)''',
]
stopwords = [
    "000000",
    "about",
]
[[rules.allowlists]]
condition = "AND"
paths = [
    '''\\.bb$''','''\\.inc$''',
]
regexTarget = "line"
regexes = [
    '''LICENSE[^=]*=\\s*"[^"]+''',
]
`;

test('port tool: reads the rule and the global allowlist from gitleaks\' config, and nothing it can\'t port', () => {
  const { rule, globals } = portFromConfig(CONFIG);
  assert.deepEqual(rule, {
    id: 'generic-api-key',
    regex: String.raw`(?i)[\w.-]{0,50}?(?:key|token)[\s'"]{0,3}(?:=|:)([\w.=-]{10,150})`,
    entropy: 3.5,
    keywords: ['key', 'token'],
    allowlists: [
      { regexes: ['^[a-zA-Z_.-]+$'] },
      { description: 'Allowlist for Generic API Keys', regexTarget: 'match', regexes: ['(?i)(?:access(?:ibility|or)|author)'], stopwords: ['000000', 'about'] },
      { condition: 'AND', regexTarget: 'line', paths: [String.raw`\.bb$`, String.raw`\.inc$`], regexes: [String.raw`LICENSE[^=]*=\s*"[^"]+`] },
    ],
  });
  assert.deepEqual(globals, [{ description: 'global allow lists', paths: [String.raw`gitleaks\.toml`, '(?:^|/)node_modules(?:/.*)?$'], regexes: ['(?i)^true|false|null$'], stopwords: ['abcdefghijklmnopqrstuvwxyz'] }]);
  // A later config with [[allowlists]] instead of [allowlist] reads the same.
  assert.deepEqual(portFromConfig(CONFIG.replace('[allowlist]', '[[allowlists]]')).globals, globals);
  // A field the port's matching doesn't implement stops the tool, and so does a missing rule.
  assert.throws(() => portFromConfig(CONFIG.replace('entropy = 3.5', 'entropy = 3.5\nsecretGroup = 1')), /secretGroup, which the port doesn't implement/);
  assert.throws(() => portFromConfig(CONFIG.replace('condition = "AND"', 'condition = "AND"\ncommits = ["abc"]')), /commits, which the port doesn't implement/);
  assert.throws(() => portFromConfig(CONFIG.replace('id = "generic-api-key"', 'id = "generic-key"')), /0 generic-api-key rules/);
});

test('port tool: the module it writes holds what it read, and CI moves to the same version', async () => {
  const { rule, globals } = portFromConfig(CONFIG);
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-port-'));
  try {
    await writeFile(path.join(dir, 'rule.mjs'), renderModule({ version: '9.1.2', source: 'https://example.com/gitleaks.toml', sha256: 'a'.repeat(64), rule, globals }));
    const m = await import(pathToFileURL(path.join(dir, 'rule.mjs')).href);
    assert.equal(m.GITLEAKS_VERSION, '9.1.2');
    assert.deepEqual(m.RULE, rule);
    assert.deepEqual(m.GLOBAL_ALLOWLISTS, globals);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  const ci = await readFile(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const sha = 'b'.repeat(64);
  const moved = setCiVersion(ci, '9.1.2', sha);
  assert.deepEqual([...moved.matchAll(/GITLEAKS_VERSION: (\S+)/g)].map((x) => x[1]), ['9.1.2', '9.1.2']);
  assert.deepEqual([...moved.matchAll(/GITLEAKS_SHA256: (\S+)/g)].map((x) => x[1]), [sha, sha]);
  assert.equal(moved.split('\n').length, ci.split('\n').length);
  assert.throws(() => setCiVersion('jobs:\n', '9.1.2', sha), /0 GITLEAKS_VERSION/);
  assert.equal(tarballSha256(`${'c'.repeat(64)}  gitleaks_9.1.2_darwin_arm64.tar.gz\n${sha}  gitleaks_9.1.2_linux_x64.tar.gz\n`, '9.1.2'), sha);
  assert.throws(() => tarballSha256(`${sha}  gitleaks_9.1.1_linux_x64.tar.gz\n`, '9.1.2'), /no checksum/);
  // ATTRIBUTIONS.md credits the version the port came from, and the tool moves it too.
  const credits = await readFile(path.join(ROOT, 'ATTRIBUTIONS.md'), 'utf8');
  const named = [...credits.matchAll(/\[gitleaks\]\(https:\/\/github\.com\/gitleaks\/gitleaks\) v(\S+),/g)].map((x) => x[1]);
  assert.deepEqual(named, [GITLEAKS_VERSION, GITLEAKS_VERSION]);
  assert.deepEqual([...setAttributionVersion(credits, '9.1.2').matchAll(/\[gitleaks\]\(https:\/\/github\.com\/gitleaks\/gitleaks\) v(\S+),/g)].map((x) => x[1]), ['9.1.2', '9.1.2']);
});

test('the TOML reader reads gitleaks\' config files, and refuses what it doesn\'t know', async () => {
  const text = await readFile(path.join(ROOT, '.gitleaks.toml'), 'utf8');
  assert.deepEqual(readTomlLib(text), readToml(text));
  assert.deepEqual(readTomlLib('a = 1\nb = -2.5\nc = "x\\ty"\nd = true\n[[t.u]]\n[[t.u]]\ne = [1, 2,]\n'), { a: 1, b: -2.5, c: 'x\ty', d: true, t: { u: [{}, { e: [1, 2] }] } });
  for (const bad of ['a = """x"""\n', 'a = 1\na = 2\n', 'a = 1 b = 2\n', 'a = {x = 1}\n', 'a = 1979-05-27\n']) assert.throws(() => readTomlLib(bad), /TOML/, bad);
});

test('the port came from gitleaks\' own rule: the shapes its matching expects', () => {
  assert.equal(RULE.id, 'generic-api-key');
  assert.ok(RULE.regex && RULE.entropy > 0 && RULE.keywords.length, JSON.stringify(RULE).slice(0, 200));
  for (const a of [...RULE.allowlists, ...GLOBAL_ALLOWLISTS]) for (const r of [...(a.paths || []), ...(a.regexes || [])]) assert.doesNotThrow(() => goRegex(r), r);
});

// Every library file git tracks, by its path from the repo root.
async function libraryFiles() {
  const out = execFileSync('git', ['ls-files', '-z', '--', 'parsers', 'playbooks', 'connectors'], { cwd: ROOT, encoding: 'utf8' }).split('\0').filter(Boolean);
  return Promise.all(out.map(async (file) => ({ file, content: await readFile(path.join(ROOT, file), 'utf8') })));
}

test('gitleaks itself, with all its rules and decoding, finds nothing in the library the port misses', { skip: !realGitleaks && `needs gitleaks ${GITLEAKS_VERSION} on the PATH` }, async () => {
  // With gitleaks' default config alone, no repo allowlists, the library has findings. The port
  // must make each of them, and each must be its rule's, none found only after decoding.
  const dir = await mkdtemp(path.join(tmpdir(), 'ps-gitleaks-lib-'));
  try {
    const files = await libraryFiles();
    for (const { file, content } of files) {
      await mkdir(path.dirname(path.join(dir, 'src', file)), { recursive: true });
      await writeFile(path.join(dir, 'src', file), content);
    }
    await writeFile(path.join(dir, 'default.toml'), '[extend]\nuseDefault = true\n');
    const report = path.join(dir, 'report.json');
    const r = spawnSync('gitleaks', ['dir', '--no-banner', '--config', path.join(dir, 'default.toml'), '--report-format', 'json', '--report-path', report, '--exit-code', '0', '.'], { cwd: path.join(dir, 'src'), encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const found = JSON.parse(await readFile(report, 'utf8'));
    assert.ok(found.length > 0, 'without the repo allowlists the library has findings, so this compares something');
    assert.deepEqual(found.filter((f) => f.RuleID !== RULE.id || (f.Tags || []).some((t) => /decoded/.test(t))).map((f) => `${f.File}:${f.StartLine} ${f.RuleID} ${f.Tags}`), [], 'findings the port has no rule for');
    const real = found.map((f) => `${f.File}:${f.StartLine} ${f.Secret}`).sort();
    const ported = files.flatMap(({ file, content }) => findGenericApiKeys(content, file, { allowlists: [] }).map((f) => `${file}:${f.line} ${f.secret}`)).sort();
    assert.deepEqual(ported, real);
    // With the repo's allowlists both find nothing, as CI requires.
    assert.deepEqual(files.flatMap(({ file, content }) => findGenericApiKeys(content, file)), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
