// The port of gitleaks' generic-api-key rule (studio/core/gitleaks.js): it flags what CI's gitleaks
// flags, the library check reports it, and its copies of the repo's .gitleaks.toml allowlists and
// the gitleaks version match the repo's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { goRegex, findGenericApiKeys, gitleaksProblems, REPO_ALLOWLISTS, GITLEAKS_VERSION } from '../studio/core/gitleaks.js';
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
  assert.ok(goRegex('(?i)^key$').test('Key'));
  assert.ok(goRegex('(?i)^secret$').test('ſecret'));
  assert.ok(goRegex('(?i)^[a-z]+$').test('ſK'));
  assert.ok(goRegex('(?i)^\\w$').test('K'));
  assert.equal(goRegex('^\\w$').test('K'), false);
  // \s is [\t\n\f\r ], . leaves out only \n, and \z is the end of the text.
  assert.ok(goRegex('^a\\sb$').test('a\fb'));
  for (const s of ['a\vb', 'a b']) assert.equal(goRegex('^a\\sb$').test(s), false);
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
  const ci = await readFile(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  assert.equal(/GITLEAKS_VERSION: (\S+)/.exec(ci)[1], GITLEAKS_VERSION, 'CI runs another gitleaks version: port its generic-api-key rule again');
});
