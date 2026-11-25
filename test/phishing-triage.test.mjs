// Phishing triage and purge: a run by hand names its case by short ID or full ID. Sophos Fusion
// issues short IDs like E-01167 beside CSE00042 since 18/11/2026, so both have to be searched by
// short ID, and only a full ID goes straight to the case read. Runs the template's own let
// expressions with the test CEL evaluator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS } from '../tools/lib/yaml.mjs';
import { evalCel } from './cel-eval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TEMPLATE = toJS(parseYaml(readFileSync(path.join(ROOT, 'playbooks/microsoft/phishing-triage-and-purge/template.yaml'), 'utf8')));
const task = (name) => TEMPLATE.dsl.tasks.find((t) => t.name === name);
const CASE_UUID = '11111111-2222-4333-8444-555555555555';
// Sophos Fusion's two argument has(value, 'a.b'): whether the dotted path is there, and type(),
// compared only with another type().
const FNS = {
  type: (v) => (Array.isArray(v) ? 'list' : v === null ? 'null' : typeof v === 'object' ? 'map' : typeof v),
  has: (value, dotted) => {
    let v = value;
    for (const key of String(dotted).split('.')) {
      if (v === null || typeof v !== 'object' || !(key in v)) return false;
      v = v[key];
    }
    return true;
  },
};

// The start task, then find_case's search and case_ref's choice, for a run by hand naming `manualCase`.
function manualRun(manualCase, { caseId = '', found = [] } = {}) {
  const vars = { setup: { variables: { case_id: caseId, manual_id: '<abc123@mail.example.com>', manual_case: manualCase } } };
  vars.start = { variables: Object.fromEntries(Object.entries(task('start').let).map(([k, e]) => [k, evalCel(String(e), vars, FNS)])) };
  const search = evalCel(task('find_case').condition, vars, FNS);
  vars.find_case = search ? { outputs: { cases: found } } : {};
  return {
    shortId: vars.start.variables.short_id,
    search,
    query: search ? evalCel(String(task('find_case').inputs.arguments), vars, FNS).query : null,
    id: evalCel(String(task('case_ref').let.id), vars, FNS),
  };
}

test('a run by hand searches E-01167 and CSE00042 by short ID, in any case, and reads a full ID directly', () => {
  for (const [ref, query] of [['E-01167', "shortId = 'E-01167'"], ['e-01167', "shortId = 'E-01167'"], ['CSE00042', "shortId = 'CSE00042'"], ['cse00042', "shortId = 'CSE00042'"]]) {
    const run = manualRun(ref, { found: [{ id: CASE_UUID }] });
    assert.equal(run.shortId, true, ref);
    assert.equal(run.query, query, ref);
    assert.equal(run.id, CASE_UUID, ref);
  }
  const full = manualRun(CASE_UUID);
  assert.equal(full.search, false);
  assert.equal(full.id, CASE_UUID);
  // A short ID that matches nothing leaves the run without a case.
  assert.equal(manualRun('E-09999').id, '');
  // A case run never searches.
  assert.equal(manualRun('E-01167', { caseId: CASE_UUID }).search, false);
});

// Sophos Fusion issues short IDs like F-08717 beside CSE00042 and E-01167 since 26/11/2026.
test('a run by hand searches F-08717 by short ID, in any case', () => {
  for (const ref of ['F-08717', 'f-08717']) {
    const run = manualRun(ref, { found: [{ id: CASE_UUID }] });
    assert.equal(run.shortId, true, ref);
    assert.equal(run.query, "shortId = 'F-08717'", ref);
    assert.equal(run.id, CASE_UUID, ref);
  }
  assert.equal(manualRun('F-09999').id, '');
});

test('the 1.1.2 change notes describe the F- short ID fix, not an earlier change', () => {
  assert.equal(TEMPLATE.version, '1.1.2');
  assert.match(TEMPLATE.changeNotes, /F-08717/);
  assert.doesNotMatch(TEMPLATE.changeNotes, /Ask for approval first/);
});
