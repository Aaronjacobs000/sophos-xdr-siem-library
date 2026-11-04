// The playbooks that send case comments outside Sophos Fusion besides the chat syncs: Rewst case
// handoff, and the Autotask, ConnectWise and ServiceNow case syncs. Each runs task by task on a
// made-up case with the test CEL evaluator, to check that a Comment Added event for an internal
// comment sends nothing, and a normal comment still goes out.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS } from '../tools/lib/yaml.mjs';
import { evalCel } from './cel-eval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (rel) => toJS(parseYaml(readFileSync(path.join(ROOT, 'playbooks', rel, 'template.yaml'), 'utf8')));

// The platform functions the templates call. The comment comes from case.delta.comment on a case
// event, or case.comment on a manual run, as Sophos Fusion's own functions read it.
const eventComment = (inputs) => inputs?.case?.delta?.comment ?? inputs?.case?.comment ?? {};
const FNS = {
  caseComment: (inputs) => eventComment(inputs).comment ?? '',
  caseCommentAuthorId: (inputs) => eventComment(inputs).authorId ?? '',
  caseFieldChanged: (inputs, f) => (inputs?.case?.delta?.updatedFields ?? []).includes(f),
  caseId: (inputs) => inputs.case.id,
  caseTitle: (inputs) => inputs.case.title ?? '',
  caseTenantId: () => 'aj-test-tenant',
  casePriority: () => 'Medium',
  caseKeyFindings: () => 'AJ test key findings',
  caseLinks: (outputs) => outputs?.case?.links ?? [],
  caseLinkType: (link) => link.type,
  caseLinkReference: (link) => link.reference ?? '',
  createShareLink: (inputs) => `https://central.example.com/aj-test/secops/cases/${inputs.case.id}/summary`,
  resolveSubjectName: () => 'AJ Test User',
  decodeJSON: (s) => JSON.parse(s),
  merge: (a, b) => ({ ...a, ...b }),
  now: () => 0,
  duration: () => 0,
};

const PLAYBOOKS = [
  { name: 'Rewst case handoff', template: load('rewst/rewst-case-handoff'), send: 'Taegis.Webhook.post', settings: { send_comments: true } },
  { name: 'Autotask PSA case sync', template: load('autotask/autotask-psa-case-sync'), send: 'Unofficial_AutotaskPSA.addNote', link: 'AutotaskPSA', ticket: { company_id: 1 } },
  { name: 'ConnectWise PSA case sync', template: load('connectwise/connectwise-psa-case-sync'), send: 'Unofficial_ConnectWisePSA.addNote', link: 'ConnectWisePSA', ticket: { company: 'AJTest' } },
  { name: 'ServiceNow case sync', template: load('servicenow/servicenow-case-sync'), send: 'Taegis.ServiceNow.update', link: 'ServiceNow' },
];

// What the stood-in actions return: the case, the linked ticket or incident (open), and a rendered
// work note that holds the comment.
function outputsFor(task, kase, inputs) {
  if (task.action === 'Taegis.Case.queryCustom') return { case: kase };
  if (task.action === 'Taegis.ServiceNow.query') return [{ sys_id: 'aj-test-incident', state: '2', active: 'true' }];
  if (/\.getTicket$/.test(task.action || '')) return { ticket: { id: 'aj-test-ticket', status: 1, closedFlag: false } };
  if (task.exec === 'Taegis.CaseWorkNote') return { plain: `Comment: ${eventComment(inputs).comment ?? ''}` };
  return {};
}

// Runs the template's tasks in order up to finish and lists every action and exec it called.
function run(pb, { event, comment, linked = true, manual = false }) {
  const kase = {
    id: 'case-1', shortId: 'CSE00001', title: 'AJ Test Case', severity: 6, managedBy: 'CUSTOMER',
    primaryStatus: { name: 'open', title: 'Open', isClosed: false },
    links: linked && pb.link ? [{ type: pb.link, reference: 'aj-test-ref', url: 'https://example.com/aj-test', title: 'AJ Test' }] : [],
  };
  const settings = { dry_run: false, min_severity: 4, managed_by: 'any', ...pb.settings };
  const where = manual ? { comment } : { delta: { comment, updatedFields: ['comment'] } };
  const inputs = { event, settings, case: { id: kase.id, title: kase.title, ...(comment ? where : {}) }, ...(pb.ticket ? { ticket: pb.ticket } : {}) };
  const vars = { inputs };
  const calls = [];
  for (const task of pb.template.dsl.tasks) {
    if (task.name === 'finish') break;
    if (task.condition && !evalCel(task.condition, vars, FNS)) { vars[task.name] = {}; continue; }
    if (task.let) {
      vars[task.name] = { variables: {} };
      for (const [k, expr] of Object.entries(task.let)) vars[task.name].variables[k] = evalCel(String(expr), vars, FNS);
    } else if (task.action || task.exec) {
      calls.push(task.action || task.exec);
      vars[task.name] = { outputs: outputsFor(task, kase, inputs) };
    } else {
      vars[task.name] = {};
    }
  }
  const stop = vars.decide?.variables?.skip ?? vars.scope?.variables?.stop;
  return { calls, stop, vars };
}

const normal = { id: 'c-1', authorId: 'aj-test-user', comment: 'AJ test comment: the user confirmed the sign-in.' };
const internal = { ...normal, id: 'c-2', comment: 'AJ test internal note: not for the ticket.', isInternal: true };
const outbound = (calls) => calls.filter((c) => c !== 'Taegis.Case.queryCustom');

for (const pb of PLAYBOOKS) {
  test(`${pb.name}: an internal comment sends nothing, a normal one still goes out`, () => {
    const skipped = run(pb, { event: 'Comment Added', comment: internal });
    assert.match(skipped.stop, /^The comment is internal, so (it was not sent|nothing was synced)\.$/);
    assert.deepEqual(outbound(skipped.calls), []);
    // Without a linked ticket, an internal comment opens nothing either.
    if (pb.link) assert.deepEqual(outbound(run(pb, { event: 'Comment Added', comment: internal, linked: false }).calls), []);
    // A manual run can pass the comment as case.comment instead.
    assert.deepEqual(outbound(run(pb, { event: 'Comment Added', comment: internal, manual: true }).calls), []);

    const sent = run(pb, { event: 'Comment Added', comment: normal });
    assert.equal(sent.stop, '');
    assert.ok(sent.calls.includes(pb.send), `${pb.name} sends a normal comment: ${sent.calls.join(', ')}`);
    assert.ok(run(pb, { event: 'Comment Added', comment: { ...normal, isInternal: false } }).calls.includes(pb.send));
    // Other events never count as internal.
    assert.notEqual(run(pb, { event: 'Update', comment: internal }).stop, skipped.stop);
  });
}
