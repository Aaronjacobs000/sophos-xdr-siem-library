// The case chat sync playbooks, run task by task on sample cases with the test CEL evaluator: what the
// Teams card says for key findings and recommendations, and that an internal comment posts nothing.
// The samples are made up; the ITDR one copies the shape of ITDR finding cases, with whole paragraphs
// on heading lines and <br> for line breaks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml, toJS } from '../tools/lib/yaml.mjs';
import { evalCel } from './cel-eval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (rel) => toJS(parseYaml(readFileSync(path.join(ROOT, rel), 'utf8')));
const TEAMS = load('playbooks/microsoft/teams-case-chat-sync/template.yaml');
const SLACK = load('playbooks/slack/slack-case-chat-sync/template.yaml');

const SETTINGS = {
  min_severity: 4, managed_by: 'any', post_comments: true, bridge_name: '', comment_prefix: '[chat-sync]', ignore_authors: '',
  show_case_details: true, show_key_findings: true, show_recommendations: true, recent_comments: 3, section_length: 600,
};

// The platform functions the templates call, reading the event the way Sophos Fusion's do: the
// comment from case.delta.comment (a case event) or case.comment (a manual run).
const eventComment = (inputs) => inputs?.case?.delta?.comment ?? inputs?.case?.comment ?? {};
const FNS = {
  caseComment: (inputs) => eventComment(inputs).comment ?? '',
  caseCommentAuthorId: (inputs) => eventComment(inputs).authorId ?? '',
  caseFieldChanged: (inputs, f) => (inputs?.case?.delta?.updatedFields ?? []).includes(f),
  caseId: (inputs) => inputs.case.id,
  caseTitle: (inputs) => inputs.case.title ?? '',
  caseTenantId: (inputs) => inputs.case.tenantId ?? '',
  resolveSubjectName: (id) => (id === 'aj-test-user' ? 'AJ Test User' : id),
  createShareLink: (inputs) => `https://central.example.com/aj-test/secops/cases/${inputs.case.id}/summary`,
};

// Runs the template's tasks in order up to finish. Action tasks are stood in for: the case read
// returns `kase`, the comment read returns `comments`, and a post is recorded, not sent.
function run(template, { event = 'manual', kase, comments = [], settings = SETTINGS, comment, tenant } = {}) {
  const inputs = { event, settings, case: { id: kase.id, title: kase.title, tenantId: '1', ...(comment ? { delta: { comment, updatedFields: ['comment'] } } : {}) }, ...(tenant ? { tenant } : {}) };
  const vars = { inputs };
  const posts = [];
  const reads = [];
  for (const task of template.dsl.tasks) {
    if (task.name === 'finish') break;
    if (task.condition && !evalCel(task.condition, vars, FNS)) { vars[task.name] = {}; continue; }
    if (task.let) {
      vars[task.name] = { variables: {} };
      for (const [k, expr] of Object.entries(task.let)) vars[task.name].variables[k] = evalCel(String(expr), vars, FNS);
    } else if (task.action === 'Taegis.Case.queryCustom') {
      reads.push(task.name);
      vars[task.name] = { outputs: { case: kase } };
    } else if (task.action === 'Taegis.Case.getComments') {
      vars[task.name] = { outputs: { comments } };
    } else {
      posts.push(task.action);
      vars[task.name] = {};
    }
  }
  const v = (t, k) => vars[t]?.variables?.[k];
  return { vars, posts, reads, skip: v('decide', 'skip'), findings: v('card', 'findings'), recommendations: v('card', 'recommendations'), body: v('build', 'body') };
}

const caseWith = (content, extra = {}) => ({
  id: 'case-1', shortId: 'CSE00001', title: 'AJ Test Case', severity: 6, managedBy: 'PROVIDER',
  primaryStatus: { name: 'open', title: 'Open', isClosed: false }, type: { title: 'ITDR Finding' }, tenant: { name: 'AJ Test Tenant' },
  detectionsCount: 1, assetsCount: 0, eventsCount: 1, tags: [],
  keyFindings: { documentType: 'MARKDOWN', content }, ...extra,
});

const ITDR = [
  "### ITDR Finding This case was opened automatically because Sophos ITDR found a new Medium risk finding in the AJ Test directory. It isn't an active threat, but it is a risk to the directory's identity security posture. <br>",
  '### Finding Details: **Finding:** Guests can invite other guests for AJ-TEST-DIRECTORY **Finding Details:** Detects when guest users may invite more guests into the directory.',
  '',
  'Details: This check reads the external collaboration settings of the AJ Test directory and flags a setting that lets any guest invite more guests.',
  '',
  'Risk: An invited guest could bring in more outside accounts without review. <br><br> --- ### Recommendations: Please review the recommendations on Identity Findings page.',
].join('\n');

const MDR = [
  '## Primary Detection',
  '',
  'AJ test finding: the primary Detection is [AJ Test Detection](/secops/detections/aj-test/summary), with a Threat Score of `7.5`.',
  '',
  '## Key Entities Involved',
  '',
  '- AJ-TEST-LAPTOP',
  '- aj.test@example.com',
  '',
  '## Recommended Next Steps',
  '',
  '1. Ask the user whether they ran the script.',
  '2. Isolate AJ-TEST-LAPTOP if they did not.',
].join('\n');

test('Teams: an ITDR finding case shows its paragraphs as text, <br> as line breaks, and its recommendation', () => {
  const r = run(TEAMS, { kase: caseWith(ITDR), settings: { ...SETTINGS, section_length: 2000 } });
  assert.equal(r.skip, '');
  assert.equal(r.findings, [
    "ITDR Finding This case was opened automatically because Sophos ITDR found a new Medium risk finding in the AJ Test directory. It isn't an active threat, but it is a risk to the directory's identity security posture.",
    '',
    '**Finding Details**',
    '**Finding:** Guests can invite other guests for AJ-TEST-DIRECTORY **Finding Details:** Detects when guest users may invite more guests into the directory.',
    '',
    'Details: This check reads the external collaboration settings of the AJ Test directory and flags a setting that lets any guest invite more guests.',
    '',
    'Risk: An invited guest could bring in more outside accounts without review.',
  ].join('\n'));
  assert.equal(r.recommendations, 'Please review the recommendations on Identity Findings page.');
  const text = JSON.stringify(r.body);
  assert.doesNotMatch(text, /<br/i);
  assert.doesNotMatch(text, /#|---/);
  // No line is a whole paragraph in bold.
  for (const line of r.findings.split('\n')) assert.ok(!(line.startsWith('**') && line.endsWith('**') && line.length > 84), line);
});

test('Teams: real short headings stay bold, and the recommended next steps are their own section', () => {
  const r = run(TEAMS, { kase: caseWith(MDR) });
  assert.equal(r.findings, [
    '**Primary Detection**',
    '',
    'AJ test finding: the primary Detection is AJ Test Detection, with a Threat Score of 7.5.',
    '',
    '**Key Entities Involved**',
    '',
    '- AJ-TEST-LAPTOP',
    '- aj.test@example.com',
  ].join('\n'));
  assert.equal(r.recommendations, '1. Ask the user whether they ran the script.\n2. Isolate AJ-TEST-LAPTOP if they did not.');
});

test('Teams: heading and line break variants', () => {
  const content = [
    '  ### Endpoint: AJ-TEST-LAPTOP',
    'First line<br/>second line<br />third line<BR>fourth line',
    '---',
    '### **Bold heading**',
    'Text under it, with C# and #2 left alone.',
    '### This heading line is long enough to be a paragraph, and its colon comes far too late to be a label: so it stays text',
    '#### Timeline: 09:00 sign-in, 09:05 rule change, 09:10 mailbox export, all from the same address.',
  ].join('\n');
  const r = run(TEAMS, { kase: caseWith(content) });
  assert.equal(r.findings, [
    '**Endpoint: AJ-TEST-LAPTOP**',
    'First line',
    'second line',
    'third line',
    'fourth line',
    '',
    '**Bold heading**',
    'Text under it, with C# and #2 left alone.',
    'This heading line is long enough to be a paragraph, and its colon comes far too late to be a label: so it stays text',
    '**Timeline**',
    '09:00 sign-in, 09:05 rule change, 09:10 mailbox export, all from the same address.',
  ].join('\n'));
  assert.equal(r.recommendations, '');
  // A run of line breaks and blank lines leaves one blank line.
  assert.equal(run(TEAMS, { kase: caseWith('One<br><br><br><br>Two\n\n\n\n  \nThree <br> <br>\n---\n\nFour') }).findings, 'One\n\nTwo\n\nThree\n\nFour');
});

test('Teams: Section length still cuts long findings at a line break', () => {
  const long = Array.from({ length: 12 }, (_, i) => `AJ test paragraph ${i + 1}, padded out with enough words to fill the line.<br>`).join('');
  const r = run(TEAMS, { kase: caseWith(`### Summary\n${long}`), settings: { ...SETTINGS, section_length: 300 } });
  assert.ok(r.findings.endsWith(' ...'), r.findings);
  assert.ok(r.findings.length <= 304, r.findings.length);
  assert.ok(r.findings.startsWith('**Summary**\nAJ test paragraph 1,'));
  assert.doesNotMatch(r.findings, /<br/);
});

test('Teams: key findings that are empty, missing or rich text add no section', () => {
  for (const kf of [{ documentType: 'MARKDOWN', content: '' }, { documentType: 'RICH_TEXT', content: '<p>x</p>' }]) {
    const r = run(TEAMS, { kase: caseWith('', { keyFindings: kf }) });
    assert.equal(r.findings, '');
    assert.equal(r.recommendations, '');
  }
});

const normal = { id: 'c-1', authorId: 'aj-test-user', comment: 'AJ test comment: the user confirmed the sign-in.' };
const internal = { ...normal, id: 'c-2', comment: 'AJ test internal note: not for the channel.', isInternal: true };

for (const [name, template, action] of [['Teams', TEAMS, 'Taegis.MicrosoftTeams.sendWorkflowMessage'], ['Slack', SLACK, 'Taegis.SalesforceSlack.sendMessage']]) {
  test(`${name}: an internal comment posts nothing, a normal one still posts`, () => {
    const kase = caseWith(MDR);
    // A case event carries the comment in case.delta.comment; a normal comment has no isInternal key.
    const skipped = run(template, { event: 'Comment Added', kase, comment: internal });
    assert.equal(skipped.skip, 'The comment is internal, so it was not posted.');
    assert.deepEqual(skipped.posts, []);
    const posted = run(template, { event: 'Comment Added', kase, comment: normal });
    assert.equal(posted.skip, '');
    assert.deepEqual(posted.posts, [action]);
    assert.match(JSON.stringify(posted.vars), /the user confirmed the sign-in/);
    assert.equal(run(template, { event: 'Comment Added', kase, comment: { ...normal, isInternal: false } }).skip, '');
    // A manual run can pass the comment as case.comment instead.
    const inputs = { event: 'Comment Added', settings: SETTINGS, case: { id: kase.id, title: kase.title, tenantId: '1', comment: internal } };
    assert.equal(evalCel(template.dsl.tasks.find((t) => t.name === 'read').let.internal_comment, { inputs, setup: { variables: { event: 'comment added' } } }, FNS), true);
    // Other events never count as internal.
    assert.equal(run(template, { event: 'Update', kase, comment: internal }).vars.read.variables.internal_comment, false);
  });
}

test('Teams: the card names the tenant and links the case, and each can be turned off', () => {
  const facts = (r) => r.body.find((b) => b.type === 'FactSet').facts;
  const actions = (r) => r.vars.build.variables.actions;
  // A case event names the tenant, so it isn't read again.
  const shared = run(TEAMS, { kase: caseWith(MDR), tenant: { name: 'AJ Test Event Tenant' } });
  assert.deepEqual(facts(shared)[0], { title: 'Tenant', value: 'AJ Test Event Tenant' });
  assert.deepEqual(shared.reads, ['fetch_case']);
  assert.deepEqual(actions(shared), [{ type: 'Action.OpenUrl', title: 'Open in Sophos Fusion', url: 'https://central.example.com/aj-test/secops/cases/case-1/summary' }]);
  // A run by hand or from a case carries no tenant, so the playbook reads it.
  const manual = run(TEAMS, { kase: caseWith(MDR) });
  assert.deepEqual(manual.reads, ['fetch_case', 'fetch_tenant']);
  assert.deepEqual(facts(manual)[0], { title: 'Tenant', value: 'AJ Test Tenant' });
  // Turned off: no Tenant row, no read for it, and no button.
  const off = run(TEAMS, { kase: caseWith(MDR), settings: { ...SETTINGS, show_tenant: false, show_case_link: false } });
  assert.equal(facts(off)[0].title, 'Severity');
  assert.deepEqual(off.reads, ['fetch_case']);
  assert.deepEqual(actions(off), []);
  // No name anywhere leaves the row out.
  const none = run(TEAMS, { kase: caseWith(MDR, { tenant: null }) });
  assert.equal(facts(none)[0].title, 'Severity');
});
