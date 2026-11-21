// The chat bridge (chat-bridge/worker.js): request signatures, command parsing, and what it sends to
// Sophos Fusion and Slack, against a mocked fetch. Nothing here reaches the network.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import worker, { verifySlack, verifyTeams, teamsText, parseCommand, settings, resetCache, safeEqual, slackStatus } from '../chat-bridge/worker.js';

const CASE_ID = '11111111-2222-4333-8444-555555555555';
const STATUS = { open: 'aaaaaaaa-0000-4000-8000-000000000001', active: 'aaaaaaaa-0000-4000-8000-000000000002', closed: 'aaaaaaaa-0000-4000-8000-000000000003', awaiting_action: 'aaaaaaaa-0000-4000-8000-000000000004', in_progress: 'aaaaaaaa-0000-4000-8000-000000000005', customer_action_required: 'aaaaaaaa-0000-4000-8000-000000000006' };
const VERDICT = 'bbbbbbbb-0000-4000-8000-000000000001';
const SLACK_SECRET = 'test-signing-secret';
const TEAMS_SECRET = randomBytes(32).toString('base64');
// Most tests model a tenant without Sophos MDR, whose cases use active and awaiting_action.
const ENV = { FUSION_CLIENT_ID: 'client', FUSION_CLIENT_SECRET: 'secret', FUSION_TENANT_ID: 'tenant-1', SLACK_SIGNING_SECRET: SLACK_SECRET, SLACK_BOT_TOKEN: 'xoxb-test', TEAMS_HMAC_SECRET: TEAMS_SECRET, BRIDGE_ALLOWED_STATUSES: 'active,awaiting_action,closed' };
// The defaults: a Sophos MDR tenant, whose cases use in_progress and customer_action_required.
const MDR_ENV = { ...ENV, BRIDGE_ALLOWED_STATUSES: undefined };

// ---------------------------------------------------------------- a mocked Sophos Fusion and Slack

let calls;
let kase;
let logs;
let caseComments;
const realFetch = globalThis.fetch;
const realLog = console.log;

function fusionCase(over = {}) {
  return { id: CASE_ID, shortId: 'CSE00042', title: 'Test case', managedBy: 'CUSTOMER', primaryStatus: { id: STATUS.open, name: 'open', title: 'Open', isClosed: false }, ...over };
}

beforeEach(() => {
  calls = [];
  logs = [];
  kase = fusionCase();
  caseComments = [];
  resetCache();
  console.log = (line) => logs.push(line);
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const body = typeof init.body === 'string' ? init.body : init.body ? init.body.toString() : '';
    calls.push({ url: u, init, body });
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
    if (u === 'https://id.sophos.com/api/v2/oauth2/token') return json({ access_token: 'tok', expires_in: 3600 });
    if (u.startsWith('https://slack.com/api/')) return json({ ok: true });
    if (u.startsWith('https://hooks.slack.com/')) return new Response('ok');
    if (u === 'https://api.taegis.sophos.com/graphql') {
      const { query, variables } = JSON.parse(body);
      if (query.includes('caseComments')) return json({ data: { caseComments: { comments: caseComments } } });
      if (query.includes('cases(arguments')) return json({ data: { cases: { cases: kase && variables.q === `shortId = '${kase.shortId}'` ? [kase] : [] } } });
      if (query.includes('case(arguments')) return json({ data: { case: kase && variables.a.id === CASE_ID ? kase : null } });
      if (query.includes('casePrimaryStatuses')) return json({ data: { casePrimaryStatuses: { primaryStatuses: Object.entries(STATUS).map(([name, id]) => ({ id, name, title: name.replace('_', ' ').replace(/^./, (c) => c.toUpperCase()), isClosed: name === 'closed' })) } } });
      if (query.includes('casePrimaryVerdicts')) return json({ data: { casePrimaryVerdicts: { primaryVerdicts: [{ id: VERDICT, name: 'false_positive', title: 'False Positive' }] } } });
      if (query.includes('updateCase')) {
        const st = Object.entries(STATUS).find(([, id]) => id === variables.i.primaryStatusId);
        return json({ data: { updateCase: { ...kase, primaryStatus: { id: st[1], name: st[0], title: st[0] === 'active' ? 'Active' : st[0], isClosed: st[0] === 'closed' } } } });
      }
      if (query.includes('addCaseComment')) return json({ data: { addCaseComment: { id: 'c1' } } });
    }
    return new Response('unexpected', { status: 500 });
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
  console.log = realLog;
});

const mutations = () => calls.filter((c) => c.url.endsWith('/graphql')).map((c) => JSON.parse(c.body)).filter((b) => /^\s*mutation/.test(b.query));
const ctx = () => { const waits = []; return { waits, waitUntil: (p) => waits.push(p), settle: () => Promise.all(waits) }; };

function slackRequest(payload, { secret = SLACK_SECRET, ts = Math.floor(Date.now() / 1000), sig } = {}) {
  const raw = new URLSearchParams({ payload: JSON.stringify(payload) }).toString();
  const signature = sig ?? 'v0=' + createHmac('sha256', secret).update(`v0:${ts}:${raw}`).digest('hex');
  return new Request('https://bridge.example.com/slack/interactivity', { method: 'POST', headers: { 'x-slack-request-timestamp': String(ts), 'x-slack-signature': signature, 'Content-Type': 'application/x-www-form-urlencoded' }, body: raw });
}

function teamsRequest(text, { secret = TEAMS_SECRET, from = { name: 'Jane Analyst', aadObjectId: 'user-1' }, auth } = {}) {
  const raw = JSON.stringify({ type: 'message', text, from, channelData: { tenant: { id: 'ms-tenant' } }, conversation: { id: '19:abc@thread.tacv2;messageid=1' } });
  const header = auth ?? 'HMAC ' + createHmac('sha256', Buffer.from(secret, 'base64')).update(raw).digest('base64');
  return new Request('https://bridge.example.com/teams/outgoing', { method: 'POST', headers: { Authorization: header, 'Content-Type': 'application/json' }, body: raw });
}

const blockAction = (actionId, value = `${CASE_ID}|CSE00042`, user = { id: 'U123', name: 'jane' }) => ({
  type: 'block_actions', user, team: { id: 'T1' }, trigger_id: 'trig', response_url: 'https://hooks.slack.com/actions/T1/1/abc',
  actions: [{ action_id: actionId, value }],
});

// ---------------------------------------------------------------- signatures

test('Slack signatures: Slack\'s own published example verifies, and tampering fails', async () => {
  // The worked example on Slack's "Verifying requests from Slack" page.
  const raw = 'token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c';
  const headers = new Headers({ 'x-slack-request-timestamp': '1531420618', 'x-slack-signature': 'v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503' });
  assert.equal(await verifySlack('8f742231b10e8888abcd99yyyzzz85a5', headers, raw, 1531420618), null);
  assert.match(await verifySlack('8f742231b10e8888abcd99yyyzzz85a5', headers, raw + 'x', 1531420618), /does not match/);
  assert.match(await verifySlack('8f742231b10e8888abcd99yyyzzz85a5', headers, raw, 1531420618 + 301), /five minutes/);
  assert.match(await verifySlack('', headers, raw, 1531420618), /not set/);
  assert.match(await verifySlack('s', new Headers(), raw), /missing/);
});

test('Teams signatures: HMAC-SHA256 of the body with the base64-decoded token, and nothing else', async () => {
  const raw = '{"text":"hi"}';
  const good = 'HMAC ' + createHmac('sha256', Buffer.from(TEAMS_SECRET, 'base64')).update(raw).digest('base64');
  assert.equal(await verifyTeams(TEAMS_SECRET, new Headers({ authorization: good }), raw), null);
  assert.match(await verifyTeams(TEAMS_SECRET, new Headers({ authorization: good }), raw + ' '), /does not match/);
  assert.match(await verifyTeams(TEAMS_SECRET, new Headers({ authorization: 'Bearer x' }), raw), /missing/);
  assert.match(await verifyTeams('', new Headers({ authorization: good }), raw), /not set/);
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
  assert.equal(safeEqual('abc', 'abcd'), false);
});

test('requests without a valid signature get 401 and reach neither Sophos Fusion nor Slack', async () => {
  const c = ctx();
  assert.equal((await worker.fetch(slackRequest(blockAction('fusion_status_active'), { sig: 'v0=00' }), ENV, c)).status, 401);
  assert.equal((await worker.fetch(slackRequest(blockAction('fusion_status_active'), { ts: Math.floor(Date.now() / 1000) - 600 }), ENV, c)).status, 401);
  assert.equal((await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042', { auth: 'HMAC AAAA' }), ENV, c)).status, 401);
  assert.equal((await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042', { secret: randomBytes(32).toString('base64') }), ENV, c)).status, 401);
  await c.settle();
  assert.equal(calls.length, 0);
  assert.ok(logs.some((l) => /rejected/.test(l)));
});

// ---------------------------------------------------------------- settings and parsing

test('settings: the Fusion API must be https on taegis.sophos.com, and the lists have safe defaults', () => {
  assert.throws(() => settings({ FUSION_API: 'https://evil.example.com/graphql' }), /FUSION_API/);
  assert.throws(() => settings({ FUSION_API: 'http://api.taegis.sophos.com/graphql' }), /FUSION_API/);
  assert.equal(settings({ FUSION_API: 'https://api.region1.taegis.sophos.com/graphql' }).api, 'https://api.region1.taegis.sophos.com/graphql');
  const s = settings({});
  assert.deepEqual(s.statuses, ['in_progress', 'customer_action_required', 'closed']);
  assert.ok(s.verdicts.includes('false_positive') && s.verdicts.includes('true_positive_benign') && s.verdicts.includes('true_positive_malicious'));
  assert.equal(s.prefix, '[chat-sync]');
  assert.equal(s.dryRun, false);
});

test('Teams text: mentions and markup come out, and commands parse only with a case ID', () => {
  assert.equal(teamsText('<at>Fusion</at>&nbsp;close CSE00042 false_positive <b>test</b> box'), 'close CSE00042 false_positive test box');
  const cfg = settings({ BRIDGE_ALLOWED_STATUSES: 'active,awaiting_action,closed' });
  assert.deepEqual(parseCommand('active CSE00042 looking now', cfg), { kind: 'status', ref: 'CSE00042', status: 'active', text: 'looking now' });
  assert.deepEqual(parseCommand('close CSE00042 false_positive lab box', cfg), { kind: 'close', ref: 'CSE00042', verdict: 'false_positive', text: 'lab box' });
  assert.deepEqual(parseCommand(`comment ${CASE_ID} hello there`, cfg), { kind: 'comment', ref: CASE_ID, text: 'hello there' });
  assert.equal(parseCommand('suspended CSE00042', cfg), null);
  assert.equal(parseCommand('closed CSE00042', cfg), null);
  assert.equal(parseCommand('active 42', cfg), null);
  assert.equal(parseCommand('help', cfg), null);
});

test('Teams text: the default statuses are a Sophos MDR tenant\'s, and active still means in_progress there', () => {
  const cfg = settings({});
  assert.deepEqual(parseCommand('in_progress CSE00042 looking now', cfg), { kind: 'status', ref: 'CSE00042', status: 'in_progress', text: 'looking now' });
  assert.deepEqual(parseCommand('customer_action_required CSE00042', cfg), { kind: 'status', ref: 'CSE00042', status: 'customer_action_required', text: '' });
  assert.deepEqual(parseCommand('Active CSE00042 on it', cfg), { kind: 'status', ref: 'CSE00042', status: 'in_progress', text: 'on it' });
  assert.equal(parseCommand('awaiting_action CSE00042', cfg), null);
  assert.equal(parseCommand('on_hold CSE00042', cfg), null);
  // Where active is a real status, it stays active.
  assert.equal(parseCommand('active CSE00042', settings({ BRIDGE_ALLOWED_STATUSES: 'active,in_progress,closed' })).status, 'active');
  // With neither, it isn't a command.
  assert.equal(parseCommand('active CSE00042', settings({ BRIDGE_ALLOWED_STATUSES: 'awaiting_action,closed' })), null);
});

// ---------------------------------------------------------------- Teams

test('Teams: a status command changes the case and comments with who did it, then replies', async () => {
  const c = ctx();
  const res = await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042 on it'), ENV, c);
  await c.settle();
  const reply = await res.json();
  assert.match(reply.text, /CSE00042 is now Active\. Recorded on the case as Jane Analyst via Teams/);
  const m = mutations();
  assert.equal(m.length, 2);
  assert.deepEqual(m[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.active });
  assert.equal(m[1].variables.i.comment, '[chat-sync] Jane Analyst via Teams set the status to Active: on it');
  // Credentials go only where they belong, and never follow a redirect.
  for (const call of calls) assert.equal(call.init.redirect, 'manual');
  const log = JSON.parse(logs.find((l) => l.includes('"action":"status"')));
  assert.equal(log.user_id, 'user-1');
  assert.equal(log.user_name, 'Jane Analyst');
  assert.equal(log.case_id, CASE_ID);
});

test('Teams: close needs an allowed verdict, and sends it with the reason', async () => {
  let c = ctx();
  let reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> close CSE00042 nope'), ENV, c)).json();
  await c.settle();
  assert.match(reply.text, /Closing needs a verdict/);
  assert.equal(mutations().length, 0);
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> close CSE00042 false_positive lab test'), ENV, c)).json();
  await c.settle();
  const m = mutations();
  assert.deepEqual(m[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.closed, primaryVerdictId: VERDICT, closeReason: 'lab test' });
  assert.match(m[1].variables.i.comment, /^\[chat-sync\] Jane Analyst via Teams set the status to Closed with the verdict False Positive: lab test$/);
});

test('Teams: a comment command adds a prefixed comment; unknown text gets the usage', async () => {
  let c = ctx();
  await worker.fetch(teamsRequest('<at>Fusion</at> comment CSE00042 user confirmed it was them'), ENV, c);
  await c.settle();
  assert.equal(mutations()[0].variables.i.comment, '[chat-sync] Jane Analyst via Teams: user confirmed it was them');
  c = ctx();
  const reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> what is this'), ENV, c)).json();
  assert.match(reply.text, /^Commands: active <case>, awaiting_action <case>, close <case> <verdict>/);
});

test('Teams: with the default statuses the usage names in_progress and customer_action_required, and an old card\'s active sets in_progress', async () => {
  let c = ctx();
  let reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> help'), MDR_ENV, c)).json();
  assert.match(reply.text, /^Commands: in_progress <case>, customer_action_required <case>, close <case> <verdict> \[note\], comment <case> <text>, approve <case> <request>, deny <case> <request>\./);
  assert.doesNotMatch(reply.text, /active|awaiting/);
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> customer_action_required CSE00042 waiting on the user'), MDR_ENV, c)).json();
  await c.settle();
  let m = mutations();
  assert.deepEqual(m[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.customer_action_required });
  assert.match(m[1].variables.i.comment, /^\[chat-sync\] Jane Analyst via Teams set the status to .+: waiting on the user$/);
  calls = [];
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042'), MDR_ENV, c)).json();
  await c.settle();
  m = mutations();
  assert.equal(m.length, 2);
  assert.deepEqual(m[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.in_progress });
  assert.match(reply.text, /^CSE00042 is now in_progress\./);
});

test('Teams: allowlists, Sophos MDR cases, closed cases and dry run all stop before a write', async () => {
  let c = ctx();
  let reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042'), { ...ENV, TEAMS_ALLOWED_USERS: 'someone-else' }, c)).json();
  assert.match(reply.text, /not on this bridge's list/);
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042'), { ...ENV, TEAMS_TENANT_ID: 'other-tenant' }, c)).json();
  assert.match(reply.text, /different Microsoft 365 tenant/);
  kase = fusionCase({ managedBy: 'PROVIDER' });
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042'), ENV, c)).json();
  assert.match(reply.text, /managed by Sophos MDR/);
  kase = fusionCase({ primaryStatus: { id: STATUS.closed, name: 'closed', title: 'Closed', isClosed: true } });
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> comment CSE00042 hi'), ENV, c)).json();
  assert.match(reply.text, /is closed/);
  kase = fusionCase();
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042'), { ...ENV, BRIDGE_DRY_RUN: '1' }, c)).json();
  assert.match(reply.text, /^Dry run: would set CSE00042 to Active/);
  await c.settle();
  assert.equal(mutations().length, 0);
  c = ctx();
  reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE09999'), ENV, c)).json();
  assert.match(reply.text, /No case CSE09999/);
});

test('Teams: past the five-second budget the bridge answers and finishes the work after', async () => {
  const slow = globalThis.fetch;
  globalThis.fetch = async (url, init) => { await new Promise((r) => setTimeout(r, 30)); return slow(url, init); };
  const c = ctx();
  const reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> active CSE00042'), { ...ENV, TEAMS_BUDGET_MS: '10' }, c)).json();
  assert.match(reply.text, /Still working on CSE00042/);
  await c.settle();
  assert.equal(mutations().length, 2);
});

// ---------------------------------------------------------------- Slack

test('Slack: a status button changes the case, comments, and answers through response_url', async () => {
  const c = ctx();
  const res = await worker.fetch(slackRequest(blockAction('fusion_status_active')), ENV, c);
  assert.equal(res.status, 200);
  await c.settle();
  const m = mutations();
  assert.deepEqual(m[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.active });
  assert.equal(m[1].variables.i.comment, '[chat-sync] jane via Slack set the status to Active.');
  const answer = calls.find((x) => x.url.startsWith('https://hooks.slack.com/'));
  assert.match(JSON.parse(answer.body).text, /CSE00042 is now Active/);
  assert.equal(JSON.parse(answer.body).response_type, 'ephemeral');
});

test('Slack: close and comment open a form, and the form\'s answers become the write', async () => {
  let c = ctx();
  await worker.fetch(slackRequest(blockAction('fusion_close')), ENV, c);
  await c.settle();
  const open = calls.find((x) => x.url === 'https://slack.com/api/views.open');
  const view = JSON.parse(open.body).view;
  assert.equal(view.callback_id, 'fusion_close');
  assert.equal(open.init.headers.Authorization, 'Bearer xoxb-test');
  assert.equal(mutations().length, 0);
  const meta = view.private_metadata;
  calls = [];
  c = ctx();
  const submit = { type: 'view_submission', user: { id: 'U123', name: 'jane' }, team: { id: 'T1' }, view: { callback_id: 'fusion_close', private_metadata: meta, state: { values: { verdict: { v: { selected_option: { value: 'false_positive' } } }, note: { n: { value: 'test box' } } } } } };
  assert.equal((await worker.fetch(slackRequest(submit), ENV, c)).status, 200);
  await c.settle();
  const m = mutations();
  assert.deepEqual(m[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.closed, primaryVerdictId: VERDICT, closeReason: 'test box' });
  assert.match(m[1].variables.i.comment, /^\[chat-sync\] jane via Slack set the status to Closed with the verdict False Positive: test box$/);
  calls = [];
  c = ctx();
  const comment = { ...submit, view: { callback_id: 'fusion_comment', private_metadata: meta, state: { values: { note: { n: { value: 'called the user' } } } } } };
  await worker.fetch(slackRequest(comment), ENV, c);
  await c.settle();
  assert.equal(mutations()[0].variables.i.comment, '[chat-sync] jane via Slack: called the user');
  const empty = { ...submit, view: { callback_id: 'fusion_comment', private_metadata: meta, state: { values: { note: { n: { value: '  ' } } } } } };
  const res = await worker.fetch(slackRequest(empty), ENV, ctx());
  assert.equal((await res.json()).response_action, 'errors');
});

test('Slack: the open button, other workspaces, users off the list and odd values change nothing', async () => {
  let c = ctx();
  assert.equal((await worker.fetch(slackRequest(blockAction('fusion_open')), ENV, c)).status, 200);
  assert.equal((await worker.fetch(slackRequest(blockAction('fusion_status_active')), { ...ENV, SLACK_TEAM_ID: 'T999' }, c)).status, 403);
  await worker.fetch(slackRequest(blockAction('fusion_status_active')), { ...ENV, SLACK_ALLOWED_USERS: 'U999' }, c);
  await worker.fetch(slackRequest(blockAction('fusion_status_active', 'not-a-case')), ENV, c);
  await worker.fetch(slackRequest(blockAction('fusion_status_suspended')), ENV, c);
  await c.settle();
  assert.equal(mutations().length, 0);
  assert.ok(calls.some((x) => x.url.startsWith('https://hooks.slack.com/') && /not on this bridge's list/.test(x.body)));
  assert.ok(calls.some((x) => x.url.startsWith('https://hooks.slack.com/') && /isn't one this bridge sets/.test(x.body)));
});

test('Slack: a response_url that isn\'t Slack\'s is never called', async () => {
  const c = ctx();
  const payload = { ...blockAction('fusion_status_active'), response_url: 'https://attacker.example.com/collect' };
  await worker.fetch(slackRequest(payload), ENV, c);
  await c.settle();
  assert.equal(calls.filter((x) => x.url.includes('attacker')).length, 0);
});

// ---------------------------------------------------------------- approvals

const REQUEST = 'AP-7K2M9QX4';
const requestComment = (id = REQUEST) => ({ id: 'r1', authorId: 'playbook-subject', comment: `**Approval needed: Microsoft 365 account takeover cleanup**\nRequest ${id}.\n\n\`\`\`\napproval-request: ${id}\napproval-expires: 2026-11-16T10:30:00Z\n\`\`\`` });

test('approvals: approve and deny parse with the request ID, in any case', () => {
  const cfg = settings({});
  assert.deepEqual(parseCommand('approve CSE00042 ap-7k2m9qx4', cfg), { kind: 'approve', ref: 'CSE00042', request: REQUEST });
  assert.deepEqual(parseCommand(`deny ${CASE_ID} ${REQUEST} not now`, cfg), { kind: 'deny', ref: CASE_ID, request: REQUEST });
  assert.deepEqual(parseCommand('approve CSE00042', cfg), { kind: 'approve', ref: 'CSE00042', request: '' });
  assert.equal(parseCommand('approve AP-7K2M9QX4', cfg), null);
});

test('approvals: Teams approve writes one signed decision comment, as the bridge, and replies', async () => {
  caseComments = [requestComment()];
  const c = ctx();
  const reply = await (await worker.fetch(teamsRequest(`<at>Fusion</at> approve CSE00042 ${REQUEST}`), MDR_ENV, c)).json();
  await c.settle();
  assert.match(reply.text, /^Approved AP-7K2M9QX4 on CSE00042\./);
  const m = mutations();
  assert.equal(m.length, 1);
  assert.deepEqual(m[0].variables.i, { caseId: CASE_ID, comment: '[chat-sync] Approval decision: approve AP-7K2M9QX4 by Jane Analyst via Teams.' });
  const read = calls.filter((x) => x.url.endsWith('/graphql')).map((x) => JSON.parse(x.body)).find((b) => b.query.includes('caseComments'));
  assert.deepEqual(read.variables.a, { caseId: CASE_ID, orderBy: 'DESCENDING', perPage: 100 });
  assert.ok(logs.some((l) => JSON.parse(l).request === REQUEST));
});

test('approvals: Teams deny records the decision and says nothing will run', async () => {
  caseComments = [requestComment()];
  const c = ctx();
  const reply = await (await worker.fetch(teamsRequest(`<at>Fusion</at> deny CSE00042 ${REQUEST}`), MDR_ENV, c)).json();
  await c.settle();
  assert.equal(reply.text, 'Denied AP-7K2M9QX4 on CSE00042. Nothing will run.');
  assert.equal(mutations()[0].variables.i.comment, '[chat-sync] Approval decision: deny AP-7K2M9QX4 by Jane Analyst via Teams.');
});

test('approvals: no request, a bad ID, a closed case, an earlier decision and dry run write nothing', async () => {
  const say = async (text, env = MDR_ENV) => { const c = ctx(); const r = await (await worker.fetch(teamsRequest(`<at>Fusion</at> ${text}`), env, c)).json(); await c.settle(); return r.text; };
  assert.equal(await say(`approve CSE00042 ${REQUEST}`), 'No approval request AP-7K2M9QX4 on CSE00042.');
  caseComments = [requestComment('AP-22222222')];
  assert.equal(await say(`approve CSE00042 ${REQUEST}`), 'No approval request AP-7K2M9QX4 on CSE00042.');
  assert.match(await say('approve CSE00042'), /Add the request ID/);
  assert.match(await say('approve CSE00042 AP-1234'), /Add the request ID/);
  caseComments = [requestComment()];
  kase = fusionCase({ primaryStatus: { id: STATUS.closed, name: 'closed', title: 'Closed', isClosed: true } });
  assert.match(await say(`approve CSE00042 ${REQUEST}`), /is closed/);
  kase = fusionCase();
  // A decision the bridge wrote earlier stops a second one; the same text from anyone else doesn't.
  caseComments = [{ id: 'd0', authorId: 'someone-in-the-console', comment: '[chat-sync] Approval decision: deny AP-7K2M9QX4 by Mallory via Teams.' }, { id: 'd1', authorId: 'CLIENT', comment: '[chat-sync] Approval decision: approve AP-7K2M9QX4 by Jane Analyst via Slack.' }, requestComment()];
  assert.equal(await say(`deny CSE00042 ${REQUEST}`), 'AP-7K2M9QX4 was already approved by Jane Analyst, so nothing changed.');
  assert.equal(mutations().length, 0);
  caseComments = [{ id: 'd0', authorId: 'someone-in-the-console', comment: '[chat-sync] Approval decision: deny AP-7K2M9QX4 by Mallory via Teams.' }, requestComment()];
  assert.match(await say(`approve CSE00042 ${REQUEST}`, { ...MDR_ENV, BRIDGE_DRY_RUN: '1' }), /^Dry run: would record on CSE00042: \[chat-sync\] Approval decision: approve AP-7K2M9QX4 by Jane Analyst via Teams\.$/);
  assert.equal(mutations().length, 0);
  // The bridge recognizes its own earlier decision by its client ID, whatever the case of the letters.
  caseComments = [{ id: 'd1', authorId: 'client', comment: '[chat-sync] Approval decision: deny AP-7K2M9QX4 by Bob via Teams.' }, requestComment()];
  assert.equal(await say(`approve CSE00042 ${REQUEST}`, { ...MDR_ENV, FUSION_CLIENT_ID: 'Client' }), 'AP-7K2M9QX4 was already denied by Bob, so nothing changed.');
  assert.equal(mutations().length, 0);
});

test('approvals: Slack Approve and Deny buttons carry the request and answer through response_url', async () => {
  caseComments = [requestComment()];
  const c = ctx();
  const res = await worker.fetch(slackRequest(blockAction('fusion_approve', `${CASE_ID}|CSE00042|${REQUEST}`)), MDR_ENV, c);
  assert.equal(res.status, 200);
  await c.settle();
  assert.equal(mutations()[0].variables.i.comment, '[chat-sync] Approval decision: approve AP-7K2M9QX4 by jane via Slack.');
  const answer = calls.find((x) => x.url.startsWith('https://hooks.slack.com/'));
  assert.match(JSON.parse(answer.body).text, /^Approved AP-7K2M9QX4 on CSE00042/);
  calls = [];
  const c2 = ctx();
  await worker.fetch(slackRequest(blockAction('fusion_deny', `${CASE_ID}|CSE00042|`)), MDR_ENV, c2);
  await c2.settle();
  assert.equal(mutations().length, 0);
  assert.ok(calls.some((x) => x.url.startsWith('https://hooks.slack.com/') && /Add the request ID/.test(x.body)));
});

test('Slack: old Set active and Set awaiting action buttons work on a Sophos MDR tenant', async () => {
  const mdr = settings({});
  assert.equal(slackStatus('active', mdr), 'in_progress');
  assert.equal(slackStatus('awaiting_action', mdr), 'customer_action_required');
  assert.equal(slackStatus('in_progress', mdr), 'in_progress');
  assert.equal(slackStatus('active', settings({ BRIDGE_ALLOWED_STATUSES: 'active,awaiting_action,closed' })), 'active');
  const c = ctx();
  await worker.fetch(slackRequest(blockAction('fusion_status_awaiting_action')), MDR_ENV, c);
  await c.settle();
  assert.deepEqual(mutations()[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.customer_action_required });
});

test('a bridge without settings refuses, and only the three routes answer', async () => {
  assert.equal((await worker.fetch(new Request('https://bridge.example.com/healthz'), ENV, ctx())).status, 200);
  assert.equal((await worker.fetch(new Request('https://bridge.example.com/other', { method: 'POST' }), ENV, ctx())).status, 404);
  assert.equal((await worker.fetch(new Request('https://bridge.example.com/slack/interactivity', { method: 'POST' }), { ...ENV, FUSION_API: 'https://example.com/graphql' }, ctx())).status, 500);
});

// ---------------------------------------------------------------- short IDs

// Sophos Fusion issues short IDs like E-01167 beside CSE00042 since 18/11/2026.
test('short IDs: E-01167 parses like CSE00042, in any case, and a Classic case ID does not', () => {
  const cfg = settings(ENV);
  for (const ref of ['E-01167', 'e-01167', 'CSE00001', 'cse00001', CASE_ID]) {
    assert.deepEqual(parseCommand(`active ${ref} on it`, cfg), { kind: 'status', ref, status: 'active', text: 'on it' }, ref);
    assert.deepEqual(parseCommand(`approve ${ref} AP-7K2M9QX4`, cfg), { kind: 'approve', ref, request: 'AP-7K2M9QX4' }, ref);
  }
  for (const ref of ['1-598868', 'E-', 'E01167', 'X-01167', 'AP-7K2M9QX4']) assert.equal(parseCommand(`active ${ref}`, cfg), null, ref);
});

test('short IDs: a Teams command and a Slack button on an E-01167 case find it by short ID and change it', async () => {
  kase = fusionCase({ shortId: 'E-01167' });
  let c = ctx();
  const res = await worker.fetch(teamsRequest('<at>Fusion</at> active e-01167 on it'), ENV, c);
  await c.settle();
  assert.match((await res.json()).text, /^E-01167 is now Active\./);
  const searches = () => calls.filter((x) => x.url.endsWith('/graphql')).map((x) => JSON.parse(x.body)).filter((b) => b.query.includes('cases(arguments'));
  assert.deepEqual(searches().map((b) => b.variables.q), ["shortId = 'E-01167'"]);
  assert.deepEqual(mutations()[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.active });

  calls = [];
  c = ctx();
  await worker.fetch(slackRequest(blockAction('fusion_status_active', '|E-01167')), ENV, c);
  await c.settle();
  assert.deepEqual(searches().map((b) => b.variables.q), ["shortId = 'E-01167'"]);
  assert.deepEqual(mutations()[0].variables.i, { id: CASE_ID, primaryStatusId: STATUS.active });
});

test('short IDs: the Teams usage names both formats', async () => {
  const reply = await (await worker.fetch(teamsRequest('<at>Fusion</at> help'), ENV, ctx())).json();
  assert.match(reply.text, /A case is its ID, such as CSE00042 or E-01167,/);
});
