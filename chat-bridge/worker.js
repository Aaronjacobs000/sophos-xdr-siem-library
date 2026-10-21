// Chat bridge for Sophos Fusion cases: turns a Slack button or modal, or a Teams outgoing webhook
// command, into a case status change or a case comment, through the Sophos Fusion Cases GraphQL API.
// Unofficial, from the Unofficial Sophos Fusion XDR and SIEM Library. A Cloudflare Worker with no
// dependencies; README.md has the setup.
//
//   POST /slack/interactivity   the Slack app's interactivity request URL
//   POST /teams/outgoing        the Teams outgoing webhook's callback URL
//   GET  /healthz               200 ok, for monitoring
//
// Every request is checked before anything else: Slack's signing secret signature and timestamp, or
// the Teams outgoing webhook HMAC. Every write names the person who acted in the case comment and in
// the log, and every comment starts with BRIDGE_COMMENT_PREFIX so the outbound chat playbooks don't
// post it back to the channel.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHORT_ID = /^CSE\d{3,10}$/i;
const SLACK_TOLERANCE_SECONDS = 300;
const TEAMS_BUDGET_MS = 4200;
const MAX_COMMENT = 4000;
const DEFAULT_STATUSES = 'active,awaiting_action,closed';
const DEFAULT_VERDICTS = 'false_positive,threat_mitigated,confirmed_security_incident,authorized_activity,inconclusive,informational,not_vulnerable';
const DEFAULT_API = 'https://api.taegis.sophos.com/graphql';
const TOKEN_URL = 'https://id.sophos.com/api/v2/oauth2/token';
const WHOAMI_URL = 'https://api.central.sophos.com/whoami/v1';

// ---------------------------------------------------------------- settings

export function settings(env) {
  const list = (v, d) => String(v ?? d).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const api = String(env.FUSION_API || DEFAULT_API);
  let host = '';
  try { host = new URL(api).hostname; } catch { /* checked below */ }
  if (!api.startsWith('https://') || !(host === 'api.taegis.sophos.com' || /^api\.[a-z0-9-]+\.taegis\.sophos\.com$/.test(host))) {
    throw new Error('FUSION_API must be an https Sophos Fusion GraphQL URL on taegis.sophos.com');
  }
  return {
    api,
    tenantId: env.FUSION_TENANT_ID ? String(env.FUSION_TENANT_ID).trim() : '',
    statuses: list(env.BRIDGE_ALLOWED_STATUSES, DEFAULT_STATUSES),
    verdicts: list(env.BRIDGE_ALLOWED_VERDICTS, DEFAULT_VERDICTS),
    prefix: String(env.BRIDGE_COMMENT_PREFIX ?? '[chat-sync]'),
    dryRun: /^(1|true|yes)$/i.test(String(env.BRIDGE_DRY_RUN || '')),
    slackUsers: list(env.SLACK_ALLOWED_USERS, ''),
    slackTeam: String(env.SLACK_TEAM_ID || '').trim(),
    teamsUsers: list(env.TEAMS_ALLOWED_USERS, ''),
    teamsTenant: String(env.TEAMS_TENANT_ID || '').trim().toLowerCase(),
  };
}

// ---------------------------------------------------------------- crypto

const enc = new TextEncoder();

async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64 = (b) => btoa(String.fromCharCode(...b));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// Compares in time that doesn't depend on where the strings differ.
export function safeEqual(a, b) {
  const x = enc.encode(String(a));
  const y = enc.encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

// Slack: v0=hex(HMAC-SHA256(signing secret, "v0:" + timestamp + ":" + raw body)), within five minutes.
export async function verifySlack(secret, headers, raw, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!secret) return 'SLACK_SIGNING_SECRET is not set';
  const ts = headers.get('x-slack-request-timestamp') || '';
  const sig = headers.get('x-slack-signature') || '';
  if (!/^\d+$/.test(ts) || !sig) return 'missing Slack signature headers';
  if (Math.abs(nowSeconds - Number(ts)) > SLACK_TOLERANCE_SECONDS) return 'Slack timestamp is outside five minutes';
  const want = 'v0=' + hex(await hmac(enc.encode(secret), `v0:${ts}:${raw}`));
  return safeEqual(want, sig) ? null : 'Slack signature does not match';
}

// Teams outgoing webhook: "HMAC " + base64(HMAC-SHA256(base64-decoded security token, raw body)).
export async function verifyTeams(secret, headers, raw) {
  if (!secret) return 'TEAMS_HMAC_SECRET is not set';
  const auth = headers.get('authorization') || '';
  const m = /^HMAC\s+(\S+)$/.exec(auth);
  if (!m) return 'missing Teams HMAC header';
  let key;
  try { key = unb64(secret); } catch { return 'TEAMS_HMAC_SECRET is not base64'; }
  const want = b64(await hmac(key, raw));
  return safeEqual(want, m[1]) ? null : 'Teams HMAC does not match';
}

// ---------------------------------------------------------------- Sophos Fusion

let cachedToken = null;
let cachedTenant = null;

export function resetCache() { cachedToken = null; cachedTenant = null; }

async function getJson(res) {
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { raw: text.slice(0, 300) }; }
}

async function token(env) {
  if (cachedToken && cachedToken.exp > Date.now() + 60000) return cachedToken.value;
  if (!env.FUSION_CLIENT_ID || !env.FUSION_CLIENT_SECRET) throw new Error('FUSION_CLIENT_ID and FUSION_CLIENT_SECRET are not set');
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: env.FUSION_CLIENT_ID, client_secret: env.FUSION_CLIENT_SECRET, scope: 'token' }),
  });
  if (res.status !== 200) throw new Error(`Sophos sign-in failed (${res.status})`);
  const body = await getJson(res);
  cachedToken = { value: body.access_token, exp: Date.now() + Number(body.expires_in || 3600) * 1000 };
  return cachedToken.value;
}

async function tenant(env, cfg) {
  if (cfg.tenantId) return cfg.tenantId;
  if (cachedTenant) return cachedTenant;
  const res = await fetch(WHOAMI_URL, { redirect: 'manual', headers: { Authorization: `Bearer ${await token(env)}` } });
  if (res.status !== 200) throw new Error(`Sophos whoami failed (${res.status})`);
  const who = await getJson(res);
  if (who.idType && who.idType !== 'tenant') throw new Error('the Sophos credential must be a tenant credential');
  cachedTenant = who.id;
  return cachedTenant;
}

export async function gql(env, cfg, query, variables) {
  const res = await fetch(cfg.api, {
    method: 'POST',
    redirect: 'manual',
    headers: { Authorization: `Bearer ${await token(env)}`, 'X-Tenant-ID': await tenant(env, cfg), 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ query, variables }),
  });
  const body = await getJson(res);
  if (res.status !== 200 || body.errors) {
    const msg = body.errors && body.errors[0] ? body.errors[0].message : `HTTP ${res.status}`;
    throw new FusionError(msg);
  }
  return body.data;
}

export class FusionError extends Error {}

const CASE_FIELDS = 'id shortId title managedBy primaryStatus { id name title isClosed }';

export async function findCase(env, cfg, ref) {
  const r = String(ref || '').trim();
  if (UUID.test(r)) {
    const d = await gql(env, cfg, `query($a: CaseArguments!) { case(arguments: $a) { ${CASE_FIELDS} } }`, { a: { id: r } });
    return d.case || null;
  }
  if (SHORT_ID.test(r)) {
    const d = await gql(env, cfg, `query($q: String) { cases(arguments: { query: $q }) { cases { ${CASE_FIELDS} } } }`, { q: `shortId = '${r.toUpperCase()}'` });
    const list = (d.cases && d.cases.cases) || [];
    return list.length === 1 ? list[0] : null;
  }
  return null;
}

async function statusFor(env, cfg, kase, name) {
  const d = await gql(env, cfg, 'query($a: CasePrimaryStatusesArguments!) { casePrimaryStatuses(arguments: $a) { primaryStatuses { id name title isClosed } } }', { a: { caseId: kase.id } });
  return (d.casePrimaryStatuses.primaryStatuses || []).find((s) => s.name.toLowerCase() === name) || null;
}

async function verdictFor(env, cfg, kase, statusId, name) {
  const d = await gql(env, cfg, 'query($a: CasePrimaryVerdictsArguments!) { casePrimaryVerdicts(arguments: $a) { primaryVerdicts { id name title } } }', { a: { caseId: kase.id, primaryStatusId: statusId } });
  return (d.casePrimaryVerdicts.primaryVerdicts || []).find((v) => v.name.toLowerCase() === name) || null;
}

const clean = (s, max = MAX_COMMENT) => String(s || '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, max);
const nice = (s) => String(s || '').replace(/_/g, ' ');

// One action from a chat platform: {kind: 'status'|'close'|'comment', ref, status, verdict, text,
// actor: {platform, id, name}}. Returns {ok, message, case}.
export async function act(env, cfg, a, log = console.log) {
  const entry = { at: new Date().toISOString(), platform: a.actor.platform, user_id: a.actor.id, user_name: a.actor.name, action: a.kind, ref: a.ref, status: a.status || null, verdict: a.verdict || null, dry_run: cfg.dryRun };
  const done = (ok, message, kase) => { log(JSON.stringify({ ...entry, case_id: kase ? kase.id : null, ok, result: message })); return { ok, message, case: kase || null }; };
  try {
    const kase = await findCase(env, cfg, a.ref);
    if (!kase) return done(false, `No case ${a.ref} in this tenant.`);
    const label = kase.shortId || kase.id;
    if (kase.primaryStatus && kase.primaryStatus.isClosed) return done(false, `${label} is closed, so it can't be changed from chat. Reopen it in Sophos Fusion first.`, kase);
    const who = `${clean(a.actor.name, 200) || 'Unknown user'} via ${a.actor.platform}`;
    const note = clean(a.text);
    if (a.kind === 'comment') {
      if (!note) return done(false, 'Add the comment text after the case ID.', kase);
      const comment = `${cfg.prefix} ${who}: ${note}`.trim();
      if (cfg.dryRun) return done(true, `Dry run: would comment on ${label}: ${comment}`, kase);
      await gql(env, cfg, 'mutation($i: AddCaseComment!) { addCaseComment(input: $i) { id } }', { i: { caseId: kase.id, comment } });
      return done(true, `Added your comment to ${label}.`, kase);
    }
    const name = a.kind === 'close' ? 'closed' : String(a.status || '').toLowerCase();
    if (!cfg.statuses.includes(name)) return done(false, `${nice(name) || 'That status'} isn't one this bridge sets. Allowed: ${cfg.statuses.map(nice).join(', ')}.`, kase);
    if (kase.managedBy === 'PROVIDER') return done(false, `${label} is managed by Sophos MDR, so its status can't be changed from here. Comment instead, or use Sophos Fusion.`, kase);
    const status = await statusFor(env, cfg, kase, name);
    if (!status) return done(false, `${label} can't move to ${nice(name)} from ${kase.primaryStatus ? kase.primaryStatus.title || kase.primaryStatus.name : 'its current status'}.`, kase);
    const input = { id: kase.id, primaryStatusId: status.id };
    let verdictText = '';
    if (status.isClosed) {
      const vname = String(a.verdict || '').toLowerCase();
      if (!cfg.verdicts.includes(vname)) return done(false, `Closing needs a verdict. Allowed: ${cfg.verdicts.map(nice).join(', ')}.`, kase);
      const verdict = await verdictFor(env, cfg, kase, status.id, vname);
      if (!verdict) return done(false, `${nice(vname)} isn't a verdict ${label} can close with.`, kase);
      input.primaryVerdictId = verdict.id;
      if (note) input.closeReason = note.slice(0, 1000);
      verdictText = ` with the verdict ${verdict.title || nice(verdict.name)}`;
    }
    const comment = `${cfg.prefix} ${who} set the status to ${status.title || nice(status.name)}${verdictText}${note ? `: ${note}` : '.'}`.trim();
    if (cfg.dryRun) return done(true, `Dry run: would set ${label} to ${status.title || nice(status.name)}${verdictText} and comment: ${comment}`, kase);
    const d = await gql(env, cfg, `mutation($i: UpdateCaseInput!) { updateCase(input: $i) { ${CASE_FIELDS} } }`, { i: input });
    await gql(env, cfg, 'mutation($i: AddCaseComment!) { addCaseComment(input: $i) { id } }', { i: { caseId: kase.id, comment } });
    const now = d.updateCase && d.updateCase.primaryStatus ? d.updateCase.primaryStatus.title || d.updateCase.primaryStatus.name : status.title;
    return done(true, `${label} is now ${now}${verdictText}. Recorded on the case as ${who}.`, d.updateCase || kase);
  } catch (e) {
    const msg = e instanceof FusionError ? `Sophos Fusion refused it: ${e.message}` : `The bridge couldn't reach Sophos Fusion: ${e.message}`;
    return done(false, msg);
  }
}

// ---------------------------------------------------------------- Teams

const ENTITIES = { '&nbsp;': ' ', '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&apos;': "'" };

export function teamsText(html) {
  return String(html || '')
    .replace(/<at[^>]*>.*?<\/at>/gi, ' ')
    .replace(/<br\s*\/?>|<\/p>|<\/div>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/&[a-z#0-9]+;/gi, (e) => ENTITIES[e.toLowerCase()] ?? ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// "<status> <ref> [note]", "close <ref> <verdict> [note]", "comment <ref> <text>".
export function parseCommand(text, cfg) {
  const words = text.split(' ').filter(Boolean);
  const verb = (words[0] || '').toLowerCase();
  const ref = words[1] || '';
  if (!ref || !(UUID.test(ref) || SHORT_ID.test(ref))) return null;
  if (verb === 'comment') return { kind: 'comment', ref, text: words.slice(2).join(' ') };
  if (verb === 'close') return { kind: 'close', ref, verdict: (words[2] || '').toLowerCase(), text: words.slice(3).join(' ') };
  if (cfg.statuses.includes(verb) && verb !== 'closed') return { kind: 'status', ref, status: verb, text: words.slice(2).join(' ') };
  return null;
}

function teamsUsage(cfg) {
  const statuses = cfg.statuses.filter((s) => s !== 'closed');
  return `Commands: ${statuses.map((s) => `${s} <case>`).join(', ')}, close <case> <verdict> [note], comment <case> <text>. A case is its ID, such as CSE00042. Verdicts: ${cfg.verdicts.join(', ')}.`;
}

const teamsReply = (text) => new Response(JSON.stringify({ type: 'message', text }), { status: 200, headers: { 'Content-Type': 'application/json' } });

async function handleTeams(request, env, ctx, cfg) {
  const raw = await request.text();
  const bad = await verifyTeams(env.TEAMS_HMAC_SECRET, request.headers, raw);
  if (bad) { console.log(JSON.stringify({ at: new Date().toISOString(), platform: 'Teams', rejected: bad })); return new Response('unauthorized', { status: 401 }); }
  let activity;
  try { activity = JSON.parse(raw); } catch { return new Response('bad request', { status: 400 }); }
  const from = activity.from || {};
  const tenantId = String((activity.channelData && activity.channelData.tenant && activity.channelData.tenant.id) || '').toLowerCase();
  if (cfg.teamsTenant && tenantId !== cfg.teamsTenant) return teamsReply('This bridge serves a different Microsoft 365 tenant.');
  const userId = String(from.aadObjectId || from.id || '');
  if (cfg.teamsUsers.length && !cfg.teamsUsers.includes(userId.toLowerCase())) return teamsReply('You are not on this bridge\'s list of people who can change cases.');
  const cmd = parseCommand(teamsText(activity.text), cfg);
  if (!cmd) return teamsReply(teamsUsage(cfg));
  const work = act(env, cfg, { ...cmd, actor: { platform: 'Teams', id: userId, name: from.name || '' } });
  ctx.waitUntil(work);
  // Teams waits five seconds for the reply. Past the budget, answer now and let the work finish.
  let timer;
  const budget = new Promise((resolve) => { timer = setTimeout(() => resolve(null), Number(env.TEAMS_BUDGET_MS || TEAMS_BUDGET_MS)); });
  const result = await Promise.race([work, budget]);
  clearTimeout(timer);
  return teamsReply(result ? result.message : `Still working on ${cmd.ref}. Check the case in Sophos Fusion in a minute.`);
}

// ---------------------------------------------------------------- Slack

async function slackApi(env, method, body) {
  if (!env.SLACK_BOT_TOKEN) throw new Error('SLACK_BOT_TOKEN is not set');
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}`, 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });
  const out = await getJson(res);
  if (!out.ok) throw new Error(`Slack ${method} failed: ${out.error || res.status}`);
  return out;
}

// A response_url only ever points at Slack's own hooks host; anything else is refused.
async function slackRespond(responseUrl, text) {
  let u;
  try { u = new URL(responseUrl); } catch { return; }
  if (u.protocol !== 'https:' || u.hostname !== 'hooks.slack.com') return;
  await fetch(u.toString(), { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ response_type: 'ephemeral', replace_original: false, text }) });
}

function parseValue(v) {
  const [id, short] = String(v || '').split('|');
  if (UUID.test(id || '')) return id;
  if (SHORT_ID.test(short || '')) return short;
  return null;
}

function closeModal(cfg, meta) {
  return {
    type: 'modal',
    callback_id: 'fusion_close',
    private_metadata: JSON.stringify(meta),
    title: { type: 'plain_text', text: 'Close case' },
    submit: { type: 'plain_text', text: 'Close case' },
    close: { type: 'plain_text', text: 'Cancel' },
    blocks: [
      { type: 'input', block_id: 'verdict', label: { type: 'plain_text', text: 'Verdict' }, element: { type: 'static_select', action_id: 'v', options: cfg.verdicts.map((v) => ({ text: { type: 'plain_text', text: nice(v) }, value: v })) } },
      { type: 'input', block_id: 'note', label: { type: 'plain_text', text: 'Why' }, element: { type: 'plain_text_input', action_id: 'n', multiline: true, max_length: 1000 } },
    ],
  };
}

function commentModal(meta) {
  return {
    type: 'modal',
    callback_id: 'fusion_comment',
    private_metadata: JSON.stringify(meta),
    title: { type: 'plain_text', text: 'Comment on case' },
    submit: { type: 'plain_text', text: 'Add comment' },
    close: { type: 'plain_text', text: 'Cancel' },
    blocks: [{ type: 'input', block_id: 'note', label: { type: 'plain_text', text: 'Comment' }, element: { type: 'plain_text_input', action_id: 'n', multiline: true, max_length: MAX_COMMENT } }],
  };
}

const ok = (body = '') => new Response(body, { status: 200, headers: body ? { 'Content-Type': 'application/json' } : {} });

async function handleSlack(request, env, ctx, cfg) {
  const raw = await request.text();
  const bad = await verifySlack(env.SLACK_SIGNING_SECRET, request.headers, raw);
  if (bad) { console.log(JSON.stringify({ at: new Date().toISOString(), platform: 'Slack', rejected: bad })); return new Response('unauthorized', { status: 401 }); }
  let payload;
  try { payload = JSON.parse(new URLSearchParams(raw).get('payload') || ''); } catch { return new Response('bad request', { status: 400 }); }
  const user = payload.user || {};
  const actor = { platform: 'Slack', id: String(user.id || ''), name: user.name || user.username || '' };
  if (cfg.slackTeam && (payload.team && payload.team.id) !== cfg.slackTeam) return new Response('wrong workspace', { status: 403 });
  const allowed = !cfg.slackUsers.length || cfg.slackUsers.includes(actor.id.toLowerCase());

  if (payload.type === 'block_actions') {
    const action = (payload.actions || [])[0] || {};
    const id = String(action.action_id || '');
    if (id === 'fusion_open' || !id.startsWith('fusion_')) return ok();
    const ref = parseValue(action.value);
    const responseUrl = payload.response_url || '';
    if (!allowed) { ctx.waitUntil(slackRespond(responseUrl, 'You are not on this bridge\'s list of people who can change cases.')); return ok(); }
    if (!ref) return ok();
    if (id === 'fusion_close' || id === 'fusion_comment') {
      const meta = { ref, response_url: responseUrl };
      try {
        await slackApi(env, 'views.open', { trigger_id: payload.trigger_id, view: id === 'fusion_close' ? closeModal(cfg, meta) : commentModal(meta) });
      } catch (e) {
        ctx.waitUntil(slackRespond(responseUrl, `The bridge couldn't open the form: ${e.message}`));
      }
      return ok();
    }
    if (id.startsWith('fusion_status_')) {
      const status = id.slice('fusion_status_'.length);
      ctx.waitUntil(act(env, cfg, { kind: 'status', ref, status, text: '', actor }).then((r) => slackRespond(responseUrl, r.message)));
      return ok();
    }
    return ok();
  }

  if (payload.type === 'view_submission') {
    const view = payload.view || {};
    let meta = {};
    try { meta = JSON.parse(view.private_metadata || '{}'); } catch { meta = {}; }
    const ref = UUID.test(meta.ref || '') || SHORT_ID.test(meta.ref || '') ? meta.ref : null;
    const values = (view.state && view.state.values) || {};
    const note = values.note && values.note.n ? values.note.n.value || '' : '';
    if (!ref || !allowed) return ok(JSON.stringify({ response_action: 'clear' }));
    if (view.callback_id === 'fusion_close') {
      const verdict = values.verdict && values.verdict.v && values.verdict.v.selected_option ? values.verdict.v.selected_option.value : '';
      if (!cfg.verdicts.includes(String(verdict).toLowerCase())) return ok(JSON.stringify({ response_action: 'errors', errors: { verdict: 'Pick a verdict.' } }));
      ctx.waitUntil(act(env, cfg, { kind: 'close', ref, verdict, text: note, actor }).then((r) => slackRespond(meta.response_url, r.message)));
      return ok();
    }
    if (view.callback_id === 'fusion_comment') {
      if (!clean(note)) return ok(JSON.stringify({ response_action: 'errors', errors: { note: 'Write a comment.' } }));
      ctx.waitUntil(act(env, cfg, { kind: 'comment', ref, text: note, actor }).then((r) => slackRespond(meta.response_url, r.message)));
      return ok();
    }
  }
  return ok();
}

// ---------------------------------------------------------------- entry point

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/healthz') return new Response('ok');
    if (request.method !== 'POST') return new Response('not found', { status: 404 });
    let cfg;
    try { cfg = settings(env); } catch (e) { console.log(JSON.stringify({ at: new Date().toISOString(), config_error: e.message })); return new Response('bridge is not configured', { status: 500 }); }
    if (url.pathname === '/slack/interactivity') return handleSlack(request, env, ctx, cfg);
    if (url.pathname === '/teams/outgoing') return handleTeams(request, env, ctx, cfg);
    return new Response('not found', { status: 404 });
  },
};
