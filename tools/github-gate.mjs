#!/usr/bin/env node
// Labels, the report comment, and the merge decision for library submissions. Runs in the
// trusted workflows (parser-merge and issue-submission) with GITHUB_TOKEN; it never runs
// code from a submission.
//
//   node tools/github-gate.mjs pr --pr <n> --sha <head sha> --report report.json --markdown report.md
//   node tools/github-gate.mjs issue --issue <n> --markdown report.md [--failed "<reason>"]
//   node tools/github-gate.mjs changed --pr <n> --out changed.txt
//
// Auto-merge happens only when the repo setting "Allow auto-merge" is on, every check passed,
// the pull request touches nothing outside parsers/, and each entry it changes is new or
// already belongs to the person who opened it. Right before merging, the pull request's own
// file list is checked again, so a change to bridges/ or anything else outside parsers/
// never merges without review, whichever route opened it. When it merges, pr and merge write
// merged=true to $GITHUB_OUTPUT and delete the pull request's branch if it is in this repo.

import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { reviewReasons } from './lib/merge-rules.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const opt = (n) => { const i = rest.indexOf(n); return i === -1 ? null : rest[i + 1]; };
const REPO = process.env.GITHUB_REPOSITORY;
const TOKEN = process.env.GITHUB_TOKEN;
const MARKER = '<!-- parser-studio-report -->';
const LABELS = {
  passed: ['library checks passed', '1a7f37', 'Every Parser Studio library check passed'],
  failed: ['library checks failed', 'd1242f', 'A Parser Studio library check failed'],
  review: ['needs review', 'bf8700', 'Passed the checks but needs a maintainer to look'],
  auto: ['auto-merge', '0969da', 'Merged by the library workflow after the checks passed'],
  submission: ['parser-submission', '8250df', 'A parser submitted through the issue form'],
};

// GitHub sometimes answers a read with a 500, and a merge with 405 "Base branch was modified"
// when another merge lands first. Both pass on a retry, so the gate tries again a few times.
const RETRIES = 3;
const RETRY_MS = Number(process.env.GATE_RETRY_MS ?? 3000);
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

async function retrying(call, again) {
  for (let i = 0; ; i++) {
    try {
      return await call();
    } catch (e) {
      if (i >= RETRIES || !again(e)) throw e;
      await pause(RETRY_MS * (i + 1));
    }
  }
}

async function gh(method, url, body) {
  if (method === 'GET') return retrying(() => request(method, url, body), (e) => e.status >= 500);
  return request(method, url, body);
}

async function request(method, url, body) {
  const res = await fetch(url.startsWith('https://') ? url : `https://api.github.com${url}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'parser-studio-gate' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { message: text.slice(0, 200) }; }
  if (!res.ok) throw Object.assign(new Error(`${method} ${url}: ${res.status} ${data && data.message}`), { status: res.status, data });
  return data;
}

async function all(url) {
  const out = [];
  for (let page = 1; page < 30; page++) {
    const batch = await gh('GET', `${url}${url.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

async function ensureLabels() {
  const have = new Set((await all(`/repos/${REPO}/labels`)).map((l) => l.name));
  for (const [name, color, description] of Object.values(LABELS)) {
    if (!have.has(name)) await gh('POST', `/repos/${REPO}/labels`, { name, color, description }).catch(() => {});
  }
}

async function setLabels(num, add, remove) {
  if (add.length) await gh('POST', `/repos/${REPO}/issues/${num}/labels`, { labels: add });
  for (const name of remove) await gh('DELETE', `/repos/${REPO}/issues/${num}/labels/${encodeURIComponent(name)}`).catch(() => {});
}

async function comment(num, markdown) {
  const body = markdown.includes(MARKER) ? markdown : `${MARKER}\n${markdown}`;
  const mine = (await all(`/repos/${REPO}/issues/${num}/comments`)).find((c) => c.body && c.body.startsWith(MARKER) && c.user && c.user.type === 'Bot');
  if (mine) await gh('PATCH', `/repos/${REPO}/issues/comments/${mine.id}`, { body });
  else await gh('POST', `/repos/${REPO}/issues/${num}/comments`, { body });
}

// Waits for the other checks on the commit (CI's unit tests, for example) and reports
// whether they all passed. The workflow that runs this script is left out by job name.
async function otherChecksPassed(sha, self) {
  for (let i = 0; i < 40; i++) {
    const runs = (await gh('GET', `/repos/${REPO}/commits/${sha}/check-runs?per_page=100`)).check_runs.filter((r) => r.name !== self);
    if (runs.every((r) => r.status === 'completed')) return runs.every((r) => ['success', 'skipped', 'neutral'].includes(r.conclusion));
    await new Promise((r) => setTimeout(r, 15000));
  }
  return false;
}

async function merge(pr, sha) {
  const repo = await gh('GET', `/repos/${REPO}`);
  if (!repo.allow_auto_merge) return 'Auto-merge is off for this repo, so a maintainer will merge it.';
  const p = await gh('GET', `/repos/${REPO}/pulls/${pr}`);
  if (p.draft) return 'The pull request is a draft, so it waits.';
  if (p.head.sha !== sha) return 'The pull request changed after these checks ran; the next run decides.';
  const files = await all(`/repos/${REPO}/pulls/${pr}/files`);
  const held = reviewReasons(files.flatMap((f) => [f.filename, f.previous_filename].filter(Boolean)));
  if (held.length) return `Not merged automatically: this pull request ${held.join('; ')}. A maintainer will review it.`;
  try {
    // Native auto-merge waits for any required checks; it needs a branch rule to exist.
    await gh('POST', '/graphql', { query: 'mutation($id:ID!,$sha:GitObjectID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:SQUASH,expectedHeadOid:$sha}){clientMutationId}}', variables: { id: p.node_id, sha } }).then((r) => { if (r.errors) throw new Error(r.errors[0].message); });
    return 'Auto-merge is on for this pull request.';
  } catch {
    if (!(await otherChecksPassed(sha, process.env.GATE_JOB || 'gate'))) return 'Another check on this commit failed or is still running, so a maintainer will look at it.';
    await retrying(() => gh('PUT', `/repos/${REPO}/pulls/${pr}/merge`, { sha, merge_method: 'squash' }), (e) => e.status === 405 && /base branch was modified/i.test(e.message));
    await deleteHeadBranch(p, sha);
    return 'Merged.';
  }
}

// The repo setting that deletes head branches doesn't act on a merge made with GITHUB_TOKEN,
// so after its own merge the gate deletes the branch: only one in this repo, never a fork's or
// main, and only while it still points at the merged commit. A failure here doesn't undo the merge.
async function deleteHeadBranch(p, sha) {
  const head = p.head || {};
  const base = p.base || {};
  if (!head.ref || !head.repo || !base.repo || head.repo.id !== base.repo.id) return;
  if ([base.ref, base.repo.default_branch, 'main'].includes(head.ref)) return;
  const ref = `heads/${head.ref.split('/').map(encodeURIComponent).join('/')}`;
  try {
    const now = await gh('GET', `/repos/${REPO}/git/ref/${ref}`);
    if (!now || !now.object || now.object.sha !== sha) return;
    await gh('DELETE', `/repos/${REPO}/git/refs/${ref}`);
  } catch (e) {
    if (e.status !== 404 && e.status !== 422) console.error(`::warning::Merged, but couldn't delete the branch ${head.ref}: ${e.message}`);
  }
}

// A merge made with GITHUB_TOKEN starts no push workflows, so the workflow reads merged=true
// from the step output and starts the Pages build itself.
async function reportMerged(outcome) {
  if (outcome === 'Merged.' && process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, 'merged=true\n');
}

if (cmd === 'changed') {
  const files = await all(`/repos/${REPO}/pulls/${opt('--pr')}/files`);
  const names = files.flatMap((f) => [f.filename, f.previous_filename].filter(Boolean));
  await writeFile(opt('--out'), names.join('\n') + '\n');
  console.log(`${names.length} changed files`);
} else if (cmd === 'pr') {
  const pr = opt('--pr');
  const sha = opt('--sha');
  const report = JSON.parse(await readFile(opt('--report'), 'utf8'));
  let md = await readFile(opt('--markdown'), 'utf8');
  await ensureLabels();
  if (!report.passed) {
    await setLabels(pr, [LABELS.failed[0]], [LABELS.passed[0], LABELS.auto[0]]);
  } else if (report.eligible) {
    await setLabels(pr, [LABELS.passed[0]], [LABELS.failed[0], LABELS.review[0]]);
    const outcome = await merge(pr, sha).catch((e) => `Merging failed: ${e.message}`);
    await reportMerged(outcome);
    if (/Merged|Auto-merge is on/.test(outcome)) await setLabels(pr, [LABELS.auto[0]], []);
    else await setLabels(pr, [LABELS.review[0]], []);
    md += `\n${outcome}\n`;
  } else {
    await setLabels(pr, [LABELS.passed[0], LABELS.review[0]], [LABELS.failed[0], LABELS.auto[0]]);
  }
  await comment(pr, md);
} else if (cmd === 'issue') {
  const num = opt('--issue');
  await ensureLabels();
  let md = opt('--markdown') ? await readFile(opt('--markdown'), 'utf8') : '';
  if (opt('--failed')) md = `${MARKER}\n### Parser library checks: failed\n\n${opt('--failed')}\n\nEdit the issue to try again.\n`;
  if (opt('--note')) md += `\n${opt('--note')}\n`;
  await comment(num, md);
  const passed = /checks: passed/.test(md);
  await setLabels(num, [passed ? LABELS.passed[0] : LABELS.failed[0]], [passed ? LABELS.failed[0] : LABELS.passed[0]]);
} else if (cmd === 'merge') {
  const outcome = await merge(opt('--pr'), opt('--sha'));
  await reportMerged(outcome);
  console.log(outcome);
} else {
  console.error('usage: github-gate.mjs changed|pr|issue|merge ...');
  process.exit(2);
}
