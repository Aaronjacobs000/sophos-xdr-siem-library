#!/usr/bin/env node
// Labels, the report comment, and the merge decision for library submissions. Runs in the
// trusted workflows (parser-merge and issue-submission) with GITHUB_TOKEN; it never runs
// code from a submission.
//
//   node tools/github-gate.mjs pr --pr <n> --sha <head sha> --report report.json --markdown report.md
//   node tools/github-gate.mjs issue --issue <n> --markdown report.md [--failed "<reason>"]
//   node tools/github-gate.mjs changed --pr <n> --out changed.txt
//   node tools/github-gate.mjs waiting --pr <n> --sha <head sha> [--ci <conclusion of CI's run>]
//
// Auto-merge happens only when the repo setting "Allow auto-merge" is on, every check passed,
// the pull request touches nothing outside parsers/, and each entry it changes is new or
// already belongs to the person who opened it. Right before merging, the pull request's own
// file list is checked again, so a change to bridges/ or anything else outside parsers/
// never merges without review, whichever route opened it. A file list that GitHub can't give
// in full holds the pull request for review. The merge waits until every other check on the
// checked commit, CI among them, has finished and passed. When it merges, pr and merge write
// merged=true to $GITHUB_OUTPUT, clear the "needs review" label, and delete the pull
// request's branch if it is in this repo. If CI is still running when the wait ends, or a check
// on the commit failed, the report says so and carries a marker for the commit. When CI finishes,
// the workflow runs the gate again for that commit if waiting says so: always for the first marker,
// and for the second only when CI passed, as after a re-run. A run whose commit is no longer the
// pull request's head, or that ends after another run merged or closed it, leaves the report and
// the labels alone, and puts back labels or a report it wrote just as the commit stopped being the head.

import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { reviewReasons } from './lib/merge-rules.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const opt = (n) => { const i = rest.indexOf(n); return i === -1 ? null : rest[i + 1]; };
const REPO = process.env.GITHUB_REPOSITORY;
const TOKEN = process.env.GITHUB_TOKEN;
const MARKER = '<!-- parser-studio-report -->';
// The last line of a report the gate wrote while CI was still running on the commit.
const waitingMarker = (sha) => `<!-- parser-studio-waiting-for-ci ${sha} -->`;
// The last line of a report the gate wrote when a check on the commit failed.
const failedMarker = (sha) => `<!-- parser-studio-check-failed ${sha} -->`;
const LABELS = {
  passed: ['library checks passed', '1a7f37', 'Every library check passed'],
  failed: ['library checks failed', 'd1242f', 'A library check failed'],
  review: ['needs review', 'bf8700', 'Passed the checks but needs a maintainer to look'],
  auto: ['auto-merge', '0969da', 'Merged by the library workflow after the checks passed'],
  submission: ['parser-submission', '8250df', 'A parser submitted through the issue form'],
};

// GitHub sometimes answers a read or a merge with a 500, and a merge with 405 "Base branch was
// modified" when another merge lands first. They pass on a retry, so the gate tries again a few times.
const RETRIES = 3;
const RETRY_MS = Number(process.env.GATE_RETRY_MS ?? 3000);
// How often the gate looks again while it waits for checks or for GitHub's auto-merge.
const POLL_MS = Number(process.env.GATE_POLL_MS ?? 15000);
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

// A pull request's changed files, with every rename's old name. GitHub lists at most 3,000 files
// and this reads at most 2,900, so the list is checked against the pull request's own count, and
// a list that comes up short is reported rather than trusted.
async function changedFiles(pr, pull = null) {
  const p = pull || await gh('GET', `/repos/${REPO}/pulls/${pr}`);
  const files = await all(`/repos/${REPO}/pulls/${pr}/files`);
  const short = files.length !== p.changed_files ? `GitHub listed ${files.length} of the ${p.changed_files} changed files` : null;
  return { names: files.flatMap((f) => [f.filename, f.previous_filename].filter(Boolean)), short };
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

// The gate's own report comment on a pull request or issue, if it has written one.
async function reportComment(num) {
  return (await all(`/repos/${REPO}/issues/${num}/comments`)).find((c) => c.body && c.body.startsWith(MARKER) && c.user && c.user.type === 'Bot');
}

// Writes the report and returns how to put it back: {id, previous} after editing the gate's comment,
// {id, created: true} after adding one.
async function comment(num, markdown) {
  const body = markdown.includes(MARKER) ? markdown : `${MARKER}\n${markdown}`;
  const mine = await reportComment(num);
  if (mine) {
    await gh('PATCH', `/repos/${REPO}/issues/comments/${mine.id}`, { body });
    return { id: mine.id, previous: mine.body };
  }
  const made = await gh('POST', `/repos/${REPO}/issues/${num}/comments`, { body });
  return { id: made && made.id, created: true };
}

// Waits for the other checks on the commit to finish and reports 'passed' when they all passed. The
// workflow that runs this script is left out by job name. On the pull request route (needCI) CI
// runs on every pull request, so the gate also waits for CI's own run on the commit: a check GitHub
// hasn't created yet can't be missed. The issue route opens its pull request with GITHUB_TOKEN,
// which starts no workflows, so there it has no checks to wait for. After 10 minutes it reports
// 'waiting' when CI's run hasn't finished and no check has failed so far, and 'failed' otherwise.
async function otherChecks(sha, self, needCI) {
  const ok = (r) => ['success', 'skipped', 'neutral'].includes(r.conclusion);
  let runs = [];
  let ciDone = true;
  for (let i = 0; i < 40; i++) {
    runs = (await gh('GET', `/repos/${REPO}/commits/${sha}/check-runs?per_page=100`)).check_runs.filter((r) => r.name !== self);
    // Newest first, so the first run is the one that counts.
    const ci = needCI ? (await gh('GET', `/repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${sha}&per_page=100`)).workflow_runs : [];
    ciDone = !needCI || (ci.length > 0 && ci.every((r) => r.status === 'completed'));
    if (runs.every((r) => r.status === 'completed') && ciDone) return runs.every(ok) && (!needCI || ci[0].conclusion === 'success') ? 'passed' : 'failed';
    await pause(POLL_MS);
  }
  return ciDone || runs.some((r) => r.status === 'completed' && !ok(r)) ? 'failed' : 'waiting';
}

// Whether the pull request can still merge on its own at the checked commit, or why not.
async function holdReason(pr, sha) {
  const p = await gh('GET', `/repos/${REPO}/pulls/${pr}`);
  if (p.state !== 'open') return { p, reason: CLOSED };
  if (p.draft) return { p, reason: 'The pull request is a draft, so it waits.' };
  if (p.head.sha !== sha) return { p, reason: 'The pull request changed after these checks ran; the next run decides.' };
  const files = await changedFiles(pr, p);
  if (files.short) return { p, reason: `Not merged automatically: ${files.short}, so a maintainer will review it.` };
  const held = reviewReasons(files.names);
  if (held.length) return { p, reason: `Not merged automatically: this pull request ${held.join('; ')}. A maintainer will review it.` };
  return { p, reason: null };
}

const CLOSED = 'The pull request is no longer open.';
const WAITING = 'CI is still running on this commit after 10 minutes, so this waits. When CI finishes, the gate runs again and merges this pull request if CI passed, with no maintainer needed.';
const CHECK_FAILED = 'Another check on this commit failed or is still running, so a maintainer will look at it. If a re-run of CI passes, the gate runs again for this commit.';

async function merge(pr, sha, { needCI = false } = {}) {
  const repo = await gh('GET', `/repos/${REPO}`);
  if (!repo.allow_auto_merge) return 'Auto-merge is off for this repo, so a maintainer will merge it.';
  const first = await holdReason(pr, sha);
  if (first.reason) return first.reason;
  // Nothing merges until the checks on this commit, CI's tests among them, have all passed. The
  // wait takes minutes, so everything above is checked again after it.
  const checks = await otherChecks(sha, process.env.GATE_JOB || 'gate', needCI);
  if (checks === 'waiting') return WAITING;
  if (checks !== 'passed') return CHECK_FAILED;
  const { p, reason } = await holdReason(pr, sha);
  if (reason) return reason;
  try {
    // Native auto-merge is for a branch rule that holds the pull request, such as a required review.
    await gh('POST', '/graphql', { query: 'mutation($id:ID!,$sha:GitObjectID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:SQUASH,expectedHeadOid:$sha}){clientMutationId}}', variables: { id: p.node_id, sha } }).then((r) => { if (r.errors) throw new Error(r.errors[0].message); });
  } catch {
    const done = await mergeCommit(pr, sha);
    if (done !== 'Merged.') return done;
    await deleteHeadBranch(p, sha);
    return 'Merged.';
  }
  // GitHub merges on its own once nothing holds the pull request. The gate waits a short while
  // for that, so it can delete the branch and start Pages after this merge too. A merge after the
  // wait starts no workflow at all: see "Notes for maintainers" in CONTRIBUTING.md.
  for (let i = 0; i < 8; i++) {
    await pause(POLL_MS);
    const now = await gh('GET', `/repos/${REPO}/pulls/${pr}`);
    if (now.merged) {
      await deleteHeadBranch(p, sha);
      return 'Merged.';
    }
    if (now.state !== 'open') return CLOSED;
  }
  return 'Auto-merge is on for this pull request.';
}

// Merges the checked commit: the merge names it, so GitHub refuses it if the head has moved. A 405
// "Base branch was modified" and a 5xx are tried again, after 3, 6 and 9 seconds. A 5xx may come
// after GitHub merged, so before each retry and after the last one the gate reads the pull request:
// merged counts as merged, and a pull request that closed or has a new head isn't merged again.
async function mergeCommit(pr, sha) {
  for (let i = 0; ; i++) {
    try {
      await gh('PUT', `/repos/${REPO}/pulls/${pr}/merge`, { sha, merge_method: 'squash' });
      return 'Merged.';
    } catch (e) {
      const server = e.status >= 500;
      if (!server && !(e.status === 405 && /base branch was modified/i.test(e.message))) throw e;
      if (i < RETRIES) await pause(RETRY_MS * (i + 1));
      if (server) {
        const now = await gh('GET', `/repos/${REPO}/pulls/${pr}`);
        if (now.merged) return 'Merged.';
        if (now.state !== 'open') return CLOSED;
        if (!now.head || now.head.sha !== sha) return 'The pull request changed after these checks ran; the next run decides.';
      }
      if (i >= RETRIES) throw e;
    }
  }
}

// The repo setting that deletes head branches doesn't act on a merge made with GITHUB_TOKEN, or on
// native auto-merge the gate turned on, so after a merge the gate deletes the branch: only one in
// this repo, never a fork's or main, and only while it still points at the merged commit. A failure
// here doesn't undo the merge.
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

// Whether the pull request is still open with the checked commit as its head. A run that is no
// longer current doesn't touch the report: the run for the new head, or the one that merged the
// pull request, writes the report that counts.
async function current(pr, sha) {
  return isHead(await gh('GET', `/repos/${REPO}/pulls/${pr}`), sha);
}

const isHead = (p, sha) => p.state === 'open' && Boolean(p.head) && p.head.sha === sha;

if (cmd === 'changed') {
  const { names, short } = await changedFiles(opt('--pr'));
  if (short) { console.error(`${short}, so the checks can't see the whole pull request.`); process.exit(1); }
  await writeFile(opt('--out'), names.join('\n') + '\n');
  console.log(`${names.length} changed files`);
} else if (cmd === 'pr') {
  const pr = opt('--pr');
  const sha = opt('--sha');
  const report = JSON.parse(await readFile(opt('--report'), 'utf8'));
  let md = await readFile(opt('--markdown'), 'utf8');
  let outcome = null;
  await ensureLabels();
  // A run labels the pull request only while its commit is still the open pull request's head, so a
  // run for a commit the pull request has moved past can't add "needs review" or undo the labels of
  // the run for the newer commit. The run that merged it labels it too. A push can land between the
  // read and the label calls, so the gate reads the pull request again after them, and if its commit
  // is no longer the open head, it puts the labels back as they were. The run for the new commit
  // can't have labeled it yet: it starts only when Parser checks finish on that commit.
  const label = async (add, remove) => {
    const before = await gh('GET', `/repos/${REPO}/pulls/${pr}`);
    if (!isHead(before, sha)) return;
    await setLabels(pr, add, remove);
    if (isHead(await gh('GET', `/repos/${REPO}/pulls/${pr}`), sha)) return;
    const had = new Set((before.labels || []).map((l) => l.name));
    await setLabels(pr, remove.filter((n) => had.has(n)), add.filter((n) => !had.has(n)));
    console.log('The pull request moved on while this run labeled it, so its labels are back as they were.');
  };
  if (!report.passed) {
    // Failed checks need a fix, not a review, so an earlier run's "needs review" goes.
    await label([LABELS.failed[0]], [LABELS.passed[0], LABELS.auto[0], LABELS.review[0]]);
  } else if (report.eligible) {
    await label([LABELS.passed[0]], [LABELS.failed[0], LABELS.review[0]]);
    outcome = await merge(pr, sha, { needCI: true }).catch((e) => `Merging failed: ${e.message}`);
    await reportMerged(outcome);
    // An earlier run, on a commit the pull request has since moved past, may have added "needs
    // review" while this run waited, so the merge clears it. A pull request that is no longer open
    // gets no new label, and one waiting for CI needs no maintainer.
    if (/Merged|Auto-merge is on/.test(outcome)) await setLabels(pr, [LABELS.auto[0]], [LABELS.review[0]]);
    else if (outcome !== CLOSED && outcome !== WAITING) await label([LABELS.review[0]], []);
    md += `\n${outcome}\n`;
    if (outcome === WAITING) md += `\n${waitingMarker(sha)}\n`;
    if (outcome === CHECK_FAILED) md += `\n${failedMarker(sha)}\n`;
  } else {
    await label([LABELS.passed[0], LABELS.review[0]], [LABELS.failed[0], LABELS.auto[0]]);
  }
  if (outcome === 'Merged.') await comment(pr, md);
  else if (!(await current(pr, sha))) console.log('The pull request merged, closed or moved on while this run worked, so its report is left as it is.');
  else {
    // The report has the labels' window: a push can land between the read above and the write, so
    // the gate reads the pull request again after it, and if its commit is no longer the open head,
    // puts the report back as it was. The run for the new commit can't have written one yet.
    const done = await comment(pr, md);
    if (!(await current(pr, sha))) {
      if (!done.created) await gh('PATCH', `/repos/${REPO}/issues/comments/${done.id}`, { body: done.previous });
      else if (done.id) await gh('DELETE', `/repos/${REPO}/issues/comments/${done.id}`);
      else console.error('::warning::The pull request moved on while this run wrote its report, and GitHub gave no ID to take the report back.');
      console.log('The pull request moved on while this run wrote its report, so the report is back as it was.');
    }
  }
} else if (cmd === 'issue') {
  const num = opt('--issue');
  await ensureLabels();
  let md = opt('--markdown') ? await readFile(opt('--markdown'), 'utf8') : '';
  if (opt('--failed')) md = `${MARKER}\n### Parser library checks: failed\n\n${opt('--failed')}\n\nEdit the issue to try again.\n`;
  if (opt('--note')) md += `\n${opt('--note')}\n`;
  await comment(num, md);
  const passed = /checks: passed/.test(md);
  await setLabels(num, [passed ? LABELS.passed[0] : LABELS.failed[0]], [passed ? LABELS.failed[0] : LABELS.passed[0]]);
} else if (cmd === 'waiting') {
  // Exits 0 when CI finishing on this commit should run the gate again: the gate's report says it is
  // waiting for CI on the commit, or says a check on it failed and CI has now passed (a re-run).
  const mine = await reportComment(opt('--pr'));
  const body = mine ? mine.body.trimEnd() : '';
  const waiting = body.endsWith(waitingMarker(opt('--sha')));
  const rerun = opt('--ci') === 'success' && body.endsWith(failedMarker(opt('--sha')));
  console.log(waiting ? 'The gate is waiting for CI on this commit.'
    : rerun ? 'A check on this commit failed and CI has passed since, so the gate runs again.'
      : 'The gate isn\'t waiting for CI on this commit.');
  process.exit(waiting || rerun ? 0 : 1);
} else if (cmd === 'merge') {
  const outcome = await merge(opt('--pr'), opt('--sha'));
  await reportMerged(outcome);
  console.log(outcome);
} else {
  console.error('usage: github-gate.mjs changed|pr|issue|merge|waiting ...');
  process.exit(2);
}
