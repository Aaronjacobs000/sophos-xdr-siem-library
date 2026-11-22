// The site's stars and Sort menu: the sort orders, with and without a search; the star state, which
// changes on a tap and follows the API's answer; and that a slow, failing or missing API, or
// blocked browser storage, leaves the page as it is without stars.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sortEntries, SORTS, popularIds, POPULAR_TOP, POPULAR_MIN } from '../studio/app/sort.js';
import { createStars, API } from '../studio/app/stars.js';
import { searchText, automationSearchText } from '../studio/core/library.js';
import { parseAddedLog } from '../tools/lib/added-dates.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const entries = [
  { id: 'acme/widget', added: '2026-10-20T00:00:00.000Z', meta: { vendor: 'Acme', product: 'Widget' } },
  { id: 'acme/gadget', added: '2026-11-02T00:00:00.000Z', meta: { vendor: 'Acme', product: 'Gadget' } },
  { id: 'beta/thing', meta: { vendor: 'Beta', product: 'Thing' } },
  { id: '3cx/phone', added: '2026-11-02T00:00:00.000Z', meta: { vendor: '3CX', product: 'Phone' } },
  { id: 'zed/acme-bridge', added: 'not a date', meta: { vendor: 'Zed', product: 'Acme bridge' } },
];
const ids = (list) => list.map((e) => e.id);
const stars = { 'parsers/beta/thing': 4, 'parsers/acme/widget': 4, 'parsers/zed/acme-bridge': 9, 'playbooks/acme/gadget': 50 };
const views = { 'parsers/acme/gadget': 30, 'parsers/3cx/phone': 2 };

test('the Sort menu: A to Z first, so the default is the list as it was', () => {
  assert.deepEqual(SORTS.map((s) => [s.value, s.label]), [['az', 'A to Z'], ['stars', 'Most starred'], ['views', 'Most viewed'], ['newest', 'Newest']]);
});

test('sorts: A to Z by id, most starred, most viewed and newest, with ties in A to Z order', () => {
  const opts = { section: 'parsers', stars, views };
  assert.deepEqual(ids(sortEntries(entries, 'az', opts)), ['3cx/phone', 'acme/gadget', 'acme/widget', 'beta/thing', 'zed/acme-bridge']);
  assert.deepEqual(ids(sortEntries(entries, 'stars', opts)), ['zed/acme-bridge', 'acme/widget', 'beta/thing', '3cx/phone', 'acme/gadget']);
  assert.deepEqual(ids(sortEntries(entries, 'views', opts)), ['acme/gadget', '3cx/phone', 'acme/widget', 'beta/thing', 'zed/acme-bridge']);
  assert.deepEqual(ids(sortEntries(entries, 'newest', opts)), ['3cx/phone', 'acme/gadget', 'acme/widget', 'beta/thing', 'zed/acme-bridge']);
  // The section is part of the key: a playbook's stars don't count for a parser with the same id.
  assert.deepEqual(ids(sortEntries(entries, 'stars', { section: 'playbooks', stars })), ['acme/gadget', '3cx/phone', 'acme/widget', 'beta/thing', 'zed/acme-bridge']);
  // No counts and an unknown sort: A to Z. The list passed in is never changed.
  const copy = [...entries];
  assert.deepEqual(ids(sortEntries(entries, 'stars')), ids(sortEntries(entries, 'az')));
  assert.deepEqual(ids(sortEntries(entries, 'bogus', opts)), ids(sortEntries(entries, 'az')));
  assert.deepEqual(entries, copy);
  assert.deepEqual(ids(sortEntries(entries, 'stars', { stars: { __proto__: null, 'parsers/acme/gadget': 'many' } })), ids(sortEntries(entries, 'az')));
});

test('sorts work on the search results', () => {
  const q = 'acme';
  const found = entries.filter((e) => searchText(e.meta).includes(q));
  assert.deepEqual(ids(found), ['acme/widget', 'acme/gadget', 'zed/acme-bridge']);
  const opts = { section: 'parsers', stars, views };
  assert.deepEqual(ids(sortEntries(found, 'az', opts)), ['acme/gadget', 'acme/widget', 'zed/acme-bridge']);
  assert.deepEqual(ids(sortEntries(found, 'stars', opts)), ['zed/acme-bridge', 'acme/widget', 'acme/gadget']);
  assert.deepEqual(ids(sortEntries(found, 'views', opts)), ['acme/gadget', 'acme/widget', 'zed/acme-bridge']);
  assert.deepEqual(ids(sortEntries(found, 'newest', opts)), ['acme/gadget', 'acme/widget', 'zed/acme-bridge']);
});

test('playbooks and connectors: the search matches what the cards show, and the sorts work on its results', () => {
  const playbooks = [
    { id: 'acme/widget-lock', added: '2026-11-01T00:00:00.000Z', meta: { title: 'Widget lock', vendor: 'Acme', product: 'Widget', use_case: 'Lock a widget when a case opens.', risk_tier: 'reversible action', connector: 'connectors/acme/acme-widget', author: 'someone' } },
    { id: 'beta/case-post', added: '2026-11-05T00:00:00.000Z', meta: { title: 'Case post', vendor: 'Beta', product: 'Chat', use_case: 'Post the case to chat.', risk_tier: 'notify', connector: null, author: 'other' } },
    { id: 'acme/gadget-read', meta: { title: 'Gadget read', vendor: 'Acme', product: 'Gadget', use_case: 'Read a gadget.', risk_tier: 'lookup', connector: null } },
  ];
  const find = (q) => ids(playbooks.filter((e) => automationSearchText('playbooks', e.meta).includes(q)));
  assert.deepEqual(find('acme'), ['acme/widget-lock', 'acme/gadget-read']);
  assert.deepEqual(find('case'), ['acme/widget-lock', 'beta/case-post']);
  assert.deepEqual(find('notify'), ['beta/case-post']);
  assert.deepEqual(find('needs a library connector'), ['acme/widget-lock']);
  assert.deepEqual(find('@other'), []);
  assert.deepEqual(find('other'), ['beta/case-post']);
  const found = playbooks.filter((e) => automationSearchText('playbooks', e.meta).includes('acme'));
  const opts = { section: 'playbooks', stars: { 'playbooks/acme/gadget-read': 2, 'parsers/acme/widget-lock': 9 }, views: { 'playbooks/acme/widget-lock': 7 } };
  assert.deepEqual(ids(sortEntries(found, 'az', opts)), ['acme/gadget-read', 'acme/widget-lock']);
  assert.deepEqual(ids(sortEntries(found, 'stars', opts)), ['acme/gadget-read', 'acme/widget-lock']);
  assert.deepEqual(ids(sortEntries(found, 'views', opts)), ['acme/widget-lock', 'acme/gadget-read']);
  assert.deepEqual(ids(sortEntries(found, 'newest', opts)), ['acme/widget-lock', 'acme/gadget-read']);
  const connector = { title: 'Acme Widget', vendor: 'Acme', product: 'Widget', auth: 'API key in a header', functions: { lockWidget: 'reversible action', getWidget: 'lookup' }, author: 'someone' };
  for (const q of ['acme', 'api key', 'lockwidget', 'reversible action', 'someone']) assert.ok(automationSearchText('connectors', connector).includes(q), q);
  assert.ok(!automationSearchText('connectors', connector).includes('needs a library connector'));
  for (const bad of [null, undefined, 'text', { functions: ['x'] }]) assert.equal(typeof automationSearchText('connectors', bad), 'string');
});

test('Popular: the top three by views in a section, none below the floor, and never an arbitrary pick from a tie', () => {
  assert.deepEqual([POPULAR_TOP, POPULAR_MIN], [3, 5]);
  const set = (...a) => new Set(a);
  // The most viewed three, in this section only.
  assert.deepEqual(popularIds({ 'parsers/a/a': 40, 'parsers/b/b': 30, 'parsers/c/c': 20, 'parsers/d/d': 10, 'playbooks/x/x': 99 }, 'parsers'), set('parsers/a/a', 'parsers/b/b', 'parsers/c/c'));
  assert.deepEqual(popularIds({ 'parsers/a/a': 40, 'playbooks/x/x': 99 }, 'playbooks'), set('playbooks/x/x'));
  // Thin data: fewer, and none under the floor.
  assert.deepEqual(popularIds({ 'connectors/a/a': 5, 'connectors/b/b': 3, 'connectors/c/c': 1 }, 'connectors'), set('connectors/a/a'));
  assert.deepEqual(popularIds({ 'connectors/a/a': 4, 'connectors/b/b': 1 }, 'connectors'), set());
  // A tie across third place tags none of the tied entries.
  assert.deepEqual(popularIds({ 'playbooks/a/a': 13, 'playbooks/b/b': 10, 'playbooks/c/c': 5, 'playbooks/d/d': 5, 'playbooks/e/e': 4 }, 'playbooks'), set('playbooks/a/a', 'playbooks/b/b'));
  assert.deepEqual(popularIds({ 'parsers/a/a': 9, 'parsers/b/b': 9, 'parsers/c/c': 9, 'parsers/d/d': 9 }, 'parsers'), set());
  // A tie that stays inside the top three is fine.
  assert.deepEqual(popularIds({ 'parsers/a/a': 9, 'parsers/b/b': 9, 'parsers/c/c': 9, 'parsers/d/d': 8 }, 'parsers'), set('parsers/a/a', 'parsers/b/b', 'parsers/c/c'));
  // No view data: no tags.
  for (const none of [{}, null, undefined]) assert.deepEqual(popularIds(none, 'parsers'), set());
});

test('Popular: the star state tags each section from its view counts once they load', async () => {
  const api = fakeApi(() => json({ stars: {}, views: { 'parsers/acme/widget': 12, 'parsers/acme/gadget': 2, 'connectors/acme/widget': 6 } }));
  const s = createStars({ fetchImpl: api.fetchImpl, storage: memoryStorage() });
  assert.deepEqual(s.popular('parsers'), new Set());
  await s.load();
  assert.deepEqual(s.popular('parsers'), new Set(['parsers/acme/widget']));
  assert.deepEqual(s.popular('connectors'), new Set(['connectors/acme/widget']));
  assert.deepEqual(s.popular('playbooks'), new Set());
});

test('A to Z is the order the site build writes the real library in', async () => {
  const out = await mkdtemp(path.join(tmpdir(), 'xsl-stars-'));
  try {
    execFileSync(process.execPath, [path.join(ROOT, 'tools/build-site.mjs'), '--out', out], { stdio: 'pipe' });
    const index = JSON.parse(await readFile(path.join(out, 'library-index.json'), 'utf8'));
    for (const [section, list] of [['parsers', index.entries], ['rules', index.rules], ['playbooks', index.playbooks], ['connectors', index.connectors]]) {
      assert.ok(list.length, section);
      assert.deepEqual(ids(sortEntries(list, 'az', { section })), ids(list), section);
      // Every id can carry a star, and a date when the checkout has its history.
      for (const e of list) {
        assert.match(`${section}/${e.id}`, /^(?:parsers|rules|playbooks|connectors)\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/);
        if (e.added !== undefined) assert.equal(new Date(e.added).toISOString(), e.added, `${section}/${e.id}`);
      }
    }
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});

test('add dates: the earliest commit that added each entry\'s meta.json', () => {
  const log = [
    '\x002026-11-14T16:27:31Z', '', 'playbooks/acme/widget-lock/meta.json', 'parsers/acme/widget/meta.json', 'rules/acme/widget-alerts/meta.json',
    '\x002026-10-13T19:43:44+11:00', '', 'parsers/acme/widget/meta.json', 'parsers/acme/widget/samples.log', 'parsers/Bad/Name/meta.json', 'parsers/acme/widget/extra/meta.json',
    '\x00not a date', '', 'connectors/acme/widget/meta.json',
  ].join('\n');
  assert.deepEqual([...parseAddedLog(log)], [
    ['playbooks/acme/widget-lock', '2026-11-14T16:27:31.000Z'],
    ['parsers/acme/widget', '2026-10-13T08:43:44.000Z'],
    ['rules/acme/widget-alerts', '2026-11-14T16:27:31.000Z'],
  ]);
  assert.deepEqual([...parseAddedLog('')], []);
});

// A fake API: answers from a function of (method, path), and records each call.
function fakeApi(answer) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, ...init });
    return answer(init.method, url.slice(API.length), init);
  };
  return { calls, fetchImpl };
}
const settle = () => new Promise((r) => setTimeout(r, 10));
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
function memoryStorage(seed = {}) {
  const m = new Map(Object.entries(seed));
  return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); } };
}

test('stars: no API, a failing API, a slow API or a bad answer means no stars and no error', async () => {
  for (const answer of [
    () => { throw new TypeError('Failed to fetch'); },
    () => json({ error: 'unavailable' }, 503),
    () => new Response('<html>', { status: 200 }),
    () => json(null),
    (m, p, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
  ]) {
    const api = fakeApi(answer);
    const s = createStars({ fetchImpl: api.fetchImpl, storage: memoryStorage(), timeoutMs: 30 });
    assert.equal(await s.load(), false);
    assert.equal(s.ready(), false);
    assert.equal(s.count('parsers/acme/widget'), 0);
    await s.toggle('parsers/acme/widget');
    assert.equal(api.calls.length, 1, 'a star is never sent when the counts didn\'t load');
    assert.deepEqual(s.snapshot(), { stars: {}, views: {} });
  }
});

test('stars: the counts load once, with no credentials and no referrer', async () => {
  const api = fakeApi(() => json({ stars: { 'parsers/acme/widget': 3, 'bad id': 4, 'parsers/acme/gadget': -1 }, views: { 'parsers/acme/widget': 12 } }));
  const s = createStars({ fetchImpl: api.fetchImpl, storage: memoryStorage() });
  assert.equal(await s.load(), true);
  assert.deepEqual(api.calls.map((c) => [c.url, c.method, c.credentials, c.referrerPolicy, c.mode]), [[`${API}/v1/stats`, 'GET', 'omit', 'no-referrer', 'cors']]);
  assert.equal(api.calls[0].body, undefined);
  assert.deepEqual(s.snapshot(), { stars: { 'parsers/acme/widget': 3 }, views: { 'parsers/acme/widget': 12 } });
  assert.equal(s.views('parsers/acme/widget'), 12);
});

test('stars: a tap fills the star and adds one at once, the answer sets the count, and a second tap takes it back', async () => {
  let server = 3;
  const gate = [];
  const api = fakeApi((method, p) => {
    if (p === '/v1/stats') return json({ stars: { 'parsers/acme/widget': server }, views: {} });
    return new Promise((resolve) => gate.push(() => {
      server += method === 'PUT' ? 1 : -1;
      // Someone else starred it meanwhile: the answer's count wins.
      if (method === 'PUT') server += 1;
      resolve(json({ id: 'parsers/acme/widget', stars: server, starred: method === 'PUT' }));
    }));
  });
  const storage = memoryStorage();
  const changed = [];
  const s = createStars({ fetchImpl: api.fetchImpl, storage, onChange: (id) => changed.push([id, s.starred(id), s.count(id)]) });
  await s.load();
  const t1 = s.toggle('parsers/acme/widget');
  assert.deepEqual([s.starred('parsers/acme/widget'), s.count('parsers/acme/widget')], [true, 4], 'straight away');
  assert.equal(storage.m.get('library-stars'), undefined, 'kept only once the API takes it');
  gate.shift()();
  await t1;
  assert.deepEqual([s.starred('parsers/acme/widget'), s.count('parsers/acme/widget')], [true, 5]);
  assert.deepEqual(JSON.parse(storage.m.get('library-stars')), ['parsers/acme/widget']);
  const t2 = s.toggle('parsers/acme/widget');
  assert.deepEqual([s.starred('parsers/acme/widget'), s.count('parsers/acme/widget')], [false, 4]);
  gate.shift()();
  await t2;
  assert.deepEqual([s.starred('parsers/acme/widget'), s.count('parsers/acme/widget')], [false, 4]);
  assert.deepEqual(JSON.parse(storage.m.get('library-stars')), []);
  // Only the id is sent: in the path, with no body, no credentials and no referrer.
  const sent = api.calls.filter((c) => c.method !== 'GET');
  assert.deepEqual(sent.map((c) => [c.method, c.url, c.body, c.credentials, c.referrerPolicy]), [
    ['PUT', `${API}/v1/stars/parsers/acme/widget`, undefined, 'omit', 'no-referrer'],
    ['DELETE', `${API}/v1/stars/parsers/acme/widget`, undefined, 'omit', 'no-referrer'],
  ]);
  assert.deepEqual(changed.at(-1), ['parsers/acme/widget', false, 4]);
});

test('stars: taps while a request is out are sent after it, and a double tap sends nothing more', async () => {
  const gate = [];
  const api = fakeApi((method, p) => (p === '/v1/stats' ? json({ stars: {}, views: {} })
    : new Promise((resolve) => gate.push(() => resolve(json({ stars: method === 'PUT' ? 1 : 0 }))))));
  const s = createStars({ fetchImpl: api.fetchImpl, storage: memoryStorage() });
  await s.load();
  const id = 'playbooks/acme/widget-lock';
  const t = s.toggle(id);
  s.toggle(id);
  s.toggle(id);
  assert.deepEqual([s.starred(id), s.count(id)], [true, 1]);
  gate.shift()();
  await settle();
  assert.equal(gate.length, 0, 'it ends where it started after the first answer: nothing more to send');
  await t;
  assert.deepEqual([s.starred(id), s.count(id)], [true, 1]);
  const t2 = s.toggle(id);
  s.toggle(id);
  gate.shift()();
  await settle();
  assert.equal(gate.length, 1, 'the second tap is sent once the first answers');
  gate.shift()();
  await t2;
  assert.deepEqual([s.starred(id), s.count(id)], [true, 1]);
  assert.deepEqual(api.calls.filter((c) => c.method !== 'GET').map((c) => c.method), ['PUT', 'DELETE', 'PUT']);
});

test('stars: a failed star goes back, says so, and is not kept', async () => {
  for (const [answer, status] of [[() => json({ error: 'too many requests' }, 429), 429], [() => { throw new TypeError('Failed to fetch'); }, 0], [() => json({ error: 'unknown entry' }, 404), 404]]) {
    const errors = [];
    const storage = memoryStorage();
    const api = fakeApi((m, p) => (p === '/v1/stats' ? json({ stars: { 'parsers/acme/widget': 2 }, views: {} }) : answer()));
    const s = createStars({ fetchImpl: api.fetchImpl, storage, onError: (st) => errors.push(st) });
    await s.load();
    await s.toggle('parsers/acme/widget');
    assert.deepEqual([s.starred('parsers/acme/widget'), s.count('parsers/acme/widget')], [false, 2]);
    assert.deepEqual(errors, [status]);
    assert.equal(storage.m.get('library-stars'), undefined);
  }
});

test('stars: the browser remembers its stars, and blocked storage still lets a star count', async () => {
  const api = fakeApi((m, p) => (p === '/v1/stats' ? json({ stars: { 'parsers/acme/widget': 1 }, views: {} }) : json({ stars: 0 })));
  const kept = createStars({ fetchImpl: api.fetchImpl, storage: memoryStorage({ 'library-stars': JSON.stringify(['parsers/acme/widget', 'junk', 5]) }) });
  await kept.load();
  assert.equal(kept.starred('parsers/acme/widget'), true);
  assert.equal(kept.starred('junk'), false);
  for (const storage of [memoryStorage({ 'library-stars': '{not json' }), { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceededError'); } }, null]) {
    const s = createStars({ fetchImpl: fakeApi((m, p) => (p === '/v1/stats' ? json({ stars: {}, views: {} }) : json({ stars: 1 }))).fetchImpl, storage });
    await s.load();
    await s.toggle('parsers/acme/widget');
    assert.deepEqual([s.starred('parsers/acme/widget'), s.count('parsers/acme/widget')], [true, 1]);
  }
});

test('the page loads the counts after it draws, and the Sort menu sits next to the search', async () => {
  const main = await readFile(path.join(ROOT, 'studio/app/main.js'), 'utf8');
  assert.ok(main.indexOf('loadStars();') > main.indexOf('route();\n'), 'the first draw doesn\'t wait for the API');
  assert.doesNotMatch(main, /await\s+loadStars/);
  const common = await readFile(path.join(ROOT, 'studio/app/views/common.js'), 'utf8');
  assert.match(common, /h\('div', \{ class: 'libtools' \}, search, h\('label', \{ class: 'sortpick' \}, 'Sort', sort\)\)/);
  // Parsers, Playbooks and Connectors all draw their list through it, with a Popular slot on each card.
  const lib = await readFile(path.join(ROOT, 'studio/app/views/library.js'), 'utf8');
  const auto = await readFile(path.join(ROOT, 'studio/app/views/automation.js'), 'utf8');
  assert.match(lib, /searchList\(root, \{ section: 'parsers'/);
  assert.match(auto, /searchList\(root, \{ section: folder/);
  for (const section of ['parsers', 'playbooks', 'connectors']) assert.ok((section === 'parsers' ? lib : auto).includes(`popularSlot(\`${section}/\${e.id}\`)`), section);
});
