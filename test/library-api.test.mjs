// The library API (library-api/worker.js): who may call it, what a star stores, that an address
// stars an entry once, which ids it takes, its rate limits, and the view counts its cron trigger
// reads from GoatCounter. The Durable Object runs on a real SQLite database (node:sqlite) and
// fetch is mocked, so nothing here reaches the network.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import worker, { LibraryStats, isEntryId, ipKey, clientHash, entryIds, sync, LIMITS } from '../library-api/worker.js';

const SITE = 'https://aaronjacobs000.github.io';
const SITE_URL = `${SITE}/sophos-xdr-siem-library/`;
const GC = 'https://gc.example';
const INDEX = {
  entries: [{ id: 'acme/widget' }, { id: 'acme/gadget' }, { id: 'beta/thing' }],
  playbooks: [{ id: 'acme/widget-lock' }],
  connectors: [{ id: 'acme/widget' }],
};

// A Durable Object namespace with one instance on an in-memory SQLite database, shaped like the
// parts of ctx.storage the Worker uses: sql.exec(...).toArray() and .one(), and transactionSync.
function namespace() {
  const db = new DatabaseSync(':memory:');
  const storage = {
    sql: {
      exec(query, ...params) {
        const rows = db.prepare(query).all(...params);
        return { toArray: () => rows, one: () => { assert.equal(rows.length, 1); return rows[0]; } };
      },
    },
    transactionSync(fn) {
      db.exec('BEGIN');
      try { const r = fn(); db.exec('COMMIT'); return r; } catch (err) { db.exec('ROLLBACK'); throw err; }
    },
  };
  let obj = null;
  const ns = {
    db,
    calls: 0,
    idFromName: (name) => name,
    get: () => ({ fetch: (url, init) => { ns.calls++; obj ||= new LibraryStats({ storage }, {}); return obj.fetch(new Request(url, init)); } }),
    restart: () => { obj = null; },
  };
  return ns;
}

let env;
let asked;
let logs;
let gc;
let index;
let idsFile;
const realFetch = globalThis.fetch;
const realLog = console.log;

// GoatCounter as its API answers: visitors per path per UTC hour, a range that includes its end
// hour, sorted by count, pages of `limit` with exclude_paths.
function goatcounter(req) {
  const u = new URL(req.url);
  if (req.headers.get('Authorization') !== 'Bearer gc-test-token') return Response.json({ error: 'unknown token' }, { status: 401 });
  const start = Date.parse(u.searchParams.get('start'));
  const end = Date.parse(u.searchParams.get('end'));
  const limit = Number(u.searchParams.get('limit'));
  const exclude = (u.searchParams.get('exclude_paths') || '').split(',').filter(Boolean).map(Number);
  const rows = gc.paths.map((p) => ({ path_id: p.id, path: p.path, event: Boolean(p.event), title: '', count: Object.entries(p.hours).filter(([h]) => Date.parse(h) >= start && Date.parse(h) <= end).reduce((k, [, n]) => k + n, 0) }))
    .filter((r) => r.count > 0 && !exclude.includes(r.path_id)).sort((a, b) => b.count - a.count || b.path_id - a.path_id);
  return Response.json({ hits: rows.slice(0, limit).map((r) => ({ ...r, stats: [] })), total: 0, more: rows.length > limit });
}

beforeEach(() => {
  asked = [];
  logs = [];
  index = INDEX;
  idsFile = null;
  gc = { paths: [] };
  env = { LIBRARY: namespace(), ALLOWED_ORIGINS: SITE, IP_HASH_SALT: 'test-salt', SITE_URL, GOATCOUNTER_SITE: GC, GOATCOUNTER_TOKEN: 'gc-test-token', VIEWS_SINCE: '2026-10-27T00:00:00Z' };
  console.log = (line) => logs.push(line);
  globalThis.fetch = async (input, init) => {
    const req = new Request(input, init);
    asked.push(req.url);
    if (req.url === `${SITE_URL}library-index.json`) return index ? Response.json(index) : new Response('nope', { status: 404 });
    if (req.url === `${SITE_URL}library-ids.json`) return idsFile ? Response.json(idsFile) : new Response('nope', { status: 404 });
    if (req.url.startsWith(`${GC}/api/v0/stats/hits`)) return goatcounter(req);
    return new Response('not mocked', { status: 599 });
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
  console.log = realLog;
});

const call = (method, path, { origin = SITE, ip = '198.51.100.7', headers = {} } = {}) => {
  const h = { ...headers };
  if (origin) h.Origin = origin;
  if (ip) h['CF-Connecting-IP'] = ip;
  return worker.fetch(new Request(`https://library-api.example${path}`, { method, headers: h }), env);
};
const star = (id, opts) => call('PUT', `/v1/stars/${id}`, opts);
const unstar = (id, opts) => call('DELETE', `/v1/stars/${id}`, opts);
const stats = async (opts) => (await call('GET', '/v1/stats', opts)).json();

test('ids: section, vendor and name slugs only', () => {
  for (const id of ['parsers/acme/widget', 'playbooks/sophos/sophos-mobile-lock', 'connectors/1password/1password-events']) assert.ok(isEntryId(id), id);
  for (const id of ['parsers/acme', 'parsers/acme/widget/extra', 'bridges/acme/widget', 'parsers/Acme/Widget', 'parsers/acme/a b', 'parsers/../widget', 'parsers/acme/-widget', 'parsers/acme/widget-', 'parsers/acme/wid--get', 'parsers%2Facme%2Fwidget', `parsers/acme/${'a'.repeat(200)}`, '', null, 42]) assert.ok(!isEntryId(id), String(id));
  assert.deepEqual(entryIds(INDEX), ['parsers/acme/widget', 'parsers/acme/gadget', 'parsers/beta/thing', 'playbooks/acme/widget-lock', 'connectors/acme/widget']);
  assert.deepEqual(entryIds({ entries: [{ id: 'Bad/ID' }, null, { id: 'ok/one' }] }), ['parsers/ok/one']);
});

test('CORS: only the library site\'s origin gets an answer', async () => {
  const pre = await call('OPTIONS', '/v1/stars/parsers/acme/widget', { ip: null });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('Access-Control-Allow-Origin'), SITE);
  assert.equal(pre.headers.get('Access-Control-Allow-Methods'), 'GET, PUT, DELETE');
  assert.equal(pre.headers.get('Access-Control-Allow-Credentials'), null);
  for (const origin of ['https://evil.example', 'http://aaronjacobs000.github.io', 'https://aaronjacobs000.github.io.evil.example', 'null', null]) {
    for (const [method, path] of [['OPTIONS', '/v1/stats'], ['GET', '/v1/stats'], ['PUT', '/v1/stars/parsers/acme/widget'], ['DELETE', '/v1/stars/parsers/acme/widget']]) {
      const res = await call(method, path, { origin });
      assert.equal(res.status, 403, `${origin} ${method} ${path}`);
      assert.equal(res.headers.get('Access-Control-Allow-Origin'), null);
    }
  }
  assert.equal(env.LIBRARY.calls, 0, 'a refused origin never reaches storage');
  const ok = await call('GET', '/v1/stats');
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('Access-Control-Allow-Origin'), SITE);
  assert.equal(ok.headers.get('Vary'), 'Origin');
  assert.equal(ok.headers.get('Cache-Control'), 'no-store');
  assert.equal(ok.headers.get('Set-Cookie'), null);
  assert.equal((await worker.fetch(new Request('https://library-api.example/healthz'), env)).status, 200);
});

test('a star toggles on and off, and an address stars an entry once', async () => {
  let r = await (await star('parsers/acme/widget')).json();
  assert.deepEqual(r, { id: 'parsers/acme/widget', stars: 1, starred: true });
  r = await (await star('parsers/acme/widget')).json();
  assert.equal(r.stars, 1, 'the same address again');
  r = await (await star('parsers/acme/widget', { ip: '203.0.113.9' })).json();
  assert.equal(r.stars, 2);
  assert.deepEqual((await stats()).stars, { 'parsers/acme/widget': 2 });
  r = await (await unstar('parsers/acme/widget')).json();
  assert.deepEqual(r, { id: 'parsers/acme/widget', stars: 1, starred: false });
  r = await (await unstar('parsers/acme/widget')).json();
  assert.equal(r.stars, 1, 'taking back a star twice takes one');
  r = await (await unstar('parsers/acme/widget', { ip: '192.0.2.200' })).json();
  assert.equal(r.stars, 1, 'an address that never starred takes nothing');
  await unstar('parsers/acme/widget', { ip: '203.0.113.9' });
  assert.deepEqual((await stats()).stars, {});
  // Counts survive the object restarting.
  await star('playbooks/acme/widget-lock');
  env.LIBRARY.restart();
  assert.deepEqual((await stats()).stars, { 'playbooks/acme/widget-lock': 1 });
  assert.deepEqual(env.LIBRARY.db.prepare('SELECT id, n FROM star_counts').all().map((x) => ({ ...x })), [{ id: 'playbooks/acme/widget-lock', n: 1 }]);
});

test('storage holds a salted hash of the address, never the address', async () => {
  await star('parsers/acme/widget', { ip: '198.51.100.7' });
  await star('parsers/acme/widget', { ip: '2001:db8:1:2::1' });
  const rows = env.LIBRARY.db.prepare('SELECT id, who FROM stars').all();
  assert.equal(rows.length, 2);
  for (const r of rows) assert.match(r.who, /^[0-9a-f]{32}$/);
  const dump = JSON.stringify(env.LIBRARY.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().flatMap((t) => env.LIBRARY.db.prepare(`SELECT * FROM ${t.name}`).all()));
  for (const s of ['198.51.100.7', '2001:db8', 'test-salt']) assert.ok(!dump.includes(s), s);
  assert.deepEqual(rows.map((r) => r.who).sort(), [await clientHash('198.51.100.7', 'test-salt'), await clientHash('2001:db8:1:2::1', 'test-salt')].sort());
  assert.notEqual(await clientHash('198.51.100.7', 'other-salt'), await clientHash('198.51.100.7', 'test-salt'));
  // No salt, no stars: the API won't store an unsalted hash.
  delete env.IP_HASH_SALT;
  assert.equal((await star('parsers/acme/gadget')).status, 503);
});

test('an IPv6 address counts by its /64', async () => {
  assert.equal(ipKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), '2001:0db8:0001:0002::/64');
  assert.equal(ipKey('2001:DB8:1:2::9'), '2001:0db8:0001:0002::/64');
  assert.equal(ipKey('::ffff:198.51.100.7'), '198.51.100.7');
  assert.equal(ipKey('198.51.100.7'), '198.51.100.7');
  for (const bad of ['', '999.1.1.1', '1:2:3', '1::2::3', 'nope']) assert.equal(ipKey(bad), '', bad);
  await star('parsers/acme/widget', { ip: '2001:db8:1:2::1' });
  const r = await (await star('parsers/acme/widget', { ip: '2001:db8:1:2:ffff::7' })).json();
  assert.equal(r.stars, 1);
  assert.equal((await (await star('parsers/acme/widget', { ip: '2001:db8:1:3::1' })).json()).stars, 2);
});

test('only ids in the library index are taken', async () => {
  for (const id of ['parsers/acme', 'parsers/Acme/Widget', 'parsers/acme/widget/extra', 'other/acme/widget', 'parsers%2Facme%2Fwidget', 'parsers/acme/a%20b']) {
    const res = await star(id);
    assert.equal(res.status, 400, id);
  }
  assert.equal(asked.length, 0, 'a malformed id never reads the index');
  // Well formed but not in the library: the API reads the index once, then refuses.
  let res = await star('parsers/acme/nothing');
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'unknown entry' });
  assert.deepEqual(asked, [`${SITE_URL}library-ids.json`, `${SITE_URL}library-index.json`], 'the full index when the ids file is missing');
  res = await star('parsers/acme/nothing-else');
  assert.equal(res.status, 404);
  assert.equal(asked.length, 2, 'the index isn\'t read again straight away');
  assert.equal((await star('connectors/acme/widget')).status, 200, 'ids from the index it read are taken');
  assert.deepEqual((await stats()).stars, { 'connectors/acme/widget': 1 });
  // Methods.
  assert.equal((await call('POST', '/v1/stars/parsers/acme/widget')).status, 405);
  assert.equal((await call('PUT', '/v1/stats')).status, 405);
  assert.equal((await call('GET', '/v1/other')).status, 404);
});

test('the small ids file the site build writes comes before the full index', async () => {
  idsFile = { generated: '2026-11-15T00:00:00.000Z', ids: ['parsers/acme/widget', 'playbooks/acme/only-in-ids', 'Bad/id'] };
  assert.deepEqual(entryIds(idsFile), ['parsers/acme/widget', 'playbooks/acme/only-in-ids']);
  assert.equal((await star('playbooks/acme/only-in-ids')).status, 200);
  assert.deepEqual(asked, [`${SITE_URL}library-ids.json`]);
});

test('an entry merged after the last index read can be starred once the list is stale', async (t) => {
  await sync(env, Date.parse('2026-11-15T00:00:00Z'));
  index = { ...INDEX, playbooks: [...INDEX.playbooks, { id: 'acme/new-one' }] };
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 6 * 60e3 });
  const res = await star('playbooks/acme/new-one');
  assert.equal(res.status, 200);
  assert.equal((await res.json()).stars, 1);
});

test('rate limits: writes and reads per address', async () => {
  await sync(env, Date.parse('2026-11-15T00:00:00Z'));
  for (let i = 0; i < LIMITS.writesPerMinute; i++) assert.equal((await (i % 2 ? unstar : star)('parsers/acme/widget')).status, 200, String(i));
  const res = await star('parsers/acme/widget');
  assert.equal(res.status, 429);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), SITE);
  assert.ok(Number(res.headers.get('Retry-After')) >= 1);
  assert.equal((await star('parsers/acme/widget', { ip: '203.0.113.9' })).status, 200, 'another address is not held up');
  for (let i = 0; i < LIMITS.readsPerMinute; i++) assert.equal((await call('GET', '/v1/stats', { ip: '192.0.2.1' })).status, 200);
  assert.equal((await call('GET', '/v1/stats', { ip: '192.0.2.1' })).status, 429);
  assert.equal((await call('GET', '/v1/stats', { ip: '192.0.2.2' })).status, 200);
});

test('views: the cron trigger folds finished days into totals and reads the recent days each run', async () => {
  const at = (iso, n) => [iso, n];
  gc.paths = [
    { id: 1, path: '/parsers/acme/widget', hours: Object.fromEntries([at('2026-10-27T03:00:00Z', 5), at('2026-10-28T00:00:00Z', 2), at('2026-11-02T23:00:00Z', 1), at('2026-11-03T00:00:00Z', 4), at('2026-11-14T10:00:00Z', 3)]) },
    { id: 2, path: '/playbooks/acme/widget-lock', hours: { '2026-11-01T12:00:00Z': 7 } },
    { id: 3, path: '/parsers', hours: { '2026-11-01T12:00:00Z': 50 } },
    { id: 4, path: '/parsers/unknown', hours: { '2026-11-01T12:00:00Z': 9 } },
    { id: 5, path: '/parsers/acme/gone', hours: { '2026-11-01T12:00:00Z': 9 } },
    { id: 6, path: '/parsers/beta/thing', event: true, hours: { '2026-11-01T12:00:00Z': 9 } },
    // Enough paths to need a second page.
    ...Array.from({ length: 120 }, (_, i) => ({ id: 100 + i, path: `/build/x${i}`, hours: { '2026-11-01T12:00:00Z': 1 } })),
  ];
  const want = { 'parsers/acme/widget': 15, 'playbooks/acme/widget-lock': 7 };
  const now = Date.parse('2026-11-15T09:30:00Z');
  // The first runs catch up four days at a time; the totals never count an hour twice.
  for (let run = 0; run < 6; run++) {
    const r = await sync(env, now);
    assert.equal(r.entries, true);
    assert.doesNotMatch(r.views, /failed/, r.views);
    const views = (await stats()).views;
    for (const [id, n] of Object.entries(views)) assert.ok(n <= want[id], `${id} ${n} in run ${run}`);
  }
  assert.deepEqual((await stats()).views, want);
  // A new visit shows on the next run, and a run that changes nothing writes nothing new.
  gc.paths[0].hours['2026-11-15T09:00:00Z'] = 2;
  await sync(env, now);
  assert.deepEqual((await stats()).views, { ...want, 'parsers/acme/widget': 17 });
  // A day later that visit is folded into the totals and the count stays the same.
  await sync(env, now + 2 * 86400e3);
  assert.deepEqual((await stats()).views, { ...want, 'parsers/acme/widget': 17 });
  // The token went in the Authorization header only, and the logs don't hold it.
  assert.ok(asked.filter((u) => u.startsWith(GC)).length > 6);
  assert.ok(asked.some((u) => /exclude_paths=\d/.test(u)), 'the second page excludes the first page\'s paths');
  assert.ok(!asked.join(' ').includes('gc-test-token'));
  assert.ok(!logs.join(' ').includes('gc-test-token'));
});

test('views: a GoatCounter failure or a missing token changes nothing', async () => {
  gc.paths = [{ id: 1, path: '/parsers/acme/widget', hours: { '2026-11-14T10:00:00Z': 3 } }];
  const now = Date.parse('2026-11-15T09:30:00Z');
  env.GOATCOUNTER_TOKEN = 'wrong';
  let r = await sync(env, now);
  assert.equal(r.views, 'failed: GoatCounter answered 401: unknown token');
  assert.deepEqual((await stats()).views, {});
  delete env.GOATCOUNTER_TOKEN;
  r = await sync(env, now);
  assert.match(r.views, /^skipped/);
  // The index can't be read: the stored list stays.
  env.GOATCOUNTER_TOKEN = 'gc-test-token';
  await sync(env, now);
  index = null;
  r = await sync(env, now);
  assert.equal(r.entries, false);
  assert.equal((await star('parsers/acme/widget')).status, 200);
});
