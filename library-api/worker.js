// Stars and view counts for the Unofficial Sophos Fusion XDR and SIEM Library site. A Cloudflare
// Worker with one SQLite-backed Durable Object and no dependencies; README.md has the setup.
//
//   GET    /v1/stats        the star and view counts of every entry that has one
//   PUT    /v1/stars/<id>   star an entry, such as parsers/acme/widget
//   DELETE /v1/stars/<id>   take the star back
//   GET    /healthz         200 ok, for monitoring
//
// /v1 answers only the origins in ALLOWED_ORIGINS. A star stores the entry's id and an HMAC-SHA256
// of the caller's IP address keyed with the IP_HASH_SALT secret, never the address itself, so one
// address stars an entry once. An IPv6 address counts by its /64, which one connection usually
// holds. Callers are rate limited by the same hash. The hourly cron trigger reads the list of
// entries from the site's library-ids.json (or library-index.json), so only ids in the library are
// accepted, and the view counts from the site's GoatCounter.

const SLUG = '[a-z0-9]+(?:-[a-z0-9]+)*';
const ENTRY_ID = new RegExp(`^(?:parsers|playbooks|connectors)/${SLUG}/${SLUG}$`);
const WHO = /^[0-9a-f]{32}$/;
const MINUTE = 60e3;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const LIMITS = { readsPerMinute: 120, writesPerMinute: 30, writesPerDay: 300, allWritesPerDay: 5000 };

// View counts. GoatCounter's API returns every day of the range with its hourly counts, so a long
// range costs more CPU than the free plan's 10 ms allows. Instead, each day is folded into stored
// totals once it is two days old, up to FOLDS_PER_RUN days a run, and only the days since are
// fetched again each run. While the totals are more than CATCH_UP behind, the recent days wait.
const FOLDS_PER_RUN = 4;
const CATCH_UP = 4 * DAY;
const GC_PAGES = 6;
const GC_GAP_MS = 300;
// An id that is well formed but not in the stored list sends the Worker to read the site's index
// again, at most once a minute and only when the list is over five minutes old.
const ENTRIES_MAX_AGE = 5 * MINUTE;
const REFRESH_GAP = MINUTE;

export function isEntryId(id) {
  return typeof id === 'string' && id.length <= 200 && ENTRY_ID.test(id);
}

export function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
}

// The part of an address that names one caller: an IPv4 address, or the /64 of an IPv6 address.
// '' when it isn't an address.
export function ipKey(ip) {
  const s = String(ip || '').trim().toLowerCase();
  const v4 = /^(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (v4) return v4[1].split('.').every((o) => Number(o) <= 255) ? v4[1] : '';
  if (!s.includes(':') || !/^[0-9a-f:]+$/.test(s)) return '';
  const halves = s.split('::');
  if (halves.length > 2) return '';
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail] : head;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return '';
  return `${groups.slice(0, 4).map((g) => g.padStart(4, '0')).join(':')}::/64`;
}

let hmac = null;
// The caller's key in storage: the first 128 bits of HMAC-SHA256(salt, address), as hex.
export async function clientHash(ip, salt) {
  if (!hmac || hmac.salt !== salt) {
    hmac = { salt, key: crypto.subtle.importKey('raw', new TextEncoder().encode(salt), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']) };
  }
  const sig = await crypto.subtle.sign('HMAC', await hmac.key, new TextEncoder().encode(ipKey(ip) || String(ip)));
  return [...new Uint8Array(sig).slice(0, 16)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// The entry ids in the site's library-ids.json, or in its library-index.json as parsers/<id>,
// playbooks/<id> and connectors/<id>.
export function entryIds(index) {
  if (index && Array.isArray(index.ids)) return [...new Set(index.ids.filter(isEntryId))];
  const list = (key, section) => (Array.isArray(index && index[key]) ? index[key] : []).map((e) => `${section}/${e && e.id}`);
  return [...new Set([...list('entries', 'parsers'), ...list('playbooks', 'playbooks'), ...list('connectors', 'connectors')].filter(isEntryId))];
}

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

function reply(body, status = 200, origin = null, extra = {}) {
  const headers = { ...JSON_HEADERS, ...extra };
  if (origin) Object.assign(headers, { 'Access-Control-Allow-Origin': origin, Vary: 'Origin' });
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
}

async function relay(res, origin) {
  const retry = res.headers.get('Retry-After');
  return reply(await res.text(), res.status, origin, retry ? { 'Retry-After': retry } : {});
}

const library = (env) => env.LIBRARY.get(env.LIBRARY.idFromName('library'));

// ---------------------------------------------------------------- the public API

export async function handle(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/healthz') return new Response('ok', { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
  if (!url.pathname.startsWith('/v1/')) return reply({ error: 'not found' }, 404);
  const origin = request.headers.get('Origin') || '';
  if (!allowedOrigins(env).includes(origin)) return reply({ error: 'origin not allowed' }, 403, null, { Vary: 'Origin' });
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'GET, PUT, DELETE', 'Access-Control-Max-Age': '86400', Vary: 'Origin' } });
  }
  const ip = request.headers.get('CF-Connecting-IP');
  if (!ip || !env.IP_HASH_SALT) return reply({ error: 'unavailable' }, 503, origin);
  try {
    return await route(request, env, url, origin, await clientHash(ip, env.IP_HASH_SALT));
  } catch {
    return reply({ error: 'unavailable' }, 503, origin);
  }
}

async function route(request, env, url, origin, who) {
  const stub = library(env);
  if (url.pathname === '/v1/stats') {
    if (request.method !== 'GET') return reply({ error: 'method not allowed' }, 405, origin, { Allow: 'GET' });
    return relay(await stub.fetch('https://library/stats', { headers: { 'x-client': who } }), origin);
  }
  const m = /^\/v1\/stars\/(.+)$/.exec(url.pathname);
  if (!m) return reply({ error: 'not found' }, 404, origin);
  if (request.method !== 'PUT' && request.method !== 'DELETE') return reply({ error: 'method not allowed' }, 405, origin, { Allow: 'PUT, DELETE' });
  const id = m[1];
  if (!isEntryId(id)) return reply({ error: 'not an entry id' }, 400, origin);
  const star = () => stub.fetch(`https://library/stars/${id}`, { method: request.method, headers: { 'x-client': who } });
  let res = await star();
  if (res.status === 404) {
    const body = await res.json().catch(() => ({}));
    if (body.refresh && (await refreshEntries(env, stub))) res = await star();
    if (res.status === 404) return reply({ error: 'unknown entry' }, 404, origin);
  }
  return relay(res, origin);
}

// ---------------------------------------------------------------- the cron trigger

// Reads the site's entry ids and stores them. library-ids.json is the small list the site build
// writes for this; the full library-index.json, which costs more CPU to parse, is the fallback.
// False when neither can be read or they list none.
export async function refreshEntries(env, stub = library(env)) {
  let ids = [];
  for (const file of ['library-ids.json', 'library-index.json']) {
    try {
      const res = await fetch(new URL(file, env.SITE_URL), { headers: { Accept: 'application/json' } });
      if (res.ok) ids = entryIds(await res.json());
    } catch { /* try the next file */ }
    if (ids.length) break;
  }
  if (!ids.length) return false;
  return (await stub.fetch('https://library/entries', { method: 'POST', body: JSON.stringify({ ids }) })).ok;
}

const iso = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
const floorHour = (ms) => Math.floor(ms / HOUR) * HOUR;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Visitors per entry id from start up to end, from GoatCounter's /api/v0/stats/hits. GoatCounter
// includes the end hour, so the range stops a second before end. Pages of 100 paths, each excluding
// the paths already read. Events and paths that aren't entry routes are skipped.
export async function goatCounts(env, start, end) {
  const out = {};
  const seen = [];
  for (let page = 0; page < GC_PAGES; page++) {
    if (page) await sleep(GC_GAP_MS);
    const u = new URL('/api/v0/stats/hits', env.GOATCOUNTER_SITE);
    u.searchParams.set('start', iso(start));
    u.searchParams.set('end', iso(end - 1000));
    u.searchParams.set('limit', '100');
    if (seen.length) u.searchParams.set('exclude_paths', seen.join(','));
    const res = await fetch(u, { headers: { Authorization: `Bearer ${String(env.GOATCOUNTER_TOKEN).trim()}`, 'Content-Type': 'application/json' } });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      let why = '';
      try { why = String(JSON.parse(text).error || ''); } catch { why = /<title>([^<]*)<\/title>/i.exec(text)?.[1] || ''; }
      throw new Error(`GoatCounter answered ${res.status}${why ? `: ${why.slice(0, 120)}` : ''}`);
    }
    const body = await res.json();
    let fresh = 0;
    for (const h of Array.isArray(body.hits) ? body.hits : []) {
      if (!h || !Number.isInteger(h.path_id) || seen.includes(h.path_id)) continue;
      seen.push(h.path_id);
      fresh++;
      const id = String(h.path || '').replace(/^\//, '');
      if (!h.event && isEntryId(id) && Number.isInteger(h.count) && h.count > 0) out[id] = (out[id] || 0) + h.count;
    }
    if (!body.more || !fresh) break;
  }
  return out;
}

async function post(stub, path, body) {
  const res = await stub.fetch(`https://library${path}`, { method: 'POST', body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${path} answered ${res.status}`);
}

export async function syncViews(env, stub, now) {
  if (!env.GOATCOUNTER_TOKEN || !env.GOATCOUNTER_SITE) return 'skipped: no GoatCounter token';
  const state = await (await stub.fetch('https://library/views/state')).json();
  let expect = state.checkpoint ?? null;
  let cp = expect ? Date.parse(expect) : floorHour(Date.parse(env.VIEWS_SINCE || '') || now - 7 * DAY);
  let folds = 0;
  while (cp + 2 * DAY <= now && folds < FOLDS_PER_RUN) {
    await post(stub, '/views/fold', { expect, to: iso(cp + DAY), counts: await goatCounts(env, cp, cp + DAY) });
    expect = iso(cp + DAY);
    cp += DAY;
    folds++;
  }
  if (now - cp > CATCH_UP) return `${folds} days folded, catching up from ${iso(cp)}`;
  await post(stub, '/views/recent', { from: expect, counts: await goatCounts(env, cp, floorHour(now) + HOUR) });
  return `${folds} days folded, recent from ${iso(cp)}`;
}

export async function sync(env, now = Date.now()) {
  const stub = library(env);
  const entries = await refreshEntries(env, stub);
  let views;
  try {
    views = await syncViews(env, stub, now);
  } catch (err) {
    views = `failed: ${err.message}`;
  }
  console.log(JSON.stringify({ sync: { entries, views } }));
  return { entries, views };
}

export default {
  fetch: (request, env) => handle(request, env),
  scheduled: (controller, env, ctx) => ctx.waitUntil(sync(env, controller.scheduledTime || Date.now())),
};

// ---------------------------------------------------------------- the Durable Object

const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS stars (id TEXT NOT NULL, who TEXT NOT NULL, PRIMARY KEY (id, who))',
  'CREATE TABLE IF NOT EXISTS star_counts (id TEXT PRIMARY KEY, n INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS entries (id TEXT PRIMARY KEY)',
  'CREATE TABLE IF NOT EXISTS views_base (id TEXT PRIMARY KEY, n INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS views_recent (id TEXT PRIMARY KEY, n INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)',
];

function counts(obj) {
  const out = new Map();
  for (const [id, n] of Object.entries(obj && typeof obj === 'object' ? obj : {})) {
    if (isEntryId(id) && Number.isInteger(n) && n > 0 && n < 1e9) out.set(id, n);
  }
  return out;
}

const tooMany = (ms) => reply({ error: 'too many requests' }, 429, null, { 'Retry-After': String(Math.max(1, Math.ceil(ms / 1000))) });

// One instance holds every star and count, so writes need no coordination. The stats answer is
// kept in memory and rebuilt after a change; rate limit windows are kept in memory only.
export class LibraryStats {
  constructor(ctx) {
    this.storage = ctx.storage;
    this.sql = ctx.storage.sql;
    for (const q of SCHEMA) this.sql.exec(q);
    const pairs = (table) => new Map(this.sql.exec(`SELECT id, n FROM ${table}`).toArray().map((r) => [r.id, r.n]));
    this.stars = pairs('star_counts');
    this.base = pairs('views_base');
    this.recent = pairs('views_recent');
    this.entries = new Set(this.sql.exec('SELECT id FROM entries').toArray().map((r) => r.id));
    this.meta = Object.fromEntries(this.sql.exec('SELECT k, v FROM meta').toArray().map((r) => [r.k, JSON.parse(r.v)]));
    this.body = null;
    this.windows = new Map();
    this.refreshAsked = 0;
  }

  setMeta(k, v) {
    this.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, JSON.stringify(v));
    this.meta[k] = v;
  }

  // ms until the window opens again, or 0 when the request is allowed and counted.
  allow(key, limit, span, now) {
    const slot = Math.floor(now / span);
    const w = this.windows.get(key);
    if (!w || w.slot !== slot) {
      if (this.windows.size > 20000) for (const [k, x] of this.windows) if (x.slot !== Math.floor(now / x.span)) this.windows.delete(k);
      this.windows.set(key, { slot, span, n: 1 });
      return 0;
    }
    if (w.n >= limit) return (slot + 1) * span - now;
    w.n++;
    return 0;
  }

  statsBody() {
    if (this.body === null) {
      const stars = {};
      for (const [id, n] of this.stars) if (n > 0 && this.entries.has(id)) stars[id] = n;
      const recent = (this.meta.recent_from ?? null) === (this.meta.checkpoint ?? null) ? this.recent : new Map();
      const views = {};
      for (const id of new Set([...this.base.keys(), ...recent.keys()])) {
        const n = (this.base.get(id) || 0) + (recent.get(id) || 0);
        if (n > 0 && this.entries.has(id)) views[id] = n;
      }
      this.body = JSON.stringify({ stars, views });
    }
    return this.body;
  }

  star(id, who, on, now) {
    if (!isEntryId(id) || !WHO.test(who)) return reply({ error: 'bad request' }, 400);
    for (const [key, limit, span] of [[`w:${who}`, LIMITS.writesPerMinute, MINUTE], [`d:${who}`, LIMITS.writesPerDay, DAY], ['all', LIMITS.allWritesPerDay, DAY]]) {
      const wait = this.allow(key, limit, span, now);
      if (wait) return tooMany(wait);
    }
    if (!this.entries.has(id)) {
      const refresh = now - (this.meta.entries_at || 0) > ENTRIES_MAX_AGE && now - this.refreshAsked > REFRESH_GAP;
      if (refresh) this.refreshAsked = now;
      return reply({ error: 'unknown entry', refresh }, 404);
    }
    const had = this.sql.exec('SELECT COUNT(*) AS n FROM stars WHERE id = ? AND who = ?', id, who).one().n > 0;
    if (had !== on) {
      this.storage.transactionSync(() => {
        if (on) this.sql.exec('INSERT INTO stars (id, who) VALUES (?, ?)', id, who);
        else this.sql.exec('DELETE FROM stars WHERE id = ? AND who = ?', id, who);
        const n = this.sql.exec('SELECT COUNT(*) AS n FROM stars WHERE id = ?', id).one().n;
        if (n) this.sql.exec('INSERT INTO star_counts (id, n) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET n = excluded.n', id, n);
        else this.sql.exec('DELETE FROM star_counts WHERE id = ?', id);
        if (n) this.stars.set(id, n);
        else this.stars.delete(id);
      });
      this.body = null;
    }
    return reply({ id, stars: this.stars.get(id) || 0, starred: on });
  }

  setEntries(body, now) {
    const next = new Set((Array.isArray(body && body.ids) ? body.ids : []).filter(isEntryId));
    if (!next.size) return reply({ error: 'no ids' }, 400);
    this.storage.transactionSync(() => {
      for (const id of this.entries) if (!next.has(id)) this.sql.exec('DELETE FROM entries WHERE id = ?', id);
      for (const id of next) if (!this.entries.has(id)) this.sql.exec('INSERT INTO entries (id) VALUES (?)', id);
      this.setMeta('entries_at', now);
    });
    this.entries = next;
    this.body = null;
    return reply({ entries: next.size });
  }

  // Adds one finished day to the totals. expect is the checkpoint the caller read, so a retried or
  // overlapping run can't add the same day twice.
  fold(body) {
    if ((this.meta.checkpoint ?? null) !== (body.expect ?? null) || typeof body.to !== 'string' || !Number.isFinite(Date.parse(body.to))) return reply({ error: 'stale' }, 409);
    const add = counts(body.counts);
    this.storage.transactionSync(() => {
      for (const [id, n] of add) {
        this.sql.exec('INSERT INTO views_base (id, n) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET n = n + excluded.n', id, n);
        this.base.set(id, (this.base.get(id) || 0) + n);
      }
      this.setMeta('checkpoint', body.to);
    });
    this.body = null;
    return reply({ checkpoint: body.to });
  }

  // Replaces the counts since the checkpoint, writing only the rows that changed.
  setRecent(body) {
    if ((this.meta.checkpoint ?? null) !== (body.from ?? null)) return reply({ error: 'stale' }, 409);
    const next = counts(body.counts);
    this.storage.transactionSync(() => {
      for (const id of this.recent.keys()) if (!next.has(id)) this.sql.exec('DELETE FROM views_recent WHERE id = ?', id);
      for (const [id, n] of next) if (this.recent.get(id) !== n) this.sql.exec('INSERT INTO views_recent (id, n) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET n = excluded.n', id, n);
      if ((this.meta.recent_from ?? null) !== (body.from ?? null) || !('recent_from' in this.meta)) this.setMeta('recent_from', body.from ?? null);
    });
    this.recent = next;
    this.body = null;
    return reply({ recent: next.size });
  }

  async fetch(request) {
    const url = new URL(request.url);
    const now = Date.now();
    const who = request.headers.get('x-client') || '';
    const post = request.method === 'POST';
    try {
      if (url.pathname === '/stats' && request.method === 'GET') {
        const wait = this.allow(`r:${who}`, LIMITS.readsPerMinute, MINUTE, now);
        return wait ? tooMany(wait) : reply(this.statsBody());
      }
      const m = /^\/stars\/(.+)$/.exec(url.pathname);
      if (m && (request.method === 'PUT' || request.method === 'DELETE')) return this.star(m[1], who, request.method === 'PUT', now);
      if (url.pathname === '/entries' && post) return this.setEntries(await request.json(), now);
      if (url.pathname === '/views/state') return reply({ checkpoint: this.meta.checkpoint ?? null, recentFrom: this.meta.recent_from ?? null });
      if (url.pathname === '/views/fold' && post) return this.fold(await request.json());
      if (url.pathname === '/views/recent' && post) return this.setRecent(await request.json());
      return reply({ error: 'not found' }, 404);
    } catch {
      return reply({ error: 'failed' }, 500);
    }
  }
}
