// A read-only client for the Sophos Fusion Search GraphQL API, for maintenance tools.
//
// A search is asynchronous: createSearch (or getOrCreateSearch) starts it, search(urn) is polled
// until status is COMPLETE, outcome.success says whether every partition worked, and searchResults
// pages the rows by cursor. Those four operations are the only ones this client sends: the
// documents are fixed below and request() refuses anything else, so it can't write to a tenant.
//
// Credentials come from the environment or an env file and never reach the output: errors carry
// the API's message, not the request.

import { readFile } from 'node:fs/promises';

export const TOKEN_URL = 'https://id.sophos.com/api/v2/oauth2/token';
export const WHOAMI_URL = 'https://api.central.sophos.com/whoami/v1';
export const GRAPHQL_URL = 'https://api.taegis.sophos.com/graphql';

// searchResults refuses a limit above 1000.
export const MAX_PAGE = 1000;
// A search returns at most 10,000 rows, newest first, and its total then reads 10,000.
export const ROW_CAP = 10000;

const SEARCH_FIELDS = `urn status errors queryText createTime endTime expireTime
    outcome { success errors { urn errors } }`;

export const DOCUMENTS = {
  createSearch: `mutation QlCheckCreateSearch($input: CreateSearchInput) {
  createSearch(input: $input) { ${SEARCH_FIELDS} }
}`,
  getOrCreateSearch: `mutation QlCheckGetOrCreateSearch($input: CreateSearchInput) {
  getOrCreateSearch(input: $input) { ${SEARCH_FIELDS} }
}`,
  search: `query QlCheckSearch($urn: URN!) {
  search(urn: $urn) { ${SEARCH_FIELDS} }
}`,
  searchResults: `query QlCheckSearchResults($urn: URN!, $cursor: String, $limit: Int) {
  searchResults(urn: $urn, cursor: $cursor, limit: $limit) {
    values
    totals { total { value } }
    nextCursor
  }
}`,
};

export class SearchExpiredError extends Error {}
export class SearchFailedError extends Error {}

// KEY=VALUE lines, with # comments, blank lines, "export " and quotes allowed.
export function parseEnv(text) {
  const out = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"') && v.length > 1) || (v.startsWith("'") && v.endsWith("'") && v.length > 1)) v = v.slice(1, -1);
    out[m[1]] = v;
  }
  return out;
}

// SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET, and optionally SOPHOS_TENANT_ID, from the env file
// when one is given, else from the environment.
export async function loadCredentials({ envFile = null, env = process.env } = {}) {
  const src = envFile ? parseEnv(await readFile(envFile, 'utf8')) : env;
  const clientId = src.SOPHOS_CLIENT_ID;
  const clientSecret = src.SOPHOS_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error(`SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET must be set ${envFile ? 'in the env file' : 'in the environment, or pass --env-file'}`);
  }
  return { clientId, clientSecret, tenantId: src.SOPHOS_TENANT_ID || null };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A redirect would carry the secret or the token to another host, so it is refused.
function refuseRedirect(res, url) {
  if (res.status >= 300 && res.status < 400) throw new Error(`${new URL(url).host} answered with a redirect (HTTP ${res.status}), which this tool refuses to follow`);
}

async function readError(res) {
  const text = await res.text().catch(() => '');
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j.errors) && j.errors.length) return j.errors.map((e) => e.message).join('; ');
    return [j.error, j.message].filter(Boolean).join(': ') || text.slice(0, 300);
  } catch {
    return text.slice(0, 300);
  }
}

export class SearchClient {
  constructor({ clientId, clientSecret, tenantId = null }, { fetchImpl = globalThis.fetch, log = () => {}, timeoutMs = 120000 } = {}) {
    // Kept off the instance's enumerable fields, so printing the client prints no secret.
    Object.defineProperty(this, 'creds', { value: { clientId, clientSecret }, enumerable: false });
    this.tenantId = tenantId;
    this.fetch = fetchImpl;
    this.log = log;
    this.timeoutMs = timeoutMs;
    this.token = null;
    this.tokenExpires = 0;
  }

  async getToken() {
    if (this.token && Date.now() < this.tokenExpires - 60000) return this.token;
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: this.creds.clientId, client_secret: this.creds.clientSecret, scope: 'token' });
    const res = await this.fetch(TOKEN_URL, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(), redirect: 'manual' });
    refuseRedirect(res, TOKEN_URL);
    if (!res.ok) throw new Error(`Sophos sign-in failed (HTTP ${res.status}): ${await readError(res)}`);
    const data = await res.json();
    if (!data.access_token) throw new Error(`Sophos sign-in returned no token: ${data.errorCode || data.message || 'no detail'}`);
    Object.defineProperty(this, 'token', { value: data.access_token, enumerable: false, writable: true, configurable: true });
    this.tokenExpires = Date.now() + (Number(data.expires_in) || 3600) * 1000;
    return this.token;
  }

  // The tenant to search: SOPHOS_TENANT_ID or --tenant when given, else whoami's id for a
  // tenant credential. A partner or organization credential has to name the tenant.
  async resolveTenant() {
    if (this.tenantId) return this.tenantId;
    const token = await this.getToken();
    const res = await this.fetch(WHOAMI_URL, { headers: { Authorization: `Bearer ${token}` }, redirect: 'manual' });
    refuseRedirect(res, WHOAMI_URL);
    if (!res.ok) throw new Error(`whoami failed (HTTP ${res.status}): ${await readError(res)}`);
    const who = await res.json();
    if (who.idType !== 'tenant') throw new Error(`this credential belongs to ${who.idType === 'organization' ? 'an' : 'a'} ${who.idType}, so name the tenant with --tenant or SOPHOS_TENANT_ID`);
    this.tenantId = who.id;
    return this.tenantId;
  }

  // Sends one of DOCUMENTS. HTTP 429 is retried after Retry-After; a 5xx, a timeout or a network
  // error is retried for the two queries only, since a repeated createSearch starts another search.
  // A GraphQL error comes back as HTTP 200 with an errors array, so the body decides.
  async request(op, variables) {
    const document = DOCUMENTS[op];
    if (!document) throw new Error(`${op} is not one of the search operations this client sends`);
    const tenant = await this.resolveTenant();
    const retryable = op === 'search' || op === 'searchResults';
    for (let attempt = 0; ; attempt++) {
      const token = await this.getToken();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      let res;
      try {
        res = await this.fetch(GRAPHQL_URL, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'X-Tenant-ID': tenant, 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ query: document, variables }),
          redirect: 'manual',
          signal: controller.signal,
        });
      } catch (e) {
        clearTimeout(timer);
        const why = e.name === 'AbortError' ? `timed out after ${this.timeoutMs / 1000} s` : e.message;
        if (retryable && attempt < 2) { this.log(`${op} ${why}, trying again`); await sleep(1000 * 2 ** attempt); continue; }
        throw new Error(`${op} ${why}`);
      }
      clearTimeout(timer);
      refuseRedirect(res, GRAPHQL_URL);
      if (res.status === 429 && attempt < 4) {
        const wait = Math.min(Number(res.headers.get('retry-after')) * 1000 || 5000 * (attempt + 1), 60000);
        this.log(`${op} rate limited, waiting ${Math.round(wait / 1000)} s`);
        await sleep(wait);
        continue;
      }
      if (res.status >= 500 && retryable && attempt < 2) { this.log(`${op} HTTP ${res.status}, trying again`); await sleep(1000 * 2 ** attempt); continue; }
      if (!res.ok) throw new Error(`${op} failed (HTTP ${res.status}): ${await readError(res)}`);
      const body = await res.json();
      const errors = Array.isArray(body.errors) ? body.errors : [];
      const data = body.data && body.data[op];
      if (!data) {
        const msg = errors.map((e) => e.message).join('; ') || 'no data and no error';
        const err = new Error(`${op}: ${msg}`);
        err.graphql = errors;
        throw err;
      }
      for (const e of errors) this.log(`${op} warning: ${e.message}`);
      return data;
    }
  }
}

// A search the API no longer holds answers search() or searchResults() with an error like these.
export function looksGone(err) {
  return /not ?found|expired|does not exist|no such search|unknown search/i.test(String(err && err.message));
}

export function isExpired(search, now = Date.now()) {
  const t = Date.parse(search && search.expireTime);
  return Number.isFinite(t) && t <= now;
}

// Polls the search until COMPLETE, then checks outcome.success: ALL is fine, PARTIAL is reported
// and kept, NONE fails. UNKNOWN on a complete search means the search itself failed.
export async function waitForSearch(client, search, { pollMs = 2000, maxWaitMs = 15 * 60000, log = () => {} } = {}) {
  const started = Date.now();
  let s = search;
  let delay = pollMs;
  while (s.status !== 'COMPLETE') {
    if (Date.now() - started > maxWaitMs) throw new SearchFailedError(`the search was still ${s.status} after ${Math.round(maxWaitMs / 60000)} minutes`);
    await sleep(delay);
    delay = Math.min(delay * 1.5, 10000);
    try {
      s = await client.request('search', { urn: s.urn });
    } catch (e) {
      if (looksGone(e)) throw new SearchExpiredError(`the search is gone: ${e.message}`);
      throw e;
    }
  }
  for (const w of s.errors || []) log(`search warning: ${w}`);
  const success = s.outcome && s.outcome.success;
  const partErrors = ((s.outcome && s.outcome.errors) || []).flatMap((p) => p.errors || []);
  if (success === 'ALL') return { search: s, partial: false, partitionErrors: partErrors };
  if (success === 'PARTIAL') {
    log(`PARTIAL: some search partitions failed, so rows may be missing${partErrors.length ? `: ${partErrors.join('; ')}` : ''}`);
    return { search: s, partial: true, partitionErrors: partErrors };
  }
  const why = partErrors.length ? partErrors.join('; ') : (s.errors || []).join('; ') || 'no error given';
  throw new SearchFailedError(`the search failed (outcome ${success || 'UNKNOWN'}): ${why}`);
}

// Pages searchResults by cursor until there is no next cursor or max rows are in hand.
export async function readRows(client, search, { max = ROW_CAP, pageSize = MAX_PAGE, log = () => {} } = {}) {
  const limit = Math.max(1, Math.min(pageSize, MAX_PAGE));
  const rows = [];
  let cursor = null;
  let total = null;
  do {
    if (isExpired(search)) throw new SearchExpiredError(`the search's results expired at ${search.expireTime}`);
    let page;
    try {
      page = await client.request('searchResults', { urn: search.urn, cursor, limit: Math.min(limit, max - rows.length) });
    } catch (e) {
      if (looksGone(e)) throw new SearchExpiredError(`the search's results are gone: ${e.message}`);
      throw e;
    }
    const values = Array.isArray(page.values) ? page.values : typeof page.values === 'string' ? JSON.parse(page.values) : [];
    rows.push(...values);
    if (total === null && page.totals && page.totals.total) total = Number(page.totals.total.value);
    cursor = page.nextCursor || null;
    if (cursor) log(`read ${rows.length}${total !== null ? ` of ${total}` : ''} rows`);
  } while (cursor && rows.length < max);
  return { rows, total };
}

// Runs a QL query to completion and returns its rows. reuse sends getOrCreateSearch, which hands
// back a matching search when the query has absolute time bounds. A search that expires or
// disappears is said so and started again once with createSearch; a second expiry fails.
export async function searchRows(client, text, { reuse = false, max = ROW_CAP, log = () => {}, pollMs, maxWaitMs } = {}) {
  for (let round = 0; ; round++) {
    const op = reuse && round === 0 ? 'getOrCreateSearch' : 'createSearch';
    let search = await client.request(op, { input: { text } });
    try {
      if (op === 'getOrCreateSearch' && isExpired(search)) throw new SearchExpiredError(`the matching search's results expired at ${search.expireTime}`);
      const done = await waitForSearch(client, search, { pollMs, maxWaitMs, log });
      search = done.search;
      const { rows, total } = await readRows(client, search, { max, log });
      return { rows, total, partial: done.partial, partitionErrors: done.partitionErrors, capped: total !== null && total >= ROW_CAP };
    } catch (e) {
      if (!(e instanceof SearchExpiredError)) throw e;
      if (round > 0) throw new SearchFailedError(`${e.message}, and the new search expired too`);
      log(`${e.message}. Starting a new search.`);
    }
  }
}

// Quotes a value for a QL string literal.
export function qlString(s) {
  return `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}
