// The QL check maintenance tool: the search client against a fake API, and the comparison of real
// records with expected.json and with the emulator. No network. Every record here is made up.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseEnv, loadCredentials, SearchClient, searchRows, waitForSearch, readRows, DOCUMENTS,
  SearchFailedError, isExpired, qlString, GRAPHQL_URL, TOKEN_URL, WHOAMI_URL,
} from '../tools/lib/fusion-search.mjs';
import {
  qlSchema, schemaFromQl, entrySchemas, buildQuery, pathOf, entryParserOf, flatten, fieldDef, isDefault,
  compareFields, expectedRecords, groupRows, compareValues, emulate, formatFieldReport, formatValueReport,
} from '../tools/lib/ql-compare.mjs';
import { parseArgs } from '../tools/ql-check.mjs';
import { librarySchemas, parserOwners, aggregateQuery, sampleQuery, pathGroups, classify, claimLines, discover, formatDiscovery, DEFAULT_SAMPLE } from '../tools/lib/ql-discover.mjs';
import { runParsers, expectedShape } from '../studio/core/engine.js';

const SECRET = 'not-a-real-secret-0000';
const CREDS = { clientId: 'example-client', clientSecret: SECRET };

// ------------------------------------------------------------------ a made-up entry

const PARENT = `!CONFIRMWITH=PATTERN
!CONFIRMSTRING=^\\{"acme":
!SCHEMA=scwx.generic
!TRIMALLOFF
json = JSON(originalData$)
sensorType$ = "Acme Gateway"
kind = STRING(json["$.kind"])`;

const AUTH = `!CONFIRMWITH=EXPRESSION
!CONFIRMSTRING=kind=="login"
!SCHEMA=scwx.auth
targetUserName$ = json["$.user"]
sourceAddress$ = json["$.src"]
eventTimeUsec$ = DATETIME(json["$.ts"], "2006-01-02T15:04:05Z07:00")
ok = json["$.result"] == "ok"
action$ = IF ok THEN "LOGON" ELSE "FAILURE"
actionResult$ = IF ok THEN "SUCCESS" ELSE "FAILED"
mfaUsed$ = json["$.mfa"]`;

const LINES = [
  '{"acme":1,"kind":"login","user":"pat@example.com","src":"192.0.2.10","ts":"2026-10-13T01:00:00Z","result":"ok","mfa":true}',
  '{"acme":1,"kind":"login","user":"sam@example.com","src":"192.0.2.11","ts":"2026-10-13T02:00:00Z","result":"bad","mfa":false}',
  '{"acme":1,"kind":"other"}',
];

function makeEntry() {
  const parsers = [
    { name: 'ACME_GW_JSON_PARENT', text: PARENT, role: 'parent' },
    { name: 'ACME_GW_JSON_CHILD_AUTH', text: AUTH, parent: 'ACME_GW_JSON_PARENT', role: 'child' },
  ];
  const meta = {
    reference_time: '2026-10-15T00:00:00Z',
    parsers: [
      { name: 'ACME_GW_JSON_PARENT', schema: 'scwx.generic', role: 'parent' },
      { name: 'ACME_GW_JSON_CHILD_AUTH', schema: 'scwx.auth', role: 'child', parent: 'ACME_GW_JSON_PARENT' },
    ],
  };
  const expected = runParsers(parsers, LINES, { now: meta.reference_time }).map(expectedShape);
  return { id: 'acme/gateway', meta, parsers, samples: LINES, expected };
}

// A real auth record as a search returns it: every field, unset ones at their defaults, and the
// fields Sophos Fusion adds.
function realAuth(over = {}) {
  return {
    schema_type: 'auth', normalizer: 'RoadRunner', normalizer_revision: 'Master -> ACME_GW_JSON_PARENT -> ACME_GW_JSON_CHILD_AUTH',
    normalizer_version: 'v0.0.0', tenant_id: '000000', sensor_tenant: '000000', resource_id: 'event://priv:scwx.auth:000000:1:example',
    visibility: 'PRIVATE', enrichSummary: 'LOGON by pat@example.com', ingest: { availability_time_usec: 1791853300000000, product: null },
    ingest_time_usec: 1791853300000000, original_data: LINES[0],
    sensor_type: 'Acme Gateway', sensor_id: '', event_time_usec: 1791853200000000, event_time_fidelity: 'MICRO',
    target_user_name: 'pat@example.com', source_address: '192.0.2.10', action: 'LOGON', action_result: 'SUCCESS', mfa_used: true,
    auth_category: 'UNKNOWN_AUTH_CATEGORY', failure_category: 'UNKNOWN_FAILURE_CATEGORY', logon_type: null, source_port: 0, target_port_number: 0, commandline: '',
    src_ipgeo_summary: null, event_metadata: null, target_user: { domain: 'example.com', name: 'pat', original_name: 'pat@example.com' },
    ...over,
  };
}

// ------------------------------------------------------------------ query building

test('schema names map to QL and back, thirdparty included', () => {
  assert.equal(qlSchema('scwx.thirdpartyalert'), 'thirdparty');
  assert.equal(qlSchema('scwx.auth'), 'auth');
  assert.equal(schemaFromQl('thirdparty'), 'scwx.thirdpartyalert');
  assert.equal(schemaFromQl('generic'), 'scwx.generic');
});

test('the query searches every schema of the entry by parser path', () => {
  const e = makeEntry();
  assert.deepEqual(entrySchemas(e), ['scwx.generic', 'scwx.auth']);
  assert.equal(buildQuery(e), "from generic, auth where normalizer_revision contains 'ACME_GW_JSON_PARENT' or normalizer_revision contains 'ACME_GW_JSON_CHILD_AUTH' earliest=-7d");
  assert.equal(
    buildQuery(e, { earliest: '2026-10-01T00:00:00Z', latest: '2026-10-08T00:00:00Z', where: "sensor_type = 'Acme Gateway'" }),
    "from generic, auth where sensor_type = 'Acme Gateway' earliest='2026-10-01T00:00:00Z' latest='2026-10-08T00:00:00Z'",
  );
  e.meta.parsers.push({ name: 'ACME_GW_JSON_ALERT', schema: 'scwx.thirdpartyalert, scwx.auth' });
  assert.match(buildQuery(e), /^from generic, auth, thirdparty where/);
  assert.equal(qlString("it's"), "'it\\'s'");
});

test('rows are grouped by the entry parser at the end of their path', () => {
  const names = ['ACME_GW_JSON_PARENT', 'ACME_GW_JSON_CHILD_AUTH'];
  assert.deepEqual(pathOf({ normalizer_revision: 'Master -> A -> B' }), ['Master', 'A', 'B']);
  const rows = [
    realAuth(),
    realAuth({ normalizer_revision: 'Master -> ACME_GW_JSON_PARENT_V2' }),
    { schema_type: 'generic', normalizer_revision: 'Master -> ACME_GW_JSON_PARENT' },
  ];
  assert.equal(entryParserOf(rows[1], names), null);
  const { groups, other } = groupRows(rows, names);
  assert.equal(other, 1, 'a longer name that only contains an entry parser name is left out');
  assert.deepEqual(groups.map((g) => [g.schema, g.parser, g.rows.length]), [['scwx.auth', 'ACME_GW_JSON_CHILD_AUTH', 1], ['scwx.generic', 'ACME_GW_JSON_PARENT', 1]]);
  const any = groupRows(rows, names, { anyParser: true });
  assert.equal(any.other, 0);
  assert.deepEqual(any.groups.find((g) => g.parser === 'ACME_GW_JSON_PARENT_V2').entryParser, false);
});

// ------------------------------------------------------------------ flattening and defaults

test('records flatten to paths, with key-value lists by key', () => {
  const f = flatten({
    a: 1, b: { c: 'x', d: { e: true } }, list: ['p', 'q'], empty: {},
    event_metadata: { record: [{ key: 'k1', value: 'v1' }, { key: 'k2', value: 'v2' }] },
    steps: [{ method: 'password' }, { method: 'otp' }],
  });
  assert.equal(f.get('a'), 1);
  assert.equal(f.get('b.c'), 'x');
  assert.equal(f.get('b.d.e'), true);
  assert.deepEqual(f.get('list'), ['p', 'q']);
  assert.deepEqual(f.get('empty'), {});
  assert.equal(f.get('event_metadata.record[k1]'), 'v1');
  assert.equal(f.get('event_metadata.record[k2]'), 'v2');
  assert.deepEqual(f.get('steps[].method'), { multi: ['password', 'otp'] });
});

test('a real record field counts as set only when it holds more than the default', () => {
  for (const v of [null, undefined, '', 0, false, [], {}]) assert.equal(isDefault(v), true, JSON.stringify(v));
  for (const v of ['x', 1, true, ['a'], { a: 1 }]) assert.equal(isDefault(v), false, JSON.stringify(v));
  // The zero member of a known enum, by the schema data.
  assert.equal(isDefault('UNCLASSIFIED', fieldDef('scwx.auth', 'action')), true);
  assert.equal(isDefault('LOGON', fieldDef('scwx.auth', 'action')), false);
  // An enum the schema data doesn't know: UNKNOWN, UNSET and *_UNKNOWN read as unset.
  assert.equal(isDefault('UNSET'), true);
  assert.equal(isDefault('ENCRYPTION_UNKNOWN'), true);
  assert.equal(isDefault('UNKNOWN_AUTH_PROTOCOL'), true);
  assert.equal(isDefault('UNKNOWN_HOST'), true);
  assert.equal(isDefault('LOGON'), false);
  assert.equal(fieldDef('scwx.auth', 'event_metadata.record[k1]').type, 'string');
  assert.equal(fieldDef('scwx.auth', 'not_a_field'), null);
});

// ------------------------------------------------------------------ field report

test('fields are sorted into set by both, real only, expected only, mismatches and Sophos Fusion fields', () => {
  const expected = [
    { sensor_type: 'Acme Gateway', event_time_usec: 1791853200000000, target_user_name: 'pat@example.com', action: 'LOGON', mfa_used: false, source_port_number: 443, status: 'ok', host_id: 'gw-01' },
  ];
  const real = [
    realAuth({ action: 1, mfa_used: false, source_port_number: '443', status: 'ok', user_agent: 'curl/8.0' }),
    realAuth({ action: 8, mfa_used: false, source_port_number: '443', status: 'ok' }),
  ];
  const f = compareFields(expected, real, 'scwx.auth');
  assert.deepEqual(f.both.map((x) => x.path), ['action', 'event_time_usec', 'sensor_type', 'source_port_number', 'status', 'target_user_name']);
  assert.ok(f.realOnly.some((x) => x.path === 'user_agent' && x.real === 1));
  assert.ok(f.realOnly.some((x) => x.path === 'source_address' && x.real === 2));
  // Unset fields at their defaults, and enum zero members, are not reported as set.
  for (const p of ['auth_category', 'failure_category', 'logon_type', 'source_port', 'commandline', 'src_ipgeo_summary']) assert.ok(!f.realOnly.some((x) => x.path === p), p);
  assert.deepEqual(f.expectedOnly.map((x) => [x.path, x.defaultOnly]), [['host_id', false], ['mfa_used', true]]);
  assert.deepEqual(f.mismatches, [{ path: 'source_port_number', expected: 'number', real: 'string' }]);
  assert.deepEqual(f.enumForm, [{ path: 'action', expected: 'string', real: 'number' }]);
  const platform = f.platform.map((x) => x.path);
  for (const p of ['enrichSummary', 'normalizer_revision', 'tenant_id', 'resource_id', 'original_data', 'ingest_time_usec', 'ingest.availability_time_usec', 'target_user.name']) assert.ok(platform.includes(p), p);
  assert.ok(!platform.includes('user_agent'));
});

test('expected records are picked by schema and parser, copies in other schemas included', () => {
  const expected = [
    { line: 1, extractor_path: 'P > C1', schema: 'scwx.auth', normalized: { a: 1 } },
    { line: 2, extractor_path: 'P > C2', schema: 'scwx.auth,scwx.cloudaudit', normalized: { a: 2 }, also: [{ schema: 'scwx.cloudaudit', normalized: { b: 2 } }] },
    { line: 3, extractor_path: 'P', schema: 'scwx.generic', normalized: { g: 3 } },
    { line: 4, extractor_path: 'P > C1', schema: 'scwx.generic', normalized: null, error: true },
  ];
  assert.deepEqual(expectedRecords(expected, 'scwx.auth'), [{ a: 1 }, { a: 2 }]);
  assert.deepEqual(expectedRecords(expected, 'scwx.auth', 'C1'), [{ a: 1 }]);
  assert.deepEqual(expectedRecords(expected, 'scwx.cloudaudit', 'C2'), [{ b: 2 }]);
  assert.deepEqual(expectedRecords(expected, 'scwx.generic'), [{ g: 3 }]);
});

test('the field report names fields and counts, never values', () => {
  const e = makeEntry();
  const real = [realAuth(), realAuth({ target_user_name: 'sam@example.com', original_data: LINES[1], action: 'FAILURE', action_result: 'FAILED', mfa_used: false, source_address: '192.0.2.11', event_time_usec: 1791856800000000 })];
  const f = compareFields(expectedRecords(e.expected, 'scwx.auth', 'ACME_GW_JSON_CHILD_AUTH'), real, 'scwx.auth');
  const text = formatFieldReport(f, 'ACME_GW_JSON_CHILD_AUTH');
  assert.match(text, /^auth from ACME_GW_JSON_CHILD_AUTH: 2 real records, 2 in expected\.json/);
  assert.match(text, /Both set \(\d+\): action, action_result, event_time_fidelity, event_time_usec, mfa_used \(1 of 2\)/);
  assert.doesNotMatch(text, /pat@example\.com|192\.0\.2/);
  const other = formatFieldReport(f, 'SOMEONE_ELSES_PARSER', { entryParser: false });
  assert.match(other, /SOMEONE_ELSES_PARSER is not one of the entry's parsers/);
});

// ------------------------------------------------------------------ the emulator on real lines

test('the emulator runs on each real raw line at the record\'s ingest time', () => {
  const e = makeEntry();
  const third = emulate(e, { schema_type: 'generic', original_data: LINES[2], ingest_time_usec: 1791853300000000 });
  assert.deepEqual(third.path, ['ACME_GW_JSON_PARENT']);
  assert.equal(third.record.event_time_usec, 1791853300000000, 'a line without a time gets the real ingest time');
  const first = emulate(e, realAuth());
  assert.deepEqual(first.path, ['ACME_GW_JSON_PARENT', 'ACME_GW_JSON_CHILD_AUTH']);
  assert.equal(first.record.target_user_name, 'pat@example.com');
  // A real record in a schema the emulator didn't use gets no record.
  assert.equal(emulate(e, realAuth({ schema_type: 'cloudaudit' })).record, null);
});

test('values are compared field by field: same, different, emulator only and real only', () => {
  const e = makeEntry();
  const rows = [
    realAuth(),
    realAuth({ original_data: LINES[1], ingest_time_usec: 1791856900000000, target_user_name: 'sam@example.com', source_address: '198.51.100.11', action: 'FAILURE', action_result: 'FAILED', mfa_used: false, event_time_usec: 1791856800000000, user_agent: 'curl/8.0' }),
    realAuth({ normalizer_revision: 'Master -> ACME_GW_JSON_PARENT', original_data: LINES[0] }),
    realAuth({ original_data: '' }),
  ];
  const v = compareValues(e, rows, 'scwx.auth');
  assert.equal(v.records, 3);
  assert.equal(v.noRaw, 1);
  assert.equal(v.pathSame, 2);
  assert.equal(v.pathDiffer, 1);
  const f = (p) => v.fields.get(p);
  assert.deepEqual([f('target_user_name').same, f('target_user_name').differ], [3, 0]);
  assert.deepEqual([f('source_address').same, f('source_address').differ], [2, 1]);
  assert.deepEqual(f('source_address').example, { emulator: '192.0.2.11', real: '198.51.100.11' });
  assert.equal(f('mfa_used').same, 3, 'false on both sides is the same');
  assert.equal(f('user_agent').realOnly, 1);
  assert.equal(v.fields.has('enrichSummary'), false, 'fields Sophos Fusion adds are left out');
  assert.equal(v.fields.has('target_user.name'), false);

  const hidden = formatValueReport(v);
  assert.match(hidden, /Different value \(1\): source_address 1 of 3/);
  assert.match(hidden, /Real record sets, emulator doesn't \(1\): user_agent 1 of 1/);
  assert.match(hidden, /Emulator parser path: ACME_GW_JSON_PARENT > ACME_GW_JSON_CHILD_AUTH \(3\); 2 the same as the real path, 1 different/);
  assert.doesNotMatch(hidden, /198\.51\.100\.11/);
  assert.match(formatValueReport(v, { showValues: true }), /source_address \(emulator "192\.0\.2\.11", real "198\.51\.100\.11"\) 1 of 3/);
});

test('a raw line the emulator puts in another schema is counted, not compared', () => {
  const e = makeEntry();
  const v = compareValues(e, [realAuth({ original_data: LINES[2] })], 'scwx.auth');
  assert.equal(v.noRecord, 1);
  assert.match(formatValueReport(v), /No record in auth from the emulator for 1: it used generic \(1\)/);
});

test('emulator errors quote the line, so they show only with the values', () => {
  const e = makeEntry();
  e.parsers[1] = { ...e.parsers[1], text: e.parsers[1].text.replace('action$ = IF ok THEN "LOGON" ELSE "FAILURE"', 'action$ = json["$.user"]') };
  const v = compareValues(e, [realAuth()], 'scwx.auth');
  assert.equal(v.errorLines, 1);
  assert.match(formatValueReport(v), /Emulator errors on 1 line \(--show-values prints them\)/);
  assert.doesNotMatch(formatValueReport(v), /pat@example\.com/);
  assert.match(formatValueReport(v, { showValues: true }), /Emulator errors on 1 line: .*pat@example\.com/);
});

// ------------------------------------------------------------------ the search client

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

const SEARCH = (over = {}) => ({ urn: 'urn:search:example:1', status: 'COMPLETE', errors: [], queryText: 'q', expireTime: '2099-01-01T00:00:00Z', outcome: { success: 'ALL', errors: [] }, ...over });

// A fake API: sign-in, whoami and GraphQL. graphql(op, variables, n) answers each call.
function fakeApi(graphql) {
  const calls = [];
  const counts = {};
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (url === TOKEN_URL) return json({ access_token: 'example-token', expires_in: 3600 });
    if (url === WHOAMI_URL) return json({ id: 'example-tenant', idType: 'tenant' });
    if (url === GRAPHQL_URL) {
      const body = JSON.parse(init.body);
      const op = Object.keys(DOCUMENTS).find((k) => DOCUMENTS[k] === body.query);
      counts[op] = (counts[op] || 0) + 1;
      return graphql(op, body.variables, counts[op]);
    }
    throw new Error(`unexpected ${url}`);
  };
  return { fetchImpl, calls, counts };
}

test('env files give the credentials, and the secret stays off the client', async () => {
  assert.deepEqual(parseEnv('# a comment\nexport SOPHOS_CLIENT_ID="example-client"\nSOPHOS_CLIENT_SECRET=\'s3\'\n\nNOT A LINE\n'), { SOPHOS_CLIENT_ID: 'example-client', SOPHOS_CLIENT_SECRET: 's3' });
  assert.deepEqual(await loadCredentials({ env: { SOPHOS_CLIENT_ID: 'a', SOPHOS_CLIENT_SECRET: 'b', SOPHOS_TENANT_ID: 't' } }), { clientId: 'a', clientSecret: 'b', tenantId: 't' });
  await assert.rejects(loadCredentials({ env: {} }), /SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET must be set/);
  const api = fakeApi(() => json({ data: { search: SEARCH() } }));
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  await client.getToken();
  const shown = JSON.stringify(client) + String(Object.keys(client));
  assert.doesNotMatch(shown, new RegExp(SECRET));
  assert.doesNotMatch(shown, /example-token/);
});

test('the client sends only the four search operations', async () => {
  assert.deepEqual(Object.keys(DOCUMENTS).sort(), ['createSearch', 'getOrCreateSearch', 'search', 'searchResults']);
  for (const [op, doc] of Object.entries(DOCUMENTS)) {
    const kind = /^\s*(query|mutation)\b/.exec(doc)[1];
    assert.equal(kind, op === 'createSearch' || op === 'getOrCreateSearch' ? 'mutation' : 'query', op);
    assert.equal((doc.match(/\b(createSearch|getOrCreateSearch|search|searchResults)\(/g) || []).length, 1, op);
  }
  const api = fakeApi(() => json({ data: {} }));
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  await assert.rejects(client.request('deleteParser', {}), /not one of the search operations/);
  assert.equal(api.calls.length, 0);
});

test('a search runs to completion and its rows are paged by cursor', async () => {
  const api = fakeApi((op, vars, n) => {
    if (op === 'createSearch') return json({ data: { createSearch: SEARCH({ status: 'QUEUED' }) } });
    if (op === 'search') return json({ data: { search: SEARCH({ status: n < 2 ? 'IN_PROGRESS' : 'COMPLETE' }) } });
    if (op === 'searchResults') {
      assert.ok(vars.limit <= 1000);
      return json({ data: { searchResults: { values: [{ n: vars.cursor ? 2 : 1 }], totals: { total: { value: 2 } }, nextCursor: vars.cursor ? null : 'next' } } });
    }
    throw new Error(op);
  });
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  const r = await searchRows(client, 'from auth earliest=-1d', { pollMs: 1 });
  assert.deepEqual(r.rows, [{ n: 1 }, { n: 2 }]);
  assert.equal(r.total, 2);
  assert.equal(r.partial, false);
  assert.deepEqual(api.counts, { createSearch: 1, search: 2, searchResults: 2 });
  const gql = api.calls.filter((c) => c.url === GRAPHQL_URL);
  assert.ok(gql.every((c) => c.init.headers.Authorization === 'Bearer example-token' && c.init.headers['X-Tenant-ID'] === 'example-tenant' && c.init.redirect === 'manual'));
  assert.ok(api.calls.every((c) => !String(c.url).includes(SECRET)));
});

test('reuse sends getOrCreateSearch', async () => {
  const api = fakeApi((op) => (op === 'getOrCreateSearch' ? json({ data: { getOrCreateSearch: SEARCH() } }) : json({ data: { searchResults: { values: [], nextCursor: null } } })));
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  await searchRows(client, 'q', { reuse: true, pollMs: 1 });
  assert.deepEqual(api.counts, { getOrCreateSearch: 1, searchResults: 1 });
});

test('PARTIAL is reported and kept, NONE fails', async () => {
  const logs = [];
  const partial = SEARCH({ outcome: { success: 'PARTIAL', errors: [{ urn: 'urn:p', errors: ['partition timed out'] }] } });
  const client = new SearchClient(CREDS, { fetchImpl: fakeApi(() => json({ data: {} })).fetchImpl });
  const r = await waitForSearch(client, partial, { log: (m) => logs.push(m) });
  assert.equal(r.partial, true);
  assert.match(logs.join('\n'), /PARTIAL: some search partitions failed, so rows may be missing: partition timed out/);
  await assert.rejects(waitForSearch(client, SEARCH({ outcome: { success: 'NONE', errors: [{ urn: 'urn:p', errors: ['bad field'] }] } })), (e) => e instanceof SearchFailedError && /outcome NONE\): bad field/.test(e.message));
  await assert.rejects(waitForSearch(client, SEARCH({ errors: ['query rejected'], outcome: { success: 'UNKNOWN', errors: [] } })), /outcome UNKNOWN\): query rejected/);
});

test('an expired search is said so and started again once, then fails', async () => {
  assert.equal(isExpired({ expireTime: '2000-01-01T00:00:00Z' }), true);
  assert.equal(isExpired({ expireTime: '2099-01-01T00:00:00Z' }), false);
  const logs = [];
  let api = fakeApi((op, vars, n) => {
    if (op === 'createSearch') return json({ data: { createSearch: SEARCH({ urn: `urn:search:example:${n}` }) } });
    if (op === 'searchResults') {
      if (vars.urn.endsWith(':1')) return json({ errors: [{ message: 'search not found' }], data: null });
      return json({ data: { searchResults: { values: [{ ok: true }], nextCursor: null } } });
    }
    throw new Error(op);
  });
  let client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  const r = await searchRows(client, 'q', { pollMs: 1, log: (m) => logs.push(m) });
  assert.deepEqual(r.rows, [{ ok: true }]);
  assert.equal(api.counts.createSearch, 2);
  assert.match(logs.join('\n'), /results are gone: searchResults: search not found\. Starting a new search\./);

  api = fakeApi((op) => (op === 'createSearch' ? json({ data: { createSearch: SEARCH({ expireTime: '2000-01-01T00:00:00Z' }) } }) : json({ data: {} })));
  client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  await assert.rejects(searchRows(client, 'q', { pollMs: 1 }), (e) => e instanceof SearchFailedError && /expired at 2000-01-01T00:00:00Z, and the new search expired too/.test(e.message));
  assert.equal(api.counts.createSearch, 2);
  assert.equal(api.counts.searchResults, undefined, 'no results are read from an expired search');
});

test('readRows stops at max', async () => {
  const api = fakeApi((op, vars) => json({ data: { searchResults: { values: Array.from({ length: vars.limit }, (_, i) => ({ i })), totals: { total: { value: 5000 } }, nextCursor: 'more' } } }));
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  const r = await readRows(client, SEARCH(), { max: 1500 });
  assert.equal(r.rows.length, 1500);
  assert.equal(r.total, 5000);
  assert.equal(api.counts.searchResults, 2);
});

test('GraphQL errors, sign-in failures and redirects fail clearly without the secret', async () => {
  let client = new SearchClient(CREDS, { fetchImpl: fakeApi(() => json({ errors: [{ message: 'query validation failed: Invalid schema' }], data: null })).fetchImpl });
  await assert.rejects(client.request('createSearch', { input: { text: 'from nope' } }), /createSearch: query validation failed: Invalid schema/);
  const signIn = async (url) => (url === TOKEN_URL ? json({ errorCode: 'oauth.invalid_client_secret', message: 'Invalid client secret' }, 401) : json({}));
  client = new SearchClient(CREDS, { fetchImpl: signIn });
  await assert.rejects(client.getToken(), (e) => /Sophos sign-in failed \(HTTP 401\)/.test(e.message) && !e.message.includes(SECRET));
  const redirect = async () => new Response('', { status: 307, headers: { location: 'https://example.com/' } });
  client = new SearchClient(CREDS, { fetchImpl: redirect });
  await assert.rejects(client.getToken(), /redirect \(HTTP 307\), which this tool refuses to follow/);
  const partner = async (url) => (url === TOKEN_URL ? json({ access_token: 't', expires_in: 3600 }) : json({ id: 'p', idType: 'partner' }));
  client = new SearchClient(CREDS, { fetchImpl: partner });
  await assert.rejects(client.resolveTenant(), /belongs to a partner, so name the tenant with --tenant or SOPHOS_TENANT_ID/);
});

test('command line options', () => {
  assert.deepEqual(parseArgs(['parsers/acme/gateway']), { dir: 'parsers/acme/gateway', envFile: null, tenant: null, earliest: '-7d', latest: null, max: 1000, where: null, reuse: false, showValues: false, emulator: true, discover: false, sample: DEFAULT_SAMPLE });
  const o = parseArgs(['parsers/acme/gateway', '--env-file', '/tmp/x.env', '--earliest', '-30d', '--max', '200', '--where', "sensor_type = 'Acme'", '--reuse', '--show-values', '--no-emulator']);
  assert.equal(o.envFile, '/tmp/x.env');
  assert.equal(o.max, 200);
  assert.equal(o.reuse && o.showValues && !o.emulator, true);
  assert.throws(() => parseArgs([]), /name an entry folder/);
  assert.throws(() => parseArgs(['a', '--max', '20000']), /--max must be/);
  assert.throws(() => parseArgs(['a', '--nope']), /unknown option --nope/);
  assert.throws(() => parseArgs(['a', '--earliest']), /--earliest needs a value/);
});

// ------------------------------------------------------------------ --discover

// A second made-up entry, so the raw-line pass has two to tell apart.
function otherEntry() {
  const parsers = [{ name: 'OTHER_THING_PARENT', text: '!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=^OTHER:\n!SCHEMA=scwx.generic\nsensorType$ = "Other"', role: 'parent' }];
  return { id: 'other/thing', meta: { reference_time: '2026-10-15T00:00:00Z', parsers: [{ name: 'OTHER_THING_PARENT', schema: 'scwx.generic', role: 'parent' }] }, parsers, samples: ['OTHER: x'], expected: [] };
}

const AGG_ROWS = [
  { normalizer_revision: 'Master -> ACME_GW_JSON_PARENT -> ACME_GW_JSON_CHILD_AUTH', row_count: 5, schema_type: 'auth' },
  { normalizer_revision: 'Master -> ACME_GW_JSON_PARENT', row_count: 2, schema_type: 'generic' },
  { normalizer_revision: 'Master -> Vendor_Builtin', row_count: 9, schema_type: 'antivirus' },
  { normalizer_revision: 'Master', row_count: 3, schema_type: 'generic' },
  { normalizer_revision: '', row_count: 1000, schema_type: 'process' },
  { normalizer_revision: 'Master -> ACME_GW_JSON_PARENT_COPY', row_count: 1, schema_type: 'thirdparty' },
];

test('discover: one aggregate search over every library schema, and samples that read one parser path', () => {
  assert.deepEqual(librarySchemas([makeEntry(), otherEntry()]), ['auth', 'generic']);
  assert.equal(aggregateQuery(['auth', 'generic'], { earliest: '-7d' }), 'from auth, generic earliest=-7d | aggregate count by normalizer_revision');
  assert.equal(aggregateQuery(['auth'], { earliest: '2026-10-01T00:00:00Z', latest: '2026-10-31T00:00:00Z' }), "from auth earliest='2026-10-01T00:00:00Z' latest='2026-10-31T00:00:00Z' | aggregate count by normalizer_revision");
  assert.equal(sampleQuery('antivirus', 'Master -> Vendor_Builtin', 100, { earliest: '-30d' }), "from antivirus where normalizer_revision = 'Master -> Vendor_Builtin' earliest=-30d | head 100");
  assert.equal(sampleQuery('generic', "Master -> It's", 5, { earliest: '-7d' }), "from generic where normalizer_revision = 'Master -> It\\'s' earliest=-7d | head 5");
  assert.deepEqual([...parserOwners([makeEntry(), otherEntry()])], [['ACME_GW_JSON_PARENT', 'acme/gateway'], ['ACME_GW_JSON_CHILD_AUTH', 'acme/gateway'], ['OTHER_THING_PARENT', 'other/thing']]);
});

test('discover: parser paths sort into library parsers, other parsers and records with no parser', () => {
  const groups = pathGroups(AGG_ROWS);
  assert.equal(groups.length, 6);
  const { library, other, unparsed } = classify(groups, parserOwners([makeEntry(), otherEntry()]));
  assert.deepEqual(library.map((g) => [g.id, g.schema, g.count, g.parsers]), [['acme/gateway', 'auth', 5, ['ACME_GW_JSON_PARENT', 'ACME_GW_JSON_CHILD_AUTH']], ['acme/gateway', 'generic', 2, ['ACME_GW_JSON_PARENT']]]);
  // A longer name that only contains a library parser's name is another parser.
  assert.deepEqual(other.map((g) => g.path).sort(), ['Master', 'Master -> ACME_GW_JSON_PARENT_COPY', 'Master -> Vendor_Builtin']);
  assert.deepEqual(unparsed.map((g) => [g.schema, g.count]), [['process', 1000]]);
});

test('discover: an entry is found by the raw lines its parsers claim', () => {
  const c = claimLines([makeEntry(), otherEntry()], [LINES[0], LINES[2], 'OTHER: x', 'nothing at all']);
  assert.deepEqual(c.map((x) => [x.id, x.claimed, x.of]), [['acme/gateway', 2, 4], ['other/thing', 1, 4]]);
  assert.deepEqual(c[0].paths, [['ACME_GW_JSON_PARENT > ACME_GW_JSON_CHILD_AUTH', 1], ['ACME_GW_JSON_PARENT', 1]]);
});

// A fake Search API: the aggregate search and one sample search per parser path, told apart by the
// query text. rowsFor(text) gives the rows, or throws to answer with a GraphQL error.
function discoverApi(rowsFor) {
  const texts = new Map();
  let n = 0;
  return fakeApi((op, vars) => {
    if (op === 'createSearch' || op === 'getOrCreateSearch') {
      const urn = `urn:search:example:${++n}`;
      try { texts.set(urn, rowsFor(vars.input.text)); } catch (e) { return json({ errors: [{ message: e.message }], data: null }); }
      return json({ data: { [op]: SEARCH({ urn, queryText: vars.input.text }) } });
    }
    if (op === 'searchResults') return json({ data: { searchResults: { values: texts.get(vars.urn), totals: { total: { value: texts.get(vars.urn).length } }, nextCursor: null } } });
    throw new Error(op);
  });
}

test('discover: end to end on a fake API, names and counts only, with the ql-check run for each find', async () => {
  const queries = [];
  const api = discoverApi((text) => {
    queries.push(text);
    if (text.includes('| aggregate')) return AGG_ROWS;
    if (text.includes("'Master -> Vendor_Builtin'")) return [...LINES.map((l) => ({ original_data: l })), { original_data: '' }];
    if (text.includes("= 'Master'")) return [{ original_data: 'OTHER: y' }, { original_data: 'unrelated' }];
    return [];
  });
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  const report = await discover(client, [makeEntry(), otherEntry()], { earliest: '-7d', sample: 50, pollMs: 1 });
  assert.equal(queries[0], 'from auth, generic earliest=-7d | aggregate count by normalizer_revision');
  // One sample per parser path that isn't a library parser's, and none for records with no parser.
  assert.equal(queries.length, 4);
  assert.ok(queries.slice(1).every((q) => / \| head 50$/.test(q) && !q.includes("= ''")), queries.join('\n'));
  assert.deepEqual(report.claimed.map((c) => [c.id, c.group.path, c.claimed, c.of]), [['acme/gateway', 'Master -> Vendor_Builtin', 3, 3], ['other/thing', 'Master', 1, 2]]);
  const text = formatDiscovery(report);
  assert.match(text, /Ingested with library parsers \(1 entry\)/);
  assert.match(text, /parsers\/acme\/gateway: Master -> ACME_GW_JSON_PARENT -> ACME_GW_JSON_CHILD_AUTH in auth, 5 records/);
  assert.match(text, /node tools\/ql-check\.mjs parsers\/acme\/gateway --earliest -7d/);
  assert.match(text, /parsers\/acme\/gateway claims 3 of 3 sampled lines from Master -> Vendor_Builtin in antivirus \(9 records\)/);
  assert.match(text, /node tools\/ql-check\.mjs parsers\/acme\/gateway --where "normalizer_revision = 'Master -> Vendor_Builtin'" --earliest -7d/);
  assert.match(text, /1 other parser path was sampled and no entry claimed a line; it had no raw lines/);
  assert.match(text, /1,000 records in 1 schema came with no parser path/);
  // The raw lines stay out of the report.
  assert.doesNotMatch(text, /pat@example\.com|OTHER: y/);

  // Without the emulator, only the aggregate search runs.
  queries.length = 0;
  const quick = await discover(client, [makeEntry(), otherEntry()], { earliest: '-7d', emulator: false, pollMs: 1 });
  assert.equal(queries.length, 1);
  assert.match(formatDiscovery(quick), /Raw lines were not sampled/);
});

test('discover: when the search across every schema fails, each schema is searched on its own', async () => {
  const api = discoverApi((text) => {
    if (text.startsWith('from auth, generic')) throw new Error('query validation failed: cannot aggregate');
    if (text.startsWith('from generic ')) throw new Error('query validation failed: cannot aggregate on generic');
    if (text.startsWith('from auth ')) return AGG_ROWS.slice(0, 1);
    return [];
  });
  const logs = [];
  const client = new SearchClient(CREDS, { fetchImpl: api.fetchImpl });
  const report = await discover(client, [makeEntry()], { earliest: '-7d', emulator: false, pollMs: 1, log: (m) => logs.push(m) });
  assert.deepEqual(report.failed.map((f) => f.schema), ['generic']);
  assert.equal(report.library.length, 1);
  assert.match(logs.join('\n'), /searched on its own/);
  assert.match(formatDiscovery(report), /The search failed for generic: .*cannot aggregate on generic/);
  // A sign-in failure is not a reason to try each schema.
  const denied = new SearchClient(CREDS, { fetchImpl: async (url) => (url === TOKEN_URL ? json({ message: 'Invalid client secret' }, 401) : json({})) });
  await assert.rejects(discover(denied, [makeEntry()], { earliest: '-7d', emulator: false, pollMs: 1 }), /Sophos sign-in failed/);
});

test('discover: command line options', () => {
  const o = parseArgs(['--discover', '--earliest', '-30d']);
  assert.equal(o.discover && o.dir === null && o.sample === DEFAULT_SAMPLE && o.earliest === '-30d', true);
  assert.equal(parseArgs(['--discover', '--sample', '0']).sample, 0);
  assert.equal(parseArgs(['--discover', '--no-emulator']).emulator, false);
  assert.throws(() => parseArgs(['--discover', 'parsers/acme/gateway']), /--discover looks at every library entry, so name no entry folder/);
  for (const flag of [['--where', 'x'], ['--max', '5'], ['--show-values']]) assert.throws(() => parseArgs(['--discover', ...flag]), new RegExp(`${flag[0]} doesn't apply to --discover`));
  assert.throws(() => parseArgs(['--discover', '--sample', '1001']), /--sample must be a whole number from 0 to 1000/);
  assert.throws(() => parseArgs(['parsers/acme/gateway', '--sample', '5']), /--sample only applies to --discover/);
});
