// The examples on the Fusion "Custom parser syntax" page, run through the emulator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execute } from '../studio/core/engine.js';
import { toPlain, formatTime, JsonValue } from '../studio/core/values.js';

const run = (text, vars) => execute(text, vars).vars;
const get = (text, name, vars) => toPlain(run(text, vars).get(name) ?? null);

test('SPLIT, with and without makeGreedy', () => {
  assert.equal(get('data = "aaa,bbb,ccc,eee"\nv = SPLIT(data, ",", FALSE)\nout = v[3]', 'out'), 'eee');
  const vars = run('data = "aaa,bbb,ccc,,eee"\nv1 = SPLIT(data, ",", FALSE)\nv2 = SPLIT(data, ",", TRUE)\no1 = v1[3]\no2 = v2[3]\nmiss = v1[99]');
  assert.equal(vars.get('o1'), '');
  assert.equal(vars.get('o2'), 'eee');
  assert.equal(vars.get('miss'), null);
});

test('SPLIT_NAME_VALUES', () => {
  const t = 'data = "User: Unknown, InitiatorPackets: 2, ResponderPackets: 1, InitiatorBytes: 120, ResponderBytes: 66"\ndict = SPLIT_NAME_VALUES(data, ",", ":", "\\\\")\nout = dict["InitiatorBytes"]\nuser = dict["User"]\nmiss = dict["email"]';
  const v = run(t);
  assert.equal(v.get('out'), '120');
  assert.equal(v.get('user'), 'Unknown');
  assert.equal(v.get('miss'), null);
  assert.equal(get('d = SPLIT_NAME_VALUES("user=alice,role=admin", ",", "=", "\\\\")\nout = d["role"]', 'out'), 'admin');
  assert.equal(get('d = SPLIT_NAME_VALUES(\'a=1 msg="two words" b=3\', " ", "=", "\\"")\nout = d["msg"]', 'out'), 'two words');
});

test('JSON and JSONPath', () => {
  const store = JSON.stringify({ store: { book: [
    { category: 'reference', author: 'Nigel Rees', title: 'Sayings of the Century', price: 8.95 },
    { category: 'fiction', author: 'Evelyn Waugh', title: 'Sword of Honour', price: 12.99 },
    { category: 'fiction', author: 'Herman Melville', title: 'Moby Dick', isbn: '0-553-21311-3', price: 8.99 },
    { category: 'fiction', author: 'J. R. R. Tolkien', title: 'The Lord of the Rings', isbn: '0-395-19395-8', price: 22.99 },
  ], bicycle: { color: 'red', price: 19.95 } } });
  const v = run('json = JSON(data)\nauthors = json["$.store.book[*].author"]\ncolor = json["$.store.bicycle.color"]\nmiss = json["$.store.pen"]\nlast = json["$.store.book[-1].title"]\ncheap = json["$.store.book[?(@.price < 9)].title"]', { data: store });
  assert.deepEqual(v.get('authors'), ['Nigel Rees', 'Evelyn Waugh', 'Herman Melville', 'J. R. R. Tolkien']);
  assert.equal(v.get('color'), 'red');
  assert.equal(v.get('miss'), null);
  assert.equal(v.get('last'), 'The Lord of the Rings');
  assert.deepEqual(v.get('cheap'), ['Sayings of the Century', 'Moby Dick']);
  const dotted = JSON.stringify({ store: { book: [{ 'id.category': 'reference' }] } });
  assert.equal(get('json = JSON(data)\nout = json["$.store.book[0][\\"id.category\\"]"]', 'out', { data: dotted }), 'reference');
  const items = JSON.stringify({ items: [{ id: 1, tag: 'a' }, { id: 2 }, { id: 3, tag: 'c' }] });
  assert.deepEqual(get('json = JSON(data)\nout = json["$.items.*.tag"]', 'out', { data: items }), ['a', 'c']);
  assert.deepEqual(get('json = JSON(data)\nout = json["$.items.*.tag|preserve_structure"]', 'out', { data: items }), ['a', null, 'c']);
  assert.ok(run('json = JSON(data)\nobj = json["$.store"]', { data: store }).get('obj') instanceof JsonValue);
});

test('CEF header by number and extensions by name, with csNLabel', () => {
  const line = 'Nov 6 07:49:03 192.0.2.1 %helloWorld: CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|Address spoofing|Unknown|act=Drop cs3Label=Protection Type cs3=IPS';
  const v = run('values = CEF(originalData$)\no1 = values[2]\no2 = values["act"]\no3 = values["Protection Type"]', { originalData$: line });
  assert.equal(v.get('o1'), 'VPN-1 & FireWall-1');
  assert.equal(v.get('o2'), 'Drop');
  assert.equal(v.get('o3'), 'IPS');
  const esc = run('v = CEF(l)\nmsg = v["msg"]\nname = v[5]', { l: 'CEF:0|Acme|FW|1.0|100|Pipe \\| in name|5|msg=a\\=b c suser=x' });
  assert.equal(esc.get('msg'), 'a=b c');
  // The engine keeps the backslash in header fields and unescapes extension values.
  assert.equal(esc.get('name'), 'Pipe \\| in name');
});

test('LEEF 1.0 and 2.0', () => {
  const v1 = run('v = LEEF(l)\nvendor = v[1]\nsrc = v["src"]', { l: 'LEEF:1.0|Acme|Gateway|2.1|login|src=192.0.2.5\tdst=198.51.100.2\tusrName=jdoe' });
  assert.equal(v1.get('vendor'), 'Acme');
  assert.equal(v1.get('src'), '192.0.2.5');
  const v2 = run('v = LEEF(l)\nuser = v["usrName"]', { l: 'LEEF:2.0|Acme|Gateway|2.1|login|^|src=192.0.2.5^usrName=jdoe' });
  assert.equal(v2.get('user'), 'jdoe');
  const v3 = run('v = LEEF(l, ",")\nuser = v["usrName"]', { l: 'LEEF:1.0|Acme|Gateway|2.1|login|src=192.0.2.5,usrName=jdoe' });
  assert.equal(v3.get('user'), 'jdoe');
});

test('DATETIME with Go layouts', () => {
  const t = run('out = DATETIME("Sep 21 2018 17:35:54", "Jan 02 2006 15:04:05")').get('out');
  assert.equal(formatTime(t), '2018-09-21 17:35:54 +0000 UTC');
  const z = run('out = DATETIME("2021-10-05T08:09:33-0400", "2006-01-02T15:04:05Z0700")').get('out');
  assert.equal(z.usec, Date.UTC(2021, 9, 5, 12, 9, 33) * 1000);
  const frac = run('out = DATETIME("2023-09-18T06:13:41.532140+0000", "2006-01-02T15:04:05.999999999Z0700")').get('out');
  assert.equal(frac.usec, Date.UTC(2023, 8, 18, 6, 13, 41) * 1000 + 532140);
  const spaces = run('out = DATETIME("Oct  8 09:22:40 2026", "Jan 2 15:04:05 2006")').get('out');
  assert.equal(spaces.usec, Date.UTC(2026, 9, 8, 9, 22, 40) * 1000);
  const noYear = execute('out = DATETIME("Oct  8 09:22:40", "Jan _2 15:04:05", TRUE)', {}, { now: '2026-10-13T00:00:00Z' }).vars.get('out');
  assert.equal(noYear.usec, Date.UTC(2026, 9, 8, 9, 22, 40) * 1000);
  const newYear = execute('out = DATETIME("Dec 31 23:59:00", "Jan _2 15:04:05", TRUE)', {}, { now: '2027-01-01T00:05:00Z' }).vars.get('out');
  assert.equal(new Date(newYear.usec / 1000).getUTCFullYear(), 2026);
  const yearZero = run('out = DATETIME("Oct  8 09:22:40", "Jan _2 15:04:05")').get('out');
  assert.equal(new Date(yearZero.usec / 1000).getUTCFullYear(), 0);
  const pm = run('out = DATETIME("10/07/2026 03:04:05 PM", "01/02/2006 03:04:05 PM")').get('out');
  assert.equal(pm.usec, Date.UTC(2026, 9, 7, 15, 4, 5) * 1000);
  // A value DATETIME can't read gives NULL, as in the engine.
  assert.equal(run('out = DATETIME("not a date", "2006-01-02")').get('out'), null);
});

test('IP functions', () => {
  const v = run('a = IS_PRIVATE_IP("10.0.0.1")\nb = IS_PRIVATE_IP("11.0.0.1")\nc = IS_VALID_IP("10.0.0.1")\nd = IS_VALID_IP("999.255.255.255")\ne = IS_VALID_IP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")\nf = IS_VALID_IP("2001:db8::1")\ng = IS_VALID_IP("010.0.0.1")');
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g'].map((k) => v.get(k)), [true, false, true, false, true, true, false]);
});

test('REPLACE, REPLACE_REGEX, case, TRIM, CONTAINS', () => {
  const v = run('data = "aaaBBBaaaCCC"\na = REPLACE(data, "aaa", "zzz")\nb = REPLACE_REGEX(data, "a+", "z")\nc = UPPERCASE("aaabbbccc acme")\nd = LOWERCASE("AAABBBCCC ACME")\ne = "---" + TRIM(" aaa bbb bcc ")\nf = CONTAINS("aaabbbccc acme", "roadrunner")\ng = CONTAINS("aaabbbccc acme", "acme")\nh = REPLACE_REGEX("user=jdoe", "user=(?P<u>\\\\w+)", "${u}@example.com")');
  assert.equal(v.get('a'), 'zzzBBBzzzCCC');
  assert.equal(v.get('b'), 'zBBBzCCC');
  assert.equal(v.get('c'), 'AAABBBCCC ACME');
  assert.equal(v.get('d'), 'aaabbbccc acme');
  assert.equal(v.get('e'), '---aaa bbb bcc');
  assert.equal(v.get('f'), false);
  assert.equal(v.get('g'), true);
  assert.equal(v.get('h'), 'jdoe@example.com');
});

test('LENGTH and STRLEN', () => {
  const v = run('data = "1234567890"\na = LENGTH(data)\nparts = SPLIT("a,b,c,d", ",")\nb = LENGTH(parts)\nobj = JSON("{\\"a\\":1,\\"b\\":2,\\"c\\":3}")\nc = LENGTH(obj)\nd = LENGTH(parts, "list")\ne = LENGTH(parts, "bytes")\nf = STRLEN(data)\ng = LENGTH("é")\nh = LENGTH(NULL)');
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((k) => v.get(k)), [10, 4, 3, 4, null, 10, 2, 0]);
});

test('ADDFIELD, FLATTEN, OBJKEYS, OBJVALUES', () => {
  const json = JSON.stringify({ httpSourceName: 'web', httpSourceId: 'abc', values: { c: 'x', b: { foo: 'bar' }, a: 'z' }, val: { x: ['1', '2', '3'] } });
  const v = run('json = JSON(data)\nkeys = ["httpSourceName", "httpSourceId"]\nvals = [json["$.httpSourceName"], json["$.httpSourceId"]]\nrec = ADDFIELD(NULL, "key$", keys)\nrec = ADDFIELD(rec, "value$", vals)\nok = OBJKEYS(json["$.values"])\nov = OBJVALS(json["$.values"])\nflat = FLATTEN(json["$.val"])', { data: json });
  assert.deepEqual(toPlain(v.get('rec')), [{ key$: 'httpSourceName', value$: 'web' }, { key$: 'httpSourceId', value$: 'abc' }]);
  assert.deepEqual(v.get('ok'), ['a', 'b', 'c']);
  assert.deepEqual(v.get('ov'), ['z', '{"foo":"bar"}', 'x']);
  assert.deepEqual(toPlain(v.get('flat')), [{ key$: 'x.0', value$: '1' }, { key$: 'x.1', value$: '2' }, { key$: 'x.2', value$: '3' }]);
});

test('URL_PARSE, IDX_OF_TLD, BASE64_DECODE, INT, STRING', () => {
  const v = run('u = URL_PARSE("hTtps://Example.com:443/here//is/path.html?a=1+6&x=%2f%2Fkey=%41%0Avalue&b=ddd#top", FALSE)\npathRaw = u["path_raw"]\npath = u["path"]\nhost = u["host"]\nport = u["port"]\nscheme = u["scheme"]\nfrag = u["fragment"]\nnoScheme = URL_PARSE("example.com/foo/bar/bar/../baz.html?a=1&b=2", FALSE)\nns = noScheme["scheme"]\nnp = noScheme["path"]');
  assert.equal(v.get('pathRaw'), '/here//is/path.html');
  assert.equal(v.get('path'), '/here/is/path.html');
  assert.equal(v.get('host'), 'example.com');
  assert.equal(v.get('port'), '443');
  assert.equal(v.get('scheme'), 'https');
  assert.equal(v.get('frag'), 'top');
  assert.equal(v.get('ns'), 'http');
  assert.equal(v.get('np'), '/foo/bar/baz.html');
  const w = run('a = IDX_OF_TLD("aaa http://example.com")\nb = IDX_OF_TLD("http://example.com")\nc = IDX_OF_TLD("")\nd = BASE64_DECODE("aG1lZXBcISBobWVlcFwh")\ne = INT("4e0", 16)\nf = STRING(NULL)\ng = STRING(SPLIT("a,b", ","))\nh = INT("42", 10) + 1');
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((k) => w.get(k)), [0, 0, -1, 'hmeep\\! hmeep\\!', 1248, '', '"a","b"', 43]);
  assert.throws(() => run('x = INT("abc", 10)'), /INT could not read/);
});

test('VALIDATE_ALL_JSONPATHS_EXIST', () => {
  const line = 'May 17 12:00:00 host alert {"event_id":"123","actor":{"id":"u1"},"action":"login"}';
  const v = run('ok = VALIDATE_ALL_JSONPATHS_EXIST(originalData$, "$.event_id,$.actor.id,$.action")\nno = VALIDATE_ALL_JSONPATHS_EXIST(originalData$, "$.event_id,$.session.id")\nbad = VALIDATE_ALL_JSONPATHS_EXIST("no json here", "$.a")', { originalData$: line });
  assert.equal(v.get('ok'), true);
  assert.equal(v.get('no'), false);
  assert.equal(v.get('bad'), false);
});

test('capture statements, numbered and named groups', () => {
  const v = run('srcIp = message|Source Network Address:\\s+(\\S+)\\s+\nip = srcIp[1]\ntopLevel = other|\\s+%(\\w+)-(\\w+-)?(\\d+)-(\\w+):\\s+(.+)\npart = topLevel[1]\nparts = other2|^(?P<level>\\w+):\\s+(?P<msg>.+)$\nlevel = parts["level"]\nmsg = parts["msg"]', {
    message: 'Source Network Address: 10.17.2.186   Source Port:  54692',
    other: ' %AAA-6-RADIUS_IN_GLOBAL_LIST: radius_db.c:481 RADIUS ACCT',
    other2: 'WARN: disk almost full',
  });
  assert.equal(v.get('ip'), '10.17.2.186');
  assert.equal(v.get('part'), 'AAA');
  assert.equal(v.get('level'), 'WARN');
  assert.equal(v.get('msg'), 'disk almost full');
  assert.throws(() => run('m = s|(a)(b)\nx = m[3]', { s: 'ab' }), /out of range/);
  assert.throws(() => run('m = s|(?P<x>a)\nx = m["y"]', { s: 'a' }), /not in the pattern/);
  assert.equal(run('m = s|zzz\nx = m[1]', { s: 'ab' }).get('x'), '');
});

test('IF, AND, OR, comparisons, lists and records', () => {
  const v = run('a = IF 1 == 1 THEN "yes" ELSE "no"\nb = IF NULL THEN "yes" ELSE "no"\nc = IF "x" THEN "truthy" ELSE "falsy"\nd = 3 > 2 AND "a" != "b"\ne = 1 > 2 OR FALSE\nlist = [1, 2] + [3]\nlist = list + 4\ng.key$ = "k"\ng.value$ = "v"\nrecs = NULL + [g]\nk = g.key$');
  assert.equal(v.get('a'), 'yes');
  assert.equal(v.get('b'), 'no');
  assert.equal(v.get('c'), 'truthy');
  assert.equal(v.get('d'), true);
  assert.equal(v.get('e'), false);
  assert.deepEqual(v.get('list'), [1, 2, 3, 4]);
  assert.deepEqual(toPlain(v.get('recs')), [{ key$: 'k', value$: 'v' }]);
  assert.equal(v.get('k'), 'k');
});

test('TENANT_LOOKUP takes its default, PARSE_ERROR stops the parser', () => {
  assert.equal(get('t = TENANT_LOOKUP("label", "value", "fallback")', 't'), 'fallback');
  assert.throws(() => run('x = PARSE_ERROR("bad data received")'), /PARSE_ERROR: bad data received/);
});

// Engine behaviors checked with Run Test in a lab tenant.

test('IF, AND and OR fail on a list of two or more', () => {
  assert.throws(() => run('l = SPLIT("a,b", ",")\nx = IF l THEN "y" ELSE "n"'), /cannot convert list to bool/);
  assert.throws(() => run('json = JSON(d)\nx = IF json["$.arr"] THEN "y" ELSE "n"', { d: '{"arr":["x","y"]}' }), /cannot convert list to bool/);
  assert.throws(() => run('l = SPLIT("a,b", ",")\nx = l AND TRUE'), /cannot convert list to bool/);
  // An empty list is false, a list of one counts as its item, and a JSON object is true.
  const v = run('one = SPLIT("x", ",")\na = IF one THEN "y" ELSE "n"\nb = IF [] THEN "y" ELSE "n"\njson = JSON(d)\nc = IF json["$.none"] THEN "y" ELSE "n"\ne = IF json["$.obj"] THEN "y" ELSE "n"\nf = IF LENGTH(SPLIT("a,b", ",")) > 0 THEN "y" ELSE "n"', { d: '{"none":[],"obj":{"k":"v"}}' });
  assert.deepEqual(['a', 'b', 'c', 'e', 'f'].map((k) => v.get(k)), ['y', 'n', 'n', 'y', 'y']);
});

test('AND and OR evaluate both sides', () => {
  assert.throws(() => run('x = FALSE AND INT("abc", 10) == 1'), /INT could not read/);
  assert.throws(() => run('x = TRUE OR INT("abc", 10) == 1'), /INT could not read/);
  // IF still runs only the branch it takes.
  assert.equal(get('x = IF FALSE THEN INT("abc", 10) ELSE 1', 'x'), 1);
  const v = run('a = FALSE AND TRUE\nb = TRUE OR FALSE');
  assert.deepEqual([v.get('a'), v.get('b')], [false, true]);
});

test('NULL equals "" and nothing else', () => {
  const v = run('json = JSON(d)\na = NULL == ""\nb = "" == NULL\nc = NULL != ""\nm = json["$.missing"] == ""\ne = json["$.e"] == NULL\nf = 0 == NULL\ng = FALSE == NULL\nh = " " == NULL\ni = "null" == NULL', { d: '{"e":""}' });
  assert.deepEqual(['a', 'b', 'c', 'm', 'e', 'f', 'g', 'h', 'i'].map((k) => v.get(k)), [true, true, false, true, true, false, false, false, false]);
});

test('a DATETIME value compares only with another DATETIME or a number', () => {
  const T = 't = DATETIME("2026-10-13T00:00:00Z", "2006-01-02T15:04:05Z07:00")\n';
  for (const cmp of ['t != NULL', 't == NULL', 'NULL == t', 't == "x"']) assert.throws(() => run(`${T}x = ${cmp}`), /cannot convert time to string/, cmp);
  const v = run(`${T}u = DATETIME("2026-10-14T00:00:00Z", "2006-01-02T15:04:05Z07:00")\na = t == t\nb = t != u\nc = t == 1791849600000000\nd = t > 0`);
  assert.deepEqual(['a', 'b', 'c', 'd'].map((k) => v.get(k)), [true, true, true, true]);
  // A DATETIME that couldn't read its value is NULL, which compares as usual.
  assert.equal(get('t = DATETIME("garbage", "2006-01-02")\nx = t == NULL', 'x'), true);
});
