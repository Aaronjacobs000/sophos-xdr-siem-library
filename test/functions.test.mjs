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
  // The engine rejects the parser without the quote character ("requires 4 parameters").
  assert.throws(() => run('d = SPLIT_NAME_VALUES("a=1", " ", "=")'), /takes 4 arguments, got 3/);
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
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((k) => w.get(k)), [0, 0, -1, 'hmeep\\! hmeep\\!', 1248, '', '["a","b"]', 43]);
  assert.throws(() => run('x = INT("abc", 10)'), /INT could not read/);
});

// What the engine gave for each in a lab tenant.
test('STRING() of a list writes JSON the way Go does', () => {
  const d = JSON.stringify({ arr: [{ b: 1, a: 'x<y' }, 2.5, 's', 3], nul: ['a', null, true], o: { 'k&': 'v' } });
  const v = run(`j = JSON(d)
t = DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00")
inner = ["p", "q"]
rec.key$ = "k"
rec.value$ = "v"
kv = SPLIT_NAME_VALUES("b=2 a=1", " ", "=", "\\"")
n = NULL
a = STRING(["a", "b"])
b = STRING(SPLIT("x,y,z", ","))
c = STRING([1, 2])
e = STRING(["a<b&c", "d e", "a>b", "é"])
f = STRING(["a", NULL, "c"])
g = STRING(["a", n])
h = STRING([TRUE, 7, "q"])
i = STRING(SPLIT("a,,b", ","))
k = STRING(j["$.arr[*]"])
l = STRING(j["$.nul[*]"])
m = STRING([t])
o = STRING([inner, "c"])
p = STRING([rec])
q = STRING([kv])
r = STRING([j["$.o"]])
s = STRING(SPLIT(line, "|"))`, { d, line: '<134>x a\tb|c"d\\e' });
  const want = {
    a: '["a","b"]', b: '["x","y","z"]', c: '[1,2]', e: '["a\\u003cb\\u0026c","d e","a\\u003eb","é"]', f: '["a",0,"c"]', g: '["a",0]',
    h: '[true,7,"q"]', i: '["a","","b"]', k: '[{"a":"x\\u003cy","b":1},2.5,"s",3]', l: '["a",0,true]', m: '[{}]', o: '[["p","q"],"c"]',
    p: '[{"key$":"k","value$":"v"}]', q: '[{"a":"1","b":"2"}]', r: '[{"k\\u0026":"v"}]', s: '["\\u003c134\\u003ex a\\tb","c\\"d\\\\e"]',
  };
  for (const [k, w] of Object.entries(want)) assert.equal(v.get(k), w, k);
  assert.equal(get('x = STRING(["a"])', 'x'), '["a"]');
});

// What the engine gave for each in a lab tenant. A NULL stays null only in the value JSON()
// returned; in a part read from it, the engine writes 0.
test('STRING() of a JSON object or array writes JSON the way Go does', () => {
  const d = '{"o":{"b":1,"a":"x<y&z>","c":[3,1,{"z":null,"y":true}],"n":null,"f":1.5,"e":1e21,"sm":1e-7,"big":12345678901234567890,"s":"\\u00e9\\u2028"},"arr":[{"b":2,"a":1},"q<",null,2.0],"emp":{},"ea":[],"nul":["a",null,true]}';
  const v = run(`j = JSON(d)
o = STRING(j["$.o"])
arr = STRING(j["$.arr"])
emp = STRING(j["$.emp"])
ea = STRING(j["$.ea"])
nul = STRING(j["$.nul"])
whole = STRING(j)
oc = STRING(j["$.o.c"])
plainkey = STRING(j["o"])
arr0 = STRING(j["$.arr[0]"])
num = STRING(j["$.o.f"])`, { d });
  const o = '{"a":"x\\u003cy\\u0026z\\u003e","b":1,"big":12345678901234567000,"c":[3,1,{"y":true,"z":0}],"e":1e+21,"f":1.5,"n":0,"s":"é\\u2028","sm":1e-7}';
  const want = {
    o, arr: '[{"a":1,"b":2},"q\\u003c",0,2]', emp: '{}', ea: '[]', nul: '["a",0,true]', oc: '[3,1,{"y":true,"z":0}]', plainkey: o, arr0: '{"a":1,"b":2}', num: '1',
    whole: '{"arr":[{"a":1,"b":2},"q\\u003c",null,2],"ea":[],"emp":{},"nul":["a",null,true],"o":{"a":"x\\u003cy\\u0026z\\u003e","b":1,"big":12345678901234567000,"c":[3,1,{"y":true,"z":null}],"e":1e+21,"f":1.5,"n":null,"s":"é\\u2028","sm":1e-7}}',
  };
  for (const [k, w] of Object.entries(want)) assert.equal(v.get(k), w, k);
  const d2 = '{"o":{"n":null,"b":1,"a":"x>","c":[null,{"z":null}]},"top":null}';
  const w = run(`j = JSON(d)
o = j["$.o"]
direct = STRING(JSON(d))
root = STRING(j["$"])
ostr = STRING(o)
listo = STRING([o])
star = STRING(j["$.o.*"])
deep = STRING(j["$..c"])
pres = STRING(j["$.o|preserve_structure"])`, { d: d2 });
  const o2 = '{"a":"x\\u003e","b":1,"c":[0,{"z":0}],"n":0}';
  const want2 = {
    direct: '{"o":{"a":"x\\u003e","b":1,"c":[null,{"z":null}],"n":null},"top":null}', root: `{"o":${o2},"top":0}`, ostr: o2, listo: `[${o2}]`,
    star: '[0,1,"x\\u003e",[0,{"z":0}]]', deep: '[0,{"z":0}]', pres: o2,
  };
  for (const [k, x] of Object.entries(want2)) assert.equal(w.get(k), x, k);
});

// What the engine gave for each in a lab tenant. Inside a list or a record, the value JSON()
// returned is written as {}, whatever it holds; a part read from it is written in full.
test('STRING() writes the value JSON() returned as {} inside a list or a record', () => {
  const d = '{"psr3a":1,"o":{"b":1,"a":"x<y&z>","c":[1,null]},"n":null}';
  const v = run(`j = JSON(d)
ja = JSON("[1,2]")
js = JSON("5")
o = j["$.o"]
listj = STRING([j])
direct = STRING([JSON(d)])
listja = STRING([ja])
listjs = STRING([js])
listo = STRING([o])
mixed = STRING([j, o, "x"])
nested = STRING([[j]])
listroot = STRING([j["$"]])
whole = STRING(j)`, { d });
  const o = '{"a":"x\\u003cy\\u0026z\\u003e","b":1,"c":[1,0]}';
  const want = {
    listj: '[{}]', direct: '[{}]', listja: '[{}]', listjs: '[{}]', listo: `[${o}]`, mixed: `[{},${o},"x"]`, nested: '[[{}]]',
    listroot: `[{"n":0,"o":${o},"psr3a":1}]`, whole: '{"n":null,"o":{"a":"x\\u003cy\\u0026z\\u003e","b":1,"c":[1,null]},"psr3a":1}',
  };
  for (const [k, w] of Object.entries(want)) assert.equal(v.get(k), w, k);
});

// What the engine gave for each in a lab tenant.
test('STRING() of a SPLIT_NAME_VALUES object or a record writes JSON the way Go does', () => {
  const d = '{"psr3a":1,"o":{"b":1,"a":"x<y&z>","c":[1,null]},"n":null}';
  const v = run(`j = JSON(d)
o = j["$.o"]
kv = SPLIT_NAME_VALUES("b=2 a=x<y&z> Z=3 c=", " ", "=", "\\"")
rr.b$ = "x<y>&"
rr.a$ = 1
rr.Z$ = TRUE
rr.n$ = NULL
rr.l$ = [1, "q", NULL]
rr.t$ = DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00")
rr.g.h$ = "deep"
rr.j$ = j
rr.o$ = o
rr.kv$ = kv
rn.b$ = NULL
rn.a$ = "x"
kvs = STRING(kv)
listkv = STRING([kv])
rrs = STRING(rr)
listrr = STRING([rr])
rrg = STRING(rr.g)
rns = STRING(rn)
listrn = STRING([rn])`, { d });
  const kv = '{"Z":"3","a":"x\\u003cy\\u0026z\\u003e","b":"2","c":""}';
  const rr = `{"Z$":true,"a$":1,"b$":"x\\u003cy\\u003e\\u0026","g":{"h$":"deep"},"j$":{},"kv$":${kv},"l$":[1,"q",0],"n$":0,"o$":{"a":"x\\u003cy\\u0026z\\u003e","b":1,"c":[1,0]},"t$":{}}`;
  const want = { kvs: kv, listkv: `[${kv}]`, rrs: rr, listrr: `[${rr}]`, rrg: '{"h$":"deep"}', rns: '{"a$":"x","b$":0}', listrn: '[{"a$":"x","b$":0}]' };
  for (const [k, w] of Object.entries(want)) assert.equal(v.get(k), w, k);
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

test('text added to a DATETIME value must read as a number', () => {
  const T = 't = DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00")\nn = NULL\n';
  for (const add of ['"at " + t', 't + " at"', '"" + t', 't + " 5"', 't + "5 "', 't + "0x10"']) assert.throws(() => run(`${T}x = ${add}`), /unable to add: cannot convert time to string/, add);
  const usec = Date.UTC(2026, 9, 14, 1, 2, 3) * 1000;
  const v = run(`${T}a = "5" + t\nb = t + "-5"\nc = t + "+5"\nd = t + "1e3"\ne = t + "5.5"\nf = n + t\ng = t + 5\nh = STRING(t)`);
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'g'].map((k) => v.get(k)), [usec + 5, usec - 5, usec + 5, usec + 1000, usec + 5.5, usec + 5]);
  assert.equal(v.get('f').usec, usec);
  assert.equal(v.get('h'), '2026-10-14 01:02:03 +0000 UTC');
  // Text that isn't a DATETIME still joins as before.
  assert.deepEqual([get('x = "5" + "5"', 'x'), get('x = "a" + 5', 'x')], ['55', 'a5']);
});

// What the engine gave for each in a lab tenant.
test('a DATETIME value adds to another DATETIME or to TRUE as microseconds', () => {
  const v = run(`t = DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00")
u = DATETIME("1970-01-01T00:00:01.5Z", "2006-01-02T15:04:05Z07:00")
a = t + t
b = t + u
c = t + TRUE
d = TRUE + t
e = t + FALSE
f = FALSE + t
g = t + true
h = t - u
i = t - TRUE
k = IF (t + t) == 3583879446000000 THEN "number" ELSE "text"`);
  const usec = Date.UTC(2026, 9, 14, 1, 2, 3) * 1000;
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k'].map((x) => v.get(x)), [2 * usec, usec + 1500000, usec + 1, usec + 1, usec, usec, usec + 1, usec - 1500000, usec - 1, 'number']);
});

// What the engine gave for each in a lab tenant.
test('a number and TRUE or FALSE add as numbers', () => {
  const v = run(`jn = JSON(d)
a = 5 + TRUE
b = TRUE + 5
c = TRUE + TRUE
e = FALSE + FALSE
f = 5 + FALSE
g = -1 + TRUE
h = FALSE + TRUE
i = TRUE + -5
k = STRING(5 + TRUE)
l = STRING([TRUE + 0])
m = IF (5 + TRUE) == 6 THEN "number" ELSE "text"
n = STRING([(3 / 2) + TRUE])
o = STRING([jn["$.f"] + TRUE])
p = TRUE - TRUE
q = 5 * TRUE
r = "a" + TRUE
s = TRUE + "a"
t = STRING([TRUE + NULL])
u = STRING([[1] + TRUE])`, { d: '{"f":1.5,"n":5}' });
  const want = { a: 6, b: 6, c: 2, e: 0, f: 5, g: 0, h: 1, i: -4, k: '6', l: '[1]', m: 'number', n: '[2.5]', o: '[2.5]', p: 0, q: 5, r: 'atrue', s: 'truea', t: '[true]', u: '[[1,true]]' };
  for (const [k, w] of Object.entries(want)) assert.equal(v.get(k), w, k);
});

// What the engine gave for each in a lab tenant.
test('division gives a float, and % takes the whole part of each side', () => {
  const v = run(`jn = JSON(d)
a = STRING([3 / 2])
b = STRING([4 / 2])
c = STRING([-3 / 2])
e = STRING([1 / 3])
f = STRING([2 / 3])
g = STRING([10 / 4])
h = STRING([0 / 5])
i = STRING([0 / -1])
k = STRING([3 / -2])
l = STRING(3 / 2)
m = STRING(-3 / 2)
n = STRING(0 / -1)
o = STRING([(3 / 2) * 2])
p = STRING([(3 / 2) + 1])
q = STRING([(3 / 2) - 1])
r = STRING([1 / 1000000])
s = STRING([1 / 10000000])
t = STRING(["7" / "2"])
u = IF 3 / 2 > 1 THEN "gt" ELSE "le"
w = IF 3 / 2 == 1 THEN "eq1" ELSE "ne1"
x = IF (0 / -1) == 0 THEN "eq0" ELSE "ne0"
y = STRING([(1 / 3) * 3])
z = STRING([3 * 2 / 4])
a2 = STRING([2 / 4 * 4])
b2 = STRING([jn["$.n"] / 2])
c2 = STRING([6 / 3])
e2 = STRING([100000000 / 3])
f2 = STRING([(3 / 2) / 2])
g2 = STRING([(3 / 2) * 3])
h2 = STRING([(3 / 2) - (1 / 4)])
i2 = STRING([(7 / 2) % 2])
k2 = STRING([(7 / 2) % 3])
l2 = STRING([7 % (5 / 2)])
m2 = STRING([-7 % 2])
n2 = STRING([(-7 / 2) % 2])
o2 = STRING([(3 / 2) % 1])
p2 = STRING([7 % 2])
q2 = STRING((3 / 2) * 9223372036854775807)
r2 = STRING((-3 / 2) * 9223372036854775807)
s2 = STRING((1 / 2) * 9223372036854775807)
t2 = STRING((1000000000000 / 1) * 1000000000)
raw = 3 / 2
neg = -3 / 2
whole = 4 / 2`, { d: '{"f":1.5,"n":5}' });
  const want = {
    a: '[1.5]', b: '[2]', c: '[-1.5]', e: '[0.3333333333333333]', f: '[0.6666666666666666]', g: '[2.5]', h: '[0]', i: '[-0]', k: '[-1.5]',
    l: '1', m: '-1', n: '0', o: '[3]', p: '[2.5]', q: '[0.5]', r: '[0.000001]', s: '[1e-7]', t: '[3.5]', u: 'gt', w: 'ne1', x: 'eq0',
    y: '[1]', z: '[1.5]', a2: '[2]', b2: '[2.5]', c2: '[2]', e2: '[33333333.333333332]', f2: '[0.75]', g2: '[4.5]', h2: '[1.25]',
    i2: '[1]', k2: '[0]', l2: '[1]', m2: '[-1]', n2: '[-1]', o2: '[0]', p2: '[1]',
    q2: '-9223372036854775808', r2: '-9223372036854775808', s2: '4611686018427387904', t2: '-9223372036854775808', raw: 1.5, neg: -1.5, whole: 2,
  };
  for (const [k, x] of Object.entries(want)) assert.equal(v.get(k), x, k);
  // Dividing by zero fails the event ("division by 0").
  for (const div of ['5 / 0', '0 / 0', '5 / (0 / 1)', '(3 / 2) / 0']) assert.throws(() => run(`x = ${div}`), /division by zero/, div);
});

test('a path that can select several nodes but selects one gives that node', () => {
  const d = JSON.stringify({ arr: ['x'], arr2: ['x', 'y'], items: [{ k: 'a', v: 'va' }, { k: 'b', v: 'vb' }], o: { deep: 'd1' }, tags: [{ tag: 'a' }] });
  const v = run('json = JSON(d)\none = json["$.arr[*]"]\ns1 = STRING(one)\ns2 = STRING(json["$.items[?(@.k==\'a\')].v"])\ns3 = STRING(json["$..deep"])\ntwo = json["$.arr2[*]"]\npres = json["$.tags.*.tag|preserve_structure"]\nhit = IF one == "x" THEN "eq" ELSE "ne"', { d });
  assert.equal(v.get('one'), 'x');
  assert.deepEqual(['s1', 's2', 's3', 'hit'].map((k) => v.get(k)), ['x', 'va', 'd1', 'eq']);
  assert.deepEqual(v.get('two'), ['x', 'y']);
  // |preserve_structure keeps the list.
  assert.deepEqual(v.get('pres'), ['a']);
});

test('CEF resolves cs, cn, flexString and flexNumber labels and keeps \\n as two characters', () => {
  const line = 'CEF:0|Acme|Probe|1.0|100|probe|5|cs1=abc cs1Label=Name cn1=42 cn1Label=Count flexString1=fs flexString1Label=Flex flexNumber1=7 flexNumber1Label=FlexN cfp1=1.5 cfp1Label=Score c6a1=2001:db8::1 c6a1Label=V6 deviceCustomDate1=Oct 13 2026 10:00:00 deviceCustomDate1Label=When flexDate1=Oct 13 2026 10:00:00 flexDate1Label=FDate deviceCustomString2=dcs deviceCustomString2Label=LongS msg=line1\\nline2 back\\\\slash eq\\=sign cr\\rx pipe\\|here';
  const names = ['Name', 'Count', 'Flex', 'FlexN', 'Score', 'V6', 'When', 'FDate', 'LongS', 'cfp1', 'msg'];
  const v = run(`v = CEF(l)\n${names.map((n, i) => `o${i} = v["${n}"]`).join('\n')}`, { l: line });
  assert.deepEqual(names.map((n, i) => v.get(`o${i}`)), ['abc', '42', 'fs', '7', null, null, null, null, null, '1.5', 'line1\\nline2 back\\slash eq=sign cr\\rx pipe\\|here']);
});

test('SPLIT_NAME_VALUES gives a delimiter inside quotes back as a space', () => {
  const v = run('d = SPLIT_NAME_VALUES(s, ",", "=", "\\"")\nmsg = d["msg"]\nc = d["c"]\nf = d["f"]', { s: 'a=1,msg="x, y",b=2,c="p,q,r",f=" lead"' });
  assert.deepEqual([v.get('msg'), v.get('c'), v.get('f')], ['x  y', 'p q r', ' lead']);
  // With a space delimiter the value comes back as it was.
  assert.equal(get('d = SPLIT_NAME_VALUES(s, " ", "=", "\\"")\nc = d["c"]', 'c', { s: 'a=1 c="x,y  z"' }), 'x,y  z');
});

test('INT needs its base', () => {
  assert.throws(() => run('n = INT("42")'), /INT\(\) takes 2 arguments, got 1/);
});

test('a capture source can be an expression, but not a function call', () => {
  const v = run('m = a + b|^(\\w+)-\nfirst = m[1]\nj = JSON(d)\nn = j["$.mail"] |@(\\S+)$\ndomain = n[1]', { a: 'left', b: '-right', d: '{"mail":"jdoe@example.com"}' });
  assert.deepEqual([v.get('first'), v.get('domain')], ['left', 'example.com']);
  assert.throws(() => run('m = STRING(v)|(\\w+)', { v: 'x' }), /can't read/);
  // A string with a | as the first thing on the right is read as a capture source, which fails.
  assert.throws(() => run('x = "a|b"'), /read as a capture source/);
  assert.throws(() => run("r.value$ = 'a|b'"), /read as a capture source/);
  // After another string, after "(", or inside [...], a | stays part of the assignment.
  const w = run('a = "x" + "|"\nb = REPLACE(p, "|", "/")\nj = JSON(d)\nc = j["$[\'p|q\']"]', { p: 'a|b', d: '{"p|q":"pq"}' });
  assert.deepEqual([w.get('a'), w.get('b'), w.get('c')], ['x|', 'a/b', 'pq']);
});
