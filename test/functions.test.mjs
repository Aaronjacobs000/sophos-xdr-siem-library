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

// Each table holds an expression and what the engine gave for STRING([expression]) in a lab
// tenant, or null when the engine failed the event. wrap changes what is stored, and prelude
// sets variables the expressions read.
function engineTable(rows, { wrap = (expr) => `STRING([${expr}])`, prelude = '' } = {}) {
  for (const [expr, want] of rows) {
    const text = `${prelude}\nx = ${wrap(expr)}`;
    if (want === null) assert.throws(() => run(text), undefined, expr);
    else assert.equal(get(text, 'x'), want, expr);
  }
}

test('text that reads as a number adds to a number, TRUE or FALSE', () => {
  engineTable([
  ['"5" + 5', '[10]'],
  ['5 + "5"', '[10]'],
  ['" 5" + 5', '[" 55"]'],
  ['"5 " + 5', '["5 5"]'],
  ['"+5" + 5', '[10]'],
  ['"-5" + 5', '[0]'],
  ['"0x10" + 5', '["0x105"]'],
  ['"5.5" + 5', '[10.5]'],
  ['"1e3" + 5', '[1005]'],
  ['"abc" + 5', '["abc5"]'],
  ['"" + 5', '["5"]'],
  ['"5" + "5"', '["55"]'],
  ['"inf" + 5', '["inf5"]'],
  ['"NaN" + 5', '["NaN5"]'],
  ['"1_000" + 5', '[1005]'],
  ['"9007199254740993" + 0', '[9007199254740992]'],
  ['"9223372036854775807" + 0', '[9223372036854776000]'],
  ['"5" + TRUE', '[6]'],
  ['".5" + 5', '[5.5]'],
  ['"5." + 5', '[10]'],
  ['"0x1p4" + 5', '[21]'],
  ['"1e400" + 5', '["1e4005"]'],
  ['"\\t5" + 5', '["\\t55"]'],
  ['"5" + (3 / 2)', '[6.5]'],
  ['"Infinity" + 5', '["Infinity5"]'],
  ['"5e" + 5', '["5e5"]'],
  ['"1,000" + 5', '["1,0005"]'],
  ['TRUE + "5"', '[6]'],
  ['"5" + FALSE', '[5]'],
  ['"-0" + 0', '[0]'],
  ['"1E3" + 5', '[1005]'],
  ['"0b101" + 5', '["0b1015"]'],
  ['"0o17" + 5', '["0o175"]'],
  ['"5" + 9223372036854775807', '[9223372036854776000]'],
  ['5 + "abc"', '["5abc"]'],
  ['"-" + 5', '["-5"]'],
  ['"1e3" + "1"', '["1e31"]'],
  ['"5" + NULL', '["5"]'],
  ['"+Inf" + 5', '["+Inf5"]'],
  ['"nan" + 5', '["nan5"]'],
  ['"5" + [1]', '[["5",1]]'],
  ['"1__0" + 0', '["1__00"]'],
  ['"_1" + 0', '["_10"]'],
  ['"1_" + 0', '["1_0"]'],
  ['"0x_1p4" + 0', '[16]'],
  ['"1e1_0" + 0', '[10000000000]'],
  ['"0x1.8p1" + 0', '[3]'],
  ['"0X1P4" + 0', '[16]'],
  ['"1E+3" + 0', '[1000]'],
  ['"+.5e1" + 0', '[5]'],
  ['"-0x1p4" + 0', '[-16]'],
  ['"0x1p" + 0', '["0x1p0"]'],
  ['"0xp4" + 0', '["0xp40"]'],
  ['"0x.8p1" + 0', '[1]'],
  ['"1e-400" + 0', '[0]'],
  ['"5" + JSON("{\\"n\\":5}")["$.n"]', '[10]'],
  ['"1.5e2" == 150', '[true]'],
  ['" " == ""', '[false]'],
  ['"5" + "5" + 5', '[60]'],
  ['5 + "5" + "5"', '[15]'],
  ['TRUE + TRUE + "a"', '["2a"]'],
  ]);
});

test('-, *, / and % read text the way Go\'s ParseFloat does, and fail on text it can\'t read', () => {
  engineTable([
  ['"5" - 2', '[3]'],
  ['"5" * 2', '[10]'],
  ['"5" / 2', '[2.5]'],
  ['"7" % 2', '[1]'],
  ['" 5" - 2', null], // fails: invalid syntax
  ['"0x10" - 1', null], // fails: invalid syntax
  ['"" - 1', null], // fails: invalid syntax
  ['"abc" - 1', null], // fails: invalid syntax
  ['"1_000" - 1', '[999]'],
  ['"1e3" - 1', '[999]'],
  ['"5" - TRUE', '[4]'],
  ['TRUE - "5"', '[-4]'],
  ['"5" * TRUE', '[5]'],
  ['"9007199254740993" - 0', '[9007199254740992]'],
  ['9007199254740993 - "0"', '[9007199254740992]'],
  ['"0x1p4" - 1', '[15]'],
  ['"5" - "2"', '[3]'],
  ['"inf" - 1', null], // fails: numeric value is not finite
  ['"5.5" % 2', '[1]'],
  ['"7" % "2"', '[1]'],
  ['TRUE * TRUE', '[1]'],
  ['TRUE - 1', '[0]'],
  ['9223372036854775807 - TRUE', '[9223372036854776000]'],
  ['9223372036854775807 * TRUE', '[9223372036854776000]'],
  ['"5" / "2"', '[2.5]'],
  ['NULL - 1', null], // fails: cannot convert null to int
  ['"" * 2', null], // fails: invalid syntax
  ['"5 " - 1', null], // fails: invalid syntax
  ['"1e400" - 1', null], // fails: value out of range
  ['"5" * "2"', '[10]'],
  ]);
});

test('comparisons read numbers, TRUE, FALSE and numeric text as floats, and anything else as text', () => {
  engineTable([
  ['"10" > 9', '[true]'],
  ['"10" > "9"', '[true]'],
  ['" 10" > 9', '[false]'],
  ['"abc" > 5', '[true]'],
  ['"abc" < "abd"', '[true]'],
  ['"5" == 5', '[true]'],
  ['"5.0" == 5', '[true]'],
  ['" 5" == 5', '[false]'],
  ['"0x5" == 5', '[false]'],
  ['TRUE == 1', '[true]'],
  ['TRUE == "true"', '[true]'],
  ['"1e1" == 10', '[true]'],
  ['"10" < (19 / 2)', '[false]'],
  ['"1_0" == 10', '[true]'],
  ['"1_0" > 9', '[true]'],
  ['"b" > "a"', '[true]'],
  ['"10" >= "9"', '[true]'],
  ['TRUE > FALSE', '[true]'],
  ['TRUE > 0', '[true]'],
  ['"5" != 5', '[false]'],
  ['"" == 0', '[false]'],
  ['"" < 1', '[true]'],
  ['"0x1p4" == 16', '[true]'],
  ['"0x1p4" > 15', '[true]'],
  ['5 == "5.0"', '[true]'],
  ['"abc" == 5', '[false]'],
  ['"9007199254740993" == 9007199254740992', '[true]'],
  ['9007199254740993 == 9007199254740992', '[true]'],
  ['"TRUE" == TRUE', '[false]'],
  ['" 10" > "9"', '[false]'],
  ['"abc" > "5"', '[true]'],
  ['"inf" > 5', '[true]'],
  ['"5" < 10', '[true]'],
  ['(3 / 2) == "1.5"', '[true]'],
  ['"1" == TRUE', '[true]'],
  ['"true" == TRUE', '[true]'],
  ['"1.0" == TRUE', '[true]'],
  ['FALSE == 0', '[true]'],
  ['FALSE == ""', '[false]'],
  ['FALSE == "false"', '[true]'],
  ['FALSE == "0"', '[true]'],
  ['TRUE == 2', '[false]'],
  ['"5" == "5.0"', '[true]'],
  ['"10" == "1e1"', '[true]'],
  ['TRUE == TRUE', '[true]'],
  ['"abc" == "abc"', '[true]'],
  ['(10 / 2) == 5', '[true]'],
  ['"0x1p4" == "16"', '[true]'],
  ['TRUE != "TRUE"', '[true]'],
  ['1 == "1 "', '[false]'],
  ['TRUE == "True"', '[false]'],
  ['"5" != "5.0"', '[false]'],
  ['"-0" == 0', '[true]'],
  ['"+5" == 5', '[true]'],
  ['"" == ""', '[true]'],
  ['"1_0" == "10"', '[true]'],
  ['9223372036854775807 == 9223372036854775806', '[true]'],
  ['NULL == 0', '[false]'],
  ['NULL == FALSE', '[false]'],
  ['"1e400" == 5', '[false]'],
  ['"inf" == "inf"', '[true]'],
  ['TRUE < 2', '[true]'],
  ['FALSE < "a"', '[false]'],
  ['"5" < "10"', '[true]'],
  ['"-5" < "1"', '[true]'],
  ['"0x1p4" > "15"', '[true]'],
  ['"1_000" > "999"', '[true]'],
  ['TRUE > "0"', '[true]'],
  ['"abc" < 5', '[false]'],
  ['"-inf" > -5', '[true]'],
  ['"NaN" > 5', '[true]'],
  ['9007199254740993 > 9007199254740992', '[false]'],
  ['9223372036854775807 > 9223372036854775806', '[false]'],
  ['(3 / 2) > "1.4"', '[true]'],
  ['"1e400" > 5', '[false]'],
  ['"5" < TRUE', '[false]'],
  ['"10" > " 9"', '[true]'],
  ['"b" > TRUE', '[false]'],
  ['"-1" < "-2"', '[false]'],
  ]);
});

test('every number is a float64, and % converts each side to int64', () => {
  engineTable([
  ['9223372036854775807', '[9223372036854776000]'],
  ['9007199254740993', '[9007199254740992]'],
  ['9223372036854775807 + 0', '[9223372036854776000]'],
  ['9223372036854775807 + 1', '[9223372036854776000]'],
  ['9223372036854775807 - 1', '[9223372036854776000]'],
  ['-9223372036854775807 - 2', '[-9223372036854776000]'],
  ['-9223372036854775808', '[-9223372036854776000]'],
  ['9007199254740993 * 1', '[9007199254740992]'],
  ['3037000500 * 3037000500', '[9223372037000250000]'],
  ['4611686018427387904 * 2', '[9223372036854776000]'],
  ['1000000000000 * 1000000000', '[1e+21]'],
  ['4611686018427387903 * 2', '[9223372036854776000]'],
  ['3037000499 * 3037000499', '[9223372030926249000]'],
  ['9007199254740993 + 2', '[9007199254740994]'],
  ['(6 / 2) * 3074457345618258603', '[9223372036854776000]'],
  ['(1000000000000 / 1) * 1000000000', '[1e+21]'],
  ['LENGTH("abc") * 3074457345618258603', '[9223372036854776000]'],
  ['9223372036854775807 % 10', '[-8]'],
  ['9007199254740993 % 10', '[2]'],
  ['-9223372036854775807 - 1 - 1', '[-9223372036854776000]'],
  ['INT("9223372036854775807", 10)', '[9223372036854776000]'],
  ['INT("9007199254740993", 10) + 0', '[9007199254740992]'],
  ['9007199254740993 / 1', '[9007199254740992]'],
  ['9223372036854775807 * 1', '[9223372036854776000]'],
  ['-9223372036854775807 * 2', '[-18446744073709552000]'],
  ['2147483647 * 2147483647', '[4611686014132420600]'],
  ['9007199254740993 - 0', '[9007199254740992]'],
  ['123456789012345678 + 0', '[123456789012345680]'],
  ['123456789012345678 * 1', '[123456789012345680]'],
  ['123456789012345678 - 1', '[123456789012345680]'],
  ['123456789012345678 * 2', '[246913578024691360]'],
  ['123456789012345678', '[123456789012345680]'],
  ['-123456789012345678', '[-123456789012345680]'],
  ['-9223372036854775807 - 1', '[-9223372036854776000]'],
  ['INT("-9223372036854775808", 10)', '[-9223372036854776000]'],
  ['123456789012345678 % 1000', '[680]'],
  ['-1 * 9223372036854775807 * 2', '[-18446744073709552000]'],
  ['9223372036854775807 * -1', '[-9223372036854776000]'],
  ['4611686018427387904 * -2', '[-9223372036854776000]'],
  ['1000000000000 * -1000000000', '[-1e+21]'],
  ['9223372036854775807 + 9223372036854775807', '[18446744073709552000]'],
  ['1 / 3', '[0.3333333333333333]'],
  ['2 / 3', '[0.6666666666666666]'],
  ['1 / 10000000', '[1e-7]'],
  ['0 / -1', '[-0]'],
  ['1 / 1000000000000000000', '[1e-18]'],
  ['(1 / 1000000000000000000) / 1000000000000000000', '[1.0000000000000001e-36]'],
  ['(1000000000000000000 / 1) * 1000000000000000000', '[1e+36]'],
  ['(1 / 10) + (2 / 10)', '[0.30000000000000004]'],
  ['-1 / 3', '[-0.3333333333333333]'],
  ['-1 / 10000000', '[-1e-7]'],
  ['4 / 2', '[2]'],
  ['(3 / 2) * 1000000000000', '[1500000000000]'],
  ['123456789 / 1000', '[123456.789]'],
  ['1 / 1024', '[0.0009765625]'],
  ['(100000000000 / 1) * 1000000000', '[100000000000000000000]'],
  ['9007199254740992 / 1', '[9007199254740992]'],
  ['9223372036854775807 / 1', '[9223372036854776000]'],
  ['JSON("{\\"a\\":1e-7}")["$.a"]', '[1e-7]'],
  ['JSON("{\\"a\\":1e21}")["$.a"]', '[1e+21]'],
  ['JSON("{\\"a\\":12345678901234567890}")["$.a"]', '[12345678901234567000]'],
  ['JSON("{\\"a\\":5}")["$.a"]', '[5]'],
  ['JSON("{\\"a\\":-0.0}")["$.a"]', '[-0]'],
  ['1 / 7', '[0.14285714285714285]'],
  ['(1 / 1000000) * 1', '[0.000001]'],
  ['1 / 100000', '[0.00001]'],
  ['(-3 / 2) * 1000000000000000000000', '[-1.5e+21]'],
  ['5 % 0', null], // fails: modulo by zero
  ['5 % (1 / 2)', null], // fails: modulo by zero
  ['(1 / 2) % 5', '[0]'],
  ['-7 % 3', '[-1]'],
  ['9223372036854775807 % 9223372036854775807', '[0]'],
  ['(-9223372036854775807 - 1) % -1', '[0]'],
  ['DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00") + 9223372036854775807', '[9225163976577776000]'],
  ['DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00") * 1000000', '[1.791939723e+21]'],
  ['DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00") - 9223372036854775807', '[-9221580097131776000]'],
  ['[9223372036854775807] + "a"', '[[9223372036854776000,"a"]]'],
  ['DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00") + 1', '[1791939723000001]'],
  ['DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00") * 1', '[1791939723000000]'],
  ['STRING(DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00") * 1000000)', '["-9223372036854775808"]'],
  ['9223372036854775807 % 1', '[0]'],
  ['-0', '[-0]'],
  ['7 % -3', '[1]'],
  ]);
  // STRING() of a number converts it to int64: the whole part in full, or the minimum int64.
  const v = run(`a = STRING(9223372036854775807)
b = STRING(3037000499 * 3037000499)
c = STRING(2147483647 * 2147483647)
d = STRING(9007199254740993 + 2)
e = STRING(-9223372036854775807 - 1)
f = STRING((1 / 2) * 9223372036854775807)`);
  assert.deepEqual(['a', 'b', 'c', 'd', 'e', 'f'].map((k) => v.get(k)), ['-9223372036854775808', '9223372030926248960', '4611686014132420608', '9007199254740994', '-9223372036854775808', '4611686018427387904']);
});

test('SPLIT() reads its text as CSV, with the first character of the separator', () => {
  engineTable([
  ['SPLIT("a::b::c", "::")', '[["a","","b","","c"]]'],
  ['SPLIT("a,b;c", ",;")', '[["a","b;c"]]'],
  ['SPLIT("abc", "")', null], // fails: invalid field or comment delimiter
  ['SPLIT("a,\\"b,c\\",d", ",")', '[["a","b,c","d"]]'],
  ['SPLIT("a b \\"c d\\" e", " ")', '[["a","b","c d","e"]]'],
  ['SPLIT("a,b\\nc,d", ",")', '[["a","b","c","d"]]'],
  ['SPLIT("aébéc", "é")', '[["a","b","c"]]'],
  ['SPLIT("a→b→c", "→x")', '[["a","b","c"]]'],
  ['SPLIT("a::b::c", "::", TRUE)', '[["a","b","c"]]'],
  ['SPLIT(" a , b ", ",")', '[[" a "," b "]]'],
  ['SPLIT("a\\"b,c", ",")', '[["a\\"b","c"]]'],
  ['SPLIT("", ",")', '[[]]'],
  ['SPLIT("a,b,", ",")', '[["a","b",""]]'],
  ['SPLIT("a|b", "|")', '[["a","b"]]'],
  ['SPLIT("a\\tb", "\\t")', '[["a","b"]]'],
  ['SPLIT("a\\nb", "\\n")', null], // fails: invalid field or comment delimiter
  ['SPLIT("a\\"b\\"c", "\\"")', null], // fails: invalid field or comment delimiter
  ['SPLIT(12345, "3")', '[["12","45"]]'],
  ['SPLIT("a,,b", ",", TRUE)', '[["a","b"]]'],
  ['SPLIT("\\"a,b\\"", ",")', '[["a,b"]]'],
  ['SPLIT("x;y", ";;")', '[["x","y"]]'],
  ['SPLIT("aXbxc", "x")', '[["aXb","c"]]'],
  ['SPLIT("a,b", NULL)', null], // fails: invalid field or comment delimiter
  ['SPLIT("a,b", ",", FALSE)', '[["a","b"]]'],
  ['SPLIT("a😀b😀c", "😀")', '[["a","b","c"]]'],
  ['SPLIT("ab", "")', null], // fails: invalid field or comment delimiter
  ['SPLIT("a", ",")', '[["a"]]'],
  ['SPLIT("a,b", 5)', '[["a,b"]]'],
  ['SPLIT("a5b", 5)', '[["a","b"]]'],
  ['SPLIT("a b  c", " ")', '[["a","b","","c"]]'],
  ['SPLIT("a b  c", " ", TRUE)', '[["a","b","c"]]'],
  ['SPLIT("a::b", ":::")', '[["a","","b"]]'],
  ['SPLIT("é", "")', null], // fails: invalid field or comment delimiter
  ['SPLIT("a😀b", "😀x")', '[["a","b"]]'],
  ['SPLIT("a\\\\b", "\\\\")', '[["a","b"]]'],
  ['SPLIT("a,b\\nc", ",")', null], // fails: wrong number of fields
  ['SPLIT("a\\n\\nb", ",")', '[["a","b"]]'],
  ['SPLIT("\\"a\\"\\"b\\",c", ",")', '[["a\\"b","c"]]'],
  ['SPLIT("\\"a\\"b,c", ",")', '[["a\\"b,c"]]'],
  ['SPLIT("\\"a,b", ",")', '[["a,b"]]'],
  ['SPLIT("x\\"a\\"", ",")', '[["x\\"a\\""]]'],
  ['SPLIT("\\"a\\nb\\",c", ",")', '[["a\\nb","c"]]'],
  ['SPLIT(" \\"a,b\\"", ",")', '[[" \\"a","b\\""]]'],
  ['SPLIT("\\"\\"", ",")', '[[""]]'],
  ['SPLIT(",", ",")', '[["",""]]'],
  ['SPLIT("\\n", ",")', '[[]]'],
  ['SPLIT("a\\n", ",")', '[["a"]]'],
  ['SPLIT("a,b\\nc,d,e", ",")', null], // fails: wrong number of fields
  ['SPLIT("\\"a\\" ,b", ",")', '[["a\\" ,b"]]'],
  ['SPLIT("\\"a\\"x\\"y\\",b", ",")', '[["a\\"x\\"y","b"]]'],
  ['SPLIT("a b", " ", "yes")', '[["a","b"]]'],
  ['SPLIT(" ", ",")', '[[" "]]'],
  ['SPLIT("a,b", ",", 1)', '[["a","b"]]'],
  ['SPLIT("a;b", ";")', '[["a","b"]]'],
  ['SPLIT("a,\\"\\",b", ",")', '[["a","","b"]]'],
  ['SPLIT("\\"a\\"", ",", TRUE)', '[["a"]]'],
  ['SPLIT("a\\n\\"b\\nc\\"", ",")', '[["a","b\\nc"]]'],
  ['SPLIT("\\"a\\"\\"", ",")', '[["a\\""]]'],
  ['SPLIT("a\\nb,c", ",")', null], // fails: wrong number of fields
  ]);
});

test('STRING() writes the value JSON() returned as JSON whatever it holds', () => {
  engineTable([
  ['JSON("\\"s<\\"")', '"s\\u003c"'],
  ['JSON("5")', '5'],
  ['JSON("1.5")', '1.5'],
  ['JSON("true")', 'true'],
  ['JSON("null")', 'null'],
  ['JSON("\\"a\\\\u00e9\\\\n\\"")', '"aé\\n"'],
  ['JSON("1e21")', '1e+21'],
  ['JSON("-0")', '-0'],
  ['JSON("{\\"a\\":\\"s<\\"}")["$.a"]', 's<'],
  ['JSON("[\\"s<\\"]")["$[0]"]', 's<'],
  ['JSON("\\"\\"")', '""'],
  ['JSON(" \\"x\\" ")', '"x"'],
  ['JSON("12345678901234567890")', '12345678901234567000'],
  ['JSON("\\"a&b\\"")', '"a\\u0026b"'],
  ['JSON("false")', 'false'],
  ['JSON("\\"a\\\\\\"b\\"")', '"a\\"b"'],
  ['JSON("\\"s<\\"")["$"]', 's<'],
  ['JSON("1e-7")', '1e-7'],
  ['JSON("{\\"a\\":\\"s<\\"}")["a"]', 's<'],
  ['JSON("\\"\\\\u2028\\"")', '"\\u2028"'],
  ['LENGTH(STRING(JSON("\\"abc\\"")))', '5'],
  ], { wrap: (expr) => `STRING(${expr})` });
});

test('URL_PARSE() has raw, password only when the URL has one, and "" for a missing part', () => {
  engineTable([
  ['URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag")', '[{"fragment":"frag","host":"example.com","host_raw":"example.com:8443","password":"pass","path":"/a/b","path_raw":"/a/b","port":"8443","query":"x=1\\u0026y=2","query_raw":"x=1\\u0026y=2","raw":"https://user:pass@example.com:8443/a/b?x=1\\u0026y=2#frag","scheme":"https","user":"user"}]'],
  ['URL_PARSE("https://user@example.com/")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/","path_raw":"/","port":"","query":"","query_raw":"","raw":"https://user@example.com/","scheme":"https","user":"user"}]'],
  ['URL_PARSE("http://example.com")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"","path_raw":"","port":"","query":"","query_raw":"","raw":"http://example.com","scheme":"http","user":""}]'],
  ['URL_PARSE("example.com/p")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/p","path_raw":"/p","port":"","query":"","query_raw":"","raw":"example.com/p","scheme":"http","user":""}]'],
  ['URL_PARSE("https://example.com/p?q=1#")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/p","path_raw":"/p","port":"","query":"q=1","query_raw":"q=1","raw":"https://example.com/p?q=1#","scheme":"https","user":""}]'],
  ['URL_PARSE("https://example.com:443")', '[{"fragment":"","host":"example.com","host_raw":"example.com:443","path":"","path_raw":"","port":"443","query":"","query_raw":"","raw":"https://example.com:443","scheme":"https","user":""}]'],
  ['URL_PARSE("https://[2001:db8::1]:8080/x")', '[{"fragment":"","host":"2001:db8::1","host_raw":"[2001:db8::1]:8080","path":"/x","path_raw":"/x","port":"8080","query":"","query_raw":"","raw":"https://[2001:db8::1]:8080/x","scheme":"https","user":""}]'],
  ['URL_PARSE("", TRUE)', '[{"fragment":"","host":"","host_raw":"","path":"","path_raw":"","port":"","query":"","query_raw":"","raw":"","scheme":"http","user":""}]'],
  ['URL_PARSE("https://user:@example.com/")', '[{"fragment":"","host":"example.com","host_raw":"example.com","password":"","path":"/","path_raw":"/","port":"","query":"","query_raw":"","raw":"https://user:@example.com/","scheme":"https","user":"user"}]'],
  ['URL_PARSE("https://:pass@example.com/")', '[{"fragment":"","host":"example.com","host_raw":"example.com","password":"pass","path":"/","path_raw":"/","port":"","query":"","query_raw":"","raw":"https://:pass@example.com/","scheme":"https","user":""}]'],
  ['URL_PARSE(NULL, TRUE)', '[{"fragment":"","host":"","host_raw":"","path":"","path_raw":"","port":"","query":"","query_raw":"","raw":"","scheme":"http","user":""}]'],
  ['URL_PARSE("HTTPS://EXAMPLE.COM/A?B=C")', '[{"fragment":"","host":"example.com","host_raw":"EXAMPLE.COM","path":"/A","path_raw":"/A","port":"","query":"B=C","query_raw":"B=C","raw":"HTTPS://EXAMPLE.COM/A?B=C","scheme":"https","user":""}]'],
  ['URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag")["user"]', '["user"]'],
  ['URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag")["password"]', '["pass"]'],
  ['URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag")["raw_query"]', '[0]'],
  ['URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag")["raw"]', '["https://user:pass@example.com:8443/a/b?x=1\\u0026y=2#frag"]'],
  ['URL_PARSE("http://example.com")["port"]', '[""]'],
  ['URL_PARSE("http://example.com")["user"]', '[""]'],
  ['URL_PARSE("http://example.com")["fragment"]', '[""]'],
  ['URL_PARSE("http://example.com")["query"]', '[""]'],
  ['URL_PARSE("http://example.com")["path"]', '[""]'],
  ['LENGTH(URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag"))', '[12]'],
  ['OBJKEYS(URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag"))', '[["fragment","host","host_raw","password","path","path_raw","port","query","query_raw","raw","scheme","user"]]'],
  ['IF URL_PARSE("http://example.com")["port"] == NULL THEN "eqnull" ELSE "ne"', '["eqnull"]'],
  ['URL_PARSE("http://example.com")["raw_query"] == NULL', '[true]'],
  ['OBJVALUES(URL_PARSE("http://example.com"))', '[["","example.com","example.com","","","","","","http://example.com","http",""]]'],
  ['URL_PARSE("http://example.com")["path_raw"]', '[""]'],
  ['LENGTH(URL_PARSE("http://example.com")["port"])', '[0]'],
  ['OBJVALUES(URL_PARSE("https://user:pass@example.com:8443/a/b?x=1&y=2#frag"))', '[["frag","example.com","example.com:8443","pass","/a/b","/a/b","8443","x=1\\u0026y=2","x=1\\u0026y=2","https://user:pass@example.com:8443/a/b?x=1\\u0026y=2#frag","https","user"]]'],
  ]);
});

test('CEF() and LEEF() hold their header fields under the keys "0" and on', () => {
  engineTable([
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")', '[{"0":"CEF:0","1":"Vend","2":"Prod","3":"1.0","4":"100","5":"Name\\u003cx\\u003e","6":"5","act":"b\\u003cx\\u003e","dst":"10.0.0.2","src":"10.0.0.1"}]'],
  ['CEF("Nov 6 07:49:03 192.0.2.1 %hello: CEF:0|Check Point|VPN \\\\| x|R81|Log|Spoof|Unknown|act=Drop cs3Label=Protection Type cs3=IPS")', '[{"0":"CEF:0","1":"Check Point","2":"VPN \\\\| x","3":"R81","4":"Log","5":"Spoof","6":"Unknown","Protection Type":"IPS","act":"Drop","cs3":"IPS","cs3Label":"Protection Type"}]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")[0]', '["CEF:0"]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")["0"]', '["CEF:0"]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")[6]', '["5"]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")["6"]', '["5"]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")["7"]', '[0]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")[7]', '[0]'],
  ['LENGTH(CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2"))', '[10]'],
  ['OBJKEYS(CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2"))', '[["0","1","2","3","4","5","6","act","dst","src"]]'],
  ['OBJVALUES(CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2"))', '[["CEF:0","Vend","Prod","1.0","100","Name\\u003cx\\u003e","5","b\\u003cx\\u003e","10.0.0.2","10.0.0.1"]]'],
  ['CEF("Nov 6 07:49:03 192.0.2.1 %hello: CEF:0|Check Point|VPN \\\\| x|R81|Log|Spoof|Unknown|act=Drop cs3Label=Protection Type cs3=IPS")["Protection Type"]', '["IPS"]'],
  ['CEF("Nov 6 07:49:03 192.0.2.1 %hello: CEF:0|Check Point|VPN \\\\| x|R81|Log|Spoof|Unknown|act=Drop cs3Label=Protection Type cs3=IPS")["2"]', '["VPN \\\\| x"]'],
  ['CEF("CEF:0|V|P|1|100|N|5|0=x 1=y")', '[{"0":"x","1":"y","2":"P","3":"1","4":"100","5":"N","6":"5"}]'],
  ['CEF("CEF:0|V|P|1|100|N|5|0=x 1=y")[0]', '["x"]'],
  ['CEF("CEF:0|V|P|1|100|N|5|")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100","5":"N","6":"5"}]'],
  ['LENGTH(CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2"), "keys")', '[10]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")["-1"]', '[0]'],
  ['CEF("CEF:0|Vend|Prod|1.0|100|Name<x>|5|src=10.0.0.1 act=b<x> dst=10.0.0.2")[-1]', '[0]'],
  ['CEF("CEF:0|V|P|1|100|N|5|0=x 1=y")["0"]', '["x"]'],
  ['LEEF("LEEF:1.0|Vend|Prod|1.0|Evt1|src=1.2.3.4\\tdst=5.6.7.8")', '[{"0":"LEEF:1.0","1":"Vend","2":"Prod","3":"1.0","4":"Evt1","dst":"5.6.7.8","src":"1.2.3.4"}]'],
  ['LEEF("LEEF:2.0|Vend|Prod|1.0|Evt2|^|src=1.2.3.4^dst=5.6.7.8")', '[{"0":"LEEF:2.0","1":"Vend","2":"Prod","3":"1.0","4":"Evt2","5":"^","dst":"5.6.7.8","src":"1.2.3.4"}]'],
  ['LEEF("LEEF:1.0|Vend|Prod|1.0|Evt1|src=1.2.3.4\\tdst=5.6.7.8")["0"]', '["LEEF:1.0"]'],
  ['LEEF("LEEF:1.0|Vend|Prod|1.0|Evt1|src=1.2.3.4\\tdst=5.6.7.8")[0]', '["LEEF:1.0"]'],
  ['LENGTH(LEEF("LEEF:1.0|Vend|Prod|1.0|Evt1|src=1.2.3.4\\tdst=5.6.7.8"))', '[7]'],
  ['OBJKEYS(LEEF("LEEF:2.0|Vend|Prod|1.0|Evt2|^|src=1.2.3.4^dst=5.6.7.8"))', '[["0","1","2","3","4","5","dst","src"]]'],
  ]);
});

test('NOT binds looser than + and tighter than comparisons, and follows the engine\'s truth rules', () => {
  engineTable([
  ['NOT TRUE', '[false]'],
  ['NOT FALSE', '[true]'],
  ['NOT ""', '[true]'],
  ['NOT "false"', '[true]'],
  ['NOT "abc"', '[false]'],
  ['NOT 0', '[true]'],
  ['NOT 1', '[false]'],
  ['NOT NULL', '[true]'],
  ['NOT []', '[true]'],
  ['NOT [1]', '[false]'],
  ['NOT [1, 2]', null], // fails: cannot convert list to bool
  ['NOT 1 == 2', '[false]'],
  ['NOT TRUE AND FALSE', '[false]'],
  ['NOT FALSE AND FALSE', '[false]'],
  ['NOT TRUE OR TRUE', '[true]'],
  ['NOT 0 > 1', '[false]'],
  ['NOT "a" + "b"', '[false]'],
  ['NOT NOT TRUE', '[true]'],
  ['NOT(FALSE)', '[true]'],
  ['IF NOT FALSE THEN "y" ELSE "n"', '["y"]'],
  ['TRUE AND NOT FALSE', '[true]'],
  ['NOT (1 / 2)', '[false]'],
  ['NOT " "', '[false]'],
  ['NOT "0"', '[false]'],
  ['NOT "FALSE"', '[true]'],
  ['NOT JSON("[]")', null], // fails: cannot convert json to bool
  ['NOT SPLIT("a", ",")', '[false]'],
  ['NOT 1 + 1', '[false]'],
  ['NOT "False"', '[true]'],
  ['NOT [0]', '[true]'],
  ['NOT JSON("{}")', null], // fails: cannot convert json to bool
  ['NOT [""]', '[true]'],
  ['NOT "true"', '[false]'],
  ['NOT -1', '[false]'],
  ['NOT FALSE == FALSE', '[false]'],
  ['FALSE OR NOT FALSE AND FALSE', '[false]'],
  ['NOT JSON("{\\"a\\":0}")["$.a"]', '[true]'],
  ['NOT JSON("null")', null], // fails: cannot convert json to bool
  ['NOT DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00")', '[false]'],
  ['NOT JSON("[1,2]")', null], // fails: cannot convert json to bool
  ['NOT [NULL]', '[true]'],
  ['NOT URL_PARSE("http://a.com")', '[false]'],
  ['IF " " THEN "y" ELSE "n"', '["y"]'],
  ['IF JSON("[]") THEN "y" ELSE "n"', null], // fails: cannot convert json to bool
  ['IF JSON("{}") THEN "y" ELSE "n"', null], // fails: cannot convert json to bool
  ['IF j["$.o"] THEN "y" ELSE "n"', '["y"]'],
  ['IF j["$.e"] THEN "y" ELSE "n"', '["n"]'],
  ['IF j["$.a0"] THEN "y" ELSE "n"', '["n"]'],
  ['IF j["$.a1"] THEN "y" ELSE "n"', '["n"]'],
  ['IF j["$.s"] THEN "y" ELSE "n"', '["y"]'],
  ['IF " false " THEN "y" ELSE "n"', '["y"]'],
  ['IF JSON("null") THEN "y" ELSE "n"', null], // fails: cannot convert json to bool
  ['IF JSON("0") THEN "y" ELSE "n"', null], // fails: cannot convert json to bool
  ['NOT j["$.o"]', '[false]'],
  ['NOT j["$.e"]', '[true]'],
  ['NOT j["$.a2"]', null], // fails: cannot convert list to bool
  ['NOT j["$.a0"]', '[true]'],
  ['NOT j["$.a1"]', '[true]'],
  ['NOT j["$.s"]', '[false]'],
  ['NOT " false "', '[false]'],
  ['NOT JSON("0")', null], // fails: cannot convert json to bool
  ['NOT "\\tx"', '[false]'],
  ['NOT j', null], // fails: cannot convert json to bool
  ['TRUE AND " "', '[true]'],
  ['" " OR FALSE', '[true]'],
  ['NOT 5 * 0', '[true]'],
  ['NOT 1 - 1', '[true]'],
  ['5 + NOT TRUE', '[5]'],
  ['5 + NOT TRUE + 1', '[5]'],
  ['NOT TRUE + 1', '[false]'],
  ['[NOT FALSE, NOT TRUE]', '[[true,false]]'],
  ['STRING(NOT FALSE)', '["true"]'],
  ['NOT IF TRUE THEN FALSE ELSE TRUE', '[true]'],
  ['NOT 1 != 2', '[true]'],
  ['NOT CEF("CEF:0|V|P|1|100|N|5|a=b")', '[false]'],
  ['NOT SPLIT_NAME_VALUES("a=1", " ", "=", "\\"")', '[false]'],
  ['NOT r', '[false]'],
  ['NOT "\\n"', '[false]'],
  ['NOT [" "]', '[false]'],
  ['IF [" "] THEN "y" ELSE "n"', '["y"]'],
  ['NOT "fAlSe"', '[false]'],
  ['NOT [JSON("{}")]', null], // fails: cannot convert json to bool
  ['IF [""] THEN "y" ELSE "n"', '["n"]'],
  ['NOT ["false"]', '[true]'],
  ['NOT [" false "]', '[false]'],
  ['NOT [TRUE]', '[false]'],
  ['NOT "f"', '[false]'],
  ['NOT "F"', '[false]'],
  ['NOT "fALSE"', '[false]'],
  ['NOT "falsE"', '[false]'],
  ['NOT "False "', '[false]'],
  ['NOT "no"', '[false]'],
  ['NOT "off"', '[false]'],
  ['NOT "nil"', '[false]'],
  ['NOT "null"', '[false]'],
  ['NOT "FaLsE"', '[false]'],
  ['NOT "0.0"', '[false]'],
  ['NOT "false\\n"', '[false]'],
  ['IF "fAlSe" THEN "y" ELSE "n"', '["y"]'],
  ['NOT [[1, 2]]', null], // fails: cannot convert list to bool
  ['NOT [[]]', '[true]'],
  ['NOT [[0]]', '[true]'],
  ], { prelude: 'j = JSON("{\\"o\\":{\\"k\\":1},\\"e\\":{},\\"a2\\":[1,2],\\"a0\\":[],\\"a1\\":[0],\\"z\\":0,\\"s\\":\\" \\"}")' + '\nr.k$ = 1' });
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

test('NULL reads as "" in <, >, <= and >=', () => {
  engineTable([
  ['NULL < 1', '[true]'],
  ['NULL > 1', '[false]'],
  ['NULL < "a"', '[true]'],
  ['NULL <= NULL', '[true]'],
  ['NULL < NULL', '[false]'],
  ['0 > NULL', '[true]'],
  ['NULL >= 0', '[false]'],
  ['NULL > -1', '[false]'],
  ['"" < 1', '[true]'],
  ['NULL < " "', '[true]'],
  ['NULL >= ""', '[true]'],
  ['1 > NULL', '[true]'],
  ['NULL <= -1', '[true]'],
  ]);
});

test('URL_PARSE() puts http:// in front, turns spaces into +, and decodes the user, path_raw and query', () => {
  engineTable([
  ['URL_PARSE("mailto:a@b.com")', '[{"fragment":"","host":"b.com","host_raw":"b.com","password":"a","path":"","path_raw":"","port":"","query":"","query_raw":"","raw":"mailto:a@b.com","scheme":"http","user":"mailto"}]'],
  ['URL_PARSE("//host/x")', '[{"fragment":"","host":"","host_raw":"","path":"/host/x","path_raw":"//host/x","port":"","query":"","query_raw":"","raw":"//host/x","scheme":"http","user":""}]'],
  ['URL_PARSE("")', '[{"fragment":"","host":"","host_raw":"","path":"","path_raw":"","port":"","query":"","query_raw":"","raw":"","scheme":"http","user":""}]'],
  ['URL_PARSE("http://exa mple.com/x y?q=c d#e f")', '[{"fragment":"e+f","host":"exa+mple.com","host_raw":"exa+mple.com","path":"/x+y","path_raw":"/x+y","port":"","query":"q=c d","query_raw":"q=c+d","raw":"http://exa mple.com/x y?q=c d#e f","scheme":"http","user":""}]'],
  ['URL_PARSE("http://example.com/a+b?x=1+2")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/a+b","path_raw":"/a+b","port":"","query":"x=1 2","query_raw":"x=1+2","raw":"http://example.com/a+b?x=1+2","scheme":"http","user":""}]'],
  ['URL_PARSE("http://a b@example.com/")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/","path_raw":"/","port":"","query":"","query_raw":"","raw":"http://a b@example.com/","scheme":"http","user":"a+b"}]'],
  ['URL_PARSE("http://example.com/a%2Fb")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/a/b","path_raw":"/a%2Fb","port":"","query":"","query_raw":"","raw":"http://example.com/a%2Fb","scheme":"http","user":""}]'],
  ['URL_PARSE("http://Ex ample.COM:80/")', '[{"fragment":"","host":"ex+ample.com","host_raw":"Ex+ample.COM:80","path":"/","path_raw":"/","port":"80","query":"","query_raw":"","raw":"http://Ex ample.COM:80/","scheme":"http","user":""}]'],
  ['URL_PARSE("http://example.com?q=%zz")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"","path_raw":"","port":"","query":"q=%zz","query_raw":"q=%zz","raw":"http://example.com?q=%zz","scheme":"http","user":""}]'],
  ['URL_PARSE("///x")', '[{"fragment":"","host":"","host_raw":"","path":"/x","path_raw":"///x","port":"","query":"","query_raw":"","raw":"///x","scheme":"http","user":""}]'],
  ['URL_PARSE("/path/only?q=1")', '[{"fragment":"","host":"","host_raw":"","path":"/path/only","path_raw":"/path/only","port":"","query":"q=1","query_raw":"q=1","raw":"/path/only?q=1","scheme":"http","user":""}]'],
  ['URL_PARSE("http:/x")', '[{"fragment":"","host":"http","host_raw":"http:","path":"/x","path_raw":"/x","port":"","query":"","query_raw":"","raw":"http:/x","scheme":"http","user":""}]'],
  ['URL_PARSE("http://example.com/a%20b")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/a b","path_raw":"/a b","port":"","query":"","query_raw":"","raw":"http://example.com/a%20b","scheme":"http","user":""}]'],
  ['URL_PARSE("http://example.com/%7Euser")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/~user","path_raw":"/%7Euser","port":"","query":"","query_raw":"","raw":"http://example.com/%7Euser","scheme":"http","user":""}]'],
  ['URL_PARSE("example.com/a%20b/c")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/a b/c","path_raw":"/a b/c","port":"","query":"","query_raw":"","raw":"example.com/a%20b/c","scheme":"http","user":""}]'],
  ['URL_PARSE("http://us%2Ber+x@example.com/")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/","path_raw":"/","port":"","query":"","query_raw":"","raw":"http://us%2Ber+x@example.com/","scheme":"http","user":"us+er+x"}]'],
  ['URL_PARSE("http://example.com/a%28b%29")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/a(b)","path_raw":"/a(b)","port":"","query":"","query_raw":"","raw":"http://example.com/a%28b%29","scheme":"http","user":""}]'],
  ['URL_PARSE("foo/bar?x=http://y")', '[{"fragment":"","host":"foo","host_raw":"foo","path":"/bar","path_raw":"/bar","port":"","query":"x=http://y","query_raw":"x=http://y","raw":"foo/bar?x=http://y","scheme":"http","user":""}]'],
  ['URL_PARSE("http://example.com/a/?q=x%2By+z&w=%E2%82%AC")', '[{"fragment":"","host":"example.com","host_raw":"example.com","path":"/a/","path_raw":"/a/","port":"","query":"q=x+y z\\u0026w=€","query_raw":"q=x%2By+z\\u0026w=%E2%82%AC","raw":"http://example.com/a/?q=x%2By+z\\u0026w=%E2%82%AC","scheme":"http","user":""}]'],
  ]);
  const u = 'URL_PARSE("http://us%20er:p%41ss@example.com/a%20b/c%2Fd/../e?q=a+b%20c&r=%26#top")';
  engineTable([
  [`${u}["user"]`, '["us er"]'],
  [`${u}["password"]`, '["pAss"]'],
  [`${u}["path_raw"]`, '["/a%20b/c%2Fd/../e"]'],
  [`${u}["path"]`, '["/a b/c/e"]'],
  [`${u}["query"]`, '["q=a b c\\u0026r=\\u0026"]'],
  ]);
});

test('\\r in a string stays a backslash and an r, and \\n and \\t are a newline and a tab', () => {
  engineTable([
  ['LENGTH("a\\rb")', '[4]'],
  ['LENGTH("a\\nb")', '[3]'],
  ['LENGTH("a\\tb")', '[3]'],
  ['LENGTH("a\\\\b")', '[3]'],
  ['LENGTH("a\\"b")', '[3]'],
  ['SPLIT("x\\ry", "\\r")', '[["x","ry"]]'],
  ['SPLIT("x\\\\y", "\\r")', '[["x","y"]]'],
  ]);
  assert.equal(get('e = "a\\rb"', 'e'), 'a\\rb');
});

test('IDX_OF_TLD reads in-addr.arpa and ip6.arpa as suffixes', () => {
  engineTable([
  ['IDX_OF_TLD("80.113.0.203.in-addr.arpa")', '[9]'],
  ['IDX_OF_TLD("1.0.0.0.ip6.arpa")', '[6]'],
  ['IDX_OF_TLD("www.example.co.uk")', '[4]'],
  ['IDX_OF_TLD("ec2.ap-southeast-2.amazonaws.com")', '[19]'],
  ['IDX_OF_TLD("a.b.example.com.au")', '[4]'],
  ['IDX_OF_TLD("x.y.github.io")', '[4]'],
  ]);
});

test('CEF() reads the last field of a 6 or 7 field header as the extension', () => {
  engineTable([
  ['CEF("CEF:0|V|P|1|100|N")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100"}]'],
  ['CEF("CEF:0|V|P|1|100|N|5")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100","5":"N"}]'],
  ['CEF("CEF:0|V|P|1|100|N|a=b c=d")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100","5":"N","a":"b","c":"d"}]'],
  ['CEF("CEF:0|V|P|1|100|a=b")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100","a":"b"}]'],
  ['CEF("CEF:0|V|P|1|100|")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100"}]'],
  ['CEF("CEF:0|V|P|1|100|N|5|")', '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"100","5":"N","6":"5"}]'],
  ['LENGTH(CEF("CEF:0|V|P|1|100|N"))', '[5]'],
  ]);
});

test('CEF() drops the quotes around a quoted value, which can hold spaces and keys', () => {
  const cef = (ext) => `CEF("CEF:0|V|P|1|x|y|1|${ext.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}")`;
  engineTable([
  [cef('cs1="quoted value" cs2="a b" c "d e" cs3="a" b cs4=a "b"'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"quoted value","cs2":"a b\\" c \\"d e","cs3":"\\"a\\" b","cs4":"a \\"b\\""}]'],
  [cef('cs1=""a"" cs2="a cs3=a" cs4="" cs5=" x " cs6=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"\\"a\\"","cs2":"a cs3=a","cs4":"","cs5":" x ","cs6":"x"}]'],
  [cef('cs1="C:\\\\a.exe" cs2="a\\"b" cs3="a\\=b" cs4=\'single\' cs5="a b"c'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"C:\\\\a.exe","cs2":"a\\"b","cs3":"a=b","cs4":"\'single\'","cs5":"\\"a b\\"c"}]'],
  [cef('cs2="a b" cs2Label="My Label" act="x"'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","My Label":"a b","act":"x","cs2":"a b","cs2Label":"My Label"}]'],
  [cef('msg="unterminated value'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","msg":"\\"unterminated value"}]'],
  [cef('cs1=" cs2="'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":" cs2="}]'],
  [cef('cs1=a"b cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"a\\"b","cs2":"x"}]'],
  [cef('cs1=a\\"b cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"a\\"b","cs2":"x"}]'],
  [cef('cs1="a b"cs2=x cs3=y'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"\\"a b\\"cs2=x","cs3":"y"}]'],
  [cef('cs1="a" cs2="b'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"a","cs2":"\\"b"}]'],
  [cef('cs1="a" b "c cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"\\"a\\" b \\"c","cs2":"x"}]'],
  [cef('cs1="a\\\\" cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"a\\\\","cs2":"x"}]'],
  [cef('cs1="a cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"\\"a cs2=x"}]'],
  [cef('cs1="a"   cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"a","cs2":"x"}]'],
  [cef('cs1="a\\" cs2=x'), '[{"0":"CEF:0","1":"V","2":"P","3":"1","4":"x","5":"y","6":"1","cs1":"\\"a\\" cs2=x"}]'],
  ]);
});

test('text added to a DATETIME value reads like ParseFloat, hex floats and underscores included', () => {
  const t = 'DATETIME("2026-10-14T01:02:03Z", "2006-01-02T15:04:05Z07:00")';
  engineTable([
  [`${t} + "0x1p4"`, '1791939723000016'],
  [`${t} + "1_000"`, '1791939723001000'],
  [`"0x1p4" + ${t}`, '1791939723000016'],
  [`${t} + ".5"`, '1791939723000000'],
  [`${t} + "5."`, '1791939723000005'],
  [`${t} + "+5"`, '1791939723000005'],
  [`${t} + "0X1P-2"`, '1791939723000000'],
  [`${t} + "1_000.5"`, '1791939723001000'],
  [`${t} + "1__0"`, null],
  [`${t} + "0x10"`, null],
  [`${t} + "1e400"`, null],
  ], { wrap: (expr) => `STRING(${expr})` });
});

test('UPPERCASE(number) and IS_VALID_IP(NULL) fail the event', () => {
  engineTable([
  ['UPPERCASE(5)', null],
  ['UPPERCASE(3 / 2)', null],
  ['UPPERCASE(INT("5", 10))', null],
  ['UPPERCASE("ab")', '["AB"]'],
  ['IS_VALID_IP(NULL)', null],
  ['IS_VALID_IP("")', '[false]'],
  ['IS_VALID_IP("192.0.2.1")', '[true]'],
  ]);
  assert.throws(() => run('x = UPPERCASE(5)'), /invalid data type for UPPERCASE\(\): NUMBER/);
  assert.throws(() => run('n = NULL\nx = IS_VALID_IP(n)'), /IS_VALID_IP\(\) expected a string, but received NULL/);
});

test('a - in a name after a dot fails the event; the bracket form works', () => {
  const d = { d: '{"detail-type":"x","a":{"detail-type":"y"}}' };
  assert.throws(() => run('j = JSON(d)\nx = j["$.detail-type"]', d), /parse error at 9 in \$\.detail-type/);
  assert.throws(() => run('j = JSON(d)\np = "$.detail" + "-type"\nx = j[p]', d), /parse error at 9/);
  assert.throws(() => run('j = JSON(d)\nx = j["$.a.detail-type"]', d), /parse error at 11/);
  assert.throws(() => run('j = JSON(d)\nx = j["$..detail-type"]', d), /parse error at 10/);
  assert.equal(get('j = JSON(d)\nx = j["$[\'detail-type\']"]', 'x', d), 'x');
  assert.equal(get('j = JSON(d)\nx = j["$.a[\'detail-type\']"]', 'x', d), 'y');
});

test('a field set on a variable holding a capture result fails the event', () => {
  assert.throws(() => run('r = originalData$|^(\\w+)\nr.key$ = "k"', { originalData$: 'abc' }), /variable r is not Object type/);
  assert.throws(() => run('r = originalData$|^nomatch(x)\nr.key$ = "k"', { originalData$: 'abc' }), /variable r is not Object type/);
  assert.deepEqual(toPlain(run('r.key$ = "k"\nr.value$ = "v"').get('r')), { key$: 'k', value$: 'v' });
});
