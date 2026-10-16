// Enough TOML to read gitleaks' config files: comments, bare keys, tables, arrays of tables (dotted
// ones such as [[rules.allowlists]] go to the last item of the array they name), basic and literal
// strings, multi-line literal strings ('''...'''), arrays, numbers and booleans. Anything else
// throws, so a config that uses more of TOML fails loudly rather than reading wrong.

export function readToml(text) {
  const doc = {};
  let table = doc;
  let i = 0;
  const fail = (what) => { throw new Error(`TOML: ${what} at line ${text.slice(0, i).split('\n').length}`); };
  const skip = (newlines = true) => {
    for (;;) {
      while (i < text.length && (newlines ? /\s/ : /[ \t]/).test(text[i])) i++;
      if (text[i] !== '#') return;
      while (i < text.length && text[i] !== '\n') i++;
    }
  };
  const value = () => {
    skip();
    if (text.startsWith("'''", i)) {
      const end = text.indexOf("'''", i + 3);
      if (end === -1) fail('unterminated string');
      const s = text.slice(i + 3, end).replace(/^\r?\n/, '');
      i = end + 3;
      return s;
    }
    if (text.startsWith('"""', i)) fail('multi-line basic strings are not supported');
    if (text[i] === "'") {
      const end = text.indexOf("'", i + 1);
      if (end === -1 || text.slice(i, end).includes('\n')) fail('unterminated string');
      const s = text.slice(i + 1, end);
      i = end + 1;
      return s;
    }
    if (text[i] === '"') {
      let s = '';
      for (i++; text[i] !== '"'; i++) {
        if (i >= text.length || text[i] === '\n') fail('unterminated string');
        if (text[i] !== '\\') { s += text[i]; continue; }
        const e = text[++i];
        if (e === 'u' || e === 'U') {
          const n = e === 'u' ? 4 : 8;
          const hex = text.slice(i + 1, i + 1 + n);
          if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== n) fail('bad unicode escape');
          s += String.fromCodePoint(parseInt(hex, 16));
          i += n;
          continue;
        }
        const map = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
        if (!(e in map)) fail(`escape \\${e}`);
        s += map[e];
      }
      i++;
      return s;
    }
    if (text[i] === '[') {
      const list = [];
      for (i++; ;) {
        skip();
        if (text[i] === ']') { i++; return list; }
        list.push(value());
        skip();
        if (text[i] === ',') i++;
        else if (text[i] !== ']') fail('expected , or ] in an array');
      }
    }
    const m = /^(?:true|false|[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(?=[\s,\]#]|$)/.exec(text.slice(i));
    if (!m) fail(`unexpected ${JSON.stringify(text.slice(i, i + 20))}`);
    i += m[0].length;
    return m[0] === 'true' ? true : m[0] === 'false' ? false : Number(m[0]);
  };
  // The table a header names, from the document root: an array of tables goes to its last item.
  const walk = (names, makeArray) => {
    let at = doc;
    names.forEach((name, n) => {
      const last = n === names.length - 1;
      if (last && makeArray) {
        if (at[name] === undefined) at[name] = [];
        if (!Array.isArray(at[name])) fail(`${name} is not an array of tables`);
        at[name].push({});
        at = at[name][at[name].length - 1];
        return;
      }
      if (at[name] === undefined) at[name] = {};
      at = Array.isArray(at[name]) ? at[name][at[name].length - 1] : at[name];
      if (!at || typeof at !== 'object') fail(`${name} is not a table`);
    });
    return at;
  };
  const header = (open, close) => {
    const end = text.indexOf(close, i);
    if (end === -1) fail('unterminated table header');
    const names = text.slice(i + open.length, end).split('.').map((s) => s.trim());
    if (names.some((s) => !/^[A-Za-z0-9_-]+$/.test(s))) fail('unsupported table name');
    i = end + close.length;
    return names;
  };
  for (;;) {
    skip();
    if (i >= text.length) return doc;
    if (text.startsWith('[[', i)) table = walk(header('[[', ']]'), true);
    else if (text[i] === '[') table = walk(header('[', ']'), false);
    else {
      const m = /^([A-Za-z0-9_-]+)[ \t]*=/.exec(text.slice(i));
      if (!m) fail(`unexpected ${JSON.stringify(text.slice(i, i + 20))}`);
      i += m[0].length;
      if (Object.prototype.hasOwnProperty.call(table, m[1])) fail(`${m[1]} is set twice`);
      table[m[1]] = value();
      skip(false);
      if (i < text.length && text[i] !== '\n' && text[i] !== '\r') fail('expected the end of the line');
    }
  }
}
