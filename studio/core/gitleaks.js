// The generic-api-key rule of gitleaks, the secret scan CI runs on every pull request, ported so
// the library check reports what that rule would flag before CI does. It follows gitleaks 8.30.1:
// the rule, its allowlists and the global allowlist from config/gitleaks.toml, and how a match
// becomes a finding from detect/detect.go and config/allowlist.go. The repo's own .gitleaks.toml
// allowlists for library entries apply too (REPO_ALLOWLISTS).
//
// Not ported: gitleaks' other rules (about 200), its decoding passes, which scan base64, hex and
// percent-encoded text again up to 5 levels deep, and the global allowlist's paths, which no
// library entry file matches. So CI can still flag something this lets through.
//
// The regexes, keywords, stopwords and allowlists below are copied from gitleaks:
//   Copyright (c) 2019 Zachary Rice
//   Permission is hereby granted, free of charge, to any person obtaining a copy of this software
//   and associated documentation files (the "Software"), to deal in the Software without
//   restriction, including without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
//   Software is furnished to do so, subject to the following conditions:
//   The above copyright notice and this permission notice shall be included in all copies or
//   substantial portions of the Software.
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
//   BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

export const GITLEAKS_VERSION = '8.30.1';
export const RULE_ID = 'generic-api-key';

// ---------------------------------------------------------------- Go regular expressions

// Go (RE2) regex syntax, as gitleaks writes it, translated to a JavaScript RegExp source. Node 22
// has no inline (?i) or (?-i:...), so a letter matched without case becomes a class of both cases,
// plus the letters Go folds in with them: the Kelvin sign with k and the long s with s. \s is Go's
// [\t\n\f\r ], . leaves out only \n, and \z is the end of the text. Anything else throws.
const PERL = { d: [[0x30, 0x39]], s: [[0x09, 0x0a], [0x0c, 0x0d], [0x20, 0x20]], w: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]] };
const ESCAPES = { t: 0x09, n: 0x0a, v: 0x0b, f: 0x0c, r: 0x0d, a: 0x07 };
const QUANT = /^\{\d+(?:,\d*)?\}/;

const unit = (cp) => (/^[A-Za-z0-9]$/.test(String.fromCodePoint(cp)) ? String.fromCodePoint(cp) : `\\u{${cp.toString(16)}}`);

function fold(ranges) {
  const out = [...ranges];
  const has = (lo, hi, cp) => lo <= cp && cp <= hi;
  for (const [lo, hi] of ranges) {
    for (const [a, b, d] of [[0x61, 0x7a, -32], [0x41, 0x5a, 32]]) {
      const l = Math.max(lo, a), h = Math.min(hi, b);
      if (l <= h) out.push([l + d, h + d]);
    }
    if (has(lo, hi, 0x6b) || has(lo, hi, 0x4b)) out.push([0x212a, 0x212a]);
    if (has(lo, hi, 0x73) || has(lo, hi, 0x53)) out.push([0x17f, 0x17f]);
    if (has(lo, hi, 0x212a)) out.push([0x4b, 0x4b], [0x6b, 0x6b]);
    if (has(lo, hi, 0x17f)) out.push([0x53, 0x53], [0x73, 0x73]);
  }
  return out;
}

const classOf = (ranges, ci, negate = false) => `[${negate ? '^' : ''}${(ci ? fold(ranges) : ranges).map(([lo, hi]) => (lo === hi ? unit(lo) : `${unit(lo)}-${unit(hi)}`)).join('')}]`;

// A single character: a class of its cases when it has more than one and ci is on.
const literal = (cp, ci) => (ci && fold([[cp, cp]]).length > 1 ? classOf([[cp, cp]], true) : unit(cp));

// A character escape at src[i] (a backslash): [code point, length].
function escapeChar(src, i) {
  const e = src[i + 1];
  if (e === undefined) throw new Error('trailing backslash');
  if (e in ESCAPES) return [ESCAPES[e], 2];
  if (e === 'x') {
    const m = /^\\x([0-9A-Fa-f]{2})/.exec(src.slice(i));
    if (!m) throw new Error(`unsupported escape ${src.slice(i, i + 4)}`);
    return [parseInt(m[1], 16), 4];
  }
  if (/[A-Za-z0-9]/.test(e)) throw new Error(`unsupported escape \\${e}`);
  return [src.codePointAt(i + 1), e.length + 1];
}

function parseClass(src, start, ci) {
  let i = start + 1;
  let negate = false;
  if (src[i] === '^') { negate = true; i++; }
  const ranges = [];
  const first = i;
  const char = () => {
    if (src[i] === '\\') { const [cp, n] = escapeChar(src, i); i += n; return cp; }
    const cp = src.codePointAt(i);
    i += cp > 0xffff ? 2 : 1;
    return cp;
  };
  while (i < src.length && (src[i] !== ']' || i === first)) {
    if (src.startsWith('[:', i)) throw new Error('POSIX classes are not supported');
    if (src[i] === '\\' && /[dsw]/.test(src[i + 1])) { ranges.push(...PERL[src[i + 1]]); i += 2; continue; }
    if (src[i] === '\\' && /[DSWpP]/.test(src[i + 1])) throw new Error(`unsupported class \\${src[i + 1]}`);
    const lo = char();
    if (src[i] === '-' && i + 1 < src.length && src[i + 1] !== ']') {
      i++;
      ranges.push([lo, char()]);
    } else ranges.push([lo, lo]);
  }
  if (src[i] !== ']') throw new Error('unterminated character class');
  return [classOf(ranges, ci, negate), i + 1 - start];
}

export function goRegexSource(src) {
  let out = '';
  let ci = false;
  const saved = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '(') {
      const flag = /^\(\?(-?)i([):])/.exec(src.slice(i, i + 5));
      if (flag && flag[2] === ')') { ci = !flag[1]; i += flag[0].length; continue; }
      saved.push(ci);
      if (flag) { ci = !flag[1]; out += '(?:'; i += flag[0].length; continue; }
      if (src.startsWith('(?:', i)) { out += '(?:'; i += 3; continue; }
      if (src[i + 1] === '?') throw new Error(`unsupported group ${src.slice(i, i + 4)}`);
      out += '('; i++;
      continue;
    }
    if (c === ')') { if (!saved.length) throw new Error('unbalanced )'); ci = saved.pop(); out += ')'; i++; continue; }
    if (c === '[') { const [cls, n] = parseClass(src, i, ci); out += cls; i += n; continue; }
    if (c === '\\') {
      const e = src[i + 1];
      if (e === 'z') { out += '$'; i += 2; continue; }
      if (e in PERL) { out += classOf(PERL[e], ci); i += 2; continue; }
      if (/[A-Za-z0-9]/.test(e) && !(e in ESCAPES) && e !== 'x') throw new Error(`unsupported escape \\${e}`);
      const [cp, n] = escapeChar(src, i);
      out += literal(cp, ci);
      i += n;
      continue;
    }
    if (c === '{') {
      const q = QUANT.exec(src.slice(i));
      if (q) { out += q[0]; i += q[0].length; continue; }
      out += '\\{'; i++;
      continue;
    }
    if (c === '}') { out += '\\}'; i++; continue; }
    if (c === '.') { out += '[^\\n]'; i++; continue; }
    if ('^$|*+?'.includes(c)) { out += c; i++; continue; }
    const cp = src.codePointAt(i);
    out += literal(cp, ci);
    i += cp > 0xffff ? 2 : 1;
  }
  if (saved.length) throw new Error('unbalanced (');
  return out;
}

// The u flag makes \u{...} escapes work, and leaves case alone: goRegexSource spells case out.
export const goRegex = (src, flags = '') => new RegExp(goRegexSource(src), `${flags}u`);

// ---------------------------------------------------------------- the rule

const RULE_REGEX = String.raw`(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`;
const ENTROPY = 3.5;
const KEYWORDS = ['access', 'api', 'auth', 'key', 'credential', 'creds', 'passwd', 'password', 'secret', 'token'];
const ALLOW_SIGNATURE = 'gitleaks:allow';

// The global allowlist: [allowlist] in gitleaks.toml, without its paths.
const GLOBAL_ALLOWLISTS = [{
  description: 'global allow lists',
  regexes: [
    String.raw`(?i)^true|false|null$`,
    String.raw`^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$`,
    String.raw`^\$(?:\d+|{\d+})$`,
    String.raw`^\$(?:[A-Z_]+|[a-z_]+)$`,
    String.raw`^\${(?:[A-Z_]+|[a-z_]+)}$`,
    String.raw`^\{\{[ \t]*[\w ().|]+[ \t]*}}$`,
    String.raw`^\$\{\{[ \t]*(?:(?:env|github|secrets|vars)(?:\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*}}$`,
    String.raw`^%(?:[A-Z_]+|[a-z_]+)%$`,
    String.raw`^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`,
    String.raw`^\{\d{0,2}}$`,
    String.raw`^@(?:[A-Z_]+|[a-z_]+)@$`,
    String.raw`^/Users/(?i)[a-z0-9]+/[\w .-/]+$`,
    String.raw`^/(?:bin|etc|home|opt|tmp|usr|var)/[\w ./-]+$`,
  ],
  stopwords: ['014df517-39d1-4453-b7b3-9930c563627c', 'abcdefghijklmnopqrstuvwxyz'],
}];

// [[rules.allowlists]] of generic-api-key in gitleaks.toml.
const RULE_ALLOWLISTS = [
  { regexes: [String.raw`^[a-zA-Z_.-]+$`] },
  {
    description: 'Allowlist for Generic API Keys',
    regexTarget: 'match',
    regexes: [String.raw`(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?-i:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z)))`],
    stopwords: [
    '000000', '6fe4476ee5a1832882e326b506d14126', '_ec2_', 'aaaaaa', 'about', 'abstract', 'academy',
    'acces', 'account', 'act-', 'act.', 'act_', 'action', 'active', 'actively', 'activity', 'adapter',
    'add-', 'add-on', 'add.', 'add_', 'addon', 'addres', 'admin', 'adobe', 'advanced', 'adventure',
    'agent', 'agile', 'air-', 'air.', 'air_', 'ajax', 'akka', 'alert', 'alfred', 'algorithm', 'all-',
    'all.', 'all_', 'alloy', 'alpha', 'amazon', 'amqp', 'analysi', 'analytic', 'analyzer', 'android',
    'angular', 'angularj', 'animate', 'animation', 'another', 'ansible', 'answer', 'ant-', 'ant.',
    'ant_', 'any-', 'any.', 'any_', 'apache', 'app-', 'app.', 'app_', 'apple', 'arch', 'archive',
    'archived', 'arduino', 'array', 'art-', 'art.', 'art_', 'article', 'asp-', 'asp.', 'asp_',
    'asset', 'async', 'atom', 'attention', 'audio', 'audit', 'aura', 'auth', 'author', 'authorize',
    'auto', 'automated', 'automatic', 'awesome', 'aws_', 'azure', 'back', 'backbone', 'backend',
    'backup', 'bar-', 'bar.', 'bar_', 'base', 'based', 'bash', 'basic', 'batch', 'been', 'beer',
    'behavior', 'being', 'benchmark', 'best', 'beta', 'better', 'big-', 'big.', 'big_', 'binary',
    'binding', 'bit-', 'bit.', 'bit_', 'bitcoin', 'block', 'blog', 'board', 'book', 'bookmark',
    'boost', 'boot', 'bootstrap', 'bosh', 'bot-', 'bot.', 'bot_', 'bower', 'box-', 'box.', 'box_',
    'boxen', 'bracket', 'branch', 'bridge', 'browser', 'brunch', 'buffer', 'bug-', 'bug.', 'bug_',
    'build', 'builder', 'building', 'buildout', 'buildpack', 'built', 'bundle', 'busines', 'but-',
    'but.', 'but_', 'button', 'cache', 'caching', 'cakephp', 'calendar', 'call', 'camera', 'campfire',
    'can-', 'can.', 'can_', 'canva', 'captcha', 'capture', 'card', 'carousel', 'case', 'cassandra',
    'cat-', 'cat.', 'cat_', 'category', 'center', 'cento', 'challenge', 'change', 'changelog',
    'channel', 'chart', 'chat', 'cheat', 'check', 'checker', 'chef', 'ches', 'chinese', 'chosen',
    'chrome', 'ckeditor', 'clas', 'classe', 'classic', 'clean', 'cli-', 'cli.', 'cli_', 'client',
    'clojure', 'clone', 'closure', 'cloud', 'club', 'cluster', 'cms-', 'cms_', 'coco', 'code',
    'coding', 'coffee', 'color', 'combination', 'combo', 'command', 'commander', 'comment', 'commit',
    'common', 'community', 'compas', 'compiler', 'complete', 'component', 'composer', 'computer',
    'computing', 'con-', 'con.', 'con_', 'concept', 'conf', 'config', 'connect', 'connector',
    'console', 'contact', 'container', 'contao', 'content', 'contest', 'context', 'control',
    'convert', 'converter', "conway'", 'cookbook', 'cookie', 'cool', 'copy', 'cordova', 'core',
    'couchbase', 'couchdb', 'countdown', 'counter', 'course', 'craft', 'crawler', 'create',
    'creating', 'creator', 'credential', 'crm-', 'crm.', 'crm_', 'cros', 'crud', 'csv-', 'csv.',
    'csv_', 'cube', 'cucumber', 'cuda', 'current', 'currently', 'custom', 'daemon', 'dark', 'dart',
    'dash', 'dashboard', 'data', 'database', 'date', 'day-', 'day.', 'day_', 'dead', 'debian',
    'debug', 'debugger', 'deck', 'define', 'del-', 'del.', 'del_', 'delete', 'demo', 'deploy',
    'design', 'designer', 'desktop', 'detection', 'detector', 'dev-', 'dev.', 'dev_', 'develop',
    'developer', 'device', 'devise', 'diff', 'digital', 'directive', 'directory', 'discovery',
    'display', 'django', 'dns-', 'dns_', 'doc-', 'doc.', 'doc_', 'docker', 'docpad', 'doctrine',
    'document', 'doe-', 'doe.', 'doe_', 'dojo', 'dom-', 'dom.', 'dom_', 'domain', "don't", 'done',
    'dot-', 'dot.', 'dot_', 'dotfile', 'download', 'draft', 'drag', 'drill', 'drive', 'driven',
    'driver', 'drop', 'dropbox', 'drupal', 'dsl-', 'dsl.', 'dsl_', 'dynamic', 'easy', 'ecdsa',
    'eclipse', 'edit', 'editing', 'edition', 'editor', 'element', 'emac', 'email', 'embed',
    'embedded', 'ember', 'emitter', 'emulator', 'encoding', 'endpoint', 'engine', 'english',
    'enhanced', 'entity', 'entry', 'env_', 'episode', 'erlang', 'error', 'espresso', 'event',
    'evented', 'example', 'exchange', 'exercise', 'experiment', 'expire', 'exploit', 'explorer',
    'export', 'exporter', 'expres', 'ext-', 'ext.', 'ext_', 'extended', 'extension', 'external',
    'extra', 'extractor', 'fabric', 'facebook', 'factory', 'fake', 'fast', 'feature', 'feed',
    'fewfwef', 'ffmpeg', 'field', 'file', 'filter', 'find', 'finder', 'firefox', 'firmware', 'first',
    'fish', 'fix-', 'fix_', 'flash', 'flask', 'flat', 'flex', 'flexible', 'flickr', 'flow', 'fluent',
    'fluentd', 'fluid', 'folder', 'font', 'force', 'foreman', 'fork', 'form', 'format', 'formatter',
    'forum', 'foundry', 'framework', 'free', 'friend', 'friendly', 'front-end', 'frontend', 'ftp-',
    'ftp.', 'ftp_', 'fuel', 'full', 'fun-', 'fun.', 'fun_', 'func', 'future', 'gaia', 'gallery',
    'game', 'gateway', 'gem-', 'gem.', 'gem_', 'gen-', 'gen.', 'gen_', 'general', 'generator',
    'generic', 'genetic', 'get-', 'get.', 'get_', 'getenv', 'getting', 'ghost', 'gist', 'git-',
    'git.', 'git_', 'github', 'gitignore', 'gitlab', 'glas', 'gmail', 'gnome', 'gnu-', 'gnu.', 'gnu_',
    'goal', 'golang', 'gollum', 'good', 'google', 'gpu-', 'gpu.', 'gpu_', 'gradle', 'grail', 'graph',
    'graphic', 'great', 'grid', 'groovy', 'group', 'grunt', 'guard', 'gui-', 'gui.', 'gui_', 'guide',
    'guideline', 'gulp', 'gwt-', 'gwt.', 'gwt_', 'hack', 'hackathon', 'hacker', 'hacking', 'hadoop',
    'haml', 'handler', 'hardware', 'has-', 'has_', 'hash', 'haskell', 'have', 'haxe', 'hello', 'help',
    'helper', 'here', 'hero', 'heroku', 'high', 'hipchat', 'history', 'home', 'homebrew', 'homepage',
    'hook', 'host', 'hosting', 'hot-', 'hot.', 'hot_', 'house', 'how-', 'how.', 'how_', 'html',
    'http', 'hub-', 'hub.', 'hub_', 'hubot', 'human', 'icon', 'ide-', 'ide.', 'ide_', 'idea',
    'identity', 'idiomatic', 'image', 'impact', 'import', 'important', 'importer', 'impres', 'index',
    'infinite', 'info', 'injection', 'inline', 'input', 'inside', 'inspector', 'instagram', 'install',
    'installer', 'instant', 'intellij', 'interface', 'internet', 'interview', 'into', 'intro',
    'ionic', 'iphone', 'ipython', 'irc-', 'irc_', 'iso-', 'iso.', 'iso_', 'issue', 'jade', 'jasmine',
    'java', 'jbos', 'jekyll', 'jenkin', 'jetbrains', 'job-', 'job.', 'job_', 'joomla', 'jpa-', 'jpa.',
    'jpa_', 'jquery', 'json', 'just', 'kafka', 'karma', 'kata', 'kernel', 'keyboard', 'kindle',
    'kit-', 'kit.', 'kit_', 'kitchen', 'knife', 'koan', 'kohana', 'lab-', 'lab.', 'lab_', 'lambda',
    'lamp', 'language', 'laravel', 'last', 'latest', 'latex', 'launcher', 'layer', 'layout', 'lazy',
    'ldap', 'leaflet', 'league', 'learn', 'learning', 'led-', 'led.', 'led_', 'leetcode', 'les-',
    'les.', 'les_', 'level', 'leveldb', 'lib-', 'lib.', 'lib_', 'librarie', 'library', 'license',
    'life', 'liferay', 'light', 'lightbox', 'like', 'line', 'link', 'linked', 'linkedin', 'linux',
    'lisp', 'list', 'lite', 'little', 'load', 'loader', 'local', 'location', 'lock', 'log-', 'log.',
    'log_', 'logger', 'logging', 'logic', 'login', 'logstash', 'longer', 'look', 'love', 'lua-',
    'lua.', 'lua_', 'mac-', 'mac.', 'mac_', 'machine', 'made', 'magento', 'magic', 'mail', 'make',
    'maker', 'making', 'man-', 'man.', 'man_', 'manage', 'manager', 'manifest', 'manual', 'map-',
    'map.', 'map_', 'mapper', 'mapping', 'markdown', 'markup', 'master', 'math', 'matrix', 'maven',
    'md5', 'mean', 'media', 'mediawiki', 'meetup', 'memcached', 'memory', 'menu', 'merchant',
    'message', 'messaging', 'meta', 'metadata', 'meteor', 'method', 'metric', 'micro', 'middleman',
    'migration', 'minecraft', 'miner', 'mini', 'minimal', 'mirror', 'mit-', 'mit.', 'mit_', 'mobile',
    'mocha', 'mock', 'mod-', 'mod.', 'mod_', 'mode', 'model', 'modern', 'modular', 'module', 'modx',
    'money', 'mongo', 'mongodb', 'mongoid', 'mongoose', 'monitor', 'monkey', 'more', 'motion',
    'moved', 'movie', 'mozilla', 'mqtt', 'mule', 'multi', 'multiple', 'music', 'mustache', 'mvc-',
    'mvc.', 'mvc_', 'mysql', 'nagio', 'name', 'native', 'need', 'neo-', 'neo.', 'neo_', 'nest',
    'nested', 'net-', 'net.', 'net_', 'nette', 'network', 'new-', 'new.', 'new_', 'next', 'nginx',
    'ninja', 'nlp-', 'nlp.', 'nlp_', 'node', 'nodej', 'nosql', 'not-', 'not.', 'not_', 'note',
    'notebook', 'notepad', 'notice', 'notifier', 'now-', 'now.', 'now_', 'number', 'oauth', 'object',
    'objective', 'obsolete', 'ocaml', 'octopres', 'official', 'old-', 'old.', 'old_', 'onboard',
    'online', 'only', 'open', 'opencv', 'opengl', 'openshift', 'openwrt', 'option', 'oracle', 'org-',
    'org.', 'org_', 'origin', 'original', 'orm-', 'orm.', 'orm_', 'osx-', 'osx_', 'our-', 'our.',
    'our_', 'out-', 'out.', 'out_', 'output', 'over', 'overview', 'own-', 'own.', 'own_', 'pack',
    'package', 'packet', 'page', 'panel', 'paper', 'paperclip', 'para', 'parallax', 'parallel',
    'parse', 'parser', 'parsing', 'particle', 'party', 'password', 'patch', 'path', 'pattern',
    'payment', 'paypal', 'pdf-', 'pdf.', 'pdf_', 'pebble', 'people', 'perl', 'personal', 'phalcon',
    'phoenix', 'phone', 'phonegap', 'photo', 'php-', 'php.', 'php_', 'physic', 'picker', 'pipeline',
    'platform', 'play', 'player', 'please', 'plu-', 'plu.', 'plu_', 'plug-in', 'plugin', 'plupload',
    'png-', 'png.', 'png_', 'poker', 'polyfill', 'polymer', 'pool', 'pop-', 'pop.', 'pop_', 'popcorn',
    'popup', 'port', 'portable', 'portal', 'portfolio', 'post', 'power', 'powered', 'powerful',
    'prelude', 'pretty', 'preview', 'principle', 'print', 'pro-', 'pro.', 'pro_', 'problem', 'proc',
    'product', 'profile', 'profiler', 'program', 'progres', 'project', 'protocol', 'prototype',
    'provider', 'proxy', 'public', 'pull', 'puppet', 'pure', 'purpose', 'push', 'pusher', 'pyramid',
    'python', 'quality', 'query', 'queue', 'quick', 'rabbitmq', 'rack', 'radio', 'rail', 'railscast',
    'random', 'range', 'raspberry', 'rdf-', 'rdf.', 'rdf_', 'react', 'reactive', 'read', 'reader',
    'readme', 'ready', 'real', 'real-time', 'reality', 'realtime', 'recipe', 'recorder', 'red-',
    'red.', 'red_', 'reddit', 'redi', 'redmine', 'reference', 'refinery', 'refresh', 'registry',
    'related', 'release', 'remote', 'rendering', 'repo', 'report', 'request', 'require', 'required',
    'requirej', 'research', 'resource', 'response', 'resque', 'rest', 'restful', 'resume', 'reveal',
    'reverse', 'review', 'riak', 'rich', 'right', 'ring', 'robot', 'role', 'room', 'router',
    'routing', 'rpc-', 'rpc.', 'rpc_', 'rpg-', 'rpg.', 'rpg_', 'rspec', 'ruby-', 'ruby.', 'ruby_',
    'rule', 'run-', 'run.', 'run_', 'runner', 'running', 'runtime', 'rust', 'rvm-', 'rvm.', 'rvm_',
    'salt', 'sample', 'sandbox', 'sas-', 'sas.', 'sas_', 'sbt-', 'sbt.', 'sbt_', 'scala', 'scalable',
    'scanner', 'schema', 'scheme', 'school', 'science', 'scraper', 'scratch', 'screen', 'script',
    'scroll', 'scs-', 'scs.', 'scs_', 'sdk-', 'sdk.', 'sdk_', 'sdl-', 'sdl.', 'sdl_', 'search',
    'secure', 'security', 'see-', 'see.', 'see_', 'seed', 'select', 'selector', 'selenium',
    'semantic', 'sencha', 'send', 'sentiment', 'serie', 'server', 'service', 'session', 'set-',
    'set.', 'set_', 'setting', 'setup', 'sha1', 'sha2', 'sha256', 'share', 'shared', 'sharing',
    'sheet', 'shell', 'shield', 'shipping', 'shop', 'shopify', 'shortener', 'should', 'show',
    'showcase', 'side', 'silex', 'simple', 'simulator', 'single', 'site', 'skeleton', 'sketch',
    'skin', 'slack', 'slide', 'slider', 'slim', 'small', 'smart', 'smtp', 'snake', 'snapshot',
    'snippet', 'soap', 'social', 'socket', 'software', 'solarized', 'solr', 'solution', 'solver',
    'some', 'soon', 'source', 'space', 'spark', 'spatial', 'spec', 'sphinx', 'spine', 'spotify',
    'spree', 'spring', 'sprite', 'sql-', 'sql.', 'sql_', 'sqlite', 'ssh-', 'ssh.', 'ssh_', 'stack',
    'staging', 'standard', 'stanford', 'start', 'started', 'starter', 'startup', 'stat', 'statamic',
    'state', 'static', 'statistic', 'statsd', 'statu', 'steam', 'step', 'still', 'stm-', 'stm.',
    'stm_', 'storage', 'store', 'storm', 'story', 'strategy', 'stream', 'streaming', 'string',
    'stripe', 'structure', 'studio', 'study', 'stuff', 'style', 'sublime', 'sugar', 'suite',
    'summary', 'super', 'support', 'supported', 'svg-', 'svg.', 'svg_', 'svn-', 'svn.', 'svn_',
    'swagger', 'swift', 'switch', 'switcher', 'symfony', 'symphony', 'sync', 'synopsi', 'syntax',
    'system', 'tab-', 'tab.', 'tab_', 'table', 'tag-', 'tag.', 'tag_', 'talk', 'target', 'task',
    'tcp-', 'tcp.', 'tcp_', 'tdd-', 'tdd.', 'tdd_', 'team', 'tech', 'template', 'term', 'terminal',
    'testing', 'tetri', 'text', 'textmate', 'theme', 'theory', 'three', 'thrift', 'time', 'timeline',
    'timer', 'tiny', 'tinymce', 'tip-', 'tip.', 'tip_', 'title', 'todo', 'todomvc', 'token', 'tool',
    'toolbox', 'toolkit', 'top-', 'top.', 'top_', 'tornado', 'touch', 'tower', 'tracker', 'tracking',
    'traffic', 'training', 'transfer', 'translate', 'transport', 'tree', 'trello', 'try-', 'try.',
    'try_', 'tumblr', 'tut-', 'tut.', 'tut_', 'tutorial', 'tweet', 'twig', 'twitter', 'type', 'typo',
    'ubuntu', 'uiview', 'ultimate', 'under', 'unit', 'unity', 'universal', 'unix', 'update',
    'updated', 'upgrade', 'upload', 'uploader', 'uri-', 'uri.', 'uri_', 'url-', 'url.', 'url_',
    'usage', 'usb-', 'usb.', 'usb_', 'use-', 'use.', 'use_', 'used', 'useful', 'user', 'using',
    'util', 'utilitie', 'utility', 'vagrant', 'validator', 'value', 'variou', 'varnish', 'version',
    'via-', 'via.', 'via_', 'video', 'view', 'viewer', 'vim-', 'vim.', 'vim_', 'vimrc', 'virtual',
    'vision', 'visual', 'vpn', 'want', 'warning', 'watch', 'watcher', 'wave', 'way-', 'way.', 'way_',
    'weather', 'web-', 'web_', 'webapp', 'webgl', 'webhook', 'webkit', 'webrtc', 'website',
    'websocket', 'welcome', 'what', "what'", 'when', 'where', 'which', 'why-', 'why.', 'why_',
    'widget', 'wifi', 'wiki', 'win-', 'win.', 'win_', 'window', 'wip-', 'wip.', 'wip_', 'within',
    'without', 'wizard', 'word', 'wordpres', 'work', 'worker', 'workflow', 'working', 'workshop',
    'world', 'wrapper', 'write', 'writer', 'writing', 'written', 'www-', 'www.', 'www_', 'xamarin',
    'xcode', 'xml-', 'xml.', 'xml_', 'xmpp', 'xxxxxx', 'yahoo', 'yaml', 'yandex', 'yeoman', 'yet-',
    'yet.', 'yet_', 'yii-', 'yii.', 'yii_', 'youtube', 'yui-', 'yui.', 'yui_', 'zend', 'zero', 'zip-',
    'zip.', 'zip_', 'zsh-', 'zsh.', 'zsh_',
    ],
  },
  { regexTarget: 'line', regexes: ['--mount=type=secret,', String.raw`import[ \t]+{[ \t\w,]+}[ \t]+from[ \t]+['"][^'"]+['"]`] },
  {
    condition: 'AND',
    paths: [String.raw`\.bb$`, String.raw`\.bbappend$`, String.raw`\.bbclass$`, String.raw`\.inc$`],
    regexTarget: 'line',
    regexes: [String.raw`LICENSE[^=]*=\s*"[^"]+`, String.raw`LIC_FILES_CHKSUM[^=]*=\s*"[^"]+`, String.raw`SRC[^=]*=\s*"[a-zA-Z0-9]+`],
  },
];

// The [[allowlists]] in the repo's .gitleaks.toml that can apply to a library entry file, as
// written there. A test checks the two stay the same.
export const REPO_ALLOWLISTS = [
  {
    description: 'UUID record IDs under ...Id keys in synthetic library samples',
    targetRules: ['generic-api-key'],
    condition: 'AND',
    paths: [String.raw`^parsers/[^/]+/[^/]+/samples\.log$`],
    regexTarget: 'match',
    regexes: [String.raw`(?i)^[\w.-]*id["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?$`],
  },
  {
    description: 'The synthetic token ID the Atlassian entry\'s expected.json stores as access_key',
    targetRules: ['generic-api-key'],
    condition: 'AND',
    paths: [String.raw`^parsers/atlassian/atlassian-organization-audit-log/expected\.json$`],
    regexTarget: 'match',
    regexes: [String.raw`^access_key"\s*:\s*"c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f"$`],
  },
];

// ---------------------------------------------------------------- matching

// gitleaks joins an allowlist's regexes into one, (?:a|b|...), and its paths the same way, so a
// (?i) at the start of one also applies to those after it, as in the global allowlist.
const joined = (list) => (list && list.length ? goRegex(`(?:${list.join('|')})`) : null);
const compiled = new WeakMap();
function compile(a) {
  if (!compiled.has(a)) {
    compiled.set(a, {
      and: ['AND', '&&'].includes(String(a.condition || '').toUpperCase()),
      paths: joined(a.paths),
      regexes: joined(a.regexes),
      stopwords: (a.stopwords || []).map((w) => w.toLowerCase()),
      target: a.regexTarget === 'match' || a.regexTarget === 'line' ? a.regexTarget : 'secret',
    });
  }
  return compiled.get(a);
}

const pathAllowed = (c, path) => Boolean(path && c.paths && c.paths.test(path));
const regexAllowed = (c, s) => Boolean(s && c.regexes && c.regexes.test(s));
const hasStopword = (c, s) => Boolean(s) && c.stopwords.length > 0 && c.stopwords.some((w) => s.toLowerCase().includes(w));

// checkCommitOrPathAllowed in detect.go: an allowlist that skips the whole file for the rule.
function fileAllowed(allowlists, path) {
  return allowlists.map(compile).some((c) => (c.and ? !c.regexes && !c.stopwords.length && pathAllowed(c, path) : pathAllowed(c, path)));
}

// checkFindingAllowed in detect.go. finding: {secret, match, line}.
function findingAllowed(allowlists, finding, path) {
  return allowlists.map(compile).some((c) => {
    const re = regexAllowed(c, finding[c.target]);
    const stop = hasStopword(c, finding.secret);
    if (!c.and) return re || stop;
    const checks = [];
    if (c.paths) checks.push(pathAllowed(c, path));
    if (c.regexes) checks.push(re);
    if (c.stopwords.length) checks.push(stop);
    return checks.every(Boolean);
  });
}

// shannonEntropy in gitleaks: counts characters, but divides by the length in UTF-8 bytes.
function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  const inv = 1 / new TextEncoder().encode(s).length;
  let h = 0;
  for (const n of counts.values()) { const f = n * inv; h -= f * Math.log2(f); }
  return h;
}

// The line gitleaks reports a match on (location in detect/location.go), which the line
// allowlists and the gitleaks:allow comment are tested against. Like gitleaks, it starts at the
// newline before the match, and a match after the last newline reports the text from the start.
function lineText(raw, start, end) {
  if (!raw.includes('\n')) return raw;
  const nl = raw.indexOf('\n', start + 1);
  if (nl === -1) {
    let to = end;
    while (to < raw.length && raw[to] !== '\n' && raw[to] !== '\r') to++;
    return raw.slice(0, to);
  }
  const after = raw.indexOf('\n', end);
  return raw.slice(Math.max(0, raw.lastIndexOf('\n', start)), Math.max(after === -1 ? nl : after, end));
}

let rule = null;

// Every generic-api-key finding gitleaks 8.30.1 makes in raw, the content of the file at path
// (repo-relative, such as parsers/acme/gateway/samples.log), leaving out its decoding passes.
// opts.allowlists replaces REPO_ALLOWLISTS. Returns [{line, match, secret, key}]: line is 1-based,
// and key is the match before the secret, without the separator.
export function findGenericApiKeys(raw, path = '', opts = {}) {
  const text = String(raw ?? '');
  const allowlists = [...RULE_ALLOWLISTS, ...(opts.allowlists || REPO_ALLOWLISTS)];
  const out = [];
  // Go lowers İ to i, where JavaScript gives i and a combining dot.
  const lower = text.replace(/İ/g, 'i').toLowerCase();
  if (!KEYWORDS.some((k) => lower.includes(k)) || fileAllowed(allowlists, path)) return out;
  rule ||= { all: goRegex(RULE_REGEX, 'g'), groups: goRegex(RULE_REGEX, 'd') };
  const all = new RegExp(rule.all);
  for (let m; (m = all.exec(text));) {
    const match = m[0].replace(/^\n+|\n+$/g, '');
    const line = lineText(text, m.index, m.index + match.length);
    if (line.includes(ALLOW_SIGNATURE)) continue;
    // The secret is the first group that isn't empty when the rule runs again on the match alone.
    let secret = match;
    let key = '';
    const g = rule.groups.exec(match);
    const i = g ? g.findIndex((s, n) => n > 0 && s) : -1;
    if (i > 0) {
      secret = g[i];
      key = match.slice(0, g.indices[i][0]).replace(/[\s'"`=>:|?,]+$/, '');
    }
    if (shannonEntropy(secret) <= ENTROPY) continue;
    const finding = { secret, match, line };
    if (findingAllowed(GLOBAL_ALLOWLISTS, finding, path) || findingAllowed(allowlists, finding, path)) continue;
    out.push({ line: text.slice(0, m.index).split('\n').length, match, secret, key });
  }
  return out;
}

// The findings as library check problems, one for each key and value. The message shows only the
// start of the value, so a real secret isn't copied into a public log.
export function gitleaksProblems(raw, path = '', opts = {}) {
  const seen = new Set();
  const out = [];
  for (const f of findGenericApiKeys(raw, path, opts)) {
    if (seen.has(`${f.key}\n${f.secret}`)) continue;
    seen.add(`${f.key}\n${f.secret}`);
    const shown = `${f.secret.slice(0, 4)}...`;
    out.push({
      level: 'error',
      code: 'gitleaks',
      message: `CI's secret scan (gitleaks ${RULE_ID}) would flag "${f.key}" with the value "${shown}"; change the key name or the value.`,
      line: f.line,
      text: `${f.key} ${shown}`,
      source: opts.source || null,
    });
  }
  return out;
}
