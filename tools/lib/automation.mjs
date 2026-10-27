// Checks for the library's playbooks and connectors: Sophos Fusion playbook templates and custom
// connectors in the YAML that Sophos Fusion exports and imports.
//
//   playbooks/<vendor>/<name>/   template.yaml, meta.json, SETUP.md, and an optional README.md
//   connectors/<vendor>/<name>/  connector.yaml, meta.json, README.md
//   connectors/allowed-hosts.json  the hosts each vendor documents, the only ones a connector may call
//
// These entries act on tenants, so a maintainer reviews every one; nothing here merges on its own.
// The checks catch what review shouldn't have to: YAML and CEL that don't parse, names, versions,
// dependencies, task references, the risk tier, hosts off the allowlist, and tenant IDs, icons,
// credentials, webhook URLs and personal data. playbookValidateDSLV2 in a tenant is the authority on
// the DSL; these checks only catch what can be caught without one.

import { parseYaml, get, YamlError } from './yaml.mjs';
import { parseCel, freeNames, templateParts, CelError } from './cel.mjs';
import { scanText } from '../../studio/core/scan.js';
import { gitleaksProblems } from '../../studio/core/gitleaks.js';
import { slug, LICENSES } from '../../studio/core/library.js';
import { aboutProblems } from '../../studio/core/notes.js';

export const TIERS = ['lookup', 'notify', 'reversible action', 'destructive'];
const rank = (t) => TIERS.indexOf(t);
export const PLAYBOOK_FILES = ['template.yaml', 'meta.json', 'SETUP.md', 'README.md'];
export const CONNECTOR_FILES = ['connector.yaml', 'meta.json', 'README.md'];
const REQUIRED = { playbook: ['template.yaml', 'meta.json', 'SETUP.md'], connector: ['connector.yaml', 'meta.json', 'README.md'] };
export const CONNECTOR_PATH = /^connectors\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/;

// Functions of Sophos-managed connectors that library entries call, with the tier of what they do.
// Any other Sophos-managed function, interface or playbook counts as a reversible action, so an
// entry that calls one can't claim to only look things up or notify.
export const KNOWN_TIERS = {
  'Taegis.Case.addComment': 'notify',
  'Taegis.Case.createLink': 'notify',
  'Taegis.Case.getComments': 'lookup',
  'Taegis.Case.query': 'lookup',
  'Taegis.Case.queryCustom': 'lookup',
  // Renders a case event as text and returns it; it writes nothing.
  'Taegis.CaseWorkNote': 'lookup',
};
// Connectors that send data to an address set in the connection rather than in the connector:
// the generic webhooks, and the Teams and Slack connectors, which post to the webhook URL in their connection.
const ANY_ADDRESS = new Set(['Taegis.Webhook', 'Taegis.Fetch', 'Taegis.MicrosoftTeams', 'Taegis.SalesforceSlack']);
// Wipe has no undo, and there's no corporate-only wipe, so no entry may call one for now.
const WIPE = /wipe|factory[-_ ]?reset/i;

const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TEMPLATE_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;
const TASK_NAME = /^[a-z][a-zA-Z0-9_]*$/;
const RESERVED = /^taegis/i;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const PLACEHOLDER_UUID = /^([0-9a-f])\1{7}-\1{4}-\1{4}-\1{4}-\1{12}$/i;
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]}`|]+/gi;
const WEBHOOK = /(hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|outlook\.office(?:365)?\.com\/webhook|\.webhook\.office\.com|\.logic\.azure\.com|webhook\.site|pipedream\.net|requestbin|hooks\.zapier\.com|chat\.googleapis\.com\/v1\/spaces|api\.telegram\.org\/bot|\/webhooks?\/)/i;
const SECRET_KEY = /^(client_?secret|secret|password|passwd|pwd|api_?key|apikey|x-api-key|token|access_?token|refresh_?token|private_?key|signing_?key|authorization|bearer)$/i;
const AUTH_TYPES = new Set(['None', 'Basic', 'APIKey', 'Raw', 'OAuthClientCreds', 'OAuthClientCredentials', 'OAuthPassword', 'OAuthAuthCode', 'OAuthJWT', 'AWSv4', 'AzureClientCertificate', 'GithubInstallation', 'Custom']);

const TEMPLATE_KEYS = new Set(['apiVersion', 'kind', 'name', 'version', 'title', 'description', 'documentation', 'changeNotes', 'changeNotesMarkdown', 'tags', 'connectorCategories', 'connectors', 'playbooks', 'interfaces', 'implements', 'triggerHints', 'inputs', 'outputs', 'dsl', 'type', 'licenseCapabilities', 'isCentralTenantVisible']);
const PLATFORM_KEYS = new Set(['isPlatformGlobal', 'isVisibleToChildren', 'featureCodes', 'requiredPermissions', 'isMDRProviderSupportedResponseAction', 'isMDRProviderInternalResponseAction', 'isGlobal']);
const CONNECTOR_KEYS = new Set(['apiVersion', 'kind', 'name', 'tags', 'categories', 'title', 'description', 'documentation', 'method', 'version', 'vendorName', 'vendorProduct', 'vendorVersion', 'parameters', 'actions', 'authTypes', 'authDefaults']);
const TASK_KEYS = new Set(['name', 'description', 'condition', 'inputs', 'variables', 'let', 'action', 'exec', 'call', 'range', 'for', 'value', 'index', 'do', 'while', 'switch', 'case', 'default', 'if', 'then', 'else', 'retry', 'sleep', 'optional', 'nolog']);
const CALLS = ['action', 'exec', 'call'];
// Fields of the DSL that hold an expression, whatever the quoting.
const EXPR_TASK_KEYS = ['condition', 'range', 'while', 'switch', 'if'];
// Names a template's expressions may read besides its tasks, as playbookValidateDSLV2 lists them.
const GLOBALS = new Set(['inputs', 'TDR', 'tenant']);

const isMap = (n) => n && n.kind === 'map';
const isSeq = (n) => n && n.kind === 'seq';
const isStr = (n) => n && n.kind === 'scalar' && typeof n.value === 'string';
const str = (n) => (isStr(n) ? n.value : null);

// ---------------------------------------------------------------- shared

class Report {
  constructor(file) { this.file = file; this.problems = []; }
  add(level, code, message, line = null, file = this.file) { this.problems.push({ level, code, message, file, line }); }
  error(code, message, line, file) { this.add('error', code, message, line, file); }
  warn(code, message, line, file) { this.add('warning', code, message, line, file); }
}

// Every node under a node, with the key path that leads to it.
function* walk(node, path = []) {
  yield { node, path };
  if (isMap(node)) for (const e of node.entries) yield* walk(e.value, [...path, e.key]);
  else if (isSeq(node)) for (let i = 0; i < node.items.length; i++) yield* walk(node.items[i], [...path, i]);
}

const lineOf = (text, index) => text.slice(0, index).split('\n').length;

// The allowlist file: {vendor: {api: [host], docs: [host], sources: [https url]}}.
export function checkAllowedHosts(json) {
  const out = [];
  const err = (m) => out.push({ level: 'error', code: 'hosts', message: m, file: 'allowed-hosts.json', line: null });
  if (!json || typeof json !== 'object' || Array.isArray(json)) { err('allowed-hosts.json must be an object of vendors'); return out; }
  const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
  for (const [vendor, v] of Object.entries(json)) {
    if (vendor !== slug(vendor)) err(`"${vendor}" must be a vendor folder name, in lowercase with hyphens`);
    if (!v || typeof v !== 'object') { err(`${vendor} must be an object`); continue; }
    for (const k of Object.keys(v)) if (!['api', 'docs', 'sources'].includes(k)) err(`${vendor}: "${k}" is not a field (api, docs, sources)`);
    for (const k of ['api', 'docs']) {
      if (!Array.isArray(v[k]) || v[k].some((h) => typeof h !== 'string' || !HOST.test(h))) err(`${vendor}.${k} must be a list of host names, such as api.example.com`);
    }
    if (!Array.isArray(v.sources) || !v.sources.length || v.sources.some((u) => typeof u !== 'string' || !/^https:\/\//.test(u))) err(`${vendor}.sources must list the https pages that document the hosts`);
  }
  return out;
}

function hostsFor(allowed, vendor) {
  const v = allowed && allowed[vendor];
  return { api: new Set(v ? v.api : []), docs: new Set(v ? [...v.api, ...v.docs] : []) };
}
const allDocHosts = (allowed) => new Set(Object.values(allowed || {}).flatMap((v) => [...(v.api || []), ...(v.docs || [])]));

// The scans every file gets: CI's gitleaks rule, the sample scan for secrets and personal data,
// IDs and webhook URLs. Hosts on the allowlist aren't flagged as real hostnames.
function scanFile(r, path, name, content, opts) {
  for (const s of gitleaksProblems(content, path, { source: name })) r.error(s.code, s.message, s.line, name);
  let text = content;
  if (name === 'meta.json') {
    try { text = JSON.stringify({ ...JSON.parse(content), docs: undefined }, null, 2); } catch { /* scanned as is */ }
  }
  const okHosts = opts.okHosts || new Set();
  for (const s of scanText(text, { source: name, allowNames: opts.allowNames })) {
    if (s.code === 'hostname' && okHosts.has(String(s.text).toLowerCase())) continue;
    r.add(s.level, s.code, s.message, s.line, name);
  }
  for (const m of content.matchAll(UUID)) {
    if (PLACEHOLDER_UUID.test(m[0])) continue;
    r.error('id', `${m[0]} looks like a tenant, device or other object ID. Library entries hold none: they are set when someone configures the playbook or connection.`, lineOf(content, m.index), name);
  }
  for (const m of content.matchAll(URL_RE)) {
    if (WEBHOOK.test(m[0])) r.error('webhook', `${m[0].slice(0, 60)} looks like a webhook URL. A webhook address belongs in the connection, never in the library.`, lineOf(content, m.index), name);
  }
}

// Literal credentials, and IDs or icons, anywhere in a YAML tree.
function yamlSecrets(r, root, name) {
  for (const { node, path } of walk(root)) {
    const key = path.length ? path[path.length - 1] : null;
    if (key === 'tenantId' || key === 'icon') {
      r.error(key === 'icon' ? 'icon' : 'tenant', key === 'icon' ? 'remove "icon": library files carry no icon' : 'remove "tenantId": a library file belongs to no tenant', node.line, name);
      continue;
    }
    if (isStr(node) && typeof key === 'string' && SECRET_KEY.test(key)) {
      const v = node.value.trim();
      if (v && !v.includes('${') && !/^<[^>]*>$/.test(v)) r.error('secret', `"${key}" holds a value. Credentials go in the connection, never in the library.`, node.line, name);
    }
    // Headers are written as {name, value}: a literal Authorization or key header is a credential.
    if (isMap(node) && isStr(get(node, 'name')) && isStr(get(node, 'value')) && /^(authorization|x-api-key|api-key|x-auth-token|cookie)$/i.test(get(node, 'name').value)) {
      const v = get(node, 'value').value;
      if (!v.includes('${')) r.error('secret', `the ${get(node, 'name').value} header holds a literal value. Credentials go in the connection.`, node.line, name);
    }
  }
}

function celCheck(r, text, line, where, file) {
  try {
    return parseCel(text);
  } catch (e) {
    if (!(e instanceof CelError)) throw e;
    r.error('cel', `${where}: the CEL expression doesn't parse: ${e.message}`, line, file);
    return null;
  }
}

function readYaml(r, content, name) {
  try {
    return parseYaml(content);
  } catch (e) {
    if (!(e instanceof YamlError)) throw e;
    r.error('yaml', `${name} is not YAML this check can read: ${e.reason}`, e.line, name);
    return null;
  }
}

// The connector and function a task's "action" names: Taegis.Case.addComment is Taegis.Case and addComment.
function splitAction(s) {
  const i = s.lastIndexOf('.');
  return i > 0 ? { connector: s.slice(0, i), fn: s.slice(i + 1) } : null;
}

const listOfRefs = (node) => (isSeq(node) ? node.items.map((n) => ({ text: str(n), line: n.line })) : []);
const refName = (s) => String(s).split(':')[0];

// ---------------------------------------------------------------- meta.json

function checkCommonMeta(r, meta, kind) {
  const err = (m) => r.error('meta', m, null, 'meta.json');
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) { err('meta.json must be a JSON object'); return false; }
  const text = (k, max, required = true) => {
    if (meta[k] === undefined && !required) return;
    if (typeof meta[k] !== 'string' || !meta[k].trim() || meta[k].length > max) err(`${k} is required (text up to ${max} characters)`);
  };
  text('title', 80);
  text('vendor', 80);
  text('product', 80);
  if (typeof meta.author !== 'string' || !HANDLE.test(meta.author)) err('author must be a GitHub handle, without the @');
  if (!LICENSES.includes(meta.license)) err(`license must be one of ${LICENSES.join(', ')}`);
  if (!Array.isArray(meta.docs) || !meta.docs.length || meta.docs.some((u) => typeof u !== 'string' || !/^https:\/\//.test(u))) err('docs must list the https pages of the vendor\'s public docs the entry follows');
  // The About text: a short summary, then notes in labelled sections, as for parser entries.
  // Entries from before the summary existed get warnings until they have one.
  for (const p of aboutProblems(meta, { kind, required: false })) r.add(p.level, 'about', p.message, null, 'meta.json');
  const t = meta.tested;
  if (!t || typeof t !== 'object' || Array.isArray(t)) err('tested must be an object like {"validated": "YYYY-MM-DD", "tenant": null}');
  else {
    if (t.validated !== null && !(typeof t.validated === 'string' && DATE.test(t.validated))) err(`tested.validated must be null or the date (YYYY-MM-DD) the ${kind === 'playbook' ? 'template passed playbookValidateDSLV2' : 'connector imported into a tenant'}`);
    if (t.tenant !== null && !(t.tenant && typeof t.tenant === 'object' && DATE.test(t.tenant.date || '') && typeof t.tenant.region === 'string' && /^[a-z]{2}\d{2}$/.test(t.tenant.region))) err('tested.tenant must be null or {"date": "YYYY-MM-DD", "region": "eu01"}, recorded only after a run in a real tenant');
    for (const k of Object.keys(t)) if (!['validated', 'tenant'].includes(k)) err(`tested.${k} is not a field (validated, tenant)`);
  }
  return true;
}

function checkPlaybookMeta(r, meta) {
  const err = (m) => r.error('meta', m, null, 'meta.json');
  if (!checkCommonMeta(r, meta, 'playbook')) return;
  const text = (k, max) => { if (typeof meta[k] !== 'string' || !meta[k].trim() || meta[k].length > max) err(`${k} is required (text up to ${max} characters)`); };
  text('use_case', 600);
  text('trigger', 400);
  text('requires', 300);
  text('mdr_note', 800);
  text('rollback', 800);
  if (!Array.isArray(meta.connections) || !meta.connections.length || meta.connections.some((c) => typeof c !== 'string' || !c.trim() || c.length > 200)) err('connections must list each connection the playbook needs, as text');
  if (!TIERS.includes(meta.risk_tier)) err(`risk_tier must be one of: ${TIERS.join(', ')}`);
  if (meta.connector !== null && !(typeof meta.connector === 'string' && CONNECTOR_PATH.test(meta.connector))) err('connector must be null or the path of the library connector the playbook needs, such as "connectors/sophos/sophos-mobile"');
  const known = ['title', 'vendor', 'product', 'use_case', 'trigger', 'connections', 'requires', 'license', 'risk_tier', 'mdr_note', 'rollback', 'tested', 'connector', 'author', 'docs', 'summary', 'notes'];
  for (const k of Object.keys(meta)) if (!known.includes(k)) err(`"${k}" is not a playbook meta.json field`);
}

function checkConnectorMeta(r, meta) {
  const err = (m) => r.error('meta', m, null, 'meta.json');
  if (!checkCommonMeta(r, meta, 'connector')) return;
  if (typeof meta.auth !== 'string' || !meta.auth.trim() || meta.auth.length > 200) err('auth is required: how the connection signs in, as text');
  if (!meta.functions || typeof meta.functions !== 'object' || Array.isArray(meta.functions) || !Object.keys(meta.functions).length) err('functions must map each function in connector.yaml to its risk tier');
  else for (const [k, v] of Object.entries(meta.functions)) if (!TIERS.includes(v)) err(`functions.${k} must be one of: ${TIERS.join(', ')}`);
  const known = ['title', 'vendor', 'product', 'auth', 'functions', 'license', 'tested', 'author', 'docs', 'summary', 'notes'];
  for (const k of Object.keys(meta)) if (!known.includes(k)) err(`"${k}" is not a connector meta.json field`);
}

// ---------------------------------------------------------------- connectors

// Every host a URL template can reach, by putting in each value of each ${config.X} that has a fixed
// list. Anything else in the host part is a value from run time, which no allowlist can check.
function urlHosts(template, params) {
  let parts;
  try { parts = templateParts(template); } catch { return { error: 'a ${ that never closes' }; }
  let variants = [''];
  let at = 0;
  for (const p of parts) {
    const lit = template.slice(at, p.offset - 2);
    variants = variants.map((v) => v + lit);
    const m = /^\s*config\.([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(p.expr);
    const choices = m && params[m[1]] && Array.isArray(params[m[1]].enum) ? params[m[1]].enum.map(String) : null;
    variants = choices ? variants.flatMap((v) => choices.map((c) => v + c)) : variants.map((v) => `${v}xslruntime`);
    if (variants.length > 200) return { error: 'too many combinations of settings to check' };
    at = p.offset + p.expr.length + 1;
  }
  variants = variants.map((v) => v + template.slice(at));
  const out = [];
  for (const v of variants) {
    let u;
    try { u = new URL(v); } catch { return { error: `${v.replace(/xslruntime/g, '${...}')} is not a URL` }; }
    if (u.protocol !== 'https:') return { error: `${template} doesn't use https` };
    if (u.hostname.includes('xslruntime')) return { error: `the host in ${template} comes from a value that isn't a setting with a fixed list of hosts` };
    out.push({ host: u.hostname, path: u.pathname });
  }
  return { hosts: out };
}

export function checkConnectorYaml(r, root, meta, opts = {}) {
  const name = 'connector.yaml';
  if (!isMap(root)) { r.error('yaml', 'connector.yaml must be a mapping', root && root.line, name); return null; }
  for (const e of root.entries) {
    if (e.key === 'tenantId' || e.key === 'icon') continue;
    if (PLATFORM_KEYS.has(e.key)) r.error('platform', `"${e.key}" is a field only Sophos sets; remove it`, e.line, name);
    else if (!CONNECTOR_KEYS.has(e.key)) r.error('field', `"${e.key}" is not a connector field`, e.line, name);
  }
  const want = (k, test, msg) => { const n = get(root, k); if (!n || !test(n)) r.error('field', msg, n ? n.line : root.line, name); return n; };
  want('apiVersion', (n) => str(n) === 'v0.0.1', 'apiVersion must be v0.0.1');
  want('kind', (n) => str(n) === 'Connector', 'kind must be Connector');
  const cname = str(want('name', (n) => isStr(n) && TEMPLATE_NAME.test(n.value) && !RESERVED.test(n.value), 'name must be letters, digits and underscores, starting with a letter, and not start with Taegis, which Sophos reserves'));
  const version = str(want('version', (n) => isStr(n) && SEMVER.test(n.value), 'version must be a version like 1.0.0'));
  want('title', (n) => isStr(n) && n.value.trim() !== '', 'title is required');
  want('description', (n) => isStr(n) && n.value.trim() !== '', 'description is required');
  want('method', (n) => str(n) === 'http', 'method must be http. The central, ssh, winrm and mcp methods reach a tenant or its hosts directly, so the library takes none of them.');
  const auth = get(root, 'authTypes');
  if (!isSeq(auth) || !auth.items.length) r.error('auth', 'authTypes must list how the connection signs in', auth ? auth.line : root.line, name);
  else for (const a of auth.items) {
    if (str(a) === 'Platform') r.error('auth', 'Platform sign-in is for connectors Sophos manages; use a credential type', a.line, name);
    else if (!AUTH_TYPES.has(str(a))) r.error('auth', `${JSON.stringify(a.value)} is not an auth type`, a.line, name);
  }
  // Settings with a fixed list of values, for the URL checks.
  const params = {};
  const props = get(get(root, 'parameters'), 'properties');
  if (isMap(props)) for (const e of props.entries) {
    const en = get(e.value, 'enum');
    params[e.key] = { enum: isSeq(en) ? en.items.map((x) => x.value) : null };
  }
  const allowed = hostsFor(opts.allowedHosts, opts.vendor);
  const checkUrl = (template, line, where) => {
    const res = urlHosts(template, params);
    if (res.error) { r.error('host', `${where}: ${res.error}`, line, name); return []; }
    for (const h of res.hosts) {
      if (!allowed.api.has(h.host)) r.error('host', `${where} calls ${h.host}, which isn't on the allowlist for ${opts.vendor || 'this vendor'} in connectors/allowed-hosts.json`, line, name);
    }
    return res.hosts;
  };
  const authDefaults = get(root, 'authDefaults');
  if (authDefaults && isStr(get(authDefaults, 'url'))) checkUrl(get(authDefaults, 'url').value, get(authDefaults, 'url').line, 'the grant URL');
  const actions = get(root, 'actions');
  const fns = new Map();
  if (!isSeq(actions) || !actions.items.length) r.error('field', 'actions must list the connector\'s functions', actions ? actions.line : root.line, name);
  else for (const a of actions.items) {
    const fname = str(get(a, 'name'));
    if (!fname || !/^[A-Za-z][A-Za-z0-9_]*$/.test(fname)) { r.error('field', 'each action needs a name of letters, digits and underscores', a.line, name); continue; }
    if (fns.has(fname)) r.error('field', `the action ${fname} appears twice`, a.line, name);
    const cfg = get(a, 'config');
    const method = str(get(cfg, 'method'));
    const url = get(cfg, 'url');
    if (!isMap(cfg) || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) r.error('field', `${fname}: config.method must be GET, POST, PUT, PATCH or DELETE`, (cfg || a).line, name);
    const hosts = isStr(url) ? checkUrl(url.value, url.line, fname) : (r.error('field', `${fname}: config.url is required`, (cfg || a).line, name), []);
    if (WIPE.test(fname) || hosts.some((h) => WIPE.test(h.path))) r.error('wipe', `${fname} wipes or resets a device. The library refuses wipe-type actions for now: there is no undo.`, a.line, name);
    fns.set(fname, { line: a.line, method, paths: hosts.map((h) => h.path) });
    // Every ${...} under the action parses, and every literal URL in its config is allowlisted.
    for (const { node } of walk(a)) {
      if (!isStr(node)) continue;
      let parts = [];
      try { parts = templateParts(node.value); } catch (e) { r.error('cel', `${fname}: ${e.reason}`, node.line, name); continue; }
      for (const p of parts) celCheck(r, p.expr, node.line, fname, name);
      if (node !== url) for (const m of node.value.matchAll(URL_RE)) if (!m[0].includes('${')) checkUrl(m[0], node.line, fname);
    }
  }
  // Defaults and fixed values of the settings: CEL parses, and URLs are allowlisted.
  for (const { node } of walk(get(root, 'parameters'))) {
    if (!isStr(node)) continue;
    let parts = [];
    try { parts = templateParts(node.value); } catch (e) { r.error('cel', `parameters: ${e.reason}`, node.line, name); continue; }
    for (const p of parts) celCheck(r, p.expr, node.line, 'parameters', name);
    for (const m of node.value.matchAll(URL_RE)) if (!m[0].includes('${')) checkUrl(m[0], node.line, 'a setting');
  }
  // Links in the documentation go to the vendor's own hosts.
  for (const k of ['documentation', 'description']) {
    const n = get(root, k);
    if (!isStr(n)) continue;
    for (const m of n.value.matchAll(URL_RE)) {
      let host = '';
      try { host = new URL(m[0]).hostname; } catch { /* reported below */ }
      if (!m[0].startsWith('https://') || !allowed.docs.has(host)) r.error('host', `${k} links ${m[0].slice(0, 80)}, which isn't https on a host in connectors/allowed-hosts.json for ${opts.vendor || 'this vendor'}`, n.line, name);
    }
  }
  // meta.json gives every function a tier, and only those functions.
  if (meta && meta.functions && typeof meta.functions === 'object') {
    for (const [f, v] of fns) if (!(f in meta.functions)) r.error('tier', `${f} has no risk tier in meta.json functions`, v.line, name);
    for (const f of Object.keys(meta.functions)) if (!fns.has(f)) r.error('tier', `meta.json functions names ${f}, which connector.yaml doesn't have`, null, 'meta.json');
  }
  return { name: cname, version, functions: fns, tiers: (meta && meta.functions) || {} };
}

// ---------------------------------------------------------------- templates

// Every task list of a DSL: the top list, then each nested one (do, for, then, else, case, default).
function* taskLists(list, top = true) {
  if (!isSeq(list)) return;
  yield { list, top };
  for (const t of list.items) {
    if (!isMap(t)) continue;
    for (const k of ['do', 'for', 'then', 'else', 'default']) yield* taskLists(get(t, k), false);
    const c = get(t, 'case');
    if (isMap(c)) for (const e of c.entries) yield* taskLists(e.value, false);
  }
}

// A value in let, variables, inputs or outputs: single quotes make text, anything else in a string
// is an expression. Returns the CEL checks to run, with the hint the quoting rule needs.
function* valueExprs(node, where) {
  for (const { node: n, path } of walk(node)) {
    if (!isStr(n) || n.style === 'single' || n.value.trim() === '') continue;
    const at = path.length ? `${where} ${path.join('.')}` : where;
    // Text with ${...} in it is a template: each ${...} is an expression.
    if (n.value.includes('${')) {
      yield { template: n.value, line: n.line, where: at };
      continue;
    }
    yield { text: n.value, line: n.line, where: at, quotable: n.style === 'plain' || n.style === 'double' };
  }
}

export function checkTemplateYaml(r, root, meta, opts = {}) {
  const name = 'template.yaml';
  if (!isMap(root)) { r.error('yaml', 'template.yaml must be a mapping', root && root.line, name); return; }
  for (const e of root.entries) {
    if (e.key === 'tenantId' || e.key === 'icon') continue;
    if (PLATFORM_KEYS.has(e.key)) r.error('platform', `"${e.key}" is a field only Sophos sets; remove it`, e.line, name);
    else if (!TEMPLATE_KEYS.has(e.key)) r.error('field', `"${e.key}" is not a template field`, e.line, name);
  }
  const want = (k, test, msg) => { const n = get(root, k); if (!n || !test(n)) r.error('field', msg, n ? n.line : root.line, name); return n; };
  want('apiVersion', (n) => str(n) === 'v0.0.1', 'apiVersion must be v0.0.1');
  want('kind', (n) => str(n) === 'Playbook', 'kind must be Playbook');
  const tname = str(want('name', (n) => isStr(n) && TEMPLATE_NAME.test(n.value) && !RESERVED.test(n.value), 'name must be letters, digits and underscores, starting with a letter, and not start with Taegis, which Sophos reserves'));
  want('version', (n) => isStr(n) && SEMVER.test(n.value), 'version must be a version like 1.0.0');
  want('title', (n) => isStr(n) && n.value.trim() !== '', 'title is required');
  want('description', (n) => isStr(n) && n.value.trim() !== '', 'description is required');

  // Dependencies: name:version, and the entry's own connector exactly as its connector.yaml has it.
  const deps = {};
  for (const k of ['connectors', 'playbooks', 'interfaces']) {
    const n = get(root, k);
    if (n && !isSeq(n)) { r.error('field', `${k} must be a list`, n.line, name); continue; }
    deps[k] = new Map();
    for (const item of listOfRefs(n)) {
      if (!item.text || !/^[A-Za-z][A-Za-z0-9_.]*:(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(item.text)) { r.error('field', `${k}: ${JSON.stringify(item.text)} must be Name:version, such as Taegis.Case:1.0.5`, item.line, name); continue; }
      deps[k].set(refName(item.text), item);
    }
  }
  const own = opts.connector || null;
  if (meta && meta.connector) {
    if (!own) r.error('connector', `meta.json names ${meta.connector}, which isn't in the library`, null, 'meta.json');
    else if (own.name && own.version) {
      const ref = deps.connectors && deps.connectors.get(own.name);
      if (!ref) r.error('connector', `connectors must list ${own.name}:${own.version}, the connector in ${meta.connector}`, get(root, 'connectors') ? get(root, 'connectors').line : root.line, name);
      else if (ref.text !== `${own.name}:${own.version}`) r.error('connector', `connectors lists ${ref.text}, but ${meta.connector} is version ${own.version}`, ref.line, name);
    }
  }
  for (const [n, item] of deps.connectors || []) {
    if (!n.startsWith('Taegis.') && !(own && n === own.name)) r.error('connector', `${n} is neither a Sophos-managed connector nor this entry's own; name it in meta.json "connector"`, item.line, name);
  }

  const dsl = get(root, 'dsl');
  if (!isMap(dsl)) { r.error('dsl', 'dsl is required and must be a mapping', dsl ? dsl.line : root.line, name); return; }
  const dname = str(get(dsl, 'name'));
  if (dname !== null && !TEMPLATE_NAME.test(dname)) r.error('dsl', 'dsl.name must be letters, digits and underscores', get(dsl, 'name').line, name);
  if (dname !== null && tname && dname !== tname) r.warn('dsl', `dsl.name is ${dname}; it should match the template's name, ${tname}`, get(dsl, 'name').line, name);
  const list = get(dsl, 'tasks');
  if (!isSeq(list) || !list.items.length) { r.error('dsl', 'dsl.tasks must list at least one task', (list || dsl).line, name); return; }

  // Tasks: names, types and fields. A nested task may go without a name, but then nothing can read it.
  const names = new Map();
  const all = [];
  for (const { list: l, top } of taskLists(list)) {
    const here = new Set();
    for (const t of l.items) {
      all.push(t);
      if (!isMap(t)) { r.error('task', 'each task must be a mapping', t.line, name); continue; }
      const n = str(get(t, 'name'));
      if (n === null && !top) continue;
      if (!n || !TASK_NAME.test(n)) r.error('task', `task name ${JSON.stringify(n)} must start with a lowercase letter, then letters, digits and underscores`, t.line, name);
      else if (here.has(n)) r.error('task', `two tasks in the same list are called ${n}`, t.line, name);
      else { here.add(n); names.set(n, t); }
    }
  }
  for (const t of all) {
    if (!isMap(t)) continue;
    const n = str(get(t, 'name')) || 'a task';
    for (const e of t.entries) if (!TASK_KEYS.has(e.key)) r.warn('task', `${n}: "${e.key}" isn't a task field these checks know; playbookValidateDSLV2 has the last word`, e.line, name);
    const kinds = CALLS.filter((k) => get(t, k));
    if (kinds.length > 1) r.error('task', `${n}: a task calls one thing, but this one has ${kinds.join(' and ')}`, t.line, name);
    if (get(t, 'retry') && !kinds.length) r.error('task', `${n}: retry only works on a task that calls a function (action, exec or call)`, get(t, 'retry').line, name);
    const retry = get(t, 'retry');
    if (retry && !(typeof retry.value === 'number' && Number.isInteger(retry.value) && retry.value >= 1 && retry.value <= 10)) r.error('task', `${n}: retry must be a whole number from 1 to 10`, retry.line, name);
    const sleep = get(t, 'sleep');
    if (sleep && !(isStr(sleep) && (/^\d+(ms|s|m|h)$/.test(sleep.value) || sleep.style !== 'single'))) r.error('task', `${n}: sleep must be a duration such as '30s', or an expression that gives one`, sleep.line, name);
    if (get(t, 'for') && !get(t, 'range') && !get(t, 'condition')) r.error('task', `${n}: a for loop needs range or condition`, t.line, name);
    if (get(t, 'do') && !get(t, 'while')) r.error('task', `${n}: a do loop needs while`, t.line, name);
    for (const k of CALLS) {
      const v = get(t, k);
      if (v && !isStr(v)) r.error('task', `${n}: ${k} must name what it calls`, v.line, name);
    }
  }

  // Calls: each must be declared, and the entry's own connector must have the function.
  const called = [];
  for (const t of all) {
    if (!isMap(t)) continue;
    const n = str(get(t, 'name'));
    const action = str(get(t, 'action'));
    if (action) {
      const s = splitAction(action);
      if (!s) { r.error('task', `${n}: action ${action} must be Connector.function`, get(t, 'action').line, name); continue; }
      if (!deps.connectors || !deps.connectors.has(s.connector)) r.error('dependency', `${n}: ${s.connector} isn't in connectors`, get(t, 'action').line, name);
      if (own && s.connector === own.name && own.functions && !own.functions.has(s.fn)) r.error('dependency', `${n}: ${own.name} has no function ${s.fn}`, get(t, 'action').line, name);
      called.push({ task: n, kind: 'action', id: action, connector: s.connector, fn: s.fn, line: get(t, 'action').line });
    }
    for (const [k, dep] of [['exec', 'playbooks'], ['call', 'interfaces']]) {
      const v = str(get(t, k));
      if (!v) continue;
      if (!deps[dep] || !deps[dep].has(v)) r.error('dependency', `${n}: ${v} isn't in ${dep}`, get(t, k).line, name);
      called.push({ task: n, kind: k, id: v, line: get(t, k).line });
    }
  }

  // Expressions parse, and read only inputs, TDR, tenant and tasks. A plain word that is none of those was
  // probably meant as text, which needs single quotes.
  const known = new Set([...GLOBALS, ...names.keys()]);
  const check = (text, line, where, quotable) => {
    const ast = celCheck(r, text, line, where, name);
    if (!ast) return;
    for (const v of freeNames(ast)) {
      if (known.has(v)) continue;
      const hint = quotable && /^[A-Za-z_][A-Za-z0-9_]*$/.test(text.trim()) ? ` To set the text ${text.trim()}, single-quote it: '${text.trim()}'.` : '';
      r.error('reference', `${where}: ${v} is not a task, inputs, TDR or tenant.${hint}`, line, name);
    }
  };
  const checkValue = (x) => {
    if (x.template === undefined) { check(x.text, x.line, x.where, x.quotable); return; }
    let parts = [];
    try { parts = templateParts(x.template); } catch (e) { r.error('cel', `${x.where}: ${e.reason}`, x.line, name); return; }
    for (const p of parts) check(p.expr, x.line, x.where, false);
  };
  for (const t of all) {
    if (!isMap(t)) continue;
    const n = str(get(t, 'name')) || 'a task';
    for (const k of EXPR_TASK_KEYS) {
      const v = get(t, k);
      if (isStr(v)) check(v.value, v.line, `${n} ${k}`, false);
      else if (v && v.kind === 'scalar' && typeof v.value !== 'boolean') r.error('cel', `${n} ${k} must be an expression`, v.line, name);
    }
    const sleep = get(t, 'sleep');
    if (isStr(sleep) && sleep.style !== 'single' && !/^\d+(ms|s|m|h)$/.test(sleep.value)) check(sleep.value, sleep.line, `${n} sleep`, false);
    for (const k of ['let', 'variables', 'inputs']) for (const x of valueExprs(get(t, k), `${n} ${k}`)) checkValue(x);
  }
  for (const k of ['outcomeStatus', 'outcomeMessage', 'summary']) { const v = get(dsl, k); if (isStr(v)) check(v.value, v.line, `dsl ${k}`, false); }
  for (const x of valueExprs(get(dsl, 'outputs'), 'dsl outputs')) checkValue(x);
  // Trigger hints: expressions over the trigger's inputs.
  for (const { node, path } of walk(get(root, 'triggerHints'))) {
    const key = path[path.length - 1];
    if ((key === 'expr' || key === 'filter') && isStr(node)) {
      const ast = celCheck(r, node.value, node.line, `triggerHints ${path.join('.')}`, name);
      if (ast) for (const v of freeNames(ast)) if (v !== 'inputs') r.error('reference', `triggerHints ${path.join('.')}: ${v} is not inputs`, node.line, name);
    }
  }
  // A template holds no addresses: hosts belong in a connector, where the allowlist checks them.
  const docHosts = allDocHosts(opts.allowedHosts);
  for (const { node, path } of walk(root)) {
    if (!isStr(node)) continue;
    const top = path[0];
    for (const m of node.value.matchAll(URL_RE)) {
      if (['documentation', 'description', 'changeNotes', 'changeNotesMarkdown', 'title'].includes(top)) {
        let host = '';
        try { host = new URL(m[0]).hostname; } catch { /* reported below */ }
        if (!m[0].startsWith('https://') || !docHosts.has(host)) r.error('host', `${top} links ${m[0].slice(0, 80)}, which isn't https on a host in connectors/allowed-hosts.json`, node.line, name);
      } else {
        r.error('host', `${path.join('.')} holds the address ${m[0].slice(0, 80)}. A template holds no URLs: an address belongs in a connector, where the allowlist checks it.`, node.line, name);
      }
    }
  }

  // The risk tier: what the template calls decides the least it may claim.
  if (meta && TIERS.includes(meta.risk_tier)) {
    let least = 'lookup';
    const why = [];
    for (const c of called) {
      let tier;
      if (c.kind === 'action' && own && c.connector === own.name) tier = own.tiers[c.fn];
      else tier = KNOWN_TIERS[c.id];
      if (c.kind === 'action' && ANY_ADDRESS.has(c.connector)) {
        r.warn('review', `${c.task}: ${c.id} sends data to an address set in the connection. Review what it sends.`, c.line, name);
        tier = tier || 'notify';
      }
      if (c.kind === 'action' && WIPE.test(c.fn)) r.error('wipe', `${c.task}: ${c.id} wipes or resets a device. The library refuses wipe-type actions for now: there is no undo.`, c.line, name);
      if (c.kind === 'action' && own && c.connector === own.name && own.functions && own.functions.get(c.fn) && own.functions.get(c.fn).paths.some((p) => WIPE.test(p))) r.error('wipe', `${c.task}: ${c.id} calls a wipe endpoint. The library refuses wipe-type actions for now.`, c.line, name);
      tier = tier || 'reversible action';
      if (rank(tier) > rank(least)) least = tier;
      if (rank(tier) > rank('notify')) why.push(`${c.id} (${tier})`);
    }
    if (rank(meta.risk_tier) < rank(least)) r.error('tier', `risk_tier is ${meta.risk_tier}, but the template calls ${why.length ? why.join(', ') : 'functions'} that make it at least ${least}`, null, 'meta.json');
    if (meta.risk_tier === 'destructive' && !(meta.tested && meta.tested.tenant)) r.error('tier', 'a destructive entry needs a tested.tenant record: the date and region of a run in a real tenant', null, 'meta.json');
  }
}

// ---------------------------------------------------------------- entries

// entry: {kind: 'playbook'|'connector', id: 'vendor/name', files: [{path, content}], meta, loadProblems}
// opts: {allowedHosts, connectors: Map of id -> parsed connector entry, allowNames}
export function validateAutomation(entry, opts = {}) {
  const r = new Report(null);
  const kind = entry.kind;
  const base = kind === 'playbook' ? 'playbooks' : 'connectors';
  for (const p of entry.loadProblems || []) r.add(p.level, p.code, p.message, p.line || null, p.file || null);
  const names = (entry.files || []).map((f) => f.path);
  const allowedFiles = kind === 'playbook' ? PLAYBOOK_FILES : CONNECTOR_FILES;
  for (const f of names) if (!allowedFiles.includes(f)) r.error('files', `${f} is not allowed in a ${kind} entry (allowed: ${allowedFiles.join(', ')})`, null, f);
  for (const f of REQUIRED[kind]) if (!names.includes(f)) r.error('files', `${f} is missing`, null, f);
  const meta = entry.meta;
  if (kind === 'playbook') checkPlaybookMeta(r, meta); else checkConnectorMeta(r, meta);
  const vendorSlug = entry.id.split('/')[0];
  if (meta && typeof meta === 'object' && typeof meta.vendor === 'string' && typeof (kind === 'playbook' ? meta.title : meta.product) === 'string') {
    const want = `${slug(meta.vendor)}/${slug(kind === 'playbook' ? meta.title : meta.product)}`;
    if (want !== entry.id) r.error('folder', `the folder is ${base}/${entry.id}, but ${kind === 'playbook' ? 'vendor and title' : 'vendor and product'} make it ${base}/${want}`, null, 'meta.json');
  }
  const allowed = hostsFor(opts.allowedHosts, vendorSlug);
  const okHosts = new Set([...allDocHosts(opts.allowedHosts), ...allowed.docs]);
  for (const f of entry.files || []) scanFile(r, `${base}/${entry.id}/${f.path}`, f.path, f.content, { allowNames: opts.allowNames, okHosts });
  const yamlName = kind === 'playbook' ? 'template.yaml' : 'connector.yaml';
  const yamlFile = (entry.files || []).find((f) => f.path === yamlName);
  let parsed = null;
  if (yamlFile) {
    const root = readYaml(r, yamlFile.content, yamlName);
    if (root) {
      yamlSecrets(r, root, yamlName);
      if (kind === 'connector') parsed = checkConnectorYaml(r, root, meta, { allowedHosts: opts.allowedHosts, vendor: vendorSlug });
      else {
        let connector = null;
        if (meta && typeof meta.connector === 'string' && opts.connectors) {
          const c = opts.connectors.get(meta.connector.replace(/^connectors\//, ''));
          if (c) connector = c;
        }
        checkTemplateYaml(r, root, meta, { connector, allowedHosts: opts.allowedHosts });
      }
    }
  }
  return { ok: !r.problems.some((p) => p.level === 'error'), problems: r.problems, connector: parsed };
}

// The parsed form of a connector entry that playbooks check their calls against, or null.
export function connectorInfo(entry, opts = {}) {
  const f = (entry.files || []).find((x) => x.path === 'connector.yaml');
  if (!f) return null;
  const r = new Report('connector.yaml');
  const root = readYaml(r, f.content, 'connector.yaml');
  if (!root) return null;
  return checkConnectorYaml(r, root, entry.meta, { allowedHosts: opts.allowedHosts, vendor: entry.id.split('/')[0] });
}
