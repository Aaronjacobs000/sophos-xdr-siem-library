// Node helpers to read playbook and connector entries, and the connector host allowlist, from disk.

import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { connectorInfo } from './automation.mjs';

export const KINDS = { playbooks: 'playbook', connectors: 'connector' };
export const ALLOWED_HOSTS = 'connectors/allowed-hosts.json';

async function exists(p) {
  try { await stat(p); return true; } catch { return false; }
}

// Reads <playbooks|connectors>/<vendor>/<name>. Only regular files are read; anything else is
// reported, and bad meta.json JSON is reported rather than thrown.
export async function loadAutomationEntry(dir, root, folder) {
  const abs = path.resolve(dir);
  const files = [];
  const loadProblems = [];
  for (const d of await readdir(abs, { withFileTypes: true })) {
    if (!d.isFile()) {
      loadProblems.push({ level: 'error', code: 'files', message: `${d.name} is not a regular file. Entries hold plain files only.`, file: d.name });
      continue;
    }
    files.push({ path: d.name, content: await readFile(path.join(abs, d.name), 'utf8') });
  }
  let meta = null;
  const m = files.find((f) => f.path === 'meta.json');
  if (m) {
    try { meta = JSON.parse(m.content); } catch (e) { loadProblems.push({ level: 'error', code: 'json', message: `meta.json is not valid JSON: ${e.message}`, file: 'meta.json' }); }
  }
  const id = path.relative(path.join(root, folder), abs).split(path.sep).join('/');
  return { kind: KINDS[folder], folder, id, dir: abs, files, meta, loadProblems };
}

export async function listAutomationDirs(root, folder) {
  const base = path.join(root, folder);
  if (!(await exists(base))) return [];
  const out = [];
  for (const v of await readdir(base, { withFileTypes: true })) {
    if (!v.isDirectory()) continue;
    for (const p of await readdir(path.join(base, v.name), { withFileTypes: true })) {
      if (p.isDirectory()) out.push(path.join(base, v.name, p.name));
    }
  }
  return out.sort();
}

export async function loadAutomation(root) {
  const out = {};
  for (const folder of Object.keys(KINDS)) out[folder] = await Promise.all((await listAutomationDirs(root, folder)).map((d) => loadAutomationEntry(d, root, folder)));
  return out;
}

// The allowlist, or {} with a problem when it is missing or isn't JSON.
export async function loadAllowedHosts(root) {
  const p = path.join(root, ALLOWED_HOSTS);
  if (!(await exists(p))) return { hosts: {}, problem: null };
  try {
    return { hosts: JSON.parse(await readFile(p, 'utf8')), problem: null };
  } catch (e) {
    return { hosts: {}, problem: `${ALLOWED_HOSTS} is not valid JSON: ${e.message}` };
  }
}

// Connector entries by id (vendor/name), parsed, for the playbooks that name one.
export function connectorMap(connectors, allowedHosts) {
  const map = new Map();
  for (const c of connectors) {
    const info = connectorInfo(c, { allowedHosts });
    if (info) map.set(c.id, info);
  }
  return map;
}
