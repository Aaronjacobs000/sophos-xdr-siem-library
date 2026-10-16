#!/usr/bin/env node
// Ports gitleaks' generic-api-key rule to the library check and moves CI to the same gitleaks
// release, in one change, so the check that warns contributors and CI's secret scan stay aligned:
//
//   node tools/port-gitleaks.mjs <version> [--toml <gitleaks.toml>] [--checksums <checksums.txt>]
//
// It reads config/gitleaks.toml at the release's tag and the release's checksums file from GitHub,
// or the files given, writes studio/core/gitleaks-rule.js, sets GITLEAKS_VERSION and GITLEAKS_SHA256
// in .github/workflows/ci.yml, and sets the version ATTRIBUTIONS.md credits. Read the diff, then run
// npm test: with that gitleaks on the PATH, as in CI, the tests check the port finds what it finds.

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { portFromConfig, renderModule, setCiVersion, setAttributionVersion, tarballSha256 } from './lib/gitleaks-port.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i === -1 ? null : args[i + 1]; };
const version = (args[0] || '').replace(/^v/, '');
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error('usage: node tools/port-gitleaks.mjs <version> [--toml <gitleaks.toml>] [--checksums <checksums.txt>]');
  process.exit(2);
}

async function fetchText(url) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`${url}: ${res.status} ${res.statusText}`);
  return res.text();
}

const source = `https://raw.githubusercontent.com/gitleaks/gitleaks/v${version}/config/gitleaks.toml`;
const toml = opt('--toml') ? await readFile(opt('--toml'), 'utf8') : await fetchText(source);
const checksums = opt('--checksums') ? await readFile(opt('--checksums'), 'utf8')
  : await fetchText(`https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_checksums.txt`);

const { rule, globals } = portFromConfig(toml);
const sha256 = createHash('sha256').update(toml).digest('hex');
await writeFile(path.join(ROOT, 'studio/core/gitleaks-rule.js'), renderModule({ version, source, sha256, rule, globals }));
const ciPath = path.join(ROOT, '.github/workflows/ci.yml');
await writeFile(ciPath, setCiVersion(await readFile(ciPath, 'utf8'), version, tarballSha256(checksums, version)));
const credits = path.join(ROOT, 'ATTRIBUTIONS.md');
await writeFile(credits, setAttributionVersion(await readFile(credits, 'utf8'), version));
console.log(`ported ${rule.id} from gitleaks ${version} (${rule.allowlists.length} rule allowlists, ${globals.length} global) and set CI to gitleaks ${version}`);
