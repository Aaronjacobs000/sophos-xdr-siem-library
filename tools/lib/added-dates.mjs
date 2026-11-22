// When each library entry was added: the commit time of the commit that first added its meta.json,
// read from git history, for the site's Newest sort. Renames are read as an add, so a moved entry
// dates from the move. A shallow clone has no history to read and gets no dates.

import { execFileSync } from 'node:child_process';

const META = /^(parsers|rules|playbooks|connectors)\/([a-z0-9]+(?:-[a-z0-9]+)*)\/([a-z0-9]+(?:-[a-z0-9]+)*)\/meta\.json$/;

// Reads `git log --format=%x00%cI --name-only` output: a NUL and a commit time, then the files it
// added. Returns a Map of '<section>/<vendor>/<name>' to the earliest time, as UTC ISO.
export function parseAddedLog(text) {
  const out = new Map();
  let when = null;
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('\0')) {
      const t = Date.parse(line.slice(1));
      when = Number.isFinite(t) ? t : null;
      continue;
    }
    const m = META.exec(line);
    if (!m || when === null) continue;
    const key = `${m[1]}/${m[2]}/${m[3]}`;
    if (!out.has(key) || when < Date.parse(out.get(key))) out.set(key, new Date(when).toISOString());
  }
  return out;
}

export function addedDates(root) {
  const git = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  try {
    if (git(['rev-parse', '--is-shallow-repository']).trim() !== 'false') return new Map();
    return parseAddedLog(git(['log', '--no-renames', '--diff-filter=A', '--format=%x00%cI', '--name-only', '--',
      'parsers/*/*/meta.json', 'rules/*/*/meta.json', 'playbooks/*/*/meta.json', 'connectors/*/*/meta.json']));
  } catch {
    return new Map();
  }
}
