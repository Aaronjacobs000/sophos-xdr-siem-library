// The library entries git tracks in a checkout, as vendor/product ids, or null when the folder isn't
// a git checkout. Tests that check the whole library check these only, so an entry that is only on
// disk, such as one written for a bridge that isn't on this branch yet, doesn't fail npm test.
// npm run validate still checks every entry on disk.
import { execFileSync } from 'node:child_process';

export function trackedEntries(root) {
  let out;
  try {
    out = execFileSync('git', ['ls-files', '-z', '--', 'parsers'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return null;
  }
  const ids = new Set(out.split('\0').map((f) => f.split('/')).filter((p) => p.length >= 4).map((p) => `${p[1]}/${p[2]}`));
  // No tracked entry at all means the library isn't this checkout's, so every entry counts.
  return ids.size ? ids : null;
}

export const isTracked = (tracked, id) => tracked === null || tracked.has(id);
