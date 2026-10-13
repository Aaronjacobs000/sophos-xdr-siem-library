// Which changed paths keep a pull request from merging without review. Library entries under
// parsers/ are inert text and can merge on their own once the checks pass. Collectors are code
// that people download and run, so a maintainer reviews every change to them, and anything
// else is the site or its tooling. Used by validate-library.mjs when it decides eligibility,
// and again by github-gate.mjs on the pull request's real file list right before it merges.

const list = (a) => a.slice(0, 10).join(', ') + (a.length > 10 ? ` and ${a.length - 10} more` : '');

export function reviewReasons(paths) {
  const clean = paths.map((p) => String(p || '').trim()).filter(Boolean);
  const collectors = clean.filter((p) => p.startsWith('collectors/'));
  const outside = clean.filter((p) => !p.startsWith('parsers/') && !p.startsWith('collectors/'));
  const out = [];
  if (collectors.length) out.push(`changes collector code, which a maintainer always reviews: ${list(collectors)}`);
  if (outside.length) out.push(`changes files outside parsers/: ${list(outside)}`);
  return out;
}
