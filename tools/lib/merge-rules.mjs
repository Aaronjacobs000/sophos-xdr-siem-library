// Which changed paths keep a pull request from merging without review. Library entries under
// parsers/ are inert text and can merge on their own once the checks pass. Bridges are code
// that people download and run, and playbooks and connectors act on tenants, so the owner reviews
// every change to them. Anything else is the site or its tooling, including the old collectors/
// folder that a branch from before the rename may still touch. Used by validate-library.mjs when
// it decides eligibility, and again by github-gate.mjs on the pull request's real file list right
// before it merges.

const list = (a) => a.slice(0, 10).join(', ') + (a.length > 10 ? ` and ${a.length - 10} more` : '');

// Paths are compared exactly as GitHub lists them. Trimming would read a top-level folder such as
// " parsers" as parsers/.
export function reviewReasons(paths) {
  const clean = paths.map((p) => String(p || '')).filter(Boolean);
  const bridges = clean.filter((p) => p.startsWith('bridges/'));
  const automation = clean.filter((p) => p.startsWith('playbooks/') || p.startsWith('connectors/'));
  const outside = clean.filter((p) => !p.startsWith('parsers/') && !p.startsWith('bridges/') && !p.startsWith('playbooks/') && !p.startsWith('connectors/'));
  const out = [];
  if (bridges.length) out.push(`changes bridge code, which a maintainer always reviews: ${list(bridges)}`);
  if (automation.length) out.push(`changes playbooks or connectors, which act on tenants, so the owner always reviews them: ${list(automation)}`);
  if (outside.length) out.push(`changes files outside parsers/: ${list(outside)}`);
  return out;
}
