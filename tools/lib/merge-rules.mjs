// Which changed paths keep a pull request from merging without review. Library entries under
// parsers/ are inert text and can merge on their own once the checks pass. Bridges are code
// that people download and run, and playbooks and connectors act on tenants, so the owner reviews
// every change to them. Rules act on tenants the same way: a detection rule makes detections, and a
// bad case rule takes detections away from other case rules, so the owner reviews them too. Anything else is the site or its tooling, including the old collectors/
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
  const rules = clean.filter((p) => p.startsWith('rules/'));
  const outside = clean.filter((p) => !p.startsWith('parsers/') && !p.startsWith('bridges/') && !p.startsWith('playbooks/') && !p.startsWith('connectors/') && !p.startsWith('rules/'));
  const out = [];
  if (bridges.length) out.push(`changes bridge code, which a maintainer always reviews: ${list(bridges)}`);
  if (automation.length) out.push(`changes playbooks or connectors, which act on tenants, so the owner always reviews them: ${list(automation)}`);
  if (rules.length) out.push(`changes rules, which act on tenants like playbooks and can take detections from other case rules, so the owner always reviews them: ${list(rules)}`);
  if (outside.length) out.push(`changes files outside parsers/: ${list(outside)}`);
  return out;
}
