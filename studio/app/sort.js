// The orders a library list can show. A to Z is by entry id, the order the site build writes, so
// the default is the list as it has always been. Most starred and Most viewed need the counts from
// the library API; Newest needs the dates the site build reads from git history. Ties, and entries
// with no count or date, stay in A to Z order.

export const SORTS = [
  { value: 'az', label: 'A to Z' },
  { value: 'stars', label: 'Most starred', needs: 'stats' },
  { value: 'views', label: 'Most viewed', needs: 'stats' },
  { value: 'newest', label: 'Newest', needs: 'added' },
];

const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const has = (o, k) => Boolean(o) && Object.prototype.hasOwnProperty.call(o, k);

// list is entries with {id, added?}; section is parsers, playbooks or connectors, which with the id
// names the entry in stars and views, as {'parsers/acme/widget': 3}.
export function sortEntries(list, sort, { section = 'parsers', stars = {}, views = {} } = {}) {
  const n = (m, e) => {
    const k = `${section}/${e.id}`;
    return has(m, k) && Number.isFinite(m[k]) ? m[k] : 0;
  };
  const when = (e) => {
    const t = typeof e.added === 'string' ? Date.parse(e.added) : NaN;
    return Number.isFinite(t) ? t : -Infinity;
  };
  const cmp = sort === 'stars' ? (a, b) => n(stars, b) - n(stars, a) || byId(a, b)
    : sort === 'views' ? (a, b) => n(views, b) - n(views, a) || byId(a, b)
      : sort === 'newest' ? (a, b) => (when(b) - when(a)) || byId(a, b)
        : byId;
  return [...list].sort(cmp);
}

// The entries a list tags Popular: its most viewed, at most POPULAR_TOP of them, each with at least
// POPULAR_MIN views, so thin data tags fewer or none. A tie across the last place tags none of the
// tied entries, so the tag never picks between equal counts. The view numbers are never shown.
// Returns ids as in views, such as 'parsers/acme/widget'.
export const POPULAR_TOP = 3;
export const POPULAR_MIN = 5;

export function popularIds(views, section, { top = POPULAR_TOP, min = POPULAR_MIN } = {}) {
  const rows = Object.entries(views && typeof views === 'object' ? views : {})
    .filter(([k, v]) => k.startsWith(`${section}/`) && Number.isFinite(v) && v >= min)
    .sort((a, b) => b[1] - a[1]);
  const cut = rows.length > top && rows[top][1] === rows[top - 1][1] ? rows[top][1] : -Infinity;
  return new Set(rows.slice(0, top).filter(([, v]) => v > cut).map(([k]) => k));
}
