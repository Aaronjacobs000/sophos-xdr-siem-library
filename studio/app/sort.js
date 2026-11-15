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
