// Stars on library entries. The counts come from the library API, a Cloudflare Worker on its own
// hostname (library-api/ in the repo). The page asks it for every count once, in the background.
// Until it answers, and for good if it fails or takes too long, no star shows and the lists work as
// they do without it. A star sends only the entry's id. Which entries this browser starred is kept
// in localStorage, so there is no sign-in and no cookie.

import { h, pill, toast } from './dom.js';
import { popularIds } from './sort.js';

export const API = 'https://library-api.aaronjacobs.dev';
const KEY = 'library-stars';
const ID = /^(?:parsers|playbooks|connectors)\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/;
const KEEP = 2000;

function browserStorage() {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}

const counts = (o) => {
  const out = {};
  if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) if (ID.test(k) && Number.isInteger(v) && v > 0) out[k] = v;
  return out;
};

// The star state for one page. A tap changes the star and its count at once, then the API's answer
// sets the count; a failed request puts both back. Taps while a request is out are sent after it.
export function createStars({ api = API, fetchImpl = (...a) => globalThis.fetch(...a), storage = browserStorage(), timeoutMs = 5000, onChange = () => {}, onError = () => {} } = {}) {
  let stats = null;
  const popular = new Map();
  const mine = new Set();
  const want = new Map();
  const busy = new Set();
  try {
    const kept = JSON.parse((storage && storage.getItem(KEY)) || '[]');
    if (Array.isArray(kept)) for (const id of kept.slice(0, KEEP)) if (typeof id === 'string' && ID.test(id)) mine.add(id);
  } catch { /* blocked or unreadable storage: start with none */ }
  const save = () => {
    try {
      if (storage) storage.setItem(KEY, JSON.stringify([...mine]));
    } catch { /* blocked or full storage: the star still counts */ }
  };

  const call = async (path, method) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`${api}${path}`, { method, mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: ctl.signal });
      let body = null;
      try { body = await res.json(); } catch { body = null; }
      return { ok: res.ok, status: res.status, body };
    } finally {
      clearTimeout(timer);
    }
  };

  const self = {
    async load() {
      try {
        const r = await call('/v1/stats', 'GET');
        if (!r.ok || !r.body || typeof r.body !== 'object') return false;
        stats = { stars: counts(r.body.stars), views: counts(r.body.views) };
        popular.clear();
        return true;
      } catch {
        return false;
      }
    },
    ready: () => stats !== null,
    starred: (id) => (want.has(id) ? want.get(id) : mine.has(id)),
    count(id) {
      if (!stats) return 0;
      const base = stats.stars[id] || 0;
      if (!want.has(id) || want.get(id) === mine.has(id)) return base;
      return Math.max(0, base + (want.get(id) ? 1 : -1));
    },
    views: (id) => (stats && stats.views[id]) || 0,
    // The section's entries tagged Popular (see popularIds), none until the counts load.
    popular(section) {
      if (!stats) return new Set();
      if (!popular.has(section)) popular.set(section, popularIds(stats.views, section));
      return popular.get(section);
    },
    // The counts as shown, for sorting.
    snapshot() {
      if (!stats) return { stars: {}, views: {} };
      const stars = { ...stats.stars };
      for (const id of want.keys()) stars[id] = self.count(id);
      return { stars, views: { ...stats.views } };
    },
    async toggle(id) {
      if (!stats || !ID.test(id)) return;
      want.set(id, !self.starred(id));
      onChange(id);
      if (busy.has(id)) return;
      busy.add(id);
      try {
        while (want.has(id) && want.get(id) !== mine.has(id)) {
          const on = want.get(id);
          let r = null;
          try { r = await call(`/v1/stars/${id}`, on ? 'PUT' : 'DELETE'); } catch { r = null; }
          if (!r || !r.ok || !r.body || !Number.isInteger(r.body.stars)) {
            want.delete(id);
            onChange(id);
            onError(r ? r.status : 0);
            return;
          }
          if (r.body.stars > 0) stats.stars[id] = r.body.stars;
          else delete stats.stars[id];
          if (on) mine.add(id);
          else mine.delete(id);
          save();
          if (want.get(id) === on) want.delete(id);
          onChange(id);
        }
        if (want.has(id) && want.get(id) === mine.has(id)) {
          want.delete(id);
          onChange(id);
        }
      } finally {
        busy.delete(id);
      }
    },
  };
  return self;
}

export const stars = createStars({
  onChange: (id) => paintStars(id),
  onError: (status) => toast(status === 429 ? 'Too many stars in a row. Try again in a minute.' : 'Your star didn\'t save. Try again later.'),
});

const SVG = 'http://www.w3.org/2000/svg';
function icon() {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const p = document.createElementNS(SVG, 'path');
  p.setAttribute('d', 'M12 2.8l2.83 5.73 6.32.92-4.57 4.46 1.08 6.3L12 17.24l-5.66 2.97 1.08-6.3-4.57-4.46 6.32-.92z');
  svg.append(p);
  return svg;
}

function fill(slot) {
  const id = slot.dataset.star;
  let b = slot.firstElementChild;
  if (!b) {
    b = h('button', { type: 'button', class: 'star', onclick: (ev) => { ev.preventDefault(); stars.toggle(id); } }, icon(), h('span', { class: 'n' }));
    slot.append(b);
  }
  const on = stars.starred(id);
  const n = stars.count(id);
  b.classList.toggle('on', on);
  b.setAttribute('aria-pressed', String(on));
  b.setAttribute('aria-label', `Star ${slot.dataset.name}, ${n} ${n === 1 ? 'star' : 'stars'}`);
  b.title = on ? 'Take your star back' : 'Star this';
  b.lastElementChild.textContent = String(n);
}

// Where an entry's star goes: empty until the counts load, then a button. id is the section and
// the entry's id, such as parsers/acme/widget; name says which entry it is to a screen reader.
export function starSlot(id, name) {
  const slot = h('span', { class: 'starslot', dataset: { star: id, name } });
  if (stars.ready()) fill(slot);
  return slot;
}

function fillPopular(slot) {
  const id = slot.dataset.popular;
  const on = stars.popular(id.split('/')[0]).has(id);
  if (on && !slot.firstElementChild) {
    const tag = pill('Popular', 'popular');
    tag.title = 'One of the most viewed in this list';
    slot.append(tag);
  } else if (!on && slot.firstElementChild) slot.firstElementChild.remove();
}

// Where a card's Popular tag goes, in its row of pills: empty until the counts load, then the tag
// when the entry is one of its section's most viewed. id is as for starSlot.
export function popularSlot(id) {
  const slot = h('span', { class: 'popslot', dataset: { popular: id } });
  if (stars.ready()) fillPopular(slot);
  return slot;
}

// Draws the stars on the page, or only one entry's, and turns on the sorts that need the counts and
// the Popular tags.
export function paintStars(id = null) {
  if (typeof document === 'undefined' || !stars.ready()) return;
  for (const slot of document.querySelectorAll(id ? `.starslot[data-star="${id}"]` : '.starslot[data-star]')) fill(slot);
  if (id) return;
  for (const o of document.querySelectorAll('select[data-sort] option[data-needs="stats"]')) o.disabled = false;
  for (const slot of document.querySelectorAll('.popslot[data-popular]')) fillPopular(slot);
}

export async function loadStars() {
  if (await stars.load()) paintStars();
}
