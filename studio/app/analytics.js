// Visit counts with GoatCounter (goatcounter.com). index.html loads GoatCounter's count.js
// (vendor/goatcounter-count.v5.js, the published v5 file as is) with its own counting turned off, and
// this module decides what each count carries: the route, such as /parsers/<vendor>/<product>, on
// load and on every hash change, and the origin of the site that linked here on the first count
// only. It never sends the query string, the hash beyond the route, the title or the screen size,
// so nothing typed or pasted into the page can reach GoatCounter.

import { routeOf } from './routes.js';

const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const STEPS = new Set(['sample', 'map', 'test']);
// The only parameters a count may carry: path, referrer, count.js's bot flag and its cache buster.
const KEEP = new Set(['p', 'r', 'b', 'rnd']);

const slugId = (id) => {
  const parts = String(id || '').split('/');
  return parts.length === 2 && parts.every((s) => s.length <= 60 && SLUG.test(s));
};

// The path GoatCounter gets for an address: the route the page shows, built from fixed names and
// library slugs. An id that isn't two slugs counts as <section>/unknown, and an unknown address as
// the home, the same as the page treats it.
export function countPath(hash) {
  const r = routeOf(hash);
  if (r.view === 'entry') return slugId(r.id) ? `/parsers/${r.id}` : '/parsers/unknown';
  if (r.view === 'playbook' || r.view === 'connector') return slugId(r.id) ? `/${r.nav}/${r.id}` : `/${r.nav}/unknown`;
  if (r.view === 'parsers' || r.view === 'playbooks' || r.view === 'connectors') return `/${r.view}`;
  if (r.view === 'help') return '/help';
  if (r.view === 'studio') return `/build/${STEPS.has(r.step) ? r.step : 'sample'}`;
  return '/';
}

// The referring site's origin, such as https://github.com, or '' when there is none.
export function referrerOrigin(referrer) {
  try {
    const u = new URL(referrer);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : '';
  } catch {
    return '';
  }
}

// count.js's request URL with every parameter outside KEEP removed, or null if it isn't one.
export function beaconUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== 'https:') return null;
  for (const k of [...u.searchParams.keys()]) if (!KEEP.has(k)) u.searchParams.delete(k);
  u.hash = '';
  return u.href;
}

// Counts the page on load (once it is visible) and on every hash change. go() redraws a route with
// a hash change that doesn't change the address, so a repeat of the last counted path is skipped.
export function startCounting(win = globalThis) {
  const doc = win.document;
  let last = null;
  const send = (referrer) => {
    const gc = win.goatcounter;
    if (!gc || typeof gc.url !== 'function' || typeof gc.filter !== 'function') return;
    if (!win.navigator || typeof win.navigator.sendBeacon !== 'function') return;
    const path = countPath(win.location.hash);
    if (path === last) return;
    let url;
    try {
      // filter() skips localhost, file pages, frames, prerendering and #toggle-goatcounter.
      if (gc.filter()) return;
      url = beaconUrl(gc.url({ path, referrer }));
    } catch {
      return;
    }
    if (!url) return;
    last = path;
    win.navigator.sendBeacon(url);
  };
  const first = () => send(referrerOrigin(doc.referrer));
  if (doc.visibilityState === 'hidden') {
    const shown = () => {
      if (doc.visibilityState === 'hidden') return;
      doc.removeEventListener('visibilitychange', shown);
      first();
    };
    doc.addEventListener('visibilitychange', shown);
  } else {
    first();
  }
  win.addEventListener('hashchange', () => send(''));
}
