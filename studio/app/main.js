import { state, emit, subscribe } from './store.js';
import { loadLibrary } from './library-client.js';
import { renderSample } from './views/sample.js';
import { renderMap } from './views/map.js';
import { renderTest } from './views/test.js';
import { renderLibrary, renderEntry } from './views/library.js';
import { renderHelp } from './views/help.js';
import { renderHome } from './views/home.js';
import { TOOL_VERSION, SITE_NAME } from '../core/version.js';
import { routeOf } from './routes.js';
import { clear } from './dom.js';

const app = document.getElementById('app');

function route() {
  const r = routeOf(location.hash);
  // Links from before the parser library moved to #/parsers keep working, and show the new address.
  if (r.canonical !== null && r.canonical !== location.hash) history.replaceState(null, '', r.canonical);
  for (const a of document.querySelectorAll('[data-nav]')) a.classList.toggle('on', a.dataset.nav === r.nav);
  document.title = r.title ? `${r.title} | ${SITE_NAME}` : SITE_NAME;
  clear(app);
  if (r.view === 'entry') renderEntry(app, r.id);
  else if (r.view === 'parsers') renderLibrary(app);
  else if (r.view === 'help') renderHelp(app);
  else if (r.view === 'home') renderHome(app);
  else if (r.step === 'map' && state.plan) renderMap(app);
  else if (r.step === 'test' && state.parsers) renderTest(app);
  else renderSample(app);
  app.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function updateMeta() {
  const el = document.getElementById('top-meta');
  const n = state.library.entries.reduce((k, e) => k + ((e.meta && Array.isArray(e.meta.parsers)) ? e.meta.parsers.length : 0), 0);
  el.textContent = `v${TOOL_VERSION} · MIT · library: ${state.library.status === 'ready' ? `${n} parsers` : 'loading'}`;
}

export async function refreshLibrary() {
  state.library.status = 'loading';
  emit('library');
  const r = await loadLibrary();
  Object.assign(state.library, { status: 'ready', entries: r.entries, bridges: r.bridges || [], source: r.source, at: r.at, sha: r.sha || null, error: r.error || null });
  emit('library');
}

window.addEventListener('hashchange', route);
window.addEventListener('parser-studio:refresh-library', () => refreshLibrary());
subscribe((what) => {
  if (what !== 'library') return;
  updateMeta();
  if (routeOf(location.hash).library) route();
});
route();
updateMeta();
refreshLibrary();
