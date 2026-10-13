import { state, emit, subscribe } from './store.js';
import { loadLibrary } from './library-client.js';
import { renderSample } from './views/sample.js';
import { renderMap } from './views/map.js';
import { renderTest } from './views/test.js';
import { renderLibrary, renderEntry } from './views/library.js';
import { renderHelp } from './views/help.js';
import { TOOL_VERSION } from '../core/version.js';
import { clear } from './dom.js';

const app = document.getElementById('app');

function route() {
  const hash = location.hash.replace(/^#\/?/, '') || 'build/sample';
  const parts = hash.split('/').map((p) => { try { return decodeURIComponent(p); } catch { return p; } });
  for (const a of document.querySelectorAll('[data-nav]')) a.classList.toggle('on', a.dataset.nav === parts[0]);
  clear(app);
  if (parts[0] === 'library' && parts.length >= 3) renderEntry(app, `${parts[1]}/${parts[2]}`);
  else if (parts[0] === 'library') renderLibrary(app);
  else if (parts[0] === 'help') renderHelp(app);
  else if (parts[1] === 'map' && state.plan) renderMap(app);
  else if (parts[1] === 'test' && state.parsers) renderTest(app);
  else renderSample(app);
  app.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function updateMeta() {
  const el = document.getElementById('top-meta');
  const n = state.library.entries.reduce((k, e) => k + ((e.meta && Array.isArray(e.meta.parsers)) ? e.meta.parsers.length : 0), 0);
  el.textContent = `v${TOOL_VERSION} · MIT · library: ${state.library.status === 'ready' ? `${n} parsers` : 'loading'}`;
}

export async function refreshLibrary(force = false) {
  state.library.status = 'loading';
  emit('library');
  const r = await loadLibrary({ force });
  Object.assign(state.library, { status: 'ready', entries: r.entries, source: r.source, at: r.at, error: r.error || null });
  emit('library');
}

window.addEventListener('hashchange', route);
window.addEventListener('parser-studio:refresh-library', () => refreshLibrary(true));
subscribe((what) => {
  if (what !== 'library') return;
  updateMeta();
  if (/^#\/library/.test(location.hash || '')) route();
});
route();
updateMeta();
refreshLibrary();
