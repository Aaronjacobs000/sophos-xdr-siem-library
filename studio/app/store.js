// App state. Kept in memory only: samples are never written to browser storage, so closing
// the tab forgets them.

export const state = {
  raw: '',
  fileName: null,
  lines: [],
  analysis: null,
  source: { vendor: '', product: '', version: '', shipMethod: 'syslog' },
  plan: null,
  mapTab: 0,
  parsers: null,       // [{name, role, parent, schema, text}]
  edited: false,       // parser text changed by hand since it was generated
  testTab: 0,
  selectedLine: 0,
  lint: null,
  running: false,
  runError: null,
  origin: null,        // {kind: 'library'|'fork', id, meta}
  now: null,           // reference time for the emulator
  library: { status: 'idle', entries: [], bridges: [], source: null, at: null, error: null },
};

const listeners = new Set();
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export function emit(what) { for (const fn of listeners) fn(what); }

export function sampleLines(raw) {
  return String(raw || '').replace(/\r\n?/g, '\n').split('\n').map((l) => l.replace(/\s+$/, '')).filter((l) => l.trim() !== '');
}
