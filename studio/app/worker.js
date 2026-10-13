// Runs the emulator off the main thread so a slow regex can be stopped.

import { lintParsers } from '../core/lint.js';
import { runParsers } from '../core/engine.js';
import { validateEntry } from '../core/library.js';

self.onmessage = (e) => {
  const { id, kind, payload } = e.data;
  try {
    let result;
    if (kind === 'lint') result = lintParsers(payload.parsers, { samples: payload.samples, now: payload.now, library: payload.library, selfId: payload.selfId });
    else if (kind === 'run') result = runParsers(payload.parsers, payload.samples, { now: payload.now });
    else if (kind === 'validate') result = validateEntry(payload.entry, { library: payload.library });
    else throw new Error(`unknown job ${kind}`);
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message ? err.message : err) });
  }
};
