// Talks to the emulator worker. A job that runs past the time limit is stopped and the
// worker restarted, so a pattern that backtracks in this browser can't freeze the page.
// Go's RE2 engine, which Sophos NG-SIEM uses, runs in linear time and would not hang.

const LIMIT_MS = 5000;
let worker = null;
let seq = 0;
const pending = new Map();

function start() {
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = (e) => {
    const job = pending.get(e.data.id);
    if (!job) return;
    pending.delete(e.data.id);
    clearTimeout(job.timer);
    if (e.data.ok) job.resolve(e.data.result); else job.reject(new Error(e.data.error));
  };
  worker.onerror = (e) => {
    for (const job of pending.values()) { clearTimeout(job.timer); job.reject(new Error(e.message || 'the emulator worker failed')); }
    pending.clear();
  };
}

export function call(kind, payload) {
  if (!worker) start();
  const id = ++seq;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      worker.terminate();
      worker = null;
      for (const job of pending.values()) { clearTimeout(job.timer); job.reject(new Error('cancelled')); }
      pending.clear();
      reject(new Error(`The emulator stopped after ${LIMIT_MS / 1000} seconds. A regex is probably backtracking in this browser; Sophos NG-SIEM uses Go's RE2 engine, which would not hang, but simplify nested quantifiers such as (a+)+ to test here.`));
    }, LIMIT_MS);
    pending.set(id, { resolve, reject, timer });
    worker.postMessage({ id, kind, payload });
  });
}
