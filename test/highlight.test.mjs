// Syntax coloring for sample lines and parser scripts: what it marks, and that a long line from a
// library entry colors in time linear in its length.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { highlightSample, highlightScriptLine } from '../studio/app/highlight.js';

// Just enough of the DOM for highlight.js: nodes as [class, text] pairs.
globalThis.document = {
  createElement: () => ({ className: '', textContent: '' }),
  createTextNode: (t) => ({ className: null, textContent: t }),
  createDocumentFragment: () => ({ nodes: [], append(...n) { for (const x of n) { if (x.nodes) this.nodes.push(...x.nodes); else this.nodes.push(x); } } }),
};
const pairs = (f) => f.nodes.map((n) => [n.className, n.textContent]);
const text = (f) => f.nodes.map((n) => n.textContent).join('');

test('sample lines: keys, strings and numbers are marked', () => {
  assert.deepEqual(pairs(highlightSample('src.ip=192.0.2.1 "user": "a\\"b" n=5')).filter(([c]) => c), [
    ['tk-k', 'src.ip'], ['tk-n', '192.0'], ['tk-n', '2.1'], ['tk-k', '"user"'], ['tk-s', '"a\\"b"'], ['tk-k', 'n'], ['tk-n', '5'],
  ]);
  assert.deepEqual(pairs(highlightScriptLine('x$ = LOWER("a\\"b") # note')).filter(([c]) => c), [
    ['tk-v', 'x$'], ['tk-f', 'LOWER'], ['tk-s', '"a\\"b"'], ['tk-c', '# note'],
  ]);
});

test('a long line from a library entry colors in linear time', () => {
  // Each of these used to rescan the rest of the line from almost every position.
  const lines = [
    'k.'.repeat(8190),
    `"${'\\"'.repeat(8190)}`,
    `'${"\\'".repeat(8190)}`,
    `${'a.b-c'.repeat(3270)}x=1`,
  ];
  const t0 = performance.now();
  for (let round = 0; round < 10; round++) {
    for (const line of lines) {
      assert.equal(text(highlightSample(line)), line);
      assert.equal(text(highlightScriptLine(line)), line);
    }
  }
  const ms = performance.now() - t0;
  assert.ok(ms < 1500, `took ${Math.round(ms)} ms`);
  // The key at the end of a long dotted run is still found.
  assert.deepEqual(pairs(highlightSample(lines[3])).filter(([c]) => c === 'tk-k').map(([, t]) => t.length), [16351]);
});
