// A small code editor: a transparent textarea over a highlighted <pre>, with line numbers
// and markers for lines the lint flags.

import { h, clear } from './dom.js';
import { highlightScript } from './highlight.js';

export function createEditor({ value = '', onChange, readOnly = false, label = 'Parser script' } = {}) {
  const gutter = h('div', { class: 'gutter', 'aria-hidden': 'true' });
  const pre = h('pre', { 'aria-hidden': 'true' });
  const ta = h('textarea', { spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', 'aria-label': label, wrap: 'off' });
  ta.value = value;
  ta.readOnly = readOnly;
  const area = h('div', { class: 'area' }, pre, ta);
  const stack = h('div', { class: 'stack' }, gutter, area);
  const root = h('div', { class: 'editor' }, stack);
  let markers = new Map();
  let timer = null;

  function sizeToContent() {
    // The textarea sits over the <pre>; make it as tall and wide as the highlighted text.
    ta.style.height = '0px';
    ta.style.width = '0px';
    const w = Math.max(pre.scrollWidth, area.clientWidth);
    const hgt = Math.max(pre.scrollHeight, 340);
    ta.style.width = `${w}px`;
    ta.style.height = `${hgt}px`;
  }

  function render() {
    clear(pre);
    pre.append(highlightScript(ta.value));
    pre.append(document.createTextNode('\n'));
    clear(gutter);
    const n = ta.value.split('\n').length;
    for (let i = 1; i <= n; i++) {
      const m = markers.get(i);
      const el = h('span', { class: `mk${m ? ` ${m.level}` : ''}`, text: String(i) });
      if (m) el.title = m.message;
      gutter.append(el);
    }
    requestAnimationFrame(sizeToContent);
  }

  ta.addEventListener('input', () => {
    render();
    clearTimeout(timer);
    timer = setTimeout(() => onChange && onChange(ta.value), 350);
  });
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !e.shiftKey && !readOnly) {
      e.preventDefault();
      const { selectionStart: s, selectionEnd: t } = ta;
      ta.setRangeText('    ', s, t, 'end');
      ta.dispatchEvent(new Event('input'));
    }
  });
  render();

  return {
    el: root,
    get value() { return ta.value; },
    set value(v) { ta.value = v; render(); },
    setMarkers(list) {
      markers = new Map();
      const rank = { error: 0, warning: 1, inferred: 2 };
      for (const m of list) {
        if (!m.line || !(m.level in rank)) continue;
        const cur = markers.get(m.line);
        if (!cur || rank[m.level] < rank[cur.level]) markers.set(m.line, m);
      }
      render();
    },
    focusLine(line) {
      const lines = ta.value.split('\n');
      const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
      ta.focus();
      ta.setSelectionRange(start, start + (lines[line - 1] || '').length);
      stack.scrollTop = Math.max(0, (line - 4) * 20);
    },
    refresh: render,
  };
}
