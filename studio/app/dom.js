// DOM helpers. Text always goes in through textContent, never innerHTML, because samples and
// library entries are untrusted.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = Boolean(v);
    else if (k === 'selected') el.selected = Boolean(v);
    else if (k === 'disabled') el.disabled = Boolean(v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'href') el.setAttribute('href', safeHref(v));
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// Only https links, same-page hash links, and relative links survive.
export function safeHref(v) {
  const s = String(v);
  if (s.startsWith('#') || s.startsWith('./') || /^https:\/\//i.test(s)) return s;
  return '#';
}

export function ext(href, ...children) {
  return h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, ...children);
}

export function pill(text, kind = 'grey') {
  return h('span', { class: `pill p-${kind}`, text });
}

let toastTimer = null;
export function toast(msg) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}

export async function copyText(text, what = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    toast(what);
    return true;
  } catch {
    const ta = h('textarea', { class: 'sr' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    toast(ok ? what : 'Copy failed. Select the text and copy it by hand.');
    return ok;
  }
}

export function download(name, data, type = 'application/octet-stream') {
  const blob = data instanceof Blob ? data : new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: '#', download: name });
  a.href = url;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function select(options, value, onchange, attrs = {}) {
  const el = h('select', { ...attrs, onchange: (e) => onchange(e.target.value) });
  for (const o of options) {
    if (o.group) {
      const g = h('optgroup', { label: o.group });
      for (const x of o.options) g.append(h('option', { value: x.value, selected: x.value === value, disabled: x.disabled, text: x.label ?? x.value }));
      el.append(g);
    } else {
      el.append(h('option', { value: o.value, selected: o.value === value, disabled: o.disabled, text: o.label ?? o.value }));
    }
  }
  return el;
}

export function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function isoTime(usec) {
  if (typeof usec !== 'number' || !Number.isFinite(usec)) return null;
  const d = new Date(Math.floor(usec / 1000));
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().replace('T', ' ').replace(/\.000Z$/, ' UTC').replace(/\.(\d{3})Z$/, '.$1 UTC');
}
