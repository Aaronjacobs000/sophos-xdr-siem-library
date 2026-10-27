// The visit counter: the bundled count.js is GoatCounter's published v5 file, the page loads it
// with its own counting off, and each count carries the route and, on the first one, the referring
// site's origin. Nothing else from the address, the page or what is typed into it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { countPath, referrerOrigin, beaconUrl, startCounting } from '../studio/app/analytics.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENDPOINT = 'https://xdr-siem-library.goatcounter.com/count';
// The hash GoatCounter publishes for count.v5.js (goatcounter.com/help/countjs-versions).
const V5_SRI = 'sha384-atnOLvQb9t+jTSipvd75X2yginT4PjVbqDdlJAmxMm+wYElFmeR6EmLP5bYeoRVQ';
const COUNT_JS = path.join(ROOT, 'studio/app/vendor/goatcounter-count.v5.js');

test('count.js is GoatCounter\'s v5 file unchanged, and the page loads it with its own counting off', async () => {
  const js = await readFile(COUNT_JS);
  assert.equal(`sha384-${createHash('sha384').update(js).digest('base64')}`, V5_SRI);
  assert.match(js.toString(), /^\/\/ GoatCounter: https:\/\/www\.goatcounter\.com\n\/\/ This file is released under the ISC license/);
  const html = await readFile(path.join(ROOT, 'studio/index.html'), 'utf8');
  const tag = /<script src="app\/vendor\/goatcounter-count\.v5\.js"[^>]*><\/script>/.exec(html)[0];
  assert.match(tag, new RegExp(`integrity="${V5_SRI.replace(/[+/]/g, '\\$&')}"`));
  assert.match(tag, new RegExp(`data-goatcounter="${ENDPOINT}"`));
  assert.deepEqual(JSON.parse(/data-goatcounter-settings='([^']+)'/.exec(tag)[1]), { no_onload: true, no_events: true });
  assert.ok(html.indexOf(tag) < html.indexOf('src="app/main.js"'), 'count.js runs before the page\'s module');
});

test('the content security policy keeps scripts and images on the site and allows only the count endpoint', async () => {
  const html = await readFile(path.join(ROOT, 'studio/index.html'), 'utf8');
  const csp = Object.fromEntries(/http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1]
    .split(';').map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v.join(' ')]));
  assert.equal(csp['script-src'], "'self'");
  assert.equal(csp['img-src'], "'self' data:");
  assert.equal(csp['connect-src'], `'self' ${ENDPOINT}`);
  assert.equal(Object.values(csp).filter((v) => v.includes('goatcounter')).length, 1);
});

test('countPath sends the route only', () => {
  const cases = {
    '': '/', '#': '/', '#/': '/', '#/nothing-here': '/', '#toggle-goatcounter': '/',
    '#/parsers': '/parsers', '#/library': '/parsers',
    '#/parsers/kiteworks/kiteworks-private-data-network': '/parsers/kiteworks/kiteworks-private-data-network',
    '#/library/eset/eset-protect-on-prem': '/parsers/eset/eset-protect-on-prem',
    '#/parsers/acme/thing/extra/parts': '/parsers/acme/thing',
    '#/parsers/acme/a%20b': '/parsers/unknown',
    '#/parsers/acme/thing?sample=Oct 14 01:02:03 host secret': '/parsers/unknown',
    '#/parsers/Acme/Thing': '/parsers/unknown',
    [`#/parsers/acme/${'a'.repeat(61)}`]: '/parsers/unknown',
    '#/playbooks': '/playbooks', '#/connectors': '/connectors',
    '#/playbooks/sophos/sophos-mobile-lock': '/playbooks/sophos/sophos-mobile-lock',
    '#/connectors/sophos/sophos-mobile': '/connectors/sophos/sophos-mobile',
    '#/connectors/sophos/<script>': '/connectors/unknown',
    '#/help': '/help', '#/help/anything': '/help',
    '#/build': '/build/sample', '#/build/sample': '/build/sample', '#/build/map': '/build/map', '#/build/test': '/build/test',
    '#/build/my pasted line': '/build/sample',
  };
  for (const [hash, want] of Object.entries(cases)) assert.equal(countPath(hash), want, JSON.stringify(hash));
});

test('referrerOrigin keeps the scheme and host only', () => {
  assert.equal(referrerOrigin('https://www.google.com/search?q=sophos+parser'), 'https://www.google.com');
  assert.equal(referrerOrigin('https://github.com/Aaronjacobs000/sophos-xdr-siem-library#readme'), 'https://github.com');
  for (const r of ['', 'not a url', 'android-app://com.slack/', 'file:///tmp/x.html']) assert.equal(referrerOrigin(r), '', r);
});

test('beaconUrl drops every parameter but the path, referrer, bot flag and cache buster', () => {
  assert.equal(beaconUrl(`${ENDPOINT}?p=%2Fhelp&r=https%3A%2F%2Fgithub.com&t=Title&e=false&s=1920&b=0&q=%3Fsample%3Dx&rnd=ab12c#x`),
    `${ENDPOINT}?p=%2Fhelp&r=https%3A%2F%2Fgithub.com&b=0&rnd=ab12c`);
  assert.equal(beaconUrl('http://xdr-siem-library.goatcounter.com/count?p=%2F'), null);
  assert.equal(beaconUrl(undefined), null);
});

// A page at the site's address with the real count.js loaded, as index.html loads it.
async function page({ hash = '', search = '', referrer = '', visibility = 'visible', skip = null } = {}) {
  const beacons = [];
  const listeners = {};
  const on = (target) => ({
    addEventListener: (type, f) => { (listeners[`${target}:${type}`] ||= []).push(f); },
    removeEventListener: (type, f) => { listeners[`${target}:${type}`] = (listeners[`${target}:${type}`] || []).filter((g) => g !== f); },
  });
  const location = { hash, search, hostname: 'aaronjacobs000.github.io', protocol: 'https:', pathname: '/sophos-xdr-siem-library/' };
  const script = { dataset: { goatcounter: ENDPOINT, goatcounterSettings: '{"no_onload": true, "no_events": true}' } };
  const document = {
    ...on('document'),
    body: {}, title: 'Unofficial Sophos Fusion XDR and SIEM Library', referrer, visibilityState: visibility,
    querySelector: (sel) => (sel === 'script[data-goatcounter]' ? script : null),
    querySelectorAll: () => [],
  };
  const win = {
    ...on('window'),
    document, location, console,
    navigator: { webdriver: false, sendBeacon: (url) => { beacons.push(url); return true; } },
    screen: { width: 1920, height: 1080 }, devicePixelRatio: 2,
    localStorage: { getItem: (k) => (k === 'skipgc' ? skip : null), setItem() {}, removeItem() {} },
  };
  win.window = win;
  win.parent = win;
  vm.createContext(win);
  vm.runInContext(await readFile(COUNT_JS, 'utf8'), win);
  startCounting(win);
  const fire = (target, type) => { for (const f of listeners[`${target}:${type}`] || []) f({}); };
  const go = (h) => { location.hash = h; fire('window', 'hashchange'); };
  const show = () => { document.visibilityState = 'visible'; fire('document', 'visibilitychange'); };
  const sent = () => beacons.map((u) => Object.fromEntries(new URL(u).searchParams));
  return { beacons, sent, go, show };
}

test('the page sends one count per route, with the route and the first referrer only', async () => {
  const p = await page({ hash: '#/parsers', search: '?sample=Oct%2014%20host%20secret', referrer: 'https://www.google.com/search?q=sophos' });
  p.go('#/parsers/kiteworks/kiteworks-private-data-network');
  p.go('#/parsers/kiteworks/kiteworks-private-data-network');
  p.go('#/build/sample');
  p.go('#/build/map');
  p.go('#/parsers/acme/thing?pasted=secret');
  assert.ok(p.beacons.every((u) => u.startsWith(`${ENDPOINT}?`)));
  const sent = p.sent();
  assert.deepEqual(sent.map((s) => s.p), ['/parsers', '/parsers/kiteworks/kiteworks-private-data-network', '/build/sample', '/build/map', '/parsers/unknown']);
  assert.deepEqual(sent.map((s) => s.r), ['https://www.google.com', undefined, undefined, undefined, undefined]);
  for (const s of sent) {
    assert.deepEqual(Object.keys(s).filter((k) => !['p', 'r', 'b', 'rnd'].includes(k)), [], JSON.stringify(s));
    assert.equal(s.b, '0');
  }
  assert.ok(!p.beacons.join(' ').includes('secret'));
});

test('the page waits until it is shown, and counts nothing when GoatCounter is toggled off', async () => {
  const hidden = await page({ hash: '#/help', visibility: 'hidden' });
  assert.equal(hidden.beacons.length, 0);
  hidden.show();
  assert.deepEqual(hidden.sent().map((s) => s.p), ['/help']);
  const off = await page({ hash: '#/help', skip: 't' });
  off.go('#/parsers');
  assert.equal(off.beacons.length, 0);
});
