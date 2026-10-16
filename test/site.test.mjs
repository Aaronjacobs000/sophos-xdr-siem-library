// The site's addresses and build: the home is the library, Parser Studio and the parser library keep
// the hash routes they had before the site had sections, and the build publishes everything the
// page reads next to it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { routeOf } from '../studio/app/routes.js';
import { trackedEntries, isTracked } from './tracked.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('routes: the empty address is the home, and the studio and help keep their addresses', () => {
  for (const hash of ['', '#', '#/']) assert.equal(routeOf(hash).view, 'home', JSON.stringify(hash));
  assert.deepEqual(['#/build/sample', '#/build/map', '#/build/test', '#/build'].map((h) => [routeOf(h).view, routeOf(h).step]), [['studio', 'sample'], ['studio', 'map'], ['studio', 'test'], ['studio', 'sample']]);
  assert.equal(routeOf('#/help').view, 'help');
  assert.equal(routeOf('#/nothing-here').view, 'home');
});

test('routes: the parser library\'s old addresses land on the same page under #/parsers', () => {
  const list = routeOf('#/library');
  assert.equal(list.view, 'parsers');
  assert.equal(list.canonical, '#/parsers');
  const entry = routeOf('#/library/eset/eset-protect-on-prem');
  assert.equal(entry.view, 'entry');
  assert.equal(entry.id, 'eset/eset-protect-on-prem');
  assert.equal(entry.canonical, '#/parsers/eset/eset-protect-on-prem');
  const now = routeOf('#/parsers/eset/eset-protect-on-prem');
  assert.deepEqual([now.view, now.id, now.canonical], ['entry', 'eset/eset-protect-on-prem', null]);
  assert.equal(routeOf('#/library/acme/a%20b').id, 'acme/a b');
});

test('routes: playbooks and connectors have a list and a page each', () => {
  assert.deepEqual(['#/playbooks', '#/connectors'].map((h) => routeOf(h).view), ['playbooks', 'connectors']);
  const pb = routeOf('#/playbooks/sophos/sophos-mobile-lock');
  assert.deepEqual([pb.view, pb.id, pb.nav], ['playbook', 'sophos/sophos-mobile-lock', 'playbooks']);
  const c = routeOf('#/connectors/sophos/sophos-mobile');
  assert.deepEqual([c.view, c.id, c.nav], ['connector', 'sophos/sophos-mobile', 'connectors']);
});

test('the site build publishes the index, the entry files and the bridges next to the page', async () => {
  const out = await mkdtemp(path.join(tmpdir(), 'xsl-site-'));
  try {
    execFileSync(process.execPath, [path.join(ROOT, 'tools/build-site.mjs'), '--out', out], { stdio: 'pipe' });
    const index = JSON.parse(await readFile(path.join(out, 'library-index.json'), 'utf8'));
    const tracked = trackedEntries(ROOT);
    const entries = index.entries.filter((e) => isTracked(tracked, e.id));
    assert.ok(entries.length > 100, `${entries.length} entries`);
    for (const e of entries) {
      assert.equal(e.texts, undefined, e.id);
      for (const p of e.meta.parsers) assert.ok((await stat(path.join(out, 'parsers', e.id, `${p.name}.parser.txt`))).isFile(), `${e.id} ${p.name}`);
      assert.ok((await stat(path.join(out, 'parsers', e.id, 'samples.log'))).isFile(), e.id);
    }
    const relay = index.bridges.find((b) => b.path === 'bridges/webhook-relay');
    assert.ok(relay.files.includes('README.md') && relay.files.includes('webhook_relay.py'));
    assert.ok((await stat(path.join(out, 'bridges/webhook-relay/webhook_relay.py'))).isFile());
    // Each bridge is listed by its path and files only, and the page reads it from that path.
    for (const b of index.bridges) assert.deepEqual(Object.keys(b).sort(), ['files', 'path'], b.path);
    // Playbooks and connectors: listed with their metadata, and their files published.
    assert.ok(Array.isArray(index.playbooks) && Array.isArray(index.connectors));
    for (const [folder, list] of [['playbooks', index.playbooks], ['connectors', index.connectors]]) {
      for (const e of list) {
        assert.ok(e.meta && e.meta.title, `${folder}/${e.id}`);
        for (const f of e.files) assert.ok((await stat(path.join(out, folder, e.id, f))).isFile(), `${folder}/${e.id}/${f}`);
      }
    }
    // The page itself, with the new name.
    const html = await readFile(path.join(out, 'index.html'), 'utf8');
    assert.match(html, /<title>Unofficial Sophos Fusion XDR and SIEM Library<\/title>/);
    assert.doesNotMatch(html, /sophos-ngsiem-parser-studio|community/i);
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});
