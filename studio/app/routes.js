// The page's hash routes, as {view, nav, title, canonical, library, id?, step?}: the home, the
// parser library, playbooks and connectors (#/playbooks/<vendor>/<name> for one), Parser Studio
// (#/build/<step>) and its help. The parser library
// was at #/library before the site had sections, so #/library and #/library/<vendor>/<product> still
// work and canonical gives the #/parsers address that replaces them. library is true for the views
// that show the library, which draw again when it loads.

const decode = (p) => { try { return decodeURIComponent(p); } catch { return p; } };

export function routeOf(hash) {
  const raw = String(hash || '').replace(/^#\/?/, '');
  if (!raw) return { view: 'home', nav: 'home', title: '', canonical: null, library: true };
  const parts = raw.split('/').map(decode);
  const head = parts[0];
  if (head === 'parsers' || head === 'library') {
    const canonical = head === 'library' ? `#/parsers${raw.slice('library'.length)}` : null;
    if (parts.length >= 3) return { view: 'entry', nav: 'parsers', title: 'Parsers', canonical, library: true, id: `${parts[1]}/${parts[2]}` };
    return { view: 'parsers', nav: 'parsers', title: 'Parsers', canonical, library: true };
  }
  if (head === 'playbooks' || head === 'connectors') {
    const title = head === 'playbooks' ? 'Playbooks' : 'Connectors';
    if (parts.length >= 3) return { view: head.slice(0, -1), nav: head, title, canonical: null, library: true, id: `${parts[1]}/${parts[2]}` };
    return { view: head, nav: head, title, canonical: null, library: true };
  }
  if (head === 'help') return { view: 'help', nav: 'help', title: 'How Parser Studio works', canonical: null, library: false };
  if (head === 'build') return { view: 'studio', nav: 'build', title: 'Parser Studio', canonical: null, library: false, step: parts[1] || 'sample' };
  return { view: 'home', nav: 'home', title: '', canonical: null, library: true };
}
