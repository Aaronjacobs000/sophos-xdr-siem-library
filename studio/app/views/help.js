import { h, ext } from '../dom.js';
import { githubUrl } from '../library-client.js';

const DOCS = 'https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/';

export function renderHelp(root) {
  const s = h('article', { class: 'help' });
  const p = (...c) => h('p', {}, ...c);
  const li = (...c) => h('li', {}, ...c);
  s.append(
    h('h1', { text: 'How Parser Studio works' }),
    p('Parser Studio helps you write custom parsers for Sophos NG-SIEM in your browser and test them before you open a tenant. It is an unofficial community project, not a Sophos product, and Sophos does not support it.'),
    h('h2', { text: 'The three steps' }),
    h('ul', {},
      li(h('b', { text: 'Sample.' }), ' Paste or drop lines. The page works out the syslog header, the body format (JSON, CEF, LEEF, key=value, delimited or plain text) and the key that splits event types, then suggests a parent with one child per event type, or one standalone parser.'),
      li(h('b', { text: 'Map fields.' }), ' Each source key gets a parser field from a dictionary of common names and the shape of its values. You change any mapping, map values to enum names, add fixed values, and send leftovers to event_metadata.'),
      li(h('b', { text: 'Test and export.' }), ' The page writes the scripts, runs every sample through an emulator, and lints the result. Edit the scripts and the results update. Copy them into Sophos Fusion or download a test pack.')),
    h('h2', { text: 'What the emulator is, and is not' }),
    p('The emulator runs the parser language as the ', ext(DOCS, 'Sophos custom parser docs'), ' describe it: statements, capture patterns, JSONPath, every documented function, parent and child routing, SANITIZE_ALL and TRIM_ALL. It is our reading of the docs, not the Sophos engine. Where the docs are silent, it makes a choice and the lint marks that line as inferred, for example enum fields set by name, sub-fields such as fileHash$.sha1$, the AND and OR operators, and what `message` holds.'),
    p('So a parser that passes here is a tested draft. Add it in Sophos Fusion under Security Operations > Integrations > Custom Parsers, add the samples, and use Parse Message and Run Test before you turn it on. The emulator can\'t see the built-in parsers in your tenant, which may claim the same lines first.'),
    h('h2', { text: 'What the lint checks' }),
    h('ul', {},
      li('Syntax, directives, documented functions and their arguments.'),
      li('Every $ field against the destination schema, sub-fields against their types, and enum values against the enum names.'),
      li('Regex patterns against what Go\'s RE2 engine accepts: no lookarounds, no backreferences, repeat counts up to 1000.'),
      li('DATETIME layouts, including a layout with no year, which Go reads as year 0.'),
      li('Confirm strings that overlap a parser in the community library.')),
    h('h2', { text: 'Privacy' }),
    p('Everything runs in this tab. The page has no backend and no analytics, and its content security policy only lets it fetch from GitHub, to read the public library. Your samples are never uploaded and never written to browser storage. Mapping is rules only; there is no AI service.'),
    h('h2', { text: 'The community library' }),
    p('The library is a folder of a public GitHub repo. The page reads it from GitHub each time it loads, so new parsers show up as soon as they merge. To add yours, use Share to the library on the Test step: it runs the repo\'s checks here, then you open a pull request in the browser or fill in an issue form. ', ext(githubUrl('/blob/main/CONTRIBUTING.md'), 'Contributing guide'), '.'),
    p('Samples in the library must be synthetic: documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), example.com names, and no real users, hosts, companies or keys. The repo checks for these on every submission.'),
    h('h2', { text: 'When to use Sophos Professional Services' }),
    p('Parser Studio does not replace Sophos Professional Services, which builds and supports custom parsers for customers. Sophos does not maintain custom parsers, including these.'),
    h('h2', { text: 'Problems and ideas' }),
    p('Open an ', ext(githubUrl('/issues'), 'issue on GitHub'), '. Please don\'t contact Sophos support about this tool.'));
  root.append(s);
}
