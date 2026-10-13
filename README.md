# Parser Studio for Sophos NG-SIEM

> **Unofficial project, not from Sophos.** This is a personal project by an individual. It is not an official Sophos product and it is not built, endorsed, supported, or warranted by Sophos. Raise problems as issues on this repository, not with Sophos support.

Parser Studio helps you write custom parsers for Sophos Next-Gen SIEM (Sophos NG-SIEM) and test them in your browser before you add them in Sophos Fusion. It also holds a community library of parsers that anyone can use, test against their own logs, fork, and add to.

Open the studio at https://aaronjacobs000.github.io/sophos-ngsiem-parser-studio/

![Parser Studio's Test step: an ESET PROTECT parser in the editor on the left, and the parsed NIDS record for one sample line on the right](docs/screenshot.png)

## What it does

1. Sample: paste or drop log lines. The page finds the syslog header and the body format (JSON, CEF, LEEF, key=value, delimited or plain text), the key that splits event types, and a confirm string. It suggests a parent parser with one child per event type, or a single standalone parser.
2. Map fields: each source key gets a parser field for the schema you pick, from a dictionary of common key names and the shape of each value. You change any mapping, map source values to enum names, add fixed values, and send the rest to `event_metadata`. Plain-text logs get a capture pattern with named groups that you can edit.
3. Test and export: the page writes the scripts and runs every sample through an emulator of the parser language. You see the extractor path and the parsed record for each line, and a lint report. Edit a script and the results update. Then copy the scripts into Sophos Fusion, download a test pack, or share the parsers to the library.

The lint checks syntax and directives, documented functions and their arguments, every `$` field against the destination schema, sub-fields against their types, enum values, regex patterns that Go's RE2 engine rejects, DATETIME layouts, and confirm strings that overlap a parser in the library. Each schema page on docs.sophos.com is linked from the map step.

Mapping is rules only. There is no AI service and no backend.

## Privacy

Everything runs in the browser tab. Your samples are never uploaded and never written to browser storage. The page's content security policy only lets it fetch from `api.github.com` and `raw.githubusercontent.com`, and it only uses them to read the public library.

## The emulator and its limits

There is no public Sophos parser engine or parser API, so the emulator follows the [custom parser docs](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/): statements, capture patterns, JSONPath, every documented function, parent and child routing, `SANITIZE_ALL` and `TRIM_ALL`. Where the docs are silent, it does what the Sophos engine did in a lab tenant. For example, enum fields take names in any case or numbers, sub-fields such as `fileHash$.sha1$` work, the root parser sets `sensor_type`, `sensor_id` and the event time from the syslog header, and reading a variable that was never set fails the event. The lint marks the few behaviors that haven't been checked as inferred.

The emulator has been validated against 10 real event types.

The emulator knows the fields in the docs' schema tables, plus the few more the engine was seen to store: `event_type`, `sensor_version` and `source_address` in Antivirus, and `source_address` in Management Event. The engine's schemas may have others, so a field the emulator drops with a warning may still be stored. A line with no event time gets the ingest time, which for a library entry is its `reference_time`. It also can't see the built-in parsers in your tenant, which may claim the same lines first. So a parser that passes here is a tested draft: add it in Sophos Fusion under Security Operations > Integrations > Custom Parsers, add your samples, and use Parse Message and Run Test before you turn it on. Sophos does not maintain custom parsers, and this tool does not replace Sophos Professional Services, which builds custom parsers for customers.

## The community library

The library is the `parsers/` folder of this repo, one folder per vendor and product:

```
parsers/eset/eset-protect-on-prem/
  meta.json                              vendor, product, versions, format, ship method, author, license
  ESET_PROTECT_JSON_PARENT.parser.txt    one file per parser
  ESET_PROTECT_JSON_CHILD_NIDS.parser.txt
  ESET_PROTECT_JSON_CHILD_ANTIVIRUS.parser.txt
  samples.log                            synthetic sample lines
  expected.json                          the emulator's result for each line
```

The studio reads the library from GitHub each time it loads, so a parser shows up as soon as it merges, with no redeploy. If GitHub can't be reached, the page falls back to a copy built into the site, refreshed on every merge and daily. In the studio you can open any entry, run your own lines through it, or fork it as a starting point.

It has 45 entries with 97 parsers:

- Network, firewall and web: dnsmasq, DNSFilter, DrayTek Vigor, F5 BIG-IP ASM and APM, MikroTik RouterOS, nginx and Apache access logs, OpenSSH sshd, OpenVPN, Squid, Suricata EVE JSON, UniFi gateway firewall logs and Zscaler Private Access.
- Email: Barracuda Email Security Gateway and Email Gateway Defense, Cisco Secure Email Gateway, FortiMail and Red Sift OnDMARC.
- Endpoint and application control: Airlock Digital, Bitdefender GravityZone, ESET PROTECT On-Prem (JSON), ThreatDown Nebula and OneView, ThreatLocker Detect and Trend Micro Apex Central.
- MSP tools: Autotask, Auvik, ConnectWise ScreenConnect, Datto RMM, Hudu, Huntress, IT Glue, Kaseya VSA 10 and 9.5, N-able N-central and N-sight RMM, NinjaOne, Splashtop, Syncro and TeamViewer.
- Identity, devices and AI audit: IBM MaaS360, Keeper Security, OpenAI ChatGPT Enterprise compliance logs, OpenAI API Platform audit logs and the Claude Compliance API activity feed.
- Other: 3CX, Synology DSM and VMware ESXi.

Every sample is synthetic. Library parsers have passed the emulator and the repo's checks, and an entry is marked tenant tested only when someone reports a passing Run Test.

## Collectors

Some sources only offer a pull API, so a parser alone can't get their logs into Sophos NG-SIEM. The `collectors/` folder holds small scripts that poll those APIs and send each record to a Sophos NG-SIEM HTTP Ingest integration. There are collectors for the OpenAI and Anthropic enterprise compliance logs ([collectors/ai-compliance-logs](collectors/ai-compliance-logs/)), Datto RMM, IBM MaaS360, IT Glue, Kaseya VSA 10 and 9.5, N-able N-sight RMM, Red Sift OnDMARC, Syncro and TeamViewer. A webhook relay ([collectors/webhook-relay](collectors/webhook-relay/)) covers Huntress, ConnectWise ScreenConnect, Hudu and Autotask, whose webhooks can't add the header HTTP Ingest needs. Collectors are tested against the vendors' documented response shapes, not live services.

A library entry that needs a collector names it in `meta.json`, for example `"collector": "collectors/ai-compliance-logs"`. Its card in the studio shows a **needs collector** badge, and its page shows the collector's README and Python script, with Copy and Download. Collectors are code that people run, so the maintainer reviews every one before it merges.

## Contributing

Use **Share to the library** on the Test step. It runs the same checks as the repo, then you either open a pull request in the browser or fill in an issue form, both with your GitHub account. A workflow checks every submission. When the checks pass and the entry is new or already yours, it can merge without waiting for a person. [CONTRIBUTING.md](CONTRIBUTING.md) has the details, including how to work from a git clone.

## Run it locally

You need Node.js 22 or later. There are no packages to install.

```bash
git clone https://github.com/Aaronjacobs000/sophos-ngsiem-parser-studio.git
cd sophos-ngsiem-parser-studio
npm test                 # unit tests
npm run validate         # the library checks CI runs
npm run build            # builds the site into _site/
npm run serve            # serves _site/ on http://127.0.0.1:8080
```

The emulator also runs from the command line:

```bash
node tools/emulate.mjs --entry parsers/oisf/suricata
node tools/emulate.mjs --lint samples.log TOP.parser.txt CHILD.parser.txt
```

`npm run schemas` rebuilds the schema data from the public schema pages.

## Project layout

| Path | What it holds |
| --- | --- |
| `studio/` | The static site. `studio/core/` is the emulator, lint, detection, mapping and library code, shared by the page and the Node tools. `studio/app/` is the interface. |
| `parsers/` | The community library. |
| `collectors/` | Example collectors for pull-only sources, each with a README and unit tests. The maintainer reviews every one. |
| `tools/` | Command-line tools and the scripts the workflows run. |
| `test/` | Unit tests (`node --test`). |
| `.github/workflows/` | CI, the library checks for pull requests, the issue-form route, and the Pages deploy. |

## License

MIT. See [LICENSE](LICENSE) and [ATTRIBUTIONS.md](ATTRIBUTIONS.md). Sophos, Sophos NG-SIEM and Sophos Fusion are names of Sophos Ltd, used here only to say what the tool works with.
