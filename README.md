# Unofficial Sophos Fusion XDR and SIEM Library

> **Unofficial project, not from Sophos.** This is a personal project by an individual. It is not an official Sophos product and it is not built, endorsed, supported, or warranted by Sophos. Raise problems as issues on this repository, not with Sophos support. Report a security problem privately, as [SECURITY.md](SECURITY.md) explains.

A library of custom parsers for Sophos Next-Gen SIEM (Sophos NG-SIEM) that people share, and Parser Studio, a page that helps you write your own parsers and test them in your browser before you add them in Sophos Fusion. Anyone can use the parsers, test them against their own logs, fork them, and add to them.

Open the library at https://aaronjacobs000.github.io/sophos-xdr-siem-library/ and Parser Studio at https://aaronjacobs000.github.io/sophos-xdr-siem-library/#/build/sample

This repo was called sophos-ngsiem-parser-studio until October 2026. Links to the old site redirect here, and the old repo's page links here.

![Parser Studio's Test step: an ESET PROTECT parser in the editor on the left, and the parsed NIDS record for one sample line on the right](docs/screenshot.png)

## Parser Studio

1. Sample: paste or drop log lines. The page finds the syslog header and the body format (JSON, CEF, LEEF, key=value, delimited or plain text), the key that splits event types, and a confirm string. It suggests a parent parser with one child per event type, or a single standalone parser.
2. Map fields: each source key gets a parser field for the schema you pick, from a dictionary of common key names and the shape of each value. You change any mapping, map source values to enum names, add fixed values, and send the rest to `event_metadata`. Plain-text logs get a capture pattern with named groups that you can edit.
3. Test and export: the page writes the scripts and runs every sample through an emulator of the parser language. You see the extractor path and the parsed record for each line, and a lint report. Edit a script and the results update. Then copy the scripts into Sophos Fusion, download a test pack, or share the parsers to the library.

The lint checks syntax and directives, documented functions and their arguments, every `$` field against the destination schema, sub-fields against their types, enum values, regex patterns that Go's RE2 engine rejects, DATETIME layouts, and confirm strings that overlap a parser in the library. Each schema page on docs.sophos.com is linked from the map step.

Mapping is rules only. There is no AI service and no backend.

## Privacy

Everything runs in the browser tab. Your samples are never uploaded and never written to browser storage. The page's content security policy only lets it fetch from the site itself, and it only does that to read the library.

## The emulator and its limits

There is no public Sophos parser engine or parser API, so the emulator follows the [custom parser docs](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/): statements, capture patterns, JSONPath, every documented function, parent and child routing, `SANITIZE_ALL` and `TRIM_ALL`. Where the docs are silent, it does what the Sophos engine did in a lab tenant. For example, enum fields take names in any case or numbers, sub-fields such as `fileHash$.sha1$` work, the root parser sets `sensor_type`, takes `sensor_id` and the event time from a plain BSD syslog header, and Run Test rejects a parser that reads a variable before a statement sets it, even in an IF branch that isn't taken. The lint marks the few behaviors that haven't been checked as inferred. Sophos Fusion won't save a parser with `*=` anywhere in its code, a comment or a regex included, though Run Test accepts it, so the lint flags it as an error. It saves a `!PARENT` line, which the docs use to extend a global parser, only with Set Global Parent in Parser Script turned on, so the lint warns about one.

The emulator handles the syslog header the way Run Test does: it takes a plain BSD header such as `Oct 14 01:02:03 host` off `message`. A line that starts with a `<PRI>` such as `<134>`, an RFC 5424 header or an ISO time keeps its header: `message` is the whole line, there is no `sensor_id`, and the event time is the ingest time. `eventTimeUsec$` already holds it, in microseconds and to the whole second, when the parser starts. Whether ingest takes the `<PRI>` off first hasn't been checked.

Numbers work the way the engine's do. Every number is a 64-bit float, so a whole number past 9007199254740992 rounds: `9007199254740993` is `9007199254740992`. Text that reads as a number adds to a number or `TRUE`, so `"5" + 5` is `10`, but two texts still join: `"5" + "5"` is `"55"`. A minus sign only works as part of a number such as `-5`. The engine rejects `-x`, `-(3 / 2)` and `x-1`, so write `0 - x` and put spaces around a minus: `x - 1`.

The emulator has been validated against 10 real event types.

The emulator knows the fields in the docs' schema tables, plus the few more the engine was seen to store: `event_type`, `sensor_version` and `source_address` in Antivirus, `source_address` in Management Event, and `sensor_version` and `sensor_event_id` in the generic schema. It leaves out `rule_context` in Registry, which the engine drops. The engine's schemas may have others, so a field the emulator drops with a warning may still be stored. A line with no event time gets the ingest time, which for a library entry is its `reference_time`. It also can't see the built-in parsers in your tenant, which may claim the same lines first. A built-in parent sets fields of its own on its children's events, such as `os`, `computer` and `target_host` from the Windows Snare parent, which the emulator leaves out. The engine also tries first whichever of a built-in parent's children took the latest line, so when your child and a built-in one both match, the lines before decide which one takes a line. So a parser that passes here is a tested draft: add it in Sophos Fusion under Security Operations > Integrations > Custom Parsers, add your samples, and use Parse Message and Run Test before you turn it on. Sophos does not maintain custom parsers, and this tool does not replace Sophos Professional Services, which builds custom parsers for customers.

## The parser library

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

The site publishes a copy of the library each time a change merges, and daily, so a parser shows up a few minutes after it merges. You can open any entry, run your own lines through it, or open it in Parser Studio and fork it as a starting point.

It has 143 entries with 385 parsers:

- Network, firewall and web: Allied Telesis AlliedWare Plus, Amazon CloudFront standard logs, Amazon Route 53 Resolver query logs, Appgate SDP, Arista VeloCloud SD-WAN, AWS Network Firewall, Cisco ACI, Cisco Catalyst SD-WAN, Cisco IOS XE Zone-Based Firewall, dnsmasq, DNSFilter, DrayTek Vigor, ExtraHop RevealX detections, F5 BIG-IP ASM, APM and AFM, Fortinet FortiDeceptor, Fortinet FortiManager, Fortinet FortiNAC-F, Fortinet FortiNDR, Fortinet FortiSandbox, H3C and HPE Comware, HAProxy, HPE Aruba EdgeConnect SD-WAN, HPE Aruba Networking AOS 8 and AOS 10 controllers and gateways, HPE Aruba Networking AOS-CX, Huawei USG and HiSecEngine firewalls, Huawei VRP switches and routers, ISC DHCP and Kea, Juniper Mist, MikroTik RouterOS, NEC UNIVERGE IX, nginx and Apache access logs, nginx error log, Omnissa Unified Access Gateway, OpenSSH sshd, OpenVPN, Peplink Balance and Pepwave MAX, Skyhigh Secure Web Gateway, Snort 3, Squid, Suricata EVE JSON, Tenable OT Security, TP-Link Omada, Trellix Intrusion Prevention System (McAfee NSP), Trellix Network Security (NX), Trend Micro Deep Discovery Inspector, Trend Micro TippingPoint SMS, UniFi gateway firewall logs, Vectra AI Respond UX, VMware NSX, Yamaha RTX and NVR routers, Zscaler Private Access and Zyxel USG FLEX, ATP and ZyWALL VPN.
- Email: Barracuda Email Security Gateway and Email Gateway Defense, Cisco Secure Email Gateway, Exchange Server message tracking, FortiMail, Postfix and Red Sift OnDMARC.
- Endpoint and application control: Airlock Digital, Arctic Wolf Aurora Protect Desktop (CylancePROTECT), Bitdefender GravityZone, Carbon Black Cloud, Cisco Secure Endpoint, Cortex XDR alerts, CyberArk Endpoint Privilege Manager, ESET PROTECT On-Prem (JSON) and ESET PROTECT Cloud, Fortinet FortiEDR, Kaspersky Security Center, Linux auditd, Microsoft Sysmon, osquery, ThreatDown Nebula and OneView, ThreatLocker Detect, Trend Micro Apex Central, WatchGuard Endpoint Security, Windows PowerShell and AppLocker and WithSecure Elements.
- Identity, access and secrets: 1Password Business, Azure Key Vault, BeyondTrust Password Safe, BeyondTrust Privileged Remote Access and Remote Support, Bitwarden, HashiCorp Vault, JumpCloud Directory Insights, Keeper Security, Microsoft NPS accounting logs, Netwrix Auditor, NordPass Business, OneLogin, PingFederate, PingOne, RSA SecurID Authentication Manager, SailPoint Identity Security Cloud, Tenable Identity Exposure and Thales CipherTrust Manager.
- Cloud, DevOps and security operations: Atlassian organization audit logs, AWS Security Hub CSPM findings, Azure SQL auditing, Dynatrace audit events, Fortinet FortiCNAPP, GitHub Enterprise Cloud audit logs, GitLab audit events, Google Workspace audit logs, Kubernetes audit logs (AKS and EKS), Snowflake login history, SQL Server audit, Wazuh alerts and Zoom sign-in and operation logs.
- Backup, storage and data protection: Commvault, Druva Cloud Platform, Forcepoint DLP, Fortinet FortiDLP, IBM Guardium Data Protection, Nasuni Edge Appliance, Symantec DLP and Veritas NetBackup.
- MSP tools: Autotask, Auvik, ConnectWise ScreenConnect, Datto RMM, Hudu, Huntress, IT Glue, Kaseya VSA 10 and 9.5, N-able N-central and N-sight RMM, NinjaOne, Splashtop, Syncro and TeamViewer.
- Devices and AI audit: IBM MaaS360, Microsoft Intune audit logs, OpenAI ChatGPT Enterprise compliance logs, OpenAI API Platform audit logs and the Claude Compliance API activity feed.
- Other: 3CX, IBM i security audit journal, Nutanix Prism Central, QNAP QTS and QuTS hero, Synology DSM and VMware ESXi.

Every sample is synthetic. Library parsers have passed the emulator and the repo's checks, and an entry is marked tenant tested only when someone reports a passing Run Test.

## Bridges

Some sources only offer a pull API, and some push webhooks that can't add the header HTTP Ingest needs, so a parser alone can't get their logs into Sophos NG-SIEM. The `bridges/` folder holds small scripts that poll those APIs or relay those webhooks, and send each record to a Sophos NG-SIEM HTTP Ingest integration. There are bridges for the OpenAI and Anthropic enterprise compliance logs ([bridges/ai-compliance-logs](bridges/ai-compliance-logs/)), 1Password Business, Atlassian organization audit logs, Bitwarden, Cisco Secure Endpoint, CyberArk Endpoint Privilege Manager, Datto RMM, Druva Cloud Platform, Dynatrace audit events, ESET PROTECT Cloud (through ESET Connect), Google Workspace, IBM MaaS360, IT Glue, JumpCloud Directory Insights, Kaseya VSA 10 and 9.5, N-able N-sight RMM, Netwrix Auditor, NordPass Business, Red Sift OnDMARC, SailPoint Identity Security Cloud, Snowflake login history, Syncro, TeamViewer, TP-Link Omada, WithSecure Elements and Zoom. A webhook relay ([bridges/webhook-relay](bridges/webhook-relay/)) covers Huntress, ConnectWise ScreenConnect, Hudu, Autotask, Juniper Mist and FortiCNAPP. Bridges are tested against the vendors' documented response shapes, not live services.

A library entry that needs a bridge names it in `meta.json`, for example `"bridge": "bridges/ai-compliance-logs"`. Its card in the studio shows a **needs a bridge** badge, and its page shows the bridge's README and Python script, with Copy and Download. Bridges are code that people run, so the maintainer reviews every one before it merges.

Bridges were called collectors until October 2026, when they were renamed so nobody mistakes them for the Sophos data collector. The old `"collector"` key and `COLLECTOR_*` settings still work.

## Contributing

Use **Share to the library** on the Test step. It runs the same checks as the repo, then you either open a pull request in the browser or fill in an issue form, both with your GitHub account. A workflow checks every submission. When the checks pass and the entry is new or already yours, it can merge without waiting for a person. [CONTRIBUTING.md](CONTRIBUTING.md) has the details, including how to work from a git clone.

## Run it locally

You need Node.js 22 or later. There are no packages to install.

```bash
git clone https://github.com/Aaronjacobs000/sophos-xdr-siem-library.git
cd sophos-xdr-siem-library
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
| `parsers/` | The parser library. |
| `bridges/` | Example bridges for pull-only sources and a relay for webhooks, each with a README and unit tests. The maintainer reviews every one. |
| `tools/` | Command-line tools and the scripts the workflows run. |
| `test/` | Unit tests (`node --test`). |
| `.github/workflows/` | CI, the library checks for pull requests, the issue-form route, and the Pages deploy. |

## License

MIT. See [LICENSE](LICENSE) and [ATTRIBUTIONS.md](ATTRIBUTIONS.md). Sophos, Sophos NG-SIEM and Sophos Fusion are names of Sophos Ltd, used here only to say what the tool works with.
