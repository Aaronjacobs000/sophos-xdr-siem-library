<!-- Adding or updating a library entry? Parser Studio's "Share to the library" builds these files and runs the same checks. CONTRIBUTING.md lists what each kind of entry holds. Tick what applies. -->

- [ ] Parsers: the samples are synthetic or copied from public vendor docs: no customer data, real IP addresses, hostnames, users, emails or keys.
- [ ] `meta.json` has a `summary` (two or three sentences: what the parsers read, how the logs get in, which schemas they land in; for a playbook or connector, what it does, how it runs or signs in, what it needs) and `notes` in labelled sections, as CONTRIBUTING.md describes.
- [ ] Parsers: `expected.json` comes from `node tools/update-expected.mjs` (or Parser Studio), and I read the diff.
- [ ] Playbooks and connectors: the YAML is the Sophos Fusion export without `tenantId` and `icon`, and holds no tenant IDs, credentials or webhook URLs.
- [ ] Bridges: `test_<name>.py` passes, and `--dry-run` sends nothing.
- [ ] I agree to publish these files under the license in `meta.json`.
