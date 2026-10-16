# Contributing

Library contributions are open to anyone with a GitHub account. You don't need git.

To report a security problem, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Add parsers to the library

Build and test the parsers in [Parser Studio](https://aaronjacobs000.github.io/sophos-xdr-siem-library/#/build/sample), then choose **Share to the library** on the Test step. Fill in the details and run the library checks; they are the same checks the repo runs. When they pass, pick a route.

### Route 1: pull request in the browser

1. Download the zip the dialog offers and unzip it.
2. Open the upload page the dialog links to. It points at `parsers/<vendor>/<product>/`. GitHub asks you to sign in and makes a fork for you.
3. Drag in all the unzipped files, then choose **Propose changes** and **Create pull request**.

### Route 2: issue form

1. Choose **Copy the submission** in the dialog.
2. Open the issue form, paste the submission into the **Submission** box, tick the two boxes, and submit.
3. A workflow checks the submission, comments the result on the issue, and opens a pull request for it. You are recorded as the author. To fix a problem, edit the issue and the workflow runs again.

### From a git clone

1. Copy an existing entry folder to `parsers/<vendor>/<product>/`, using lowercase names with hyphens.
2. Edit `meta.json`, the `.parser.txt` files and `samples.log`.
3. Run `node tools/update-expected.mjs parsers/<vendor>/<product>` and read the diff of `expected.json`.
4. Run `npm run validate` and `npm test`, then open a pull request.

## What the checks look at

Every pull request that touches `parsers/` and every issue-form submission is checked with the code on the main branch:

- `meta.json` has the required fields, the folder holds only the allowed files, and its path is `parsers/<vendor>/<product>/` from the vendor and product in `meta.json`.
- The parsers lint without errors.
- The emulator's output for `samples.log` matches `expected.json`.
- Samples, parsers and metadata contain no secrets or keys, no private or real IP addresses, no real email addresses or hostnames, and no company names that could be customers.
- No top-level parser's confirm string matches another entry's samples.
- `bridge`, when set, names a folder under `bridges/` that is already on the main branch and holds a `README.md` and a `.py` file. An entry shipped by HTTP Ingest without one gets a warning, since a source that sends to HTTP Ingest with the `Authorization` header itself needs none.

## Samples must be synthetic

Use documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), names under example.com, example.net or example.org, and made-up user and host names. Fictional companies such as Acme and Contoso are fine, and so is the company name of a vendor already in the library, written as the vendor name plus its legal suffix, such as Microsoft Corporation. Copy the line structure from the vendor's public log format docs and link those docs in `meta.json`. Customer logs are not accepted, even sanitized ones.

## When a pull request merges without review

The repo merges a pull request on its own when all of these hold:

- The repo owner has turned on auto-merge in the repo settings.
- Every check passed.
- The pull request changes nothing outside `parsers/`.
- Each entry it changes is new, or its `meta.json` already names the person who opened the pull request as `author`.

Anything else, such as a change to someone else's entry, a deletion, a bridge, a playbook or connector, or a change to the tools, waits for a maintainer review. Library entries are a starting point for other people, so a maintainer may still edit or remove one later.

## Mark an entry tenant tested

When the parsers pass Run Test in a Sophos NG-SIEM tenant, set `tested.tenant` in `meta.json` to that date (`YYYY-MM-DD`) in a pull request. Only do this after a real Run Test.

## Bridges

A bridge is a small script that gets a source's logs to a Sophos NG-SIEM HTTP Ingest integration, where the library parsers normalize them. Most poll a vendor API that only offers pull access and send each record as one JSON line. [bridges/webhook-relay](bridges/webhook-relay/) relays pushed webhooks instead, for vendors whose webhooks can't add the `Authorization: Bearer` header HTTP Ingest needs. Each one is a folder under `bridges/`, in lowercase with hyphens, named for the source it serves (`bridges/ibm-maas360/`) or, when it serves several, for what it does (`bridges/webhook-relay/`). It holds:

- `<name>.py`: Python 3, standard library only.
- `README.md`: what to set up on both sides, every setting, and what the script sends.
- `test_<name>.py`: unit tests against a local mock of the vendor's documented API or webhooks. CI runs every `bridges/*/test_*.py`.

Follow [bridges/ai-compliance-logs](bridges/ai-compliance-logs/):

- Every setting comes from an environment variable, keys included: `NGSIEM_INGEST_URL` and `NGSIEM_INGEST_KEY` for HTTP Ingest, `BRIDGE_*` for the bridge's own behavior, and a vendor prefix for the vendor's keys and options.
- `--dry-run` (or `BRIDGE_DRY_RUN=1`) prints each record it would send, one per line, and sends and saves nothing.
- A request that carries a key or token doesn't follow redirects. A redirect fails the request with an error that says it was refused, so the key only goes to the URL it was set up for.
- Keys, the HTTP Ingest URL path and signed download URLs never reach the log.

To show a bridge on an entry's page, set `"bridge": "bridges/<name>"` in the entry's `meta.json`. The bridge has to be on the main branch first, so it merges before the entry that points at it.

Bridges are code that people download and run, so the maintainer reviews every bridge before it merges. You can propose one in a pull request, but it won't merge automatically.

## Add a playbook or connector

Playbooks act on tenants: they lock devices, isolate hosts and send data out. So the owner reviews every playbook and connector, and nothing under `playbooks/` or `connectors/` merges on its own. The checks label the pull request "needs review" and leave it open. Work from a git clone and open a pull request.

### What an entry holds

```
playbooks/<vendor>/<name>/      template.yaml, meta.json, SETUP.md, and an optional README.md
connectors/<vendor>/<name>/     connector.yaml, meta.json, README.md
```

The folder comes from `meta.json`: the vendor and the title for a playbook, the vendor and the product for a connector, in lowercase with hyphens. [playbooks/sophos/sophos-mobile-lock](playbooks/sophos/sophos-mobile-lock/) and [connectors/sophos/sophos-mobile](connectors/sophos/sophos-mobile/) show the shape.

- `template.yaml` and `connector.yaml` are the files as Sophos Fusion exports them (More Actions > Export on the template, or the Connector Library), with `tenantId` and `icon` taken out. Edit the raw text. A single-quoted value in a template is text, and a plain or double-quoted one is an expression, so a tool that reads and rewrites the YAML can change what a playbook does.
- A playbook's `meta.json` has `title`, `vendor`, `product`, `use_case`, `trigger` (the trigger to set), `connections`, `requires` (the products it needs), `license`, `risk_tier`, `mdr_note`, `rollback`, `tested`, `connector` (the library connector it needs, or null), `author`, `docs` and optional `notes`.
- A connector's `meta.json` has `title`, `vendor`, `product`, `auth` (how the connection signs in), `functions` (each function's risk tier), `license`, `tested`, `author`, `docs` and optional `notes`.
- `tested` is `{"validated": "YYYY-MM-DD", "tenant": null}`: the date the template passed `playbookValidateDSLV2` (or the connector imported) in a tenant, and `{"date": "YYYY-MM-DD", "region": "us01"}` once it really ran in a tenant. Only record what happened.
- `SETUP.md` lists what a template can't carry: the trigger, the run condition, the inputs, the connections, and the response mode where it applies. It says to pin the template version, because a configured playbook picks up minor and patch versions on its own, and to leave the playbook off until a test run.

### Risk tiers

| Tier | What the playbook does |
| --- | --- |
| lookup | Reads data and changes nothing. |
| notify | Sends a message or adds a comment, and changes nothing else. |
| reversible action | Changes something that can be undone, such as locking a device or isolating a host. |
| destructive | Changes something that can't be undone. It needs a `tested.tenant` record, a run in a real tenant, before it can merge. |

The checks work out the least tier from what the template calls: the tiers in its own connector's `meta.json`, a few Sophos-managed functions they know, and a reversible action for anything else. An entry can claim a higher tier, never a lower one. Wipe-type actions are refused for now: there is no undo, and no corporate-only wipe.

### Entries ship off, and safe

Every playbook ships off: you import it, choose Use this Template and leave the configured playbook off until a test run. A playbook that acts also needs:

- a `dry_run` input that defaults to true, with every acting task conditioned on it, so a first run only reports what it would do
- a scoping input, such as a device group or a tag, with nothing in scope when it is empty
- a per-run limit with a low default, so a broad trigger can't act on a fleet
- an honest rollback: what undoes it, or that nothing does
- an MDR note: Sophos MDR doesn't run customer playbooks, and one can act on a host or device MDR is working on

### What the checks look at

- The YAML parses, with no anchors, tags or tabs, and the fields are ones a template or connector has.
- Names, versions (`1.0.0`), the `Taegis` prefix Sophos reserves, and the files and folder.
- Dependencies: every `action`, `exec` and `call` is in the template's `connectors`, `playbooks` or `interfaces` list, the entry's own connector is listed at the version its `connector.yaml` has, and it has the functions the template calls.
- Every CEL expression parses, and reads only tasks, `inputs`, `TDR` and `tenant`. A bare word that is none of them was probably meant as text, which needs single quotes.
- The risk tier, wipe-type actions, and the tenant record for destructive entries.
- Every URL a connector calls is https on a host in [connectors/allowed-hosts.json](connectors/allowed-hosts.json) for its vendor, including hosts that come from a connection setting with a fixed list of values. A host set at run time is refused. A template holds no URLs at all.
- No tenant IDs, object IDs, icons, credentials, webhook URLs or personal data, and the same secret scan CI runs.

A new host goes into `connectors/allowed-hosts.json` in its own pull request first, with the vendor page that documents it under `sources`. The checks read the allowlist from the main branch.

The checks run offline. Run `playbookValidateDSLV2` in your own tenant on the template's `dsl` before you open the pull request; it is the authority, and it saves nothing.

### What review looks at

- What each acting task does, against the risk tier and the vendor's docs.
- The dry run, scoping input and per-run limit, and that the defaults are safe.
- Every use of the Generic Webhook or Fetch connectors, and exactly which fields leave the tenant.
- Whether `SETUP.md` is enough to set it up without guessing.

### What never goes in

- Template or connector YAML that Sophos manages, copied as is. Refer to it by name and version, such as `Taegis.Case:1.0.5`.
- Exports from real tenants with their data, tenant IDs, connection details, credentials and webhook URLs.
- Internal Sophos material: internal discussions and the names in them, internal licensing or service notes, and roadmaps.
- Anything that looks like the Sophos Fusion console, and Sophos logos.

## Changes to the studio

Open an issue first for anything large. Keep the page free of runtime dependencies and network calls other than reading the library, add tests under `test/`, and run `npm test` before you open the pull request. Code changes always get a review.

## Notes for maintainers

- **Playbook and connector pull requests.** The gate labels them "needs review" and never merges them. Review them as the section above says, then squash-merge as owner.
- **"needs review" after you merge.** When you merge a pull request the gate labeled "needs review", the Review label workflow takes that label off. It leaves every other label, and a "needs review" that someone other than the gate added.

- **CI that takes over 10 minutes.** The gate stops waiting, and its report on the pull request says it is waiting for CI. When CI finishes, the gate runs again for that commit, with every check, and merges it if CI passed or labels it "needs review" if not.
- **CI that fails, then passes on a re-run.** The gate labels the pull request "needs review" and its report says a check failed. Re-run the failed CI jobs: when CI passes on the same commit, the gate runs again for it, with every check, and merges it if they all passed.
- **A branch rule that holds pull requests.** None does today. If you add one, such as a required review, the gate turns on GitHub's auto-merge for a library pull request whose checks passed. If GitHub merges it within the gate's 2-minute wait, the gate deletes the branch and starts Pages as usual. If it merges later, for example after your review, nothing runs: GitHub starts no workflow for an event the workflow token caused, so neither the merge's push nor the pull request closing starts one, and the repo holds no other token. Delete the branch, and run Pages from the Actions tab or let its daily run publish the change.
