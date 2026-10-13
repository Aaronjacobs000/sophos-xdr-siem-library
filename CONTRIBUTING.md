# Contributing

Library contributions are open to anyone with a GitHub account. You don't need git.

## Add parsers to the library

Build and test the parsers in [Parser Studio](https://aaronjacobs000.github.io/sophos-ngsiem-parser-studio/), then choose **Share to the library** on the Test step. Fill in the details and run the library checks; they are the same checks the repo runs. When they pass, pick a route.

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

- `meta.json` has the required fields, and the folder holds only the allowed files.
- The parsers lint without errors.
- The emulator's output for `samples.log` matches `expected.json`.
- Samples, parsers and metadata contain no secrets or keys, no private or real IP addresses, no real email addresses or hostnames, and no company names that could be customers.
- No top-level parser's confirm string matches another entry's samples.
- `collector`, when set, names a folder under `collectors/` that is already on the main branch and holds a `README.md` and a `.py` file. An entry shipped by HTTP Ingest without one gets a warning, since a source that sends to HTTP Ingest with the `Authorization` header itself needs none.

## Samples must be synthetic

Use documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), names under example.com, example.net or example.org, and made-up user and host names. Fictional companies such as Acme and Contoso are fine. Copy the line structure from the vendor's public log format docs and link those docs in `meta.json`. Customer logs are not accepted, even sanitized ones.

## When a pull request merges without review

The repo merges a pull request on its own when all of these hold:

- The repo owner has turned on auto-merge in the repo settings.
- Every check passed.
- The pull request changes nothing outside `parsers/`.
- Each entry it changes is new, or its `meta.json` already names the person who opened the pull request as `author`.

Anything else, such as a change to someone else's entry, a deletion, a collector, or a change to the tools, waits for a maintainer review. Library entries are a starting point for other people, so a maintainer may still edit or remove one later.

## Mark an entry tenant tested

When the parsers pass Run Test in a Sophos NG-SIEM tenant, set `tested.tenant` in `meta.json` to that date (`YYYY-MM-DD`) in a pull request. Only do this after a real Run Test.

## Collectors

A collector is a small script that gets a source's logs to a Sophos NG-SIEM HTTP Ingest integration, where the library parsers normalize them. Most poll a vendor API that only offers pull access and send each record as one JSON line. [collectors/webhook-relay](collectors/webhook-relay/) relays pushed webhooks instead, for vendors whose webhooks can't add the `Authorization: Bearer` header HTTP Ingest needs. Each one is a folder, `collectors/<vendor>-<product>/`, with:

- `<name>.py`: Python 3, standard library only.
- `README.md`: what to set up on both sides, every setting, and what the script sends.
- `test_<name>.py`: unit tests against a local mock of the vendor's documented API or webhooks. CI runs every `collectors/*/test_*.py`.

Follow [collectors/ai-compliance-logs](collectors/ai-compliance-logs/):

- Every setting comes from an environment variable, keys included: `NGSIEM_INGEST_URL` and `NGSIEM_INGEST_KEY` for HTTP Ingest, `COLLECTOR_*` for the collector's own behavior, and a vendor prefix for the vendor's keys and options.
- `--dry-run` (or `COLLECTOR_DRY_RUN=1`) prints the NDJSON it would send, and sends and saves nothing.
- Keys, the HTTP Ingest URL path and signed download URLs never reach the log.

To show a collector on an entry's page, set `"collector": "collectors/<name>"` in the entry's `meta.json`. The collector has to be on the main branch first, so it merges before the entry that points at it.

Collectors are code that people download and run, so the maintainer reviews every collector before it merges. You can propose one in a pull request, but it won't merge automatically.

## Changes to the studio

Open an issue first for anything large. Keep the page free of runtime dependencies and network calls other than reading the library, add tests under `test/`, and run `npm test` before you open the pull request. Code changes always get a review.
