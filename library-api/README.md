# Library API (stars and view counts)

The library site is static, so the stars on its cards and entry pages, and the counts behind its Most starred and Most viewed sorts, come from this small Cloudflare Worker at `https://library-api.aaronjacobs.dev`. The site calls it in the background. If it is down or slow, the page shows no stars and works as it did before the API existed.

| Route | What it does |
| --- | --- |
| `GET /v1/stats` | `{"stars": {"parsers/acme/widget": 3}, "views": {"parsers/acme/widget": 120}}` for every entry with a count |
| `PUT /v1/stars/<id>` | Stars an entry, such as `parsers/acme/widget`, and answers `{"id", "stars", "starred": true}` |
| `DELETE /v1/stars/<id>` | Takes the star back, and answers the same way with `"starred": false` |
| `GET /healthz` | `ok` |

An id is the entry's section and folder: `parsers/`, `playbooks/` or `connectors/`, then the vendor and name slugs. The API takes only ids in the site's `library-index.json`, which it reads every hour. When a request names a well-formed id it doesn't have, and its copy is more than five minutes old, it reads the index again, so an entry can be starred as soon as Pages publishes it.

## What it keeps

For each star it keeps the entry's id and an HMAC-SHA256 of the caller's IP address, keyed with the `IP_HASH_SALT` secret and cut to 128 bits. The address itself is never stored. One address stars an entry once, and an IPv6 address counts by its /64. The browser remembers its own stars in localStorage, so there is no sign-in and no cookie. Beyond that it keeps the star count and the GoatCounter visitor count for each entry. Workers Logs are off in `wrangler.toml`, so Cloudflare keeps no request logs with addresses for it.

The data lives in one SQLite-backed Durable Object, `LibraryStats`, which the free plan includes. The account's API token can't create D1 databases or KV namespaces, and a single object also gives the rate limits one place to count.

## Who can call it, and how often

`/v1` answers only the origins in `ALLOWED_ORIGINS` (the library site). Any other origin, or a request with none, gets 403 before it reaches storage. Per hashed address: 30 star changes a minute and 300 a day, and 120 stats reads a minute. All callers together get 5,000 star changes a day. Over a limit, the answer is 429 with `Retry-After`. If stars are ever abused, Turnstile is the next step.

## Most viewed

The cron trigger runs at minute 41 of every hour. It reads GoatCounter's `/api/v0/stats/hits` with the `GOATCOUNTER_TOKEN` secret and matches each route, such as `/parsers/acme/widget`, to its entry. GoatCounter returns every day of a range with its hourly counts, so a long range would cost more than the free plan's 10 ms of CPU. Instead each run folds finished days into stored totals, up to four days a run starting at `VIEWS_SINCE`, and reads only the last day or two again. A new deployment catches up on its history in a few hours.

The Newest sort doesn't use the API. The site build dates each entry from the commit that first added its `meta.json` (`tools/lib/added-dates.mjs`), which is why the Pages workflow checks out the whole history.

## Deploy

You need `wrangler` and a Cloudflare API token that can edit Workers scripts. The account also needs a workers.dev subdomain, even though this Worker doesn't use it: without one, Cloudflare refuses a script with a Durable Object (error 10063).

```bash
cd library-api
wrangler deploy
wrangler secret put IP_HASH_SALT        # a long random value, such as the output of openssl rand -hex 32
wrangler secret put GOATCOUNTER_TOKEN   # a GoatCounter API key with the Read statistics permission
```

`workers_dev` is off, so attach the hostname as a Workers custom domain once. Cloudflare adds the DNS record and the certificate:

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/domains" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"zone_id":"<zone id>","hostname":"library-api.aaronjacobs.dev","service":"xdr-siem-library-api","environment":"production"}'
curl https://library-api.aaronjacobs.dev/healthz
```

Changing `IP_HASH_SALT` keeps every star but forgets who gave it, so an address could star an entry again. To watch a cron run, use `wrangler tail`.

Tests: `node --test test/library-api.test.mjs`, which runs the Worker and its Durable Object against SQLite in Node.
