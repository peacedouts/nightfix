# Nightfix teaser

The public page for nightfix.dev until launch: the name and one line, nothing more. It says nothing about what Nightfix does or how it works. The full marketing site and docs are kept in the private archive repository (`archive/full-site` branch) until launch.

Plain static files, no build step.

```
teaser/
└── public/
    ├── index.html        the page
    ├── og.png            1200×630 link preview image
    ├── fonts/            Instrument Serif + Sans (SIL OFL), self-hosted
    ├── 404.html
    ├── favicon.svg
    ├── robots.txt
    ├── _headers          security headers
    └── .well-known/security.txt
```

## Preview locally

```bash
npx wrangler dev          # from the repo root; http://localhost:8787
```

## Deploy

Production is the `nightfix` Cloudflare Worker, defined by the **root** `wrangler.jsonc`, which serves `teaser/public`. Workers Builds deploys it on every push to `main` (root directory: repo root, no build command). `nightfix.dev` is attached under the Worker's **Settings → Domains & Routes**.

Preview URLs are off (`preview_urls: false`), so builds of other branches show as failed in GitHub checks. That's expected; only `main` deploys.

After changing a file at a fixed path (such as `security.txt`), purge it from Cloudflare's cache if the old version keeps appearing.

## Yearly upkeep

`security.txt` must have an `Expires` date in the future (RFC 9116 recommends less than a year ahead). CI fails 30 days before it lapses; bump the date then.

## At launch

Restore the full site with `git checkout origin/archive/full-site -- website`, put the build back in the root `wrangler.jsonc` (the lines are in its comments), and let the `nightfix` Worker redeploy.
