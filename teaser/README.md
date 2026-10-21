# Nightfix teaser

The public page for nightfix.dev until launch: the name and one line. It says nothing about what Nightfix does or how it works. The full marketing site and docs are kept on the `archive/full-site` branch until launch.

Plain static files, no build step.

```
teaser/
├── wrangler.jsonc        Worker config (static assets only)
└── public/
    ├── index.html        the page
    ├── 404.html
    ├── favicon.svg
    ├── robots.txt
    ├── _headers          security headers
    └── .well-known/security.txt
```

## Preview locally

```bash
cd teaser
npx wrangler dev          # http://localhost:8787
```

## Deploy

From this folder: `npx wrangler login`, then `npx wrangler deploy`. Or connect the repo in Cloudflare with **Root directory** set to `teaser` and an empty build command. Then attach `nightfix.dev` under the Worker's **Settings → Domains & Routes**.

## At launch

Restore the full site with `git checkout origin/archive/full-site -- website`, put the build back in the root `wrangler.jsonc` (the lines are in its comments), and let the `nightfix` Worker redeploy.
