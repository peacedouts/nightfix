# Nightfix teaser

The public page for nightfix.dev until launch: the name, one line, and an early-access sign-up. It says nothing about what Nightfix does or how it works. The full marketing site and docs are kept on the `archive/full-site` branch until launch.

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

## The sign-up form

The form's `data-endpoint` attribute in `public/index.html` is empty. While it's empty, "Get early access" opens an email to `hello@nightfix.dev`. Paste a Formspree, Tally or Basin endpoint there to collect sign-ups directly.

## At launch

Restore the full site with `git checkout origin/archive/full-site -- website`, put the build back in the root `wrangler.jsonc` (the lines are in its comments), and let the `nightfix` Worker redeploy.
