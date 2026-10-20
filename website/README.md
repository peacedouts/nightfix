# Nightfix website

The marketing site and docs: Astro + Starlight, built to static files for Cloudflare Pages.

- `/` is the landing page (`src/pages/index.astro`).
- `/docs/…` are the docs (`src/content/docs/docs/*.md`), rendered by Starlight with search built in.

## Run it locally

```bash
cd website
npm ci
npm run dev        # http://localhost:4321
npm run build      # outputs to dist/
```

## Change the name, email or form

Everything brand-related lives in `brand.mjs`, so a rename is a one-line change. The rest comes from environment variables at build time:

| Variable | What it does |
|---|---|
| `SITE_URL` | Your domain, e.g. `https://nightfix.dev`. Used for canonical URLs and the sitemap |
| `PUBLIC_CONTACT_EMAIL` | Shown when no form backend is set, and in the footer |
| `PUBLIC_FORM_ENDPOINT` | A form backend that accepts a normal HTML POST (Formspree, Tally, Basin). When set, the design-partner form appears |
| `PUBLIC_GITHUB_URL` | Adds a GitHub link to the docs header |

## Deploy to Cloudflare Pages

1. In Cloudflare, go to **Workers & Pages → Create → Pages → Connect to Git** and pick this repository.
2. Build settings:
   - Framework preset: **Astro**
   - Root directory: `website`
   - Build command: `npm run build`
   - Output directory: `dist`
3. Under **Settings → Variables and Secrets**, add the variables above for Production.
4. Under **Custom domains**, add your domain. With DNS already on Cloudflare, the record and certificate are created for you.

Every pull request gets its own preview URL.

## Design notes

The palette is the street at 2 a.m.: deep indigo, a sodium-vapor amber for actions and emphasis, and sea-glass green used only to mean "resolved, nobody paged". Type is Schibsted Grotesk throughout. Martian Mono appears only in the incident log, because that's what logs look like. The hero replays a real run from the walking-skeleton demo, and it's the page's one animation. It's skipped for people who prefer reduced motion.
