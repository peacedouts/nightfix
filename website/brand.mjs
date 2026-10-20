// One place for the product name and contact settings, so a rename is a
// one-line change. Environment variables override the defaults at build time
// (set them in Cloudflare Pages → Settings → Variables).

export const brand = {
  name: 'Nightfix',
  tagline: 'Runbooks that fix the alert before anyone is paged.',
  domain: 'nightfix.dev',
  contactEmail: process.env.PUBLIC_CONTACT_EMAIL ?? 'hello@nightfix.dev',
  securityEmail: process.env.PUBLIC_SECURITY_EMAIL ?? 'security@nightfix.dev',
  // A form backend that accepts a normal HTML POST (Formspree, Tally, Basin…).
  // Leave unset to show the email address instead of the form.
  formEndpoint: process.env.PUBLIC_FORM_ENDPOINT ?? '',
  githubUrl: process.env.PUBLIC_GITHUB_URL ?? '',
};
