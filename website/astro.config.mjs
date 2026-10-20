import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { brand } from './brand.mjs';

export default defineConfig({
  // Canonical URLs and the sitemap. Override with SITE_URL for preview builds.
  site: process.env.SITE_URL ?? `https://${brand.domain}`,
  integrations: [
    starlight({
      title: brand.name,
      description: brand.tagline,
      logo: { src: './src/assets/mark.svg', replacesTitle: false },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/docs.css'],
      social: brand.githubUrl ? [{ icon: 'github', label: 'GitHub', href: brand.githubUrl }] : [],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'What Nightfix does', slug: 'docs' },
            { label: 'How it works', slug: 'docs/how-it-works' },
          ],
        },
        {
          label: 'Trust',
          items: [{ label: 'Security model', slug: 'docs/security' }],
        },
        {
          label: 'Set up',
          items: [
            { label: 'Install the agent', slug: 'docs/agent' },
            { label: 'Write a runbook', slug: 'docs/runbooks' },
            { label: 'Sign in with Auth0', slug: 'docs/sign-in' },
          ],
        },
      ],
    }),
  ],
});
