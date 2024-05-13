import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'tlspuffin',
  tagline: 'TLS Protocol Under FuzzINg: A Dolev-Yao guided fuzzer for TLS',
  favicon: 'img/favicon.ico',

  // deployment configuration
  url: 'https://tlspuffin.github.io',
  baseUrl: '/',
  organizationName: 'tlspuffin',
  projectName: 'tlspuffin.github.io',
  deploymentBranch: 'main',
  trailingSlash: undefined,

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/logo.jpg',
    navbar: {
      title: 'tlspuffin',
      logo: {
        alt: 'tlspuffin logo',
        src: 'img/logo.jpg',
        className: 'avatar__photo',
      },
      items: [
        { to: '/docs/overview', label: 'Docs', position: 'left' },
        { to: 'pathname:///api/tlspuffin/', label: 'API', position: 'left' },
        {
          href: 'https://github.com/tlspuffin/tlspuffin',
          position: 'right',
          className: "header-github-link",
          'aria-label': 'GitHub Repository'
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Quickstart',
              to: '/docs/guides/quickstart',
            },
            {
              label: 'Getting Started',
              to: '/docs/guides/getting-started/installation',
            },
            {
              label: 'Reference Manual',
              to: '/docs/overview',
            },
          ],
        },
        {
          title: 'Development',
          items: [
            {
              label: 'Source code',
              href: 'https://github.com/tlspuffin/tlspuffin',
            },
            {
              label: 'Report a bug',
              href: 'https://github.com/tlspuffin/tlspuffin/issues',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Privacy Policy',
              to: '/privacy',
            },
          ],
        },
      ],
      copyright: `Powered by <a href="https://docusaurus.io/">Docusaurus</a> and <a href="https://pages.github.com/">GitHub Pages</a>`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    }
  } satisfies Preset.ThemeConfig,
  themes: ['@docusaurus/theme-mermaid'],
  // In order for Mermaid code blocks in Markdown to work,
  // you also need to enable the Remark plugin with this option
  markdown: {
    mermaid: true,
  },
};

export default config;
