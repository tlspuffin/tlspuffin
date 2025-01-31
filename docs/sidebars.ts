import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'overview',
    'guides/quickstart',
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'guides/getting-started/introduction',
        'guides/getting-started/installation',
        'guides/getting-started/building-openssl',
        'guides/getting-started/fuzzing-openssl',
        'guides/getting-started/replaying-traces',
      ],
    },
    {
      type: 'category',
      label: 'Reference Manual',
      collapsed: false,
      items: [
        'references/support-matrix',
        'references/mk_vendor',
      ],
    },
    {
        type: 'category',
        label: 'Developer Documentation',
        collapsed: false,
        items: [
            'developer/overview',
            'developer/build',
            'developer/howto',
        ],
    }
  ],
};

export default sidebars;
