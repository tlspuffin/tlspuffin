import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import styles from './index.module.css';
import IconRocket from './tabler-rocket.svg';
import IconDocs from './tabler-books.svg';
import IconSource from './tabler-brand-github.svg';
import React from 'react';

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>

        <div className={styles.buttons}>
          <Link
            className={clsx('button button--primary button--lg')}
            to="/docs/guides/quickstart">
            <IconRocket className={styles.buttonIcon} /> <span className={styles.buttonText}>Get Started</span>
          </Link>
          <Link
            className={clsx('button button--primary button--lg')}
            to="/docs/overview">
            <IconDocs className={styles.buttonIcon} /> <span className={styles.buttonText}>Documentation</span>
          </Link>
          <Link
            className={clsx('button button--primary button--lg')}
            to="https://github.com/tlspuffin/tlspuffin">
            <IconSource className={styles.buttonIcon} /> <span className={styles.buttonText}>Source code</span>
          </Link>
        </div>

        <p className={styles.heroLicensing}>Open-source under the <a href="https://github.com/tlspuffin/tlspuffin?tab=readme-ov-file#license">MIT and Apache-2.0 licenses</a></p>
      </div>
    </header>
  );
}

export default function Home(): JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <HomepageHeader />
  );
}
