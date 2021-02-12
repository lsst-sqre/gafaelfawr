import { Link } from 'gatsby';
import React from 'react';

import ErrorBanner from '../components/errorBanner';
import Layout from '../components/layout';
import TokenChangeSearch from '../components/tokenChangeSearch';
import useError from '../hooks/error';

export default function Changes() {
  const { error, onError } = useError();

  return (
    <Layout onError={onError}>
      <ErrorBanner error={error} />
      <p>
        <Link to="/">Return to token list</Link>
      </p>
      <TokenChangeSearch onError={onError} />
    </Layout>
  );
}
