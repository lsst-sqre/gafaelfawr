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
      <TokenChangeSearch onError={onError} />
    </Layout>
  );
}
