import { Link } from 'gatsby';
import React from 'react';

import ErrorBanner from '../components/errorBanner';
import Layout from '../components/layout';
import TokenList from '../components/tokenList';
import useError from '../hooks/error';

export default function Home() {
  const { error, onError } = useError();

  return (
    <Layout onError={onError}>
      <ErrorBanner error={error} />
      <h1>Tokens</h1>
      <p>
        <Link to="/changes">Search token change history</Link>
      </p>
      <TokenList onError={onError} />
    </Layout>
  );
}
