import { Link } from 'gatsby';
import React from 'react';

import Layout from '../components/layout';
import TokenChangeSearch from '../components/tokenChangeSearch';

export default function Changes() {
  return (
    <Layout>
      <p>
        <Link to="/">Return to token list</Link>
      </p>
      <TokenChangeSearch />
    </Layout>
  );
}
