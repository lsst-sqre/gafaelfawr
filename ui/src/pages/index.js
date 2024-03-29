import { Link } from 'gatsby';
import React from 'react';

import Layout from '../components/layout';
import TokenList from '../components/tokenList';

const Home = function () {
  return (
    <Layout>
      <h1>Tokens</h1>
      <p>
        <Link to="/changes">Search token change history</Link>
      </p>
      <TokenList />
    </Layout>
  );
};

export default Home;
