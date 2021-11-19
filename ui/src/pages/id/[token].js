import { Link } from 'gatsby';
import PropTypes from 'prop-types';
import React from 'react';

import Layout from '../../components/layout';
import TokenData from '../../components/tokenData';

const TokenPage = function ({ params }) {
  return (
    <Layout>
      <p>
        <Link to="/">Return to token list</Link>
      </p>
      <TokenData token={params.token} />
    </Layout>
  );
};
TokenPage.propTypes = {
  params: PropTypes.shape({
    token: PropTypes.string.isRequired,
  }),
};

export default TokenPage;
