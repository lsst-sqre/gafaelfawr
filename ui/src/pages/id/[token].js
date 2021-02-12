import { Link } from 'gatsby';
import PropTypes from 'prop-types';
import React from 'react';

import ErrorBanner from '../../components/errorBanner';
import Layout from '../../components/layout';
import TokenData from '../../components/tokenData';
import useError from '../../hooks/error';

export default function TokenPage({ params }) {
  const { error, onError } = useError();

  return (
    <Layout onError={onError}>
      <ErrorBanner error={error} />
      <p>
        <Link to="/">Return to token list</Link>
      </p>
      <TokenData token={params.token} onError={onError} />
    </Layout>
  );
}
TokenPage.propTypes = {
  params: PropTypes.shape({
    token: PropTypes.string.isRequired,
  }),
};
