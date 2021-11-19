import { Link } from 'gatsby';
import React from 'react';
import { useQueryParams, StringParam, withDefault } from 'use-query-params';

import Layout from '../components/layout';
import TokenChangeSearch from '../components/tokenChangeSearch';

const Changes = function () {
  const [query, setQuery] = useQueryParams({
    key: StringParam,
    tokenType: withDefault(StringParam, 'any'),
    ipAddress: StringParam,
    sinceDate: StringParam,
    untilDate: StringParam,
  });

  return (
    <Layout>
      <p>
        <Link to="/">Return to token list</Link>
      </p>
      <TokenChangeSearch query={query} setQuery={setQuery} />
    </Layout>
  );
};

export default Changes;
