import { Link } from 'gatsby';
import PropTypes from 'prop-types';
import React from 'react';

const Token = function ({ token, link = true }) {
  return link ? (
    <Link to={`/id/${token}`}>
      <code className="qa-token">{token}</code>
    </Link>
  ) : (
    <code className="qa-token">{token}</code>
  );
};
Token.propTypes = {
  token: PropTypes.string.isRequired,
  link: PropTypes.bool,
};

export default Token;
