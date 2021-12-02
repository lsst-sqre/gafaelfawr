import PropTypes from 'prop-types';
import React from 'react';

const TokenName = function ({ name }) {
  return <span className="qa-token-name">{name}</span>;
};
TokenName.propTypes = {
  name: PropTypes.string.isRequired,
};

export default TokenName;
