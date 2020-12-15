import PropTypes from 'prop-types';
import React from 'react';

export default function ErrorBanner({ error, id }) {
  return error ? (
    <div id={id}>
      <p role="alert">{error}</p>
    </div>
  ) : null;
}
ErrorBanner.propTypes = {
  error: PropTypes.string,
  id: PropTypes.string,
};
