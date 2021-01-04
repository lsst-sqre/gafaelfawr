import PropTypes from 'prop-types';
import React from 'react';

export default function ErrorBanner({ error }) {
  return error ? (
    <div>
      <p role="alert">{error}</p>
    </div>
  ) : null;
}
ErrorBanner.propTypes = {
  error: PropTypes.string,
};
