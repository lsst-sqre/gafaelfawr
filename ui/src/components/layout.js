import PropTypes from 'prop-types';
import React from 'react';

import { LoginContext } from './loginContext';
import useLogin from '../hooks/login';

export default function Layout({ children, onError }) {
  const { csrf, username, userScopes, config } = useLogin(onError);

  return (
    <LoginContext.Provider value={{ csrf, username, userScopes, config }}>
      <div id="application">{children}</div>
    </LoginContext.Provider>
  );
}
Layout.propTypes = {
  children: PropTypes.element.isRequired,
  onError: PropTypes.func.isRequired,
};
