import PropTypes from 'prop-types';
import React, { useMemo } from 'react';
import { positions, Provider as AlertProvider, useAlert } from 'react-alert';
import AlertTemplate from 'react-alert-template-basic';

import { LoginContext } from './loginContext';
import useLogin from '../hooks/login';

const Application = function ({ children }) {
  const alert = useAlert();
  const { csrf, username, userScopes, config } = useLogin(alert);
  const value = useMemo(
    () => ({
      csrf,
      username,
      userScopes,
      config,
    }),
    [csrf, username, userScopes, config],
  );

  return (
    <LoginContext.Provider value={value}>
      <div id="application">{children}</div>
    </LoginContext.Provider>
  );
};
Application.propTypes = {
  children: PropTypes.element.isRequired,
};

const Layout = function ({ children }) {
  return (
    <AlertProvider
      template={AlertTemplate}
      position={positions.TOP_CENTER}
      timeout={0}
    >
      <Application>{children}</Application>
    </AlertProvider>
  );
};
Layout.propTypes = {
  children: PropTypes.element.isRequired,
};

export default Layout;
