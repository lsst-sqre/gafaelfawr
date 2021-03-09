import PropTypes from 'prop-types';
import React from 'react';
import { positions, Provider as AlertProvider, useAlert } from 'react-alert';
import AlertTemplate from 'react-alert-template-basic';

import { LoginContext } from './loginContext';
import useLogin from '../hooks/login';

function Application({ children }) {
  const alert = useAlert();
  const { csrf, username, userScopes, config } = useLogin(alert);

  return (
    <LoginContext.Provider value={{ csrf, username, userScopes, config }}>
      <div id="application">{children}</div>
    </LoginContext.Provider>
  );
}
Application.propTypes = {
  children: PropTypes.element.isRequired,
};

export default function Layout({ children }) {
  return (
    <AlertProvider
      template={AlertTemplate}
      position={positions.TOP_CENTER}
      timeout={0}
    >
      <Application>{children}</Application>
    </AlertProvider>
  );
}
Layout.propTypes = {
  children: PropTypes.element.isRequired,
};
