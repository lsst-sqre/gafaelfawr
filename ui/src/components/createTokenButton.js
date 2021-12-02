import PropTypes from 'prop-types';
import React, { useCallback, useContext, useState } from 'react';
import AriaModal from 'react-aria-modal';
import styled from 'styled-components';

import { LoginContext } from './loginContext';
import TokenModal from './tokenModal';
import { apiPost } from '../functions/api';

const StyledModal = styled.div`
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background: white;
  foreground: black;
  width: 600px;
  max-width: 100%;
`;

const NewToken = function ({ token, onAccept }) {
  return (
    <>
      <p>Your new token is:</p>
      <p>
        <code id="qa-new-token">{token}</code>
      </p>
      <p>
        Save this token now. After closing this notification, you{' '}
        <strong>will not be able to see this token again.</strong> If lost, you
        will need to delete the token and create a new one.
      </p>
      <button type="button" id="token-accept" onClick={onAccept}>
        Okay
      </button>
    </>
  );
};
NewToken.propTypes = {
  token: PropTypes.string.isRequired,
  onAccept: PropTypes.func.isRequired,
};

const CreateTokenButton = function ({ onCreate }) {
  const { csrf, username, userScopes, config } = useContext(LoginContext);
  const [formActive, setFormActive] = useState(false);
  const [newToken, setNewToken] = useState('');

  const activateFormModal = () => setFormActive(true);
  const deactivateFormModal = () => {
    setFormActive(false);
  };
  const deactivateTokenModal = () => {
    setNewToken('');
  };
  const getApplicationNode = () => {
    document.getElementById('application');
  };

  const createToken = useCallback(
    ({ name, scopes, expires }) =>
      apiPost(`/users/${username}/tokens`, csrf, {
        token_name: name,
        scopes,
        expires,
      })
        .then((response) => setNewToken(response.token))
        .then(() => deactivateFormModal())
        .then(onCreate),
    [csrf, onCreate, setNewToken, username]
  );

  return (
    <>
      <button id="qa-create-token" type="button" onClick={activateFormModal}>
        Create Token
      </button>
      {formActive && (
        <TokenModal
          idPrefix="create-token"
          buttonLabel="Create"
          userScopes={userScopes}
          knownScopes={config.scopes}
          onSubmit={createToken}
          onExit={deactivateFormModal}
        />
      )}
      {newToken && (
        <AriaModal
          titleText="New token"
          alert
          initialFocus="#token-accept"
          onExit={deactivateTokenModal}
          getApplicationNode={getApplicationNode}
        >
          <StyledModal id="qa-new-token-modal">
            <NewToken token={newToken} onAccept={deactivateTokenModal} />
          </StyledModal>
        </AriaModal>
      )}
    </>
  );
};
CreateTokenButton.propTypes = {
  onCreate: PropTypes.func.isRequired,
};

export default CreateTokenButton;
