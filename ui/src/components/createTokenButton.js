import PropTypes from 'prop-types';
import React, { useState } from 'react';
import AriaModal from 'react-aria-modal';
import styled from 'styled-components';
import TokenModal from './tokenModal.js';

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

function NewToken({ token, onAccept }) {
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
}
NewToken.propTypes = {
  token: PropTypes.string.isRequired,
  onAccept: PropTypes.func.isRequired,
};

export default function CreateTokenButton({
  error,
  userScopes,
  knownScopes,
  onCreateToken,
}) {
  const [formActive, setFormActive] = useState(false);
  const [newToken, setNewToken] = useState('');

  const activateFormModal = () => {
    setFormActive(true);
  };
  const deactivateFormModal = () => {
    setFormActive(false);
  };
  const deactivateTokenModal = () => {
    setNewToken('');
  };
  const getApplicationNode = () => {
    document.getElementById('application');
  };

  const createToken = async (values) => {
    const onCreateSuccess = (token) => {
      deactivateFormModal();
      setNewToken(token);
    };
    await onCreateToken(values, onCreateSuccess);
  };

  return (
    <>
      <button id="qa-create-token" type="button" onClick={activateFormModal}>
        Create Token
      </button>
      {formActive && (
        <TokenModal
          idPrefix="create-token"
          buttonLabel="Create"
          error={error}
          userScopes={userScopes}
          knownScopes={knownScopes}
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
}
CreateTokenButton.propTypes = {
  error: PropTypes.string,
  userScopes: PropTypes.arrayOf(PropTypes.string),
  knownScopes: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string,
      description: PropTypes.string,
    })
  ),
  onCreateToken: PropTypes.func.isRequired,
};
