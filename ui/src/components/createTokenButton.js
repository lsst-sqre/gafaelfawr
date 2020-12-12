import React, { useState } from 'react';
import PropTypes from 'prop-types';
import AriaModal from 'react-aria-modal';
import styled from 'styled-components';
import CreateTokenForm from './createTokenForm';

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
        <code>{token}</code>
      </p>
      <p>
        Save this token now. After closing this notification, you{' '}
        <strong>will not be able to see this token again.</strong> If lost, you
        will need to delete the token and create a new one.
      </p>
      <button type="submit" id="token-accept" onClick={onAccept}>
        Okay
      </button>
    </>
  );
}
NewToken.propTypes = {
  token: PropTypes.string.isRequired,
  onAccept: PropTypes.func.isRequired,
};

export default function CreateTokenButton({ onCreateToken = async (f) => f }) {
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
    await onCreateToken(values, setNewToken);
    deactivateFormModal();
  };

  const NewTokenModal = () => (
    <AriaModal
      titleText="New token"
      alert
      initialFocus="#token-accept"
      onExit={deactivateTokenModal}
      getApplicationNode={getApplicationNode}
    >
      <StyledModal>
        <NewToken token={newToken} onAccept={deactivateTokenModal} />
      </StyledModal>
    </AriaModal>
  );

  const CreateTokenModal = () => (
    <AriaModal
      titleText="Create token"
      onExit={deactivateFormModal}
      getApplicationNode={getApplicationNode}
    >
      <StyledModal>
        <CreateTokenForm
          onCreateToken={createToken}
          onCancel={deactivateFormModal}
        />
      </StyledModal>
    </AriaModal>
  );

  return (
    <>
      <button type="button" onClick={activateFormModal}>
        Create Token
      </button>
      {newToken ? <NewTokenModal /> : formActive && <CreateTokenModal />}
    </>
  );
}
