import PropTypes from 'prop-types';
import React from 'react';
import AriaModal from 'react-aria-modal';
import styled from 'styled-components';

import ErrorBanner from './errorBanner';
import TokenForm from './tokenForm';

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

export default function TokenModal({
  idPrefix,
  buttonLabel,
  name = '',
  scopes = [],
  expiresDate = null,
  error,
  userScopes,
  knownScopes,
  onSubmit,
  onExit,
}) {
  const getApplicationNode = () => {
    document.getElementById('application');
  };

  return (
    <AriaModal
      titleText="Edit token"
      onExit={onExit}
      getApplicationNode={getApplicationNode}
    >
      <StyledModal id={`${idPrefix}-modal`}>
        <ErrorBanner error={error} />
        <TokenForm
          idPrefix={idPrefix}
          buttonLabel={buttonLabel}
          name={name}
          scopes={scopes}
          expiresDate={expiresDate}
          userScopes={userScopes}
          knownScopes={knownScopes}
          onSubmit={onSubmit}
          onCancel={onExit}
        />
      </StyledModal>
    </AriaModal>
  );
}
TokenModal.propTypes = {
  idPrefix: PropTypes.string.isRequired,
  buttonLabel: PropTypes.string.isRequired,
  name: PropTypes.string,
  scopes: PropTypes.arrayOf(PropTypes.string),
  expiresDate: PropTypes.objectOf(Date),
  error: PropTypes.string,
  userScopes: PropTypes.arrayOf(PropTypes.string),
  knownScopes: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string,
      description: PropTypes.string,
    })
  ),
  onSubmit: PropTypes.func.isRequired,
  onExit: PropTypes.func.isRequired,
};
