import PropTypes from 'prop-types';
import React from 'react';
import { useAlert } from 'react-alert';
import AriaModal from 'react-aria-modal';
import styled from 'styled-components';

import TokenForm from './tokenForm';
import { APIError } from '../functions/api';

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

// Convert an APIError to the errors data for a form.  Unknown errors are
// shown as alerts instead.
function exceptionToErrors(e, alert) {
  const errors = {};
  if (e instanceof APIError) {
    for (const detail of e.detail) {
      if (detail.loc && detail.loc[0] === 'body') {
        switch (detail.loc[1]) {
          case 'token_name':
            errors.name = detail.msg;
            break;
          case 'scopes':
            errors.scopes = detail.msg;
            break;
          case 'expires':
            errors.expires = detail.msg;
            break;
          default:
            alert.show(detail.msg);
            break;
        }
      } else {
        alert.show(detail.msg);
      }
    }
  } else {
    alert.show(e.message);
  }
  return errors;
}

const TokenModal = function ({
  idPrefix,
  buttonLabel,
  name = '',
  scopes = [],
  expiresDate = null,
  userScopes,
  knownScopes,
  onSubmit,
  onExit,
}) {
  const alert = useAlert();
  const getApplicationNode = () => {
    document.getElementById('application');
  };
  const handleSubmit = (values, setErrors) =>
    onSubmit(values).catch((e) => setErrors(exceptionToErrors(e, alert)));

  return (
    <AriaModal
      titleText={`${buttonLabel} token`}
      onExit={onExit}
      getApplicationNode={getApplicationNode}
    >
      <StyledModal id={`${idPrefix}-modal`}>
        <TokenForm
          idPrefix={idPrefix}
          buttonLabel={buttonLabel}
          name={name}
          scopes={scopes}
          expiresDate={expiresDate}
          userScopes={userScopes}
          knownScopes={knownScopes}
          onSubmit={handleSubmit}
          onCancel={onExit}
        />
      </StyledModal>
    </AriaModal>
  );
};
TokenModal.propTypes = {
  idPrefix: PropTypes.string.isRequired,
  buttonLabel: PropTypes.string.isRequired,
  name: PropTypes.string,
  scopes: PropTypes.arrayOf(PropTypes.string),
  expiresDate: PropTypes.objectOf(Date),
  userScopes: PropTypes.arrayOf(PropTypes.string),
  knownScopes: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string,
      description: PropTypes.string,
    }),
  ),
  onSubmit: PropTypes.func.isRequired,
  onExit: PropTypes.func.isRequired,
};

export default TokenModal;
