import fromUnixTime from 'date-fns/fromUnixTime';
import PropTypes from 'prop-types';
import React, { useCallback, useContext, useEffect, useState } from 'react';
import { useAlert } from 'react-alert';

import { LoginContext } from './loginContext.js';
import TokenModal from './tokenModal.js';
import useError from '../hooks/error.js';
import { apiGet, apiPatch } from '../functions/api.js';

export default function EditTokenModal({ token, onSuccess, onExit }) {
  const alert = useAlert();
  const { csrf, username, userScopes, config } = useContext(LoginContext);
  const [tokenData, setTokenData] = useState(null);
  const { error, onError } = useError();

  const loadTokenData = useCallback(() => {
    if (!username || !token) return;
    apiGet(`/users/${username}/tokens/${token}`)
      .then(setTokenData)
      .catch((e) => alert.show(e.message));
  }, [alert, token, username]);

  useEffect(loadTokenData, [loadTokenData, token, username]);

  const editToken = useCallback(
    async ({ name, scopes, expires }) => {
      const body = {};
      if (name !== tokenData.token_name) {
        body.token_name = name;
      }
      if (JSON.stringify(scopes) !== JSON.stringify(tokenData.scopes)) {
        body.scopes = scopes;
      }
      if (expires !== tokenData.expires) {
        body.expires = expires;
      }
      if (Object.keys(body).length === 0) {
        onSuccess();
      } else {
        await apiPatch(`/users/${username}/tokens/${token}`, csrf, body)
          .then(onSuccess)
          .catch(onError);
      }
    },
    [csrf, onError, onSuccess, token, tokenData, username]
  );

  if (!tokenData) return null;

  return (
    <TokenModal
      idPrefix="edit-token"
      buttonLabel="Modify"
      name={tokenData.token_name}
      scopes={tokenData.scopes}
      expiresDate={tokenData.expires ? fromUnixTime(tokenData.expires) : null}
      error={error}
      userScopes={userScopes}
      knownScopes={config.scopes}
      onSubmit={editToken}
      onExit={onExit}
    />
  );
}
EditTokenModal.propTypes = {
  token: PropTypes.string.isRequired,
  onSuccess: PropTypes.func.isRequired,
  onExit: PropTypes.func.isRequired,
};
