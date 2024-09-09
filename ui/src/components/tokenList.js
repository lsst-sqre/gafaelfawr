import React, {
  useCallback,
  useContext,
  useState,
  useEffect,
  useMemo,
} from 'react';
import { useAlert } from 'react-alert';

import CreateTokenButton from './createTokenButton';
import { LoginContext } from './loginContext.js';
import TokenTable from './tokenTable';
import { apiDelete, apiGet } from '../functions/api';

const TokenList = function () {
  const alert = useAlert();
  const { csrf, username } = useContext(LoginContext);
  const [data, setData] = useState(null);
  const tokens = useMemo(() => data, [data]);

  const loadTokenData = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens`)
      .then((tokenList) => ({
        user: tokenList.filter((t) => t.token_type === 'user'),
        session: tokenList.filter((t) => t.token_type === 'session'),
        notebook: tokenList.filter((t) => t.token_type === 'notebook'),
        internal: tokenList.filter((t) => t.token_type === 'internal'),
        oidc: tokenList.filter((t) => t.token_type === 'oidc'),
      }))
      .then(setData)
      .catch((e) => alert.show(e.message));
  }, [alert, username]);

  const deleteToken = useCallback(
    async (token) => {
      await apiDelete(`/users/${username}/tokens/${token}`, csrf)
        .then(loadTokenData)
        .catch((e) => alert.show(e.message));
    },
    [alert, csrf, loadTokenData, username],
  );

  useEffect(loadTokenData, [loadTokenData, username]);

  if (!data) return <p>Loading...</p>;

  return (
    <>
      <h2>User Tokens</h2>
      <CreateTokenButton onCreate={loadTokenData} />
      {tokens.user.length ? (
        <TokenTable
          id="tokens-user"
          data={tokens.user}
          includeName
          onDeleteToken={deleteToken}
        />
      ) : null}
      <h2>Web Sessions</h2>
      <TokenTable
        id="tokens-session"
        data={tokens.session}
        onDeleteToken={deleteToken}
      />
      {tokens.notebook.length ? (
        <>
          <h2>Notebook Tokens</h2>
          <TokenTable
            id="tokens-notebook"
            data={tokens.notebook}
            onDeleteToken={deleteToken}
          />
        </>
      ) : null}
      {tokens.internal.length ? (
        <>
          <h2>Internal Tokens</h2>
          <TokenTable
            id="tokens-internal"
            data={tokens.internal}
            onDeleteToken={deleteToken}
          />
        </>
      ) : null}
      {tokens.oidc.length ? (
        <>
          <h2>OpenID Connect Tokens</h2>
          <TokenTable
            id="tokens-oidc"
            data={tokens.oidc}
            onDeleteToken={deleteToken}
          />
        </>
      ) : null}
    </>
  );
};

export default TokenList;
