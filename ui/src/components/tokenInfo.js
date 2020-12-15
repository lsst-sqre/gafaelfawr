import React, {
  useCallback,
  useContext,
  useState,
  useEffect,
  useMemo,
} from 'react';
import CreateTokenButton from './createTokenButton';
import { LoginContext } from './loginContext.js';
import TokenTable from './tokenTable';
import useError from '../hooks/error';
import { apiDelete, apiGet, apiPost } from '../functions/api';

export default function TokenInfo({ onError = (f) => f }) {
  const { csrf, username } = useContext(LoginContext);
  const [data, setData] = useState(null);
  const tokens = useMemo(() => data, [data]);
  const { error: createError, onError: onCreateError } = useError();

  const loadTokenData = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens`)
      .then((tokenList) => ({
        user: tokenList.filter((t) => t.token_type === 'user'),
        session: tokenList.filter((t) => t.token_type === 'session'),
        notebook: tokenList.filter((t) => t.token_type === 'notebook'),
        internal: tokenList.filter((t) => t.token_type === 'internal'),
      }))
      .then(setData)
      .catch(onError);
  }, [onError, username]);

  const createToken = useCallback(
    async (values, setNewToken) => {
      await apiPost(`/users/${username}/tokens`, csrf, {
        token_name: values.name,
        scopes: values.scopes ? values.scopes.split(',') : [],
        expires: values.expires ? parseInt(values.expires) : null,
      })
        .then((response) => setNewToken(response.token))
        .then(loadTokenData)
        .catch(onCreateError);
    },
    [csrf, loadTokenData, onCreateError, username]
  );

  const deleteToken = useCallback(
    async (token) => {
      await apiDelete(`/users/${username}/tokens/${token}`, csrf)
        .then(loadTokenData)
        .catch(onError);
    },
    [csrf, loadTokenData, onError, username]
  );

  useEffect(loadTokenData, [loadTokenData, username]);

  if (!data) return <p>Loading...</p>;

  return (
    <>
      <h1>User Tokens</h1>
      <CreateTokenButton
        onCreateToken={createToken}
        createError={createError}
      />
      {tokens.user.length ? (
        <TokenTable
          data={tokens.user}
          includeName
          onDeleteToken={deleteToken}
        />
      ) : (
        false
      )}
      <h1>Web Sessions</h1>
      <TokenTable data={tokens.session} onDeleteToken={deleteToken} />
      {tokens.notebook.length ? (
        <>
          <h1>Notebook Tokens</h1>
          <TokenTable data={tokens.notebook} onDeleteToken={deleteToken} />
        </>
      ) : (
        false
      )}
      {tokens.internal.length ? (
        <>
          <h1>Internal Tokens</h1>
          <TokenTable data={tokens.internal} onDeleteToken={deleteToken} />
        </>
      ) : (
        false
      )}
    </>
  );
}
