import PropTypes from 'prop-types';
import React, {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useAlert } from 'react-alert';

import { LoginContext } from './loginContext';
import Timestamp from './timestamp';
import Token from './token';
import TokenChangeHistory from './tokenChangeHistory';
import TokenName from './tokenName';
import { apiGet } from '../functions/api';

const TokenData = function ({ token }) {
  const alert = useAlert();
  const { username } = useContext(LoginContext);
  const [_tokenData, setTokenData] = useState(null);
  const tokenData = useMemo(() => _tokenData, [_tokenData]);

  const loadTokenData = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens/${token}`)
      .then(setTokenData)
      .catch((e) => alert.show(e.message));
  }, [alert, token, username]);

  useEffect(loadTokenData, [loadTokenData, token, username]);

  if (!tokenData) return <p>Loading...</p>;

  return (
    <>
      <table className="qa-token-data">
        <tbody>
          <tr>
            <th scope="row">Token</th>
            <td>
              <Token token={tokenData.token} link={false} />
            </td>
          </tr>
          <tr>
            <th scope="row">Username</th>
            <td className="qa-username">{tokenData.username}</td>
          </tr>
          <tr>
            <th scope="row">Type</th>
            <td className="qa-type">{tokenData.token_type}</td>
          </tr>
          {tokenData.token_name && (
            <tr>
              <th scope="row">Name</th>
              <td>
                <TokenName name={tokenData.token_name} />
              </td>
            </tr>
          )}
          <tr>
            <th scope="row">Scopes</th>
            <td className="qa-scopes">{tokenData.scopes.join(', ')}</td>
          </tr>
          {tokenData.service && (
            <tr>
              <th scope="row">Service</th>
              <td>{tokenData.service}</td>
            </tr>
          )}
          {tokenData.parent && (
            <tr>
              <th scope="row">Parent</th>
              <td>
                <Token token={tokenData.parent} />
              </td>
            </tr>
          )}
          <tr>
            <th scope="row">Created</th>
            <td>
              <Timestamp timestamp={tokenData.created} />
            </td>
          </tr>
          <tr>
            <th scope="row">Last Used</th>
            <td>
              <Timestamp timestamp={tokenData.last_used} />
            </td>
          </tr>
          <tr>
            <th scope="row">Expires</th>
            <td>
              <Timestamp
                timestamp={tokenData.expires}
                className="qa-expires"
                expiration
              />
            </td>
          </tr>
        </tbody>
      </table>
      <h2>Change History</h2>
      <TokenChangeHistory token={token} />
    </>
  );
};
TokenData.propTypes = {
  token: PropTypes.string.isRequired,
};

export default TokenData;
