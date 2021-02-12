import PropTypes from 'prop-types';
import React, {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import TokenChangeTable from './tokenChangeTable';
import { LoginContext } from './loginContext';
import { apiGet } from '../functions/api';

export default function TokenChangeHistory({ token, onError }) {
  const { username } = useContext(LoginContext);
  const [_data, setData] = useState([]);
  const data = useMemo(() => _data, [_data]);

  const loadHistory = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens/${token}/change-history`)
      .then(setData)
      .catch(onError);
  }, [onError, token, username]);

  useEffect(loadHistory, [loadHistory, token, username]);

  return <TokenChangeTable data={data} />;
}
TokenChangeHistory.propTypes = {
  token: PropTypes.string.isRequired,
  onError: PropTypes.func.isRequired,
};
