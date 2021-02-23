import PropTypes from 'prop-types';
import React, {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { LoginContext } from './loginContext';
import TokenChangeSearchForm from './tokenChangeSearchForm';
import TokenChangeTable from './tokenChangeTable';
import { apiGet } from '../functions/api';

export default function TokenChangeSearch({ onError }) {
  const { username } = useContext(LoginContext);
  const [search, setSearch] = useState(null);
  const [_data, setData] = useState([]);
  const data = useMemo(() => _data, [_data]);

  const loadHistory = useCallback(() => {
    if (!username) return;
    if (search === null) return;
    apiGet(`/users/${username}/token-change-history`, search)
      .then(setData)
      .then(() => onError(null))
      .catch(onError);
  }, [onError, search, username]);

  useEffect(loadHistory, [loadHistory, search, username]);

  return (
    <>
      <TokenChangeSearchForm search={search} onSubmit={setSearch} />
      {search !== null && (
        <>
          <h2>Results</h2>
          <TokenChangeTable data={data} includeToken />
        </>
      )}
    </>
  );
}
TokenChangeSearch.propTypes = {
  onError: PropTypes.func.isRequired,
};
