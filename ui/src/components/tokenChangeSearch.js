import formatISO from 'date-fns/formatISO';
import getUnixTime from 'date-fns/getUnixTime';
import parseISO from 'date-fns/parseISO';
import PropTypes from 'prop-types';
import React, { useCallback, useContext, useMemo, useState } from 'react';
import { useAlert } from 'react-alert';

import { LoginContext } from './loginContext';
import TokenChangeSearchForm from './tokenChangeSearchForm';
import TokenChangeTable from './tokenChangeTable';
import { APIError, apiGet } from '../functions/api';

// There are three representations of a search query in play here.  One is
// the query as encoded in the URL.  One is the form values as consumed by
// Formik.  And the last is the search parameters as expected by the API.
//
// The TokenChangeSearchForm component only deals with form values.  This
// component handles the conversion from the query to form values and from
// form values to a search and to a query.
//
// Define a set of functions to perform those conversions.

function queryToValues(query) {
  return {
    key: query.key,
    tokenType: query.tokenType,
    ipAddress: query.ipAddress,
    sinceDate: query.sinceDate && parseISO(query.sinceDate),
    untilDate: query.untilDate && parseISO(query.untilDate),
  };
}

function valuesToQuery(values) {
  const newQuery = { tokenType: values.tokenType };
  if (values.key) newQuery.key = values.key;
  if (values.ipAddress) newQuery.ipAddress = values.ipAddress;
  if (values.sinceDate) newQuery.sinceDate = formatISO(values.sinceDate);
  if (values.untilDate) newQuery.untilDate = formatISO(values.untilDate);
  return newQuery;
}

function valuesToSearch(values) {
  const search = {};
  if (values.key) search.key = values.key;
  if (values.tokenType !== 'any') search.token_type = values.tokenType;
  if (values.ipAddress) search.ip_address = values.ipAddress;
  if (values.sinceDate) search.since = getUnixTime(values.sinceDate);
  if (values.untilDate) search.until = getUnixTime(values.untilDate);
  return search;
}

// Convert an APIError to the errors data for a form.  Unknown errors are
// shown as alerts instead.
function exceptionToErrors(e, alert) {
  const errors = {};
  if (e instanceof APIError) {
    for (const detail of e.detail) {
      if (detail.loc && detail.loc[0] === 'query') {
        switch (detail.loc[1]) {
          case 'key':
            errors.key = detail.msg;
            break;
          case 'token_type':
            errors.tokenType = detail.msg;
            break;
          case 'ip_address':
            errors.ipAddress = detail.msg;
            break;
          case 'since':
            errors.sinceDate = detail.msg;
            break;
          case 'until':
            errors.untilDate = detail.msg;
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

const TokenChangeSearch = function ({ query, setQuery }) {
  const alert = useAlert();
  const { username } = useContext(LoginContext);
  const [_data, setData] = useState(null);
  const data = useMemo(() => _data, [_data]);
  const initialValues = queryToValues(query);

  const loadHistory = useCallback(
    (values, setErrors) => {
      if (!username) return;
      const search = valuesToSearch(values);
      return apiGet(`/users/${username}/token-change-history`, search)
        .then(setData)
        .then(() => alert.removeAll())
        .then(() => setQuery(valuesToQuery(values)))
        .catch((e) => setErrors(exceptionToErrors(e, alert)));
    },
    [alert, setQuery, username],
  );

  return (
    <>
      <TokenChangeSearchForm
        initialValues={initialValues}
        onSubmit={loadHistory}
      />
      {data !== null && (
        <>
          <h2>Results</h2>
          <TokenChangeTable data={data} />
        </>
      )}
    </>
  );
};
TokenChangeSearch.propTypes = {
  query: PropTypes.shape({
    key: PropTypes.string,
    tokenType: PropTypes.string.isRequired,
    ipAddress: PropTypes.string,
    sinceDate: PropTypes.string,
    untilDate: PropTypes.string,
  }).isRequired,
  setQuery: PropTypes.func.isRequired,
};

export default TokenChangeSearch;
