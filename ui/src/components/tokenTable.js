// Render a list of tokens in tabular form.

import formatDistanceToNow from 'date-fns/formatDistanceToNow';
import React, { useMemo } from 'react';
import PropTypes from 'prop-types';
import { useTable } from 'react-table';
import { FaTrash } from 'react-icons/fa';

function timestampToDate(timestamp) {
  const date = new Date(0);
  date.setUTCSeconds(timestamp);
  return date;
}

function formatTimestamp(timestamp, { past }) {
  if (!timestamp) return <em>never</em>;
  const date = timestampToDate(timestamp);
  const relative = formatDistanceToNow(date, { addSuffix: past });
  const absolute = date.toISOString().replace(/\.0+Z$/, 'Z');
  return <span title={absolute}>{relative}</span>;
}

function formatDeleteTokenButton(token, onDeleteToken = (f) => f) {
  const onClick = () => {
    onDeleteToken(token);
  };
  return (
    <button type="button" onClick={onClick}>
      <FaTrash />
    </button>
  );
}

function formatToken(token) {
  return <code>{token}</code>;
}

export default function TokenInfo({
  data,
  onDeleteToken,
  includeName = false,
}) {
  const columns = useMemo(() => {
    const tokenName = [
      {
        Header: 'Name',
        accessor: 'token_name',
      },
    ];
    const tokenCode = [
      {
        Header: 'Token',
        Cell: ({ value }) => formatToken(value),
        accessor: 'token',
      },
    ];
    return (includeName ? tokenName : tokenCode).concat([
      {
        Header: 'Scopes',
        accessor: 'scopes',
      },
      {
        Header: 'Created',
        Cell: ({ value }) => formatTimestamp(value, { past: true }),
        accessor: 'created',
      },
      {
        Header: 'Expires',
        Cell: ({ value }) => formatTimestamp(value, { past: false }),
        accessor: 'expires',
      },
      {
        id: 'delete',
        Header: '',
        Cell: ({ value }) => formatDeleteTokenButton(value, onDeleteToken),
        accessor: 'token',
      },
    ]);
  }, [includeName, onDeleteToken]);

  const table = useTable({ columns, data });

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = table;

  /* eslint-disable react/jsx-props-no-spreading */
  return (
    <table {...getTableProps()}>
      <thead>
        {headerGroups.map((headerGroup) => (
          <tr {...headerGroup.getHeaderGroupProps()}>
            {headerGroup.headers.map((column) => (
              <th {...column.getHeaderProps()}>{column.render('Header')}</th>
            ))}
          </tr>
        ))}
      </thead>
      <tbody {...getTableBodyProps()}>
        {rows.map((row) => {
          prepareRow(row);
          return (
            <tr {...row.getRowProps()}>
              {row.cells.map((cell) => (
                <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
              ))}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
  /* eslint-enable react/jsx-props-no-spreading */
}
TokenInfo.propTypes = {
  data: PropTypes.arrayOf(PropTypes.object).isRequired,
  onDeleteToken: PropTypes.func.isRequired,
  includeName: PropTypes.bool,
};
