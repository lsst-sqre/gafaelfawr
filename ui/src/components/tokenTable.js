// Render a list of tokens in tabular form.

import React, { useMemo } from 'react';
import { useTable } from 'react-table';
import { FaTrash } from 'react-icons/fa';

function formatTimestamp(timestamp) {
  if (!timestamp) return <em>never</em>;
  const date = new Date(0);
  date.setUTCSeconds(timestamp);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
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
  includeName = false,
  onDeleteToken = async (f) => f,
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
        Cell: ({ value }) => formatTimestamp(value),
        accessor: 'created',
      },
      {
        Header: 'Expires',
        Cell: ({ value }) => formatTimestamp(value),
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
