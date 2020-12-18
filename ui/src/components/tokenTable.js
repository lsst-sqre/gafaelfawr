// Render a list of tokens in tabular form.

import formatDistanceToNow from 'date-fns/formatDistanceToNow';
import fromUnixTime from 'date-fns/fromUnixTime';
import React, { useMemo } from 'react';
import PropTypes from 'prop-types';
import { useTable } from 'react-table';
import { FaEdit, FaTrash } from 'react-icons/fa';

function formatTimestamp(timestamp, { past }) {
  if (!timestamp) return <em>never</em>;
  const date = fromUnixTime(timestamp);
  const relative = formatDistanceToNow(date, { addSuffix: past });
  const absolute = date.toISOString().replace(/\.0+Z$/, 'Z');
  return <span title={absolute}>{relative}</span>;
}

function formatDeleteTokenButton(token, onDeleteToken) {
  const onClick = () => {
    onDeleteToken(token);
  };
  return (
    <button type="button" className="qa-token-delete" onClick={onClick}>
      <FaTrash />
    </button>
  );
}

function formatEditTokenButton(token, onEditToken) {
  const onClick = () => {
    onEditToken(token);
  };
  return (
    <button type="button" className="qa-token-edit" onClick={onClick}>
      <FaEdit />
    </button>
  );
}

function formatToken(token) {
  return <code className="qa-token">{token}</code>;
}

function formatTokenName(name) {
  return <span className="qa-token-name">{name}</span>;
}

export default function TokenTable({
  id,
  data,
  onEditToken,
  onDeleteToken,
  includeName = false,
}) {
  const columns = useMemo(() => {
    const tokenBase = [
      {
        Header: 'Scopes',
        Cell: ({ value }) => value.join(', '),
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
    ];
    const tokenName = [
      {
        Header: 'Name',
        Cell: ({ value }) => formatTokenName(value),
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
    const tokenEdit = [
      {
        id: 'edit',
        Header: '',
        Cell: ({ value }) => formatEditTokenButton(value, onEditToken),
        accessor: 'token',
      },
    ];
    const tokenDelete = [
      {
        id: 'delete',
        Header: '',
        Cell: ({ value }) => formatDeleteTokenButton(value, onDeleteToken),
        accessor: 'token',
      },
    ];
    const partial = (includeName ? tokenName : tokenCode).concat(tokenBase);
    if (onEditToken) {
      return partial.concat(tokenEdit).concat(tokenDelete);
    }
    return partial.concat(tokenDelete);
  }, [includeName, onEditToken, onDeleteToken]);

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
    <table {...getTableProps()} id={id}>
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
            <tr {...row.getRowProps()} className="qa-token-row">
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
TokenTable.propTypes = {
  id: PropTypes.string.isRequired,
  data: PropTypes.arrayOf(PropTypes.object).isRequired,
  onEditToken: PropTypes.func.isRequired,
  onDeleteToken: PropTypes.func.isRequired,
  includeName: PropTypes.bool,
};
