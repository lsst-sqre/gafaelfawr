// Render a list of tokens in tabular form.

import React, { useContext, useState, useEffect, useMemo } from "react"
import { useTable } from "react-table"
import { FaTrash } from "react-icons/fa"

function formatTimestamp(timestamp) {
  if (!timestamp) return <em>never</em>
  const date = new Date(0)
  date.setUTCSeconds(timestamp)
  return date.toLocaleDateString() + " " + date.toLocaleTimeString()
}

export default function TokenInfo({
  data,
  includeName = false,
  onDeleteToken = async f => f,
}) {
  const columns = useMemo(() => {
    const token_name = [
      {
        Header: "Name",
        accessor: "token_name",
      }
    ]
    const token_code = [
      {
        Header: "Token",
        Cell: ({ value }) => <code>{value}</code>,
        accessor: "token",
      }
    ]
    return (includeName ? token_name : token_code).concat([
      {
        Header: "Scopes",
        accessor: "scopes",
      },
      {
        Header: "Created",
        Cell: ({ value }) => formatTimestamp(value),
        accessor: "created",
      },
      {
        Header: "Expires",
        Cell: ({ value }) => formatTimestamp(value),
        accessor: "expires",
      },
      {
        id: "delete",
        Header: "",
        Cell: ({ value }) => (
          <button onClick={() => { onDeleteToken(value) }}>
            <FaTrash />
          </button>
        ),
        accessor: "token",
      },
    ])
  }, [includeName])

  const table = useTable({ columns, data })

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = table

  return (
    <table {...getTableProps()}>
      <thead>
        {
          headerGroups.map(headerGroup => (
            <tr {...headerGroup.getHeaderGroupProps()}>
              {
                headerGroup.headers.map(column => (
                  <th {...column.getHeaderProps()}>
                    {
                      column.render("Header")
                    }
                  </th>
                ))
              }
            </tr>
          ))
        }
      </thead>
      <tbody {...getTableBodyProps()}>
        {
          rows.map(row => {
            prepareRow(row)
            return (
              <tr {...row.getRowProps()}>
                {
                  row.cells.map(cell => {
                    return (
                      <td {...cell.getCellProps()}>
                        {
                          cell.render("Cell")
                        }
                      </td>
                    )
                  })
                }
              </tr>
            )
          })
        }
      </tbody>
    </table>
  )
}
