// Render a list of tokens in tabular form.

import React, { useContext, useState, useEffect, useMemo } from "react"
import { useTable } from "react-table"
import DeleteToken from "./deleteToken"

function formatTimestamp(timestamp) {
  if (!timestamp) return <em>never</em>
  const date = new Date(0)
  date.setUTCSeconds(timestamp)
  return date.toLocaleDateString() + " " + date.toLocaleTimeString()
}

const columns = [
  {
    Header: "Token",
    Cell: ({ value }) => <code>{value}</code>,
    accessor: "token",
  },
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
    Cell: ({ value }) => <DeleteToken token={value} />,
    accessor: "token",
  },
]

export default function TokenInfo({ data }) {
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
