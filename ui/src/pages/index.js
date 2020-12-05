import React, { useState, useEffect, useMemo } from "react"
import { useTable } from "react-table"
import useLogin from "../hooks/login"
import apiUrl from "../functions/apiUrl"

function formatTimestamp(timestamp) {
  const date = new Date(0)
  date.setUTCSeconds(timestamp)
  return date.toLocaleDateString() + " " + date.toLocaleTimeString()
}

function TokenInfo() {
  const { username } = useLogin()
  const [data, setData] = useState([])

  useEffect(() => {
    if (!username) return
    fetch(apiUrl(`/users/${username}/tokens`), {
      credentials: "same-origin",
    })
      .then(response => response.json())
      .then(setData)
      .catch(console.error)
  }, [username])

  const columns = useMemo(
    () => [
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
    ],
    []
  )

  const tokens = useMemo(() => data, [data])
  const table = useTable({ columns, data: tokens })

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = table

  return (
    // apply the table props
    <table {...getTableProps()}>
      <thead>
        {
          // Loop over the header rows
          headerGroups.map(headerGroup => (
            // Apply the header row props
            <tr {...headerGroup.getHeaderGroupProps()}>
              {
                // Loop over the headers in each row
                headerGroup.headers.map(column => (
                  // Apply the header cell props
                  <th {...column.getHeaderProps()}>
                    {
                      // Render the header
                      column.render("Header")
                    }
                  </th>
                ))
              }
            </tr>
          ))
        }
      </thead>
      {/* Apply the table body props */}
      <tbody {...getTableBodyProps()}>
        {
          // Loop over the table rows
          rows.map(row => {
            // Prepare the row for display
            prepareRow(row)
            return (
              // Apply the row props
              <tr {...row.getRowProps()}>
                {
                  // Loop over the rows cells
                  row.cells.map(cell => {
                    // Apply the cell props
                    return (
                      <td {...cell.getCellProps()}>
                        {
                          // Render the cell contents
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

export default function Home() {
  return <TokenInfo></TokenInfo>
}
