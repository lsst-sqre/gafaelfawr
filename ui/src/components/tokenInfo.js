import React, { useContext, useState, useEffect, useMemo } from "react"
import TokenTable from "./tokenTable"
import apiUrl from "../functions/apiUrl"
import { LoginContext } from "../pages/"

export default function TokenInfo() {
  const { username } = useContext(LoginContext)
  const [data, setData] = useState(null)

  useEffect(() => {
    if (!username) return
    fetch(apiUrl(`/users/${username}/tokens`), {
      credentials: "same-origin",
    })
      .then(response => response.json())
      .then(data => ({
        user: data.filter(t => t.token_type === "user"),
        session: data.filter(t => t.token_type === "session"),
        notebook: data.filter(t => t.token_type === "notebook"),
        internal: data.filter(t => t.token_type === "internal"),
      }))
      .then(setData)
      .catch(console.error)
  }, [username])

  const tokens = useMemo(() => data, [data])

  if (!data) return <p>Loading...</p>

  return (
    <>
      <h1>User Tokens</h1>
      <TokenTable data={tokens.user} />
      <h1>Web Sessions</h1>
      <TokenTable data={tokens.session} />
      <h1>Notebook Tokens</h1>
      <TokenTable data={tokens.notebook} />
      <h1>Internal Tokens</h1>
      <TokenTable data={tokens.internal} />
    </>
  )
}
