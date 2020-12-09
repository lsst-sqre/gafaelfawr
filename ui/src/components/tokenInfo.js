import React, { useContext, useState, useEffect, useMemo } from "react"
import CreateTokenModal from "./createTokenModal"
import TokenTable from "./tokenTable"
import apiUrl from "../functions/apiUrl"
import { LoginContext } from "../pages/"

export default function TokenInfo() {
  const { csrf, username } = useContext(LoginContext)
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

  const createToken = async (values) => {
    await fetch(apiUrl(`/users/${username}/tokens`), {
      credentials: "same-origin",
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        token_name: values.name,
        scopes: values.scopes ? values.scopes.split(",") : [],
        expires: values.expires ? parseInt(values.expires) : null,
      })
    })
      .then(response => response.json())
      .then(response => alert(JSON.stringify(response)))
      .catch(console.error)
  }

  if (!data) return <p>Loading...</p>

  return (
    <>
      <h1>User Tokens</h1>
      <CreateTokenModal onCreateToken={createToken} />
      <TokenTable data={tokens.user} includeName={true} />
      <h1>Web Sessions</h1>
      <TokenTable data={tokens.session} />
      <h1>Notebook Tokens</h1>
      <TokenTable data={tokens.notebook} />
      <h1>Internal Tokens</h1>
      <TokenTable data={tokens.internal} />
    </>
  )
}
