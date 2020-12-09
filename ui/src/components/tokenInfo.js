import React, { useContext, useState, useEffect, useMemo } from "react"
import CreateTokenButton from "./createTokenButton"
import TokenTable from "./tokenTable"
import apiUrl from "../functions/apiUrl"
import { LoginContext } from "../pages/"

export default function TokenInfo() {
  const { csrf, username } = useContext(LoginContext)
  const [data, setData] = useState(null)

  const loadTokenData = () => {
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
  }

  useEffect(loadTokenData, [username])

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
      .then(loadTokenData)
      .catch(console.error)
  }

  const deleteToken = async token => {
    await fetch(apiUrl(`/users/${username}/tokens/${token}`), {
      method: "DELETE",
      credentials: "same-origin",
      headers: {"X-CSRF-Token": csrf},
    })
      .then(loadTokenData)
      .catch(console.error)
  }

  if (!data) return <p>Loading...</p>

  return (
    <>
      <h1>User Tokens</h1>
      <CreateTokenButton onCreateToken={createToken} />
      {
        tokens.user.length ? (
          <TokenTable
            data={tokens.user}
            includeName={true}
            onDeleteToken={deleteToken}
          />
        ) : false
      }
      <h1>Web Sessions</h1>
      <TokenTable data={tokens.session} onDeleteToken={deleteToken} />
      {
        tokens.notebook.length ? <>
          <h1>Notebook Tokens</h1>
          <TokenTable data={tokens.notebook} onDeleteToken={deleteToken} />
        </> : false
      }
      {
        tokens.internal.length ? <>
          <h1>Internal Tokens</h1>
          <TokenTable data={tokens.internal} onDeleteToken={deleteToken} />
        </> : false
      }
    </>
  )
}
