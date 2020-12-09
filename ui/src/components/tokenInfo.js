import React, { useContext, useState, useEffect, useMemo } from "react"
import CreateTokenButton from "./createTokenButton"
import TokenTable from "./tokenTable"
import { apiDelete, apiGet, apiPost } from "../functions/api"
import { LoginContext } from "../pages/"

export default function TokenInfo({ onError = f => f }) {
  const { csrf, username } = useContext(LoginContext)
  const [data, setData] = useState(null)
  const tokens = useMemo(() => data, [data])

  const loadTokenData = () => {
    if (!username) return
    apiGet(`/users/${username}/tokens`)
      .then(data => ({
        user: data.filter(t => t.token_type === "user"),
        session: data.filter(t => t.token_type === "session"),
        notebook: data.filter(t => t.token_type === "notebook"),
        internal: data.filter(t => t.token_type === "internal"),
      }))
      .then(setData)
      .catch(onError)
  }

  const createToken = async (values) => {
    await apiPost(`/users/${username}/tokens`, csrf, {
      token_name: values.name,
      scopes: values.scopes ? values.scopes.split(",") : [],
      expires: values.expires ? parseInt(values.expires) : null,
    })
      .then(response => {
        if (response.detail) {
          onError(response.detail.msg)
        } else {
          alert(JSON.stringify(response))
        }
      })
      .then(loadTokenData)
      .catch(onError)
  }

  const deleteToken = async token => {
    await apiDelete(`/users/${username}/tokens/${token}`, csrf)
      .then(loadTokenData)
      .catch(onError)
  }

  useEffect(loadTokenData, [username])

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
