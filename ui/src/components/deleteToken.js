// Deletion button for a single token.

import React, { useContext } from "react"
import { FaTrash } from "react-icons/fa"
import apiUrl from "../functions/apiUrl"
import { LoginContext } from "../pages/"

export default function DeleteToken({ token }) {
  const { csrf, username } = useContext(LoginContext)

  const deleteToken = () => {
    fetch(apiUrl(`/users/${username}/tokens/${token}`), {
      method: "DELETE",
      credentials: "same-origin",
      headers: {"X-CSRF-Token": csrf},
    })
      .catch(console.error)
  }

  return (
    <button onClick={() => deleteToken(token)}>
      <FaTrash />
    </button>
  )
}
