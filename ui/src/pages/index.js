import React, { createContext, useState } from "react"
import TokenInfo from "../components/tokenInfo"
import useLogin from "../hooks/login"

export const LoginContext = createContext()

export default function Home() {
  const [error, setError] = useState(null)

  const onError = error => {
    if (error instanceof TypeError) {
      setError("Unable to contact backend API")
    } else if (error && error.stack && error.message) {
      setError(error.message)
    } else {
      setError(error)
    }
  }

  const { csrf, username } = useLogin(onError)

  return (
    <LoginContext.Provider value={{ csrf, username }}>
      {error ? <div><p role="alert">{error}</p></div> : false}
      <TokenInfo onError={onError} />
    </LoginContext.Provider>
  )
}
