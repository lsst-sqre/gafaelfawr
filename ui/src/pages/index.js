import React, { createContext } from "react"
import TokenInfo from "../components/tokenInfo"
import useLogin from "../hooks/login"

export const LoginContext = createContext()

export default function Home() {
  const { csrf, username } = useLogin()

  return (
    <LoginContext.Provider value={{ csrf, username }}>
      <TokenInfo />
    </LoginContext.Provider>
  )
}
