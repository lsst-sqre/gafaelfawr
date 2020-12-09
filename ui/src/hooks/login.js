import React, { useState, useEffect } from "react"
import useFetch from "./fetch"

export default function useLogin(setError) {
  const { data } = useFetch("/login", setError)
  const [csrf, setCsrf] = useState()
  const [username, setUsername] = useState()

  useEffect(() => {
    if (!data) return
    setCsrf(data.csrf)
    setUsername(data.username)
  }, [data])

  return { csrf, username }
}
