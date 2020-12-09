import React, { useState, useEffect } from "react"
import useFetch from "./fetch"

export default function useLogin() {
  const { data, error } = useFetch("/login")
  const [csrf, setCsrf] = useState()
  const [username, setUsername] = useState()

  useEffect(() => {
    if (!data) return
    setCsrf(data.csrf)
    setUsername(data.username)
  }, [data])

  return { csrf, username, error }
}
