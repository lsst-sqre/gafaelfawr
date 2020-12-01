import React, { useState, useEffect } from "react"
import useFetch from "./fetch"

export default function useLogin() {
  const { data, error } = useFetch("http://localhost:8080/auth/api/v1/login")
  const [csrf, setCsrf] = useState()
  const [username, setUsername] = useState()

  useEffect(() => {
    if (!data) return
    setCsrf(data.csrf)
    setUsername(data.username)
  }, [data])

  return { csrf, username, error }
}
