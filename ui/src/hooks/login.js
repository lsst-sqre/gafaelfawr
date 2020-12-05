import React, { useState, useEffect } from "react"
import useFetch from "./fetch"
import apiUrl from "../functions/apiUrl"

export default function useLogin() {
  const { data, error } = useFetch(apiUrl("/login"))
  const [csrf, setCsrf] = useState()
  const [username, setUsername] = useState()

  useEffect(() => {
    if (!data) return
    setCsrf(data.csrf)
    setUsername(data.username)
  }, [data])

  return { csrf, username, error }
}
