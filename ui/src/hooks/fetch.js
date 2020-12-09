import React, { useState, useEffect } from "react"
import { apiGet } from "../functions/api"

export default function useFetch(uri) {
  const [data, setData] = useState()
  const [error, setError] = useState()
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!uri) return
    apiGet(uri)
      .then(setData)
      .then(() => setLoading(false))
      .catch(setError)
  }, [uri])

  return {
    loading,
    data,
    error,
  }
}
