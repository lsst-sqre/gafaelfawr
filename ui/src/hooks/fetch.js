import React, { useState, useEffect } from "react"

export default function useFetch(uri) {
  const [data, setData] = useState()
  const [error, setError] = useState()
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!uri) return
    fetch(uri, { credentials: "same-origin" })
      .then(response => response.json())
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
