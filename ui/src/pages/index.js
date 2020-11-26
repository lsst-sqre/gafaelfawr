import React, { useState, useEffect } from "react"

function TokenInfo() {
  const [data, setData] = useState();

  useEffect(() => {
    fetch("http://localhost/auth/api/v1/token-info", {
      credentials: "same-origin"
    })
      .then(response => response.json())
      .then(setData)
      .catch(console.error);
  }, [])

  if (data) {
    return <pre>{JSON.stringify(data, null, 2)}</pre>
  }

  return null;
}

export default function Home() {
  return (
    <TokenInfo></TokenInfo>
  )
}
