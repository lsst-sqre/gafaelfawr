// Determine the URL of an API route by inspecting the URL of the current page
// and assuming the API URL is /auth/api/v1 at the same host.
function apiUrl(route) {
  if (typeof window === "undefined") return;
  return location.protocol + "//" + location.host + "/auth/api/v1" + route;
}

export function apiGet(route) {
  return fetch(apiUrl(route), { credentials: "same-origin" })
    .then(response => response.json())
}

export function apiDelete(route, csrf) {
  return fetch(apiUrl(route), {
    method: "DELETE",
    credentials: "same-origin",
    headers: {"X-CSRF-Token": csrf},
  })
}

export function apiPost(route, csrf, body) {
  return fetch(apiUrl(route), {
    credentials: "same-origin",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
    },
    body: JSON.stringify(body),
  })
    .then(response => {
      if (!response.ok) {
        return response.json()
          .catch(() => { throw Error(response.statusText) })
          .then(data => { throw Error(data.detail.msg) })
      } else {
        return response.json()
      }
    })
}
