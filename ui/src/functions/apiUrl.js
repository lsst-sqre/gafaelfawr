// Determine the URL of an API route by inspecting the URL of the current page
// and assuming the API URL is /auth/api/v1 at the same host.

export default function apiUrl(route) {
  if (typeof window === "undefined") return;
  return location.protocol + "//" + location.host + "/auth/api/v1" + route;
}
