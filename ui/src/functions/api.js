// Determine the URL of an API route by inspecting the URL of the current page
// and assuming the API URL is /auth/api/v1 at the same host.
function apiUrl(route) {
  if (typeof window === 'undefined') return;
  return new URL(`/auth/api/v1${route}`, window.location.href).href;
}

// Redirect to the /login route and request a return to the current page.
function apiLoginRedirect() {
  if (typeof window === 'undefined') return;
  const currentUrl = window.location.href;
  const url = new URL('/login', currentUrl);
  url.searchParams.append('rd', currentUrl);
  return url.href;
}

function buildUrl(route, params) {
  if (!params) return apiUrl(route);
  const url = new URL(apiUrl(route));
  Object.entries(params).forEach(([key, value]) =>
    url.searchParams.set(key, value)
  );
  return url.href;
}

function jsonIfOkay(response) {
  if (response.ok) {
    return response.json().catch((error) => {
      throw Error(`Error in API call: ${error.message}`);
    });
  }
  return response
    .json()
    .catch(() => {
      throw Error(`Error in API call: ${response.statusText}`);
    })
    .then((data) => {
      throw Error(data.detail.msg);
    });
}

export function apiGet(route, params = null) {
  const url = buildUrl(route, params);
  return fetch(url, { credentials: 'same-origin' })
    .then((response) => {
      if (typeof window !== 'undefined' && response.status === 401) {
        window.location.href = apiLoginRedirect();
      } else {
        return response;
      }
    })
    .then(jsonIfOkay);
}

export function apiDelete(route, csrf) {
  return fetch(apiUrl(route), {
    method: 'DELETE',
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrf },
  });
}

function apiModify(route, csrf, body, method) {
  return fetch(apiUrl(route), {
    credentials: 'same-origin',
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    body: JSON.stringify(body),
  }).then(jsonIfOkay);
}

export function apiPatch(route, csrf, body) {
  return apiModify(route, csrf, body, 'PATCH');
}

export function apiPost(route, csrf, body) {
  return apiModify(route, csrf, body, 'POST');
}
