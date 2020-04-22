###################
Authentication flow
###################

Browser flow
============

The user's interaction with Gafaelfawr is normally initiated by an attempt to visit a protected application.
That application uses nginx-ingress Kubernetes annotations to trigger an authentication subrequest to the Gafaelfawr ``/auth`` endpoint.
That sets off the following interaction:

#. The ``/auth`` handler receives the headers of the original request.
   No token is present in an ``Authorization`` header, nor is there an authentication session cookie.
   The ``/auth`` handler therefore returns an HTTP 401 error.
#. nginx-ingress determines from its annotations that this means the user should be redirected to the ``/login`` route with the original URL included in the ``X-Auth-Request-Redirect`` header.
   Alternatively, the URL can be included in the ``rd`` parameter to the ``/login`` route, but this requires escaping.
#. The ``/login`` handler sets a session cookie containing a randomly-generated ``state`` parameter (for session fixation protection).
   It also includes the return URL in that session cookie.
   It then returns a redirect to the authentication provider that contains the ``state`` string plus other required information for the authentication request.
#. The user interacts with the authentication provider to prove their identity, which eventually results in a redirect back to the ``/login`` handler (or, for backwards compatibility, the ``/oath2/callback`` handler, which is identical).
   That return request includes an authorization code and the original ``state`` string, as well as possibly other information.
#. The ``/login`` handler checks the ``state`` code with the value from the user's session cookie to protect against session fixation.
   It then extracts the authorization code and redeems it with the authentication provider.
   For an OpenID Connect provider, the result is a JWT from that provider.
   For GitHub, the result is an OAuth 2.0 token, with which the ``/login`` handler makes additional API calls to gather metadata about a user equivalent to what the OpenID Connect provider includes in the returned JWT.
#. Based on the provider's JWT or on data gathered from GitHub, the ``/login`` route creates a new JWT and stores it in an encrypted session in the session store.
   It then creates a session handle for that session and stores that in the user's session cookie.
   Finally, it redirects the user back to the original URL.
#. When the user requests the original URL, this results in another authentication subrequest to the ``/auth`` route.
   This time, the ``/auth`` route finds the session cookie and extracts the session handle from that cookie.
   It retrieves the JWT from the session store and decrypts and verifies it.
   It then checks the ``scope`` claim of that JWT against the requested authentication scope given as a ``scope`` parameter to the ``/auth`` route.
   If the requested scope or scopes are not satisfied, it returns a 403 error.
   Otherwise, it returns 200, and nginx then proxies the request to the protected application and user interaction continues as normal.

Programmatic flow
=================

Gafaelfawr also supports programmatic clients (clients that are not browsers) and user-issued tokens.
A user-issued token is one created by the user that may have a more restricted scope than the user's regular token.
User-issued tokens are stored in the session store just like browser sessions.
The token issued to the user for use in programmatic requests is a session handle.
This is done to minimize the length of the token and thus avoid problems with header limits in some HTTP clients and call paths.

Here are the steps involved in a programmatic access to an application protected by Gafaelfawr:

#. The user controlling the application goes to the ``/auth/tokens`` route.
   This is an application protected by Gafaelfawr, so the user will have to authenticate following the above protocol.
#. The user selects create a new token, which sends them to ``/auth/tokens/new``.
   This presents a form listing the available scopes and their descriptions.
   The user selects the scopes they want the new token to have.
#. The user is given their new session handle and stores it (safely).
#. When making a programmatic request, the user includes the session handle as the parameter to an ``Authorization: Bearer`` HTTP header.
   Alternately, it can be given as either the username or the password of an ``Authorization: Basic`` header, if the other parameter (either username or password) is set to ``x-oauth-basic``.
#. The request results in an auth subrequest to the ``/auth`` route as in the browser case.
   The ``/auth`` route extracts the session handle from the ``Authorization`` header and then does scope-based authorization as described in the browser flow.
