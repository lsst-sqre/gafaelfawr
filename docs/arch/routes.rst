######
Routes
######

Gafaelfawr supports the following routes:

``/``
    Returns metadata about Gafaelfawr with status code 200.
    Used by Kubernetes for health checks.

``/auth``
    Perform authentication and authorization checks.
    Meant to be run as an auth subrequest from NGINX.
    For documentation on the parameters accepted by this route, see :ref:`auth-config`.
    For more information on how the ``/auth`` route is used, see :ref:`browser-flow`.

    The response from this route includes various headers that provide information about the JWT claims.
    For a complete list, see :ref:`auth-headers`.

``/auth/analyze``
    Analyze a token or session handle and return information about it as JSON.
    If the request method is GET, uses the session handle from the user's session cookie or from an ``Authentication`` header.
    If the request method is POST, uses a session handle or JWT from the ``token`` form parameter, provided in the POST.

``/auth/tokens``
    Displays all user-issued tokens for the authenticated user.

``/auth/tokens/new``
    Displays or handles the form that allows users to issue new tokens.

``/auth/tokens/<key>``
    Displays details about a user-issued token or processes a revocation request for that token.
    The ``<key>`` portion of the route must be the session key (from a session handle, for example).

``/login``
    Initiates or completes an authentication rqeuest.
    This route takes the following parameters.

    ``rd``
        The return URL to which to send the user after authentication is complete.
        The URL may instead be provided via the ``X-Auth-Request-Redirect`` header (for which there is built-in support in the Kubernetes ingress-nginx).
        Only used when initiating authentication.

    ``code``
        An authentication code sent by an external authentication provider after successful authentication.
        This code will be redeemed for a token or for user metadata.
        Only used when completing authentication.

    ``state``
        Random state sent as part of the authentication request.
        Used to prevent session fixation by ensuring that it matches state set in the user's session cookie.
        Only used when completing authentication.

``/logout``
    Logs out the user.
    This route takes the following parameters.

    ``rd``
        The URL to which to send the user after logout.
        If not set, the ``after_logout_url`` configuration setting is used.

``/oauth2/callback``
    Identical to the ``/login`` route.
    Provided for backwards compatibility with oauth2_proxy.

``/.well-known/jwks.json``
    Returns the key information used to issue JWTs in JWKS format.
    This can be used by protected applications to retrieve Gafaelfawr's public signing key and independently verify the JWTs issued by Gafaelfawr.
