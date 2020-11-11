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

``/auth/api``
    The token API.
    See `SQR-049 <https://sqr-049.lsst.io/>`__ for detailed documentation.

``/auth/forbidden``
    Helper error page route for ``/auth``.
    Serves a 403 (HTTP Forbidden) error with an appropriate challenge given the same request parameters as an ``/auth`` request.
    For more information on how this route is used, see :ref:`error-caching`.
    For documentation on the parameters accepted by this route, see :ref:`auth-config`.

``/auth/analyze``
    Analyze a token or session handle and return information about it as JSON.
    If the request method is GET, uses the session handle from the user's session cookie or from an ``Authentication`` header.
    If the request method is POST, uses a session handle or JWT from the ``token`` form parameter, provided in the POST.

``/auth/openid/login``
    Initiates or completes an OpenID Connect authentication request.
    The parameters to this route are those for the Authentication Request in the Authorization Code Flow as defined in `OpenID Connect`_.

.. _OpenID Connect: https://openid.net/specs/openid-connect-core-1_0.html

``/auth/openid/token``
    Retrieves a JWT given an OpenID Connect authorization code obtained via an authentication request.
    The parameters to this route are those for the Token Request in the Authorization Code Flow in `OpenID Connect`_.

``/auth/tokens/influxdb/new``
    Issue a new InfluxDB token for the authenticated user.
    The result will be a JSON object with either a ``token`` key containing the token or ``error`` and ``error_description`` keys explaining the error.

``/auth/userinfo``
    Returns the claims of a JWT, issued by Gafaelfawr, in JSON format.
    The JWT must be presented as a bearer token in an ``Authorization`` header as defined in `RFC 6750`_.

.. _RFC 6750: https://tools.ietf.org/html/rfc6750

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

    The ``X-Forwarded-Host`` header is used (and trusted) to determine the host of the ``/login`` route.
    Only return URLs at that same host are permitted.

``/logout``
    Logs out the user.
    This route takes the following parameters.

    ``rd``
        The URL to which to send the user after logout.
        If not set, the ``after_logout_url`` configuration setting is used.

    The ``X-Forwarded-Host`` header is used (and trusted) to determine the host of the ``/login`` route.
    Only return URLs at that same host are permitted in the ``rd`` parameter.

``/oauth2/callback``
    Identical to the ``/login`` route.
    Provided for backwards compatibility with oauth2_proxy.

``/.well-known/jwks.json``
    Returns the key information used to issue JWTs in JWKS format.
    This can be used by protected applications to retrieve Gafaelfawr's public signing key and independently verify the JWTs issued by Gafaelfawr.

``/.well-known/openid-configuration``
    Returns the OpenID Connect configuration information for protected applications that want to use Gafaelfawr as an OpenID Connect server.
