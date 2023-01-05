.. _ingress-overview:

#######################################
How Gafaelfawr-protected ingresses work
#######################################

Gafaelfawr is introduced into the HTTP request path for your services as an NGINX ``auth_request`` subhandler.
This is done via annotations added to the Kubernetes ``Ingress`` resource that are interpreted by ingress-nginx_.

For each HTTP request to a protected service, NGINX will send a request to the Gafaelfawr ``/auth`` route with the headers of the incoming request (including, for example, any cookies or ``Authorization`` header).
Gafaelfawr, when receiving that request, will find the user's authentication token, check that it is valid, and check that the user has the required scope.

The user may authenticate with a cookie (set by Gafaelfawr by the ``/login`` route), with a bearer token in the ``Authorization`` header, or with a token in either the username or password field of an HTTP Basic Auth ``Authorization`` header.

If the user is not authenticated, Gafaelfawr will either return a 401 error with an appropriate ``WWW-Authenticate`` challenge, or a redirect to the sign-in URL, depending on its configuration.
The sign-in URL would then send the user to CILogon, an OpenID Connect server, or GitHub to authenticate.

If the user is already authenticated but does not have the desired scope, Gafaelfawr will return a 403 error, which will be passed back to the user.
If the user's authentication is syntactically invalid, Gafaelfawr will still return a 403 error, but with additional HTTP headers that will be converted to a 400 error by the NGINX configuration.
See :ref:`error-handling` for more details.

If the user is authenticated and authorized, Gafaelfawr will return a 200 response with some additional headers containing information about the user and (optionally) a delegated token.
NGINX will then send the user's HTTP request along to the protected service, including those headers in the request.

Gafaelfawr-protected services cannot return a full 403 response to a client.
If they return a 403 error, the client will receive a 403 error, but the body of the response will be lost, as will any ``WWW-Authenticate`` header.
This is an unfortunate side effect of the limitations of the NGINX ``auth_request`` module.

.. _header-filtering:

Header filtering
================

Gafaelfawr authentication tokens should only be sent to Gafaelfawr (and, unavoidably, the NGINX ingress), not to protected applications.
Otherwise, a protected application, even one that didn't request delegated tokens, could take the cookie or token from the incoming request and then impersonate the user to other services.
Even if no protected services are malicious, they may have security vulnerabilities that would allow an attacker to gain access to their incoming requests.
Those requests unavoidably expose any credentials needed by that service, but they ideally shouldn't expose anything else.

For more details on this security concern, see :sqr:`051`.

To avoid this problem, in addition to authenticating the user and performing authorization checks, Gafaelfawr will also filter the ``Authorization`` and ``Cookie`` headers of the incoming request and return the filtered versions in its response.
All ``Authorization`` headers containing Gafaelfawr tokens will be removed, as will (if present) the Gafaelfawr session cookie.
(The headers may be missing if all incoming ``Authorization`` and ``Cookie`` headers only contained Gafaelfawr tokens and cookies.)

The ingress-nginx configuration will then replace the ``Authorization`` and ``Cookie`` headers of the incoming request with the ones filtered by Gafaelfawr before passing the request to the protected service.
If a header is missing from the Gafaelfawr response, it will be dropped from the request by ingress-nginx.
This is done with the ``nginx.ingress.kubernetes.io/auth-response-headers`` annotation, normally added automatically to the ``Ingress`` created from a ``GafaelfawrIngress``.

.. _error-handling:

Error handling
==============

Gafaelfawr runs as an NGINX ``auth_request`` subhandler.
That NGINX module only supports two error status codes: 401 and 403.
Gafaelfawr therefore has to go to some special lengths to be able to return other error codes (such as 400) to the client.

This is done via the combination of special response headers, a custom location block added to each NGINX server via Phalanx configuration, and custom NGINX configuration added to each ``Ingress`` for a Gafaelfawr-protected service.
That configuration is added automatically for ``Ingress`` resources generated from a ``GafaelfawrIngress``.
If ingresses are :ref:`configured manually <manual-ingress>`, the corresponding NGINX configuration must also be added, or the client will receive 403 error codes instead of the expected error.
That configuration is described in :ref:`manual-basic`.
