.. _service-ingress:

#############################
Configuring a service ingress
#############################

Prerequisites
=============

Gafaelfawr requires ingress-nginx_.

.. _ingress-nginx: https://kubernetes.github.io/ingress-nginx/deploy/

Gafaelfawr's routes must be exposed under the same hostname as the service that it is protecting.
IF you need to protect services running under multiple hostnames, you will need to configure Gafaelfawr's ingress to add its routes (specifically ``/auth`` and ``/login``) to each of those hostnames.

Basic configuration
===================

Authentication and authorization for a service are configured via annotations on the ``Ingress`` for that service.
The typical annotations for a web application used via a web browser are:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

Replace ``<hostname>`` with the hostname of the ingress on which the Gafaelfawr routes are configured, and ``<scope>`` with the name of the scope that should be required in order to visit this site.
You must also either set ``spec.ingressClassName`` to ``nginx`` (Kubernetes 1.19 or later) or add the annotation ``kubernetes.io/ingress.class: nginx`` (older versions of Kubernetes).

This will send a request to the Gafaelfawr ``/auth`` route for each request.
It will find the user's authentication token, check that it is valid, and check that the user has the required scope.
If the user is not authenticated, they will be redirected to the sign-in URL configured here, which in turn will either send the user to CILogon or to GitHub to authenticate.
If the user is already authenticated but does not have the desired scope, they will receive a 403 error.

The typical annotations for a API that expects direct requests from programs are:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

(In other words, omit ``nginx.ingress.kubernetes.io/auth-signin``.)
The difference in this case is that the 401 error when authentication is not provided will be returned to the client, rather than returning a redirect to the login page.

If the user authenticates and authorizes successfully, the request will be sent to the application.

Requesting internal tokens
==========================

Some applications may need to make additional web requests on behalf of the user to other applications protected by Gafaelfawr.
These applications must request an internal token from Gafaelfawr using Kubernetes annotations such as this:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Token"
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>&delegate_to=<service>&delegate_scope=<scope>,<scope>"

``<service>`` should be replaced with an internal identifier for the service and will be added to the internal tokens issued this way.
``<scope>`` is a comma-separated list of scopes the internal token should have.
``delegate_scope`` can be omitted, in which case the internal token will have no scope.
(Such a token can still be used to retrieve user information such as a UID or group membership.)

The token will be included in the request in an ``X-Auth-Request-Token`` header, hence the additional annotation saying to pass that header to the application.

The resulting token may be verified and used to obtain information about a user by presenting it in an ``Authorization`` header with type ``bearer`` to either of the ``/auth/v1/api/token-info`` or ``/auth/v1/api/user-info`` routes.

As a special case, JupyterLab notebooks can request a type of internal token called a notebook token, which will always have the same scope as the user's session token (and thus can do anything the user can do).
To request such a token, use annotations like:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Token"
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>&notebook=true"

In both cases, applications designed for API instead of browser access can omit the ``nginx.ingress.kubernetes.io/auth-signin`` to return authentication challenges to the user instead of redirecting them to the login page.

.. _error-caching:

Disabling error caching
=======================

Web browsers cache 403 (HTTP Forbidden) error replies by default.
Unfortunately, NGINX does not pass a ``Cache-Control`` response header (or any other headers) from an ``auth_request`` handler back to the client.
It also does not set ``Cache-Control`` on a 403 response itself, and the Kubernetes ingress-nginx does not provide a configuration knob to change that.
This can cause user confusion; if they reauthenticate after a 403 error and obtain additional group memberships, they may still get a 403 error when they return to the page they were trying to access even if they now have access.

This can be avoided by setting a custom error page that sets a ``Cache-Control`` header to tell the browser not to cache the error.
Gafaelfawr provides ``/auth/forbidden`` as a custom error handler for this purpose.
To use this, add the following annotation to the ingress for the application:

.. code-block:: yaml

   annotations:
     nginx.ingress.kubernetes.io/configuration-snippet: |
       error_page 403 = "/auth/forbidden?scope=<scope>";

The parameters to the ``/auth/forbidden`` URL must be the same as the parameters given in the ``auth-url`` annotation.
The scheme and host of the URL defined for the 403 error must be omitted so that NGINX will generate an internal redirect, which in turn requires (as with the rest of Gafaelfawr) that the Gafaelfawr ``/auth`` route be defined on the same virtual host as the protected application.

Be aware that this will intercept **all** 403 errors from the protected application, not just ones from Gafaelfawr.
If the protected application returns its own 403 errors, the resulting error will probably be nonsensical, and this facility may not be usable.

.. _auth-config:

Configuring authentication
==========================

The URL in the ``nginx.ingress.kubernetes.io/auth-url`` annotation accepts several parameters to customize the authentication request.

``scope`` (required)
    The scope claim that the client JWT must have.
    May be given multiple times.
    If given multiple times, the meaning is govered by the ``satisfy`` parameter.
    Scopes are determined by mapping the group membership provided by the authentication provider, using the ``config.groupMapping`` Helm chart value.
    See :ref:`scopes` for more information.

``satisfy`` (optional)
    How to interpret multiple ``scope`` parameters.
    If set to ``all`` (or unset), the user's token must have all of the given scopes.
    If set to ``any``, the user's token must have one of the given scopes.

``auth_type`` (optional)
    Controls the authentication type in the challenge returned in ``WWW-Authenticate`` if the user is not authenticated.
    By default, this is ``bearer``.
    Applications that want to prompt for HTTP Basic Authentication should set this to ``basic`` instead.

``notebook`` (optional)
    If set to a true value, requests a notebook token for the user be generated and passed to the application in the ``X-Auth-Request-Token`` header.
    This may not be set at the same time as ``delegate_to``.

``delegate_to`` (optional)
    If set, requests an internal token.
    The value of this parameter is an identifier for the service that will use this token to make additional requests on behalf of the user.
    That internal token will be generated if necessary and passed in the ``X-Auth-Request-Token`` header.
    This may not be set at the same time as ``notebook``.

``delegate_scope`` (optional)
    A comma-separated list of scopes that the internal token should have, if available from the authenticating token.
    Only meaningful when ``delegate_to`` is also set.

    By default, these scopes are optional.
    The delegated token will have each scope listed if the authenticating token has that scope, but if it does not, authentication will still succeed and a delegated token will still be passed down but some scopes will be missing.
    If the protected application wants to ensure that all requested scopes are present in the delegated token, every scope listed in ``delegate_scopes`` must also be listed in ``scope``, and ``satisfy`` must either be unset or set to ``all``.

``minimum_lifetime`` (optional)
    The required minimum lifetime for a delegated token (internal or notebook).
    Since the maximum lifetime of a delegated token is the same as the remaining lifetime of the authenticating token, capped by the maximum token lifetime, this may also be used to set the minimum remaining lifetime of the user's session.

    If the presented authentication credentials don't satisfy this required lifetime, a 401 error will be returned.
    If the ``nginx.ingress.kubernetes.io/auth-signin`` annotation is set in the ``Ingress``, this will force a user reauthentication.

These parameters must be URL-encoded as GET parameters to the ``/auth`` route.

.. _auth-headers:

Additional authentication headers
=================================

The following headers may be requested by the application by adding them to the ``nginx.ingress.kubernetes.io/auth-response-headers`` annotation for the ingress rule.
The value of that annotation is a comma-separated list of desired headers.

``X-Auth-Request-Email``
    The email address of the authenticated user, if available.

``X-Auth-Request-Token``
    If a notebook or internal token was requested, it will be provided as the value of this header.

``X-Auth-Request-User``
    The username of the authenticated user.
