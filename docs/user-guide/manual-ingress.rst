.. _manual-ingress:

###############################
Configuring an ingress manually
###############################

Normally, you should create Kubernetes ``Ingress`` resources for protected applications using the ``GafaelfawrIngress`` custom resource.
This is simpler, allows Gafaelfawr to do a lot of the work for you, and avoids annoying-to-debug syntax errors.
This is documented in :ref:`ingress`.

However, sometimes you can't create the ``Ingress`` resource via other means and instead need to manually configure ith with annotations.
The most common example is third-party Helm charts that allow changing the ingress class and annotations, but not (easily) delegating it to a custom resource.

For those cases, follow this documentation to construct the ingress annotations manually.

This documentation only discusses how to create annotations that are equivalent to what ``GafaelfawrIngress`` would have done, and does not describe in detail what those annotations do.
See :ref:`ingress` for those details.

Basic configuration
===================

The required minimum annotations for a web service that returns 401 if the user is not authenticated are:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

Replace ``<hostname>`` with the hostname of the ingress on which the Gafaelfawr routes are configured, and ``<scope>`` with the name of the scope that should be required in order to visit this site.

Multiple scopes may be requested by repeating the ``scope`` parameter.
For example, to require both ``read:tap`` and ``read:image`` scopes, use:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Email,X-Auth-Request-User"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=read:tap&scope=read:image"

To allow any one of the listed scopes to grant access, instead of requiring the user have all of the scopes, add ``satisfy=any``:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Email,X-Auth-Request-User"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=read:tap&scope=read:image&satisfy=any"

Redirecting users to log in
===========================

To redirect the user to the login page instead of returning a 401 error if the user is not authenticated, add an ``auth-signin`` annotation as well:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Email,X-Auth-Request-User"
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

Requesting delegated tokens
===========================

To request a delegated internal token, use these annotations:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Email,X-Auth-Request-User,X-Auth-Request-Token"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Token"
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>&delegate_to=<service>&delegate_scope=<delegate-scope>,<delegate-scope>"

``<service>`` should be replaced with an internal identifier for the service.
``<delegate-scope>`` is a comma-separated list of scopes requested for the internal token.

The token will be included in the request in an ``X-Auth-Request-Token`` header, and thus must be added to the ``auth-response-headers`` annotation.

For the special case of notebook tokens, instead use:

.. code-block:: yaml

   annotations:
    nginx.ingress.kubernetes.io/auth-method: "GET"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-Email,X-Auth-Request-User,X-Auth-Request-Token"
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>&notebook=true"

In both cases, services designed for API instead of browser access can omit the ``nginx.ingress.kubernetes.io/auth-signin`` to return authentication challenges to the user instead of redirecting them to the login page.

Disabling error caching
=======================

To use the Gafaelfawr ``/auth/forbidden`` route as the error page for all 403 errors so that they will not be cached, add the following annotation in addition to the normal Gafaelfawr annotations:

.. code-block:: yaml

   annotations:
     nginx.ingress.kubernetes.io/configuration-snippet: |
       error_page 403 = "/auth/forbidden?scope=<scope>";

The parameters to the ``/auth/forbidden`` URL must be the same as the parameters given in the ``auth-url`` annotation.
The scheme and host of the URL defined for the 403 error must be omitted so that NGINX will generate an internal redirect, which in turn requires (as with the rest of Gafaelfawr) that the Gafaelfawr ``/auth`` route be defined on the same virtual host as the protected service.

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
    Services that want to prompt for HTTP Basic Authentication should set this to ``basic`` instead.

``notebook`` (optional)
    If set to a true value, requests a notebook token for the user be generated and passed to the service in the ``X-Auth-Request-Token`` header.
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
    If the protected service wants to ensure that all requested scopes are present in the delegated token, every scope listed in ``delegate_scopes`` must also be listed in ``scope``, and ``satisfy`` must either be unset or set to ``all``.

``minimum_lifetime`` (optional)
    The required minimum lifetime for a delegated token (internal or notebook).
    Since the maximum lifetime of a delegated token is the same as the remaining lifetime of the authenticating token, capped by the maximum token lifetime, this may also be used to set the minimum remaining lifetime of the user's session.

    If the presented authentication credentials don't satisfy this required lifetime, a 401 error will be returned.
    If the ``nginx.ingress.kubernetes.io/auth-signin`` annotation is set in the ``Ingress``, this will force a user reauthentication.

These parameters must be URL-encoded as GET parameters to the ``/auth`` route.
