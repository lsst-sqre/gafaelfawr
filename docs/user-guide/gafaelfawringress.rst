.. _ingress:

##########################################
Configuring ingress with GafaelfawrIngress
##########################################

To create an ``Ingress`` for protected services, use the ``GafaelfawrIngress`` custom resource.

Gafaelfawr only supports HTTP ingresses and only supports a limited subset of the full syntax for the ``rules`` and ``tls`` keys for the ``GafaelfawrIngress`` resource.
See :ref:`ingress-overview` for an overview of how Gafaelfawr protects services.

Basic configuration
===================

Rather than creating an ``Ingress`` resource for a protected service, create a ``GafaelfawrIngress`` resource.

Here is a simple example, which requires ``read:all`` scope to access a service, does not delegate tokens, and returns 401 errors to unauthorized users rather than redirecting them to the login page.

.. code-block:: yaml

   apiVersion: gafaelfawr.lsst.io/v1alpha1
   kind: GafaelfawrIngress
   metadata:
     name: service-ingress
     namespace: service
   config:
     scopes:
       all:
         - "read:all"
     service: service
   template:
     metadata:
       name: service-ingress
     spec:
       rules:
         - host: cluster.example.com
           http:
             paths:
               - path: /foo
                 pathType: Prefix
                 backend:
                   service:
                     name: service
                     port:
                       name: http

The ``apiVersion`` and ``kind`` keys must always have those values.

The ``metadata`` section is standard Kubernetes resource metadata.
You can add labels and annotations here if you wish, but they will have no effect on the generated ``Ingress`` resource.

For the configuration options discussed in the rest of this page, only the relevant portion of the ``GafaelfawrIngress`` resource is shown.
Add the example configuration to the above full resource to get a valid ``GafaelfawrIngress`` resource.

``config`` section
------------------

The ``config`` section configures Gafaelfawr.
Here, only the two mandatory parameters are shown.
Many other settings are possible and are discussed below.

``config.scopes`` specifies the scopes required to access this service and is required.
The scopes can be listed under either ``all``, meaning that all of those scopes are required, or ``any``, meaning that any one of those scopes is required.
Only one of ``all`` or ``any`` may be given.
Alternately, the ingress can be anonymous; see :ref:`anonymous` for details on that.

``config.service`` names the service underlying this ingress.
This is used for logging, metrics, and token delegation (see :ref:`delegated-tokens`).
This setting is not technically required currently, but will become mandatory in the future and should always be provided.

``template`` section
--------------------

The ``template`` section is a template for the ``Ingress`` resource.
It uses a subset of the ``Ingress`` schema.

``template.metadata.name`` specifies the name of the ``Ingress`` resource to create and must be present.

``template.metadata.labels`` and ``template.metadata.annotations`` may be set to add labels and annotations to the created ``Ingress``, in addition to the annotations that will be added by Gafaelfawr.
Gafaelfawr will always add the ``app.kubernetes.io/managed-by`` label with the value ``Gafaelfawr``, overriding any label by that name specified here.

``template.spec.rules`` are the normal ``Ingress`` routing rules.
Only the above structure is supported, but all standard ``pathType`` options are supported, as is using either ``name`` or ``number`` for the port.
``template.spec.tls`` may also be given and, if present, uses the same schema as the normal ``tls`` section of an ``Ingress``.

Unless the ingress is anonymous or disables cookie authentication, the hosts listed in all ingress rules must either match the host of the configured Gafaelfawr base URL or (only if ``config.allowSubdomains`` is enabled) be a subdomain of that host.

.. _login-redirect:

Redirecting users to log in
===========================

By default, unauthenticated users receive a 401 response from Gafaelfawr, which is passed back to the user by NGINX.

If you want unauthorized users to be redirected to the login page instead, use the ``config.loginRedirect`` parameter:

.. code-block:: yaml

   config:
     loginRedirect: true

This setting should be used for services that are normally accessed interactively from a web browser.
It cannot be used with the ``config.allowCookies`` parameter set to false (see :ref:`allow-cookies`).

Do not set this to true if the ingress is not running under the same host and port as the Gafaelfawr base URL for the environment.
It will not work correctly.

.. _allow-cookies:

Disallowing cookie authentication
=================================

Normally, Gafaelfawr supports either cookie authentication (set for users who log in interactively with a web browser) or token authentication (using the ``Authorization`` header, normally used by programs).
Both are treated equivalently.

In some cases, it may be desirable to disallow cookie authentication.
This protects that ingress from many :abbr:`CSRF (Cross-Site Request Forgery)` attacks, for example, since the attacker cannot make use of browser cookies and must somehow obtain a token to put into the ``Authorization`` header.

Enabling this option blocks normal access from a web browser and therefore should only be used for ingresses that are only accessed via programs and other tools that use user tokens.

To disallow cookie authentication, set the ``config.allowCookies`` parameter to false:

.. code-block:: yaml

   config:
     allowCookies: false

This setting cannot be used in conjunction with ``config.loginRedirect`` (see :ref:`login-redirect`), since the purpose of a login redirect is to set a cookie and return.
That combination of settings would create a redirect loop that would never allow access.

Changing the challenge type
===========================

When presenting an authentication challenge (a 401 response) instead of redirecting the user to the login page, the default is to request a bearer token (:rfc:`6750`).
In some cases, you may want Gafaelfawr to request Basic authentication (:rfc:`7617`) instead.
Do this with the ``config.authType`` parameter:

.. code-block:: yaml

   config:
     authType: basic

This will normally cause the browser to pop up a request for username and password.
This setting cannot be used with ``config.loginRedirect``; Gafaelfawr can either redirect the user or present a challenge, but not both.

.. _delegated-tokens:

Requesting delegated tokens
===========================

Some services may need to make additional web requests on behalf of the user to other services protected by Gafaelfawr.

Internal tokens
---------------

Services may request an internal token from Gafaelfawr using the ``config.delegate`` parameter:

.. code-block:: yaml

   config:
     delegate:
       internal:
         scopes:
           - "read:image"
           - "read:tap"

The resulting token will be marked as delegated to the service of the ingress as configured in ``config.service``.
This information will be used in logging and metrics, and can be used to restrict access to only specific services (see :ref:`ingress-service-only`).

``config.delegate.internal.scopes`` is a list of scopes requested for the internal token.
The delegated token will have these scopes if the token used by the user to authenticate to the service had these scopes.

The scopes listed here are not mandatory; if the user's authentication token didn't have them, the Gafaelfawr authorization check will still succeed, the internal delegated token will be provided, but it will not have the missing scopes.
If the scopes must always be present, also list them in ``config.scopes.all`` as required to access this service.

``config.delegate.internal.service`` overrides ``config.service`` when determining the service associated with the delegated token, and is mandatory if ``config.service`` isn't set.
This setting is deprecated; set ``config.service`` instead.

The delegated token will be included in the request to the protected service in the ``X-Auth-Request-Token`` HTTP header.
This token may be used in an ``Authorization`` header with type ``bearer`` to make requests to other protected services.
It can also be verified and used to obtain information about a user by presenting it in an ``Authorization`` header with type ``bearer`` to either of the ``/auth/v1/api/token-info`` or ``/auth/v1/api/user-info`` Gafaelfawr routes.

Notebook tokens
---------------

As a special case, JupyterLab_ notebooks can request a type of internal token called a notebook token, which will always have the same scope as the user's session token (and thus can do anything the user can do).
To request such a token, use this configuration instead:

.. code-block:: yaml

   config:
     delegate:
       notebook: {}

Note that the ``config.delegate.notebook`` key must be empty.
(This allows for possible future configuration options.)

.. _JupyterLab: https://jupyter.org/

Minimum token lifetime
----------------------

For either internal or notebook tokens, the service can request the token have a minimum lifetime:

.. code-block:: yaml

   config:
     delegate:
       minimumLifetime: 3600

This value is in seconds, so the above requests a minimum lifetime of one hour.

If the user's authentication token does not have a sufficient remaining lifetime to create an internal or notebook token with at least this remaining life, the request will be treated the same as if the user had no token.
In other words, they will receive either a 401 response or be redirected to the login page, depending on the value of ``config.loginRedirect``.
Presumably logging in again will create a token with sufficient remaining lifetime to satisfy this restriction.

Obviously, do not request a minimum lifetime longer than the default token lifetime!
See :ref:`helm-token-lifetime` for more details.

.. _delegate-authorization:

Delegate token in Authorization header
--------------------------------------

The delegated token is passed to the protected service in the ``X-Auth-Request-Token`` header, but this is a custom Gafaelfawr header.
Some services may expect that token to be passed in the ``Authorization`` header as a bearer token, as specified in :rfc:`6750`.
To tell Gafaelfawr to do this, use:

.. code-block:: yaml

   config:
     delegate:
       useAuthorization: true

The same token will also still be passed in the ``X-Auth-Request-Token`` header.

If this configuration option is set, the incoming ``Authorization`` header will be entirely replaced by one containing only the delegated token, unlike Gafaelfawr's normal behavior of preserving any incoming ``Authorization`` header that doesn't include a Gafaelfawr token.

Caching
========

By default, Gafaelfawr is consulted for every HTTP request handled by the NGINX ingress.

For lower-volume API services, this is normally desirable, but for interactive web sites that may load large numbers of supporting resources or make a large number of small HTTP requests, this can cause unnecessary load on NGINX and Gafaelfawr.
In those cases, you may wish to trade some security and predictability for performance by telling NGINX to cache the Gafaelfawr response for a short period of time.

You can do this with the ``authCacheDuration`` setting:

.. code-block:: yaml

   config:
     authCacheDuration: 5m

The value must be an `NGINX time interval <https://nginx.org/en/docs/syntax.html>`__.
``5m`` for five minutes represents a reasonable tradeoff between respecting token invalidation and reducing the NGINX and Gafaelfawr load.

The cache is automatically invalidated if the ``Cookie`` or ``Authorization`` HTTP headers change.

.. warning::

   Enabling authentication caching means that not all requests to the service will be passed to Gafaelfawr.
   That, in turn, means that Gafaelfawr cannot enforce rate limiting.
   Only the uncached requests will count against the rate limit.
   For services that require rate limiting, either do not use ``authCacheDuration`` or implement rate limiting some other way, such as directly inside the protected service.

.. _ingress-service-only:

Service-only ingresses
======================

Sometimes it is useful to restrict an ingress to only allow access from other services acting on behalf of users.
For example, in a microservice architecture, a user-facing service may call out to other internal services to perform part of its work, but users should not be able to access the internal services directly.

Gafaelfawr supports this use case with ingresses that can only be accessed by tokens issued to other services.
Normally this is an internal token delegated to a service via its ingress.

To restrict an ingress to only access by a list of other services, use the ``onlyServices`` setting:

.. code-block:: yaml

   config:
     onlyServices:
       - portal
       - vo-cutouts

The value is a list of service names that should be allowed access.
All other services, and all direct access by users, will be denied.

The names of the services listed here must match the service name in issued tokens that should be permitted access.
This is configured in ``config.service`` in the ingress for the calling service.

For example, suppose there are two services, user-service and backend-service.
The user will make direct requests to user-service.
backend-service wants to only allow requests from user-service, but not directly from users.
In this case, the ingress for user-service should set ``config.service`` to ``user-service`` and request delegated internal tokens.
The ingress for backend-service should then set ``config.onlyServices`` to ``["user-service"]``.

All other access restrictions are still applied in addition to the service restrictions.
So, for example, if the internal token from a listed service doesn't have a required scope, Gafaelfawr will still reject the request.

Per-user ingresses
==================

Access to an ingress may be restricted to a specific user as follows:

.. code-block:: yaml

   config:
     username: <username>

Any user other than the one with the username ``<username>`` will then receive a 403 error.
The scope requirements must still be met to allow access.

.. _anonymous:

Anonymous ingresses
===================

An anonymous ingress (one that doesn't require authentication and performs no authorization checks) can be configured using ``GafaelfawrIngress`` as follows:

.. code-block:: yaml

   config:
     scopes:
       anonymous: true

None of the other configuration options are supported in this mode.

The reason to use this configuration over simply writing an ``Ingress`` resource directly is that Gafaelfawr will still be invoked to strip Gafaelfawr tokens and secrets from the request before it is passed to the underlying service.
This prevents credential leakage to anonymous services.
See :ref:`header-filtering` for more details.

Locating Gafaelfawr-managed ingresses
=====================================

Gafaelfawr adds the label ``app.kubernetes.io/managed-by`` with the value ``Gafaelfawr`` to all of the ingresses that it generates from ``GafaelfawrIngress`` resources.
This label can be used to locate all Gafaelfawr-managed ``Ingress`` resources, or all ``Ingress`` resources not managed by Gafaelfawr.

.. _auth-headers:

Request headers
===============

The following headers will be added by Gafaelfawr to the incoming request before it is sent to the protected service.

``X-Auth-Request-Email``
    The email address of the authenticated user, if available.

``X-Auth-Request-Service``
    If the authenticating token is an internal token issued to a service, the name of the service authenticating on behalf of the user.

``X-Auth-Request-User``
    The username of the authenticated user.

In addition, if a delegated token was requested, it will be sent in the ``X-Auth-Request-Token`` HTTP header as discussed in :ref:`delegated-tokens`.
If token delegation via the ``Authorization`` header is requested (see :ref:`delegate-authorization`), the delegated token will also be sent in an ``Authorization`` header with type ``bearer``.

HTTP headers starting with ``X-Auth-Request-*`` are reserved for Gafaelfawr.
More headers may be added in the future.

As discussed in :ref:`header-filtering`, Gafaelfawr also modifies the ``Authorization`` and ``Cookie`` headers to hide Gafaelfawr's own tokens and cookies.
This should be invisible to the protected application, and it can still set and receive its own cookies.
