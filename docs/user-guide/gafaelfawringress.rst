.. _ingress:

##########################################
Configuring ingress with GafaelfawrIngress
##########################################

The recommended way to configure ``Ingress`` resources for protected services is by using the ``GafaelafwrIngress`` custom resource.

Gafaelfawr only supports HTTP ingresses and only supports a limited subset of the full syntax for the ``rules`` and ``tls`` keys for the ``GafaelfawrIngress`` resource.
If you need other ``Ingress`` functionality, or if you need to add Gafaelfawr support to an ingress created outside of your control (such as by a third-party Helm chart), see :ref:`manual-ingress`.

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
     baseUrl: "https://cluster.example.com/"
     scopes:
       all:
         - "read:all"
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

The ``config`` section configures Gafaelfawr.
Here, only the two mandatory parameters are shown.

``config.baseUrl`` should be the base URL under which Gafaelfawr is installed.
In particular, appending ``/auth`` and ``/login`` should produce the URLs for those Gafaelfawr routes.
``config.scopes`` specifies the scopes required to access this service.
The scopes can be listed under either ``all``, meaning that all of those scopes are required, or ``any``, meaning that any one of those scopes is required.
Only one of ``all`` or ``any`` may be given.

The ``template`` section is a template for the ``Ingress`` resource.
It uses a subset of the ``Ingress`` schema.

``template.metadata.name`` specifies the name of the ``Ingress`` resource to create and must be present.
``template.metadata.labels`` and ``template.metadata.annotations`` may be set to add labels and annotations to the created ``Ingress``, in addition to the annotations that will be added by Gafaelfawr.

``template.spec.rules`` are the normal ``Ingress`` routing rules.
Only the above structure is supported, but all standard ``pathType`` options are supported, as is using either ``name`` or ``number`` for the port.
``template.spec.tls`` may also be given and, if present, uses the same schema as the normal ``tls`` section of an ``Ingress``.

For the configuration options discussed in the rest of this page, only the relevant portion of the ``GafaelfawrIngress`` resource is shown.
Add the example configuration to the above full resource to get a valid ``GafaelfawrIngress`` resource.

.. _login-redirect:

Redirecting users to log in
===========================

By default, unauthenticated users receive a 401 response from Gafaelfawr, which is passed back to the user by NGINX.

If you want unauthorized users to be redirected to the login page instead, use the ``config.loginRedirect`` parameter:

.. code-block:: yaml

   config:
     loginRedirect: true

This setting should be used for services that are accessed interactively from a web browser.

Do not set this to true if the ingress uses one of the non-primary hostnames added via the Helm setting ``ingress.additionalHosts`` (see :ref:`helm-additional-hosts`).
It will not work correctly.

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
         service: "service-name"
         scopes:
           - "read:image"
           - "read:tap"

``config.delegate.internal.service`` should be an identifier for the service (generally the service name).
It will be added to the metadata of the generated internal token and, from there, to log messages, so that it's possible to track which service is using a delegated token.

``config.delegate.internal.scopes`` is a list of scopes requested for the internal token.
The delegated token will have these scopes if the token used by the user to authenticate to the service had these scopes.

The scopes listed here are not mandatory; if the user's authentication token didn't have them, the Gafaelfawr authorization check will still succeed, the internal delegated token will be provided, but it will not have the missing scopes.
If the scopes must always be present, also list them in ``config.scopes.all`` as required to access this service.

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
See :ref:`basic-settings` for more details.

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
=======

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

.. _auth-headers:

Request headers
===============

The following headers will be added by Gafaelfawr to the incoming request before it is sent to the protected service.

``X-Auth-Request-Email``
    The email address of the authenticated user, if available.

``X-Auth-Request-User``
    The username of the authenticated user.

In addition, if a delegated token was requested, it will be sent in the ``X-Auth-Request-Token`` HTTP header as discussed in :ref:`delegated-tokens`.
If token delegation via the ``Authorization`` header is requested (see :ref:`delegate-authorization`), the delegated token will also be sent in an ``Authorization`` header with type ``bearer``.

HTTP headers starting with ``X-Auth-Request-*`` are reserved for Gafaelfawr.
More headers may be added in the future.

As discussed in :ref:`header-filtering`, Gafaelfawr also modifies the ``Authorization`` and ``Cookie`` headers to hide Gafaelfawr's own tokens and cookies.
This should be invisible to the protected application, and it can still set and receive its own cookies.
