.. _ingress:

#############################################
Configuring ingress with GafaelfawrIngress
#############################################

The recommended way to configure ``Ingress`` resources for protected services is by using the ``GafaelafwrIngress`` custom resource.

Prerequisites
=============

Gafaelfawr requires ingress-nginx_.

.. _ingress-nginx: https://kubernetes.github.io/ingress-nginx/deploy/

Kubernetes 1.19 or later is required to use ``GafaelfawrIngress``, since the generated ingress will use the ``networking.k8s.io/v1`` API introduced in that version.

Gafaelfawr's routes must be exposed under the same hostname as the service that it is protecting.
IF you need to protect services running under multiple hostnames, you will need to configure Gafaelfawr's ingress to add its routes (specifically ``/auth`` and ``/login``) to each of those hostnames.

Gafaelfawr only supports HTTP ingresses and only supports a limited subset of the full syntax for the ``rules`` and ``tls`` keys for the ``Ingress`` resource.

If you need other ``Ingress`` functionality, or if you need to add Gafaelfawr support to an ingress created outside of your control (such as by a third-party Helm chart), see :ref:`manual-ingress`.

How Gafaelfawr works
====================

Gafaelfawr is introduced into the HTTP request path for your services as an NGINX ``auth_request`` subhandler.
This is done via annotations added to the Kubernetes ``Ingress`` resource that are interpreted by ingress-nginx.

For each HTTP request to a protected service, NGINX will send a request to the Gafaelfawr ``/auth`` route with the headers of the incoming request (including, for example, any cookies or ``Authorization`` header).

Gafaelfawr, when receiving that request, will find the user's authentication token, check that it is valid, and check that the user has the required scope.

If the user is not authenticated, it will either return a 401 error with an appropriate ``WWW-Authenticate`` challenge, or a redirect to the sign-in URL, depending on Gafaelfawr's configuration.
The sign-in URL would then send the user to CILogon, an OpenID Connect server, or GitHub to authenticate.

If the user is already authenticated but does not have the desired scope, Gafaelfawr will return a 403 error, which will be passed back to the user.

If the user is authenticated and authorized, Gafaelfawr will return a 200 response with some additional headers containing information about the user and (optionally) a delegated token.
NGINX will then send the user's HTTP request along to the protected service, including those headers in the request.

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

Redirecting users to log in
===========================

By default, unauthenticated users receive a 401 response from Gafaelfawr, which is passed back to the user by NGINX.

If you want unauthorized users to be redirected to the login page instead, use the ``config.loginRedirect`` parameter:

.. code-block:: yaml

   config:
     loginRedirect: true

This setting should be used for services that are accessed interactively from a web browser.

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

.. _auth-headers:

Request headers
===============

The following headers will be added by Gafaelfawr to the incoming request before it is sent to the protected service.

``X-Auth-Request-Email``
    The email address of the authenticated user, if available.

``X-Auth-Request-User``
    The username of the authenticated user.

In addition, if a delegated token was requested, it will be sent in the ``X-Auth-Request-Token`` HTTP header as discussed in :ref:`delegated-tokens`.

HTTP headers starting with ``X-Auth-Request-*`` are reserved for Gafaelfawr.
More headers may be added in the future.

.. _error-caching:

Disabling error caching
=======================

Web browsers cache 403 (HTTP Forbidden) error replies by default.
Unfortunately, NGINX does not pass a ``Cache-Control`` response header (or any other headers) from an ``auth_request`` handler back to the client.
It also does not set ``Cache-Control`` on a 403 response itself, and the Kubernetes ingress-nginx ingress controller does not provide a configuration knob to change that.
This can cause user confusion; if they reauthenticate after a 403 error and obtain additional group memberships, they may still get a 403 error when they return to the page they were trying to access even if they now have access.

This can be avoided by setting a custom error page that sets a ``Cache-Control`` header to tell the browser not to cache the error.
Gafaelfawr provides ``/auth/forbidden`` as a custom error handler for this purpose.
To use this, add the following to the ``GafaelfawrIngress`` resource:

.. code-block:: yaml

   config:
     replace403: true

This will configure NGINX to use the Gafaelfawr ``/auth/forbidden`` route as a custom error page for all 403 errors.

Be aware that this will intercept **all** 403 errors from the protected service, not just ones from Gafaelfawr.
If the protected service returns its own 403 errors, the resulting error will probably be nonsensical, and this facility may not be usable.
