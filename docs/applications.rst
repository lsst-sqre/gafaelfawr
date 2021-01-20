#########################
Application configuration
#########################

Protecting a service
====================

Gafaelfawr's routes must be exposed under the same hostname as the service that it is protecting.
IF you need to protect services running under multiple hostnames, you will need to configure Gafaelfawr's ingress to add its routes (specifically ``/auth`` and ``/login``) to each of those hostnames.

Authentication and authorization for a service are configured via annotations on the ingress for that service.
The typical annotations for a web application used via a web browser are:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-method: GET
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

Replace ``<hostname>`` with the hostname of the ingress on which the Gafaelfawr routes are configured, and ``<scope>`` with the name of the scope that should be required in order to visit this site.

This will send a request to the Gafaelfawr ``/auth`` route for each request.
It will find the user's authentication token, check that it is valid, and check that the user has the required scope.
If the user is not authenticated, they will be redirected to the sign-in URL configured here, which in turn will either send the user to CILogon or to GitHub to authenticate.
If the user is already authenticated but does not have the desired scope, they will receive a 403 error.

The typical annotations for a API that expects direct requests from programs are:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-method: GET
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

The difference in this case is that the 401 error when authentication is not provided will be returned to the client, rather than returning a redirect to the login page.

If the user authenticates and authorizes successfully, the request will be sent to the application.

Requesting internal tokens
==========================

Some applications may need to make additional web requests on behalf of the user to other applications protected by Gafaelfawr.
These applications must request an internal token from Gafaelfawr using Kubernetes annotations such as this:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-method: GET
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>&delegate_to=<service>&delegate_scope=<scope>,<scope>"

``<service>`` should be replaced with an internal identifier for the service and will be added to the internal tokens issued this way.
``<scope>`` is a comma-separated list of scopes the internal token should have.
``delegate_scope`` can be omitted, in which case the internal token will have no scope.
(Such a token can still be used to retrieve user information such as a UID or group membership.)

The token will be included in the request in an ``X-Auth-Request-Token`` header, hence the additional annotation saying to pass that header to the application.

As a special case, JupyterLab notebooks can request a special type of internal token called a notebook token, which will always have the same scope as the user's session token (and thus can do anything the user can do).
To request such a token, use annotations like:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-method: GET
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>&notebook=true"

In both cases, applications designed for API instead of browser access can omit the ``nginx.ingress.kubernetes.io/auth-signin`` to return authentication challenges to the user instead of redirecting them to the login page.

.. _error-caching:

Disabling error caching
=======================

Web browsers cache 403 (HTTP Forbidden) error replies by default.
Unfortunately, NGINX does not pass a ``Cache-Control`` response header from an ``auth_request`` handler back to the client.
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
    Scopes are determined by mapping the group membership provided by the authentication provider, using the ``group_mapping`` configuration directive.
    See :ref:`settings` for more information.

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
    A comma-separated list of scopes that the internal token should have.
    This must be a subset of the scopes the authenticating token has, or the ``auth_request`` handler will deny access.
    Only meaningful when ``delegate_to`` is also set.

These parameters must be URL-encoded as GET parameters to the ``/auth`` route.

.. _auth-headers:

Additional authentication headers
=================================

The following headers may be requested by the application by adding them to the ``nginx.ingress.kubernetes.io/auth-response-headers`` annotation for the ingress rule.
The value of that annotation is a comma-separated list of desired headers.

``X-Auth-Request-Client-Ip``
    The IP address of the client, as determined after parsing ``X-Forwarded-For`` headers.
    See :ref:`client-ips` for more information.

``X-Auth-Request-User``
    The username of the authenticated user.

``X-Auth-Request-Uid``
    The numeric UID of the authenticated user if the user has one.

``X-Auth-Request-Groups``
    If the token lists groups in an ``isMemberOf`` claim, the names of the groups will be returned, comma-separated, in this header.

``X-Auth-Request-Token``
    If a notebook or internal token was requested, it will be provided as the value of this header.

``X-Auth-Request-Token-Scopes``
    If the token has scopes in the ``scope`` claim or derived from groups listed in ``isMemberOf``, they will be returned in this header.

``X-Auth-Request-Token-Scopes-Accepted``
    A space-separated list of token scopes the reliant resource accepts.
    This is configured in the ``nginx.ingress.kubernetes.io/auth-url`` annotation via the ``scope`` parameter.

``X-Auth-Request-Token-Scopes-Satisfy``
    The strategy the reliant resource uses to determine whether a token satisfies the scope requirements.
    It will be either ``any`` or ``all``.
    This is configured in the ``nginx.ingress.kubernetes.io/auth-url`` annotation via the ``satisfy`` parameter.

Verifying tokens
================

Tokens may be verified and used to obtain information about a user by presenting them in an ``Authorization`` header with type ``bearer`` to either of the ``/auth/v1/api/token-info`` or ``/auth/v1/api/user-info`` routes.

.. _openid-connect:

Using OpenID Connect
====================

To protect an application that uses OpenID Connect, first set ``oidc_server.enabled`` to true in the :ref:`helm-settings`.
Then, create (or add to, if already existing) an ``oidc-server-secrets`` Vault secret key.
The value of the key must be a JSON list, with each list member representing one OpenID Connect client.
Each list member must be an object with two keys: ``id`` and ``secret``.
``id`` can be anything informative that you want to use to uniquely represent this OpenID Connect client.
``secret`` should be a randomly-generated secret that the client will use to authenticate.

Then, configure the client.
The authorization endpoint is ``/auth/openid/login``.
The token endpoint is ``/auth/openid/token``.
The userinfo endpoint is ``/auth/userinfo``.
The JWKS endpoing is ``/.well-known/jwks.json``.
As with any other protected application, the client must run on the same URL host as Gafaelfawr, and these endpoints are all at that shared host (and should be specified using ``https``).

The OpenID Connect client should be configured to request only the ``openid`` scope.
No other scope is supported.
The client must be able to authenticate by sending a ``client_secret`` parameter in the request to the token endpoint.

Chronograf example
------------------

Assuming that Gafaelfawr and Chronograf are deployed on the host ``example.com`` and Chronograf is at the URL ``/chronograf``, here are the environment variables required to configure `Chronograf <https://docs.influxdata.com/chronograf/v1.8/administration/managing-security/#configure-chronograf-to-use-any-oauth-2-0-provider>`__:

* ``GENERIC_CLIENT_ID``: ``chronograf-client-id``
* ``GENERIC_CLIENT_SECRET``: ``fb7518beb61d27aaf20675d62778dea9``
* ``GENERIC_AUTH_URL``: ``https://example.com/auth/openid/login``
* ``GENERIC_TOKEN_URL``: ``https://example.com/auth/openid/token``
* ``USE_ID_TOKEN``: 1
* ``JWKS_URL``: ``https://example.com/.well-known/jwks.json``
* ``GENERIC_API_URL``: ``https://example.com/auth/userinfo``
* ``GENERIC_SCOPES``: ``openid``
* ``PUBLIC_URL``: ``https://example.com/chronograf``
* ``TOKEN_SECRET``: ``pCY29u3qMTdWCNetOUD3OShsqwPm+pYKDNt6dqy01qw=``

Open Distro for Elasticsearch example
-------------------------------------

Assuming that Gafaelfawr and Open Distro for Elasticsearch are deployed on the host ``example.com``, here are the settings required to configure `Open Distro for Elasticsearch <https://opendistro.github.io/for-elasticsearch-docs/docs/security/configuration/openid-connect/>`__:

* ``opendistro_security.auth.type``: ``openid``
* ``opendistro_security.openid.connect_url``: ``https://example.com/.well-known/openid-configuration``
* ``opendistro_security.openid.client_id``: ``kibana-client-id``
* ``opendistro_security.openid.client_secret``: ``fb7518beb61d27aaf20675d62778dea9``
* ``opendistro_security.openid.scope``: ``openid``
* ``opendistro_security.openid.logout_url``: ``https://example.com/logout``

.. _influxdb:

Authenticating to InfluxDB
==========================

.. warning::

   InfluxDB 2.x is not supported.
   These tokens will only work with InfluxDB 1.x.

Gafaelfawr optionally supports issuing tokens for InfluxDB 1.x authentication.
To enable this support, set ``issuer.influxdb.enabled`` to true in :ref:`helm-settings`.
Then, create an ``influxdb-secret`` Vault secret key with the shared key that InfluxDB uses to verify the token.
This can be any string of characters, such as the results of ``os.urandom(32).hex()``.
The same secret must be configured in the `InfluxDB configuration file <https://docs.influxdata.com/influxdb/v1.8/administration/authentication_and_authorization/>`__.

This will enable creation of new InfluxDB tokens via the ``/auth/tokens/influxdb/new`` route.
Users can authenticate to this route with either a web session or a bearer token.
The result is a JSON object containing a ``token`` key, the contents of which are the bearer token to present to InfluxDB.

The token will contain a ``username`` claim matching the user's Gafaelfawr username and will expire at the same time as the token or session used to authenticate to this route.

If you want all InfluxDB tokens to contain the same ``username`` field so that you can use a single generic InfluxDB account, set ``issuer.influxdb.username`` to that value in :ref:`helm-settings`.
