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
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
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
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

The difference in this case is that the 401 error when authentication is not provided will be returned to the client, rather than returning a redirect to the login page.

If the user authenticates and authorizes successfully, the request will be sent to the application.
Included in the request will be an ``X-Auth-Request-Token`` header containing the user's JWT.
This will be a reissued token signed by Gafaelfawr.

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

``audience`` (optional)
    May be set to the value of the ``issuer.aud.internal`` configuration parameter, in which case a new token will be issued from the user's token with all the same claims but with that audience.
    This newly-issued token will be returned in the ``X-Auth-Request-Token`` header instead of the user's regular token.
    The intent of this feature is to send an audience-restricted version of a token to an internal service, which may use it to make subrequests to other internal services but should not be able to make requests to public-facing services.

These parameters must be URL-encoded as GET parameters to the ``/auth`` route.

.. _auth-headers:

Additional authentication headers
=================================

The following headers may be requested by the application by adding them to the ``nginx.ingress.kubernetes.io/auth-response-headers`` annotation for the ingress rule.
The value of that annotation is a comma-separated list of desired headers.

``X-Auth-Request-Client-Ip``
    The IP address of the client, as determined after parsing ``X-Forwarded-For`` headers.
    See :ref:`client-ips` for more information.

``X-Auth-Request-Email``
    If enabled and the claim is available, this will be set based on the ``email`` claim in the token.

``X-Auth-Request-User``
    If enabled and the claim is available, this will be set from token based on the ``username_claim`` setting (by default, the ``uid`` claim).

``X-Auth-Request-Uid``
    If enabled and the claim is available, this will be set from token based on the ``uid_claim`` setting (by default, the ``uidNumber`` claim).

``X-Auth-Request-Groups``
    If the token lists groups in an ``isMemberOf`` claim, the names of the groups will be returned, comma-separated, in this header.

``X-Auth-Request-Token``
    If enabled, the encoded token will be sent.

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

A JWKS for the Gafaelfawr token issuer is available via the ``/.well-known/jwks.json`` route.
An application may use that URL to retrieve the public key of Gafaelfawr and use it to verify the token signature.

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

Example
-------

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
