.. _openid-connect:

##########################
Configuring OpenID Connect
##########################

Basic configuration
===================

To protect a service that uses OpenID Connect, first set ``oidc_server.enabled`` to true in the :ref:`helm-settings`.
Then, create (or add to, if already existing) an ``oidc-server-secrets`` Vault secret key.
The value of the key must be a JSON list, with each list member representing one OpenID Connect client.
Each list member must be an object with two keys: ``id`` and ``secret``.
``id`` can be anything informative that you want to use to uniquely represent this OpenID Connect client.
``secret`` should be a randomly-generated secret that the client will use to authenticate.

Then, configure the client.
The authorization endpoint is ``/auth/openid/login``.
The token endpoint is ``/auth/openid/token``.
The userinfo endpoint is ``/auth/openid/userinfo``.
The JWKS endpoing is ``/.well-known/jwks.json``.
As with any other protected service, the client must run on the same URL host as Gafaelfawr, and these endpoints are all at that shared host (and should be specified using ``https``).

The OpenID Connect client should be configured to request only the ``openid`` scope.
No other scope is supported.
The client must be able to authenticate by sending a ``client_secret`` parameter in the request to the token endpoint.

The JWT returned by the Gafaelfawr OpenID Connect server will include the authenticated username in the ``sub`` and ``preferred_username`` claims, and the numeric UID in the ``uid_number`` claim.

Examples
========

Chronograf
----------

Assuming that Gafaelfawr and Chronograf are deployed on the host ``example.com`` and Chronograf is at the URL ``/chronograf``, here are the environment variables required to configure `Chronograf <https://docs.influxdata.com/chronograf/v1/administration/managing-security/#configure-chronograf-to-use-any-oauth-20-provider>`__:

* ``GENERIC_CLIENT_ID``: ``chronograf-client-id``
* ``GENERIC_CLIENT_SECRET``: ``fb7518beb61d27aaf20675d62778dea9``
* ``GENERIC_AUTH_URL``: ``https://example.com/auth/openid/login``
* ``GENERIC_TOKEN_URL``: ``https://example.com/auth/openid/token``
* ``USE_ID_TOKEN``: 1
* ``JWKS_URL``: ``https://example.com/.well-known/jwks.json``
* ``GENERIC_API_URL``: ``https://example.com/auth/openid/userinfo``
* ``GENERIC_API_KEY``: ``sub``
* ``GENERIC_SCOPES``: ``openid``
* ``PUBLIC_URL``: ``https://example.com/chronograf``
* ``TOKEN_SECRET``: ``pCY29u3qMTdWCNetOUD3OShsqwPm+pYKDNt6dqy01qw=``

``GENERIC_CLIENT_ID`` and ``GENERIC_CLIENT_SECRET`` should match a client ID and secret configured in the ``oidc-server-secrets`` Vault key.

Be aware that this uses the ``sub`` token claim, which corresponds to the user's username, for authentication, rather than the default of the user's email address.
(Gafaelfawr does not always have an email address for a user.)

Open Distro for Elasticsearch
-----------------------------

Assuming that Gafaelfawr and Open Distro for Elasticsearch are deployed on the host ``example.com``, here are the settings required to configure `Open Distro for Elasticsearch <https://opendistro.github.io/for-elasticsearch-docs/docs/security/configuration/openid-connect/>`__:

* ``opendistro_security.auth.type``: ``openid``
* ``opendistro_security.openid.connect_url``: ``https://example.com/.well-known/openid-configuration``
* ``opendistro_security.openid.client_id``: ``kibana-client-id``
* ``opendistro_security.openid.client_secret``: ``fb7518beb61d27aaf20675d62778dea9``
* ``opendistro_security.openid.scope``: ``openid``
* ``opendistro_security.openid.logout_url``: ``https://example.com/logout``
