.. _openid-connect:

##########################
Configuring OpenID Connect
##########################

Configure Gafaelfawr
====================

To protect a service that uses OpenID Connect, first set ``oidcServer.enabled`` to true in the :ref:`helm-settings`.
Then, create (or add to, if already existing) an ``oidc-server-secrets`` secret for the ``gafaelfawr`` Phalanx application.

The value of the secret must be a JSON list, with each list member representing one OpenID Connect client.
Each list member must be an object with two keys: ``id`` and ``secret``.
``id`` is the unique OpenID Connect client ID that the client will present during authentication.
``secret`` should be a randomly-generated secret that the client will use to authenticate.

Configure the OpenID client
===========================

Gafaelfawr exposes the standard OpenID Connect configuration information at ``/.well-known/openid-configuration``.
Clients that can auto-discover their configuration from that may only need to be configured with the client ID and secret matching the Gafaelfawr configuration.

For clients that require more manual configuration, the OpenID Connect routes are:

- Authorization endpoint: ``/auth/openid/login``.
- Token endpoint: ``/auth/openid/token``.
- userinfo endpoint: ``/auth/openid/userinfo``.
- JWKS endpoint: ``/.well-known/jwks.json``.

As with any other protected service, the client must run on the same URL host as Gafaelfawr.
These endpoints are all at that shared host (and should be specified using ``https``).

The client must use the authentication code OpenID Connect flow (see `OpenID Connect Core 1.0 section 3.1 <https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth>`__).
The other authentication flows are not supported.

OpenID scopes
-------------

The following OpenID Connect scopes are supported and influence what claims are included in the ID token:

``openid``
    Required, per the OpenID Connect specification.
    The standard OAuth 2.0 and OpenID Connect claims will be included, as well as ``scope`` and ``sub``.
    For the Gafaelfawr OpenID Connect provider, ``sub`` will always be the user's username.

``profile``
    Adds ``preferred_username``, with the same value as ``sub``, and, if this information is available, ``name``.
    Gafaelfawr by design does not support attempting to break the name into components such as given name or family name.

``email``
    Adds the ``email`` claim if the user's email address is known.

``rubin``
    Adds the ``data_rights`` claim with a space-separated list of data releases the user has access to, if there are any.
    See :ref:`helm-oidc-server` for details on how to configure a mapping from group memberships to data releases.
    For more information about how this scope is used, see :dmtn:`253`.

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
Gafaelfawr does not always have an email address for a user.

Open Distro for Elasticsearch
-----------------------------

Assuming that Gafaelfawr and Open Distro for Elasticsearch are deployed on the host ``example.com``, here are the settings required to configure `Open Distro for Elasticsearch <https://opendistro.github.io/for-elasticsearch-docs/docs/security/configuration/openid-connect/>`__:

* ``opendistro_security.auth.type``: ``openid``
* ``opendistro_security.openid.connect_url``: ``https://example.com/.well-known/openid-configuration``
* ``opendistro_security.openid.client_id``: ``kibana-client-id``
* ``opendistro_security.openid.client_secret``: ``fb7518beb61d27aaf20675d62778dea9``
* ``opendistro_security.openid.scope``: ``openid``
* ``opendistro_security.openid.logout_url``: ``https://example.com/logout``
