.. _openid-connect:

##########################
Configuring OpenID Connect
##########################

Configure Gafaelfawr
====================

To protect a service that uses OpenID Connect, first set ``oidcServer.enabled`` to true in the :ref:`helm-settings`.
Then, create (or add to, if already existing) an ``oidc-server-secrets`` secret for the ``gafaelfawr`` Phalanx application.

The value of the secret must be a JSON list, with each list member representing one OpenID Connect client.
Each list member must be an object with the following keys:

``id``
    The unique OpenID Connect client ID (the ``client_id`` parameter in the OpenID Connect protocol) that the client will present during authentication.

``secret``
    A randomly-generated secret that the client will use to authenticate via the ``client_secret`` POST parameter.

``return_uri``
    The acceptable return URL for this client.
    The actual return URL (the ``redirect_uri`` parameter) of any authentication must exactly match this return URL except for query parameters and fragments.
    The path portion of this URL may not contain semicolons (``;``) to avoid potentially confusing parsing as either part of the path or as path parameters.

Configure the OpenID client
===========================

Gafaelfawr exposes the standard OpenID Connect configuration information at ``/.well-known/openid-configuration``.
Clients that can auto-discover their configuration from that may only need to be configured with the client ID and secret matching the Gafaelfawr configuration.

For clients that require more manual configuration, the OpenID Connect routes are:

- Authorization endpoint: ``/auth/openid/login``.
- Token endpoint: ``/auth/openid/token``.
- userinfo endpoint: ``/auth/openid/userinfo``.
- JWKS endpoint: ``/.well-known/jwks.json``.

The hostname for those routes is whatever host Gafaelfawr itself is configured to use.
(Generally this will be the default domain of the Phalanx cluster.)

The client must use the authentication code OpenID Connect flow (see `OpenID Connect Core 1.0 section 3.1 <https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth>`__).
The other authentication flows are not supported.

The authentication methods ``client_secret_basic`` and ``client_secret_post`` are supported.
Gafaelfawr does not register a specific authentication method for a client and supports either authentication method for any client.

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
The ``return_uri`` value for this entry in the ``oidc-server-secrets`` Vault key should be set to the ``PUBLIC_URL`` value above with ``/oauth/OIDC/callback`` appended.

Be aware that this uses the ``sub`` token claim, which corresponds to the user's username, for authentication, rather than the default of the user's email address.
Gafaelfawr does not always have an email address for a user.
