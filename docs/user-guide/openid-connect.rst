.. _openid-connect:

##########################
Configuring OpenID Connect
##########################

Configure Gafaelfawr
====================

To protect a service that uses OpenID Connect, first set ``oidcServer.enabled`` to true.
For more details on the available settings, see :ref:`helm-oidc-server`.

Then, register one or more OpenID Connect clients.

.. _openid-connect-register:

Register an OpenID Connect client
=================================

Clients are registered via ``POST`` of a JSON object to the ``/auth/api/v1/oidc-clients`` route.
OpenID Connect server support must be enabled for that route to be available.
The token or cookie used to authenticate to this route must have the ``admin:oidc`` scope.

The body of the registration request contains the following fields:

``return_uri``
    The acceptable return URL for this client.
    The actual return URL (the ``redirect_uri`` parameter) of any authentication must exactly match this return URL except for query parameters and fragments.
    The path portion of this URL may not contain semicolons (``;``) to avoid potentially confusing parsing as either part of the path or as path parameters.

``description``
    A human-readable, free-form description of this client.
    This is the primary identification for how this client will be used (the client identifier is randomly generated), so provide enough information to help someone reviewing OpenID Connect clients several years in the future.

``notes`` (optional)
    Additional notes about this OpenID Connect client useful for other humans.

On successful registration, the response will contain those fields, creation and last modified information, and two other important fields:

``client_id``
    The identifier this client must use when initiating an OpenID Connect authentication.
    This will also be used as the ``aud`` claim in all ID tokens returned to this client.

``client_secret``
    The secret this client must use to authenticate.
    This secret is not recoverable once the client has been created, since only a hashed version of the secret is kept by Gafaelfawr.
    The caller is responsible for storing this somewhere safe that is suitable for storing authentication secrets.
    If it needs to be changed, the client must be deleted and recreated.

The ``return_uri``, ``description``, and ``notes`` fields can be modified after creation via a ``PATCH`` request, and a client can be deleted via a ``DELETE`` request.
See the :doc:`REST API documentation </api/rest>` for more information.

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

* ``GENERIC_CLIENT_ID``: ``fb7518beb61d27aaf20675d62778dea9.clients.example.com``
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

``GENERIC_CLIENT_ID`` and ``GENERIC_CLIENT_SECRET`` should match a client ID and secret returned when the client was registered (see :ref:`openid-connect-register` above).
The ``PUBLIC_URL`` value must match the ``return_uri`` value registered with the client.

Be aware that this uses the ``sub`` token claim, which corresponds to the user's username, for authentication, rather than the default of the user's email address.
Gafaelfawr does not always have an email address for a user.
