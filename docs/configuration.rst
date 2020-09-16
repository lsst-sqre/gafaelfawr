######################
Configuration settings
######################

Gafaelfawr uses `pydantic`_ for configuration, so configuration settings can be provided in a large number of ways.
The recommended approach is to use a YAML file.
By default, the file ``/etc/gafaelfawr/gafaelfawr.yaml`` is loaded as configuration settings.
This path can be overridden via the ``--settings`` option to the ``gafaelfawr run`` command.

.. _pydantic: https://pydantic-docs.helpmanual.io/

When configuring Gafaelfawr to run in Kubernetes, consider defining your settings as the value of a ``gafaelfawr.yaml`` key in a config map, and then mounting that config map at ``/etc/gafaelfawr`` in the pod.

See the `pydantic`_ documentation for more details, including how to override specific settings with environment variables.

.. _settings:

Settings
========

Some settings are nested, in which case the parent setting takes a dict value.
The description of that setting will specify whether there is a fixed set of child keys for related settings, or a more general collection of key/value pairs.

All secrets are given in the form of a file path.
The secret is the contents of the file.
Any leading or trailing whitespace in the file will be removed.
Secrets beginning or ending in whitespace are not supported.

``realm`` (required)
    The authentication realm indicated in the ``WWW-Authenticate`` header returned as part of a 401 error when a user is not already authenticated.

``loglevel`` (optional)
    The Python log level to use, in string form.

``session_secret_file`` (required)
    File containing the secret used to encrypt the Gafaelfawr session cookie and the Redis session storage.
    Must be a Fernet key generated with :py:meth:`cryptography.fernet.Fernet.generate_key`.

``redis_url`` (required)
    URL for a Redis instance that will be used to store authentication sessions and user-issued tokens.

``redis_password_file`` (optional)
    File containing the password to use to connect to Redis.
    If not set, Gafaelfawr will assume that Redis does not require authentication.

``proxies`` (optional)
    List of IPs or network ranges (in CIDR notation) that should be assumed to be upstream proxies.
    Gafaelfawr by default uses the last address in an ``X-Forwarded-For`` header, if present, as the IP address of the client for logging purposes.
    If this configuration option is set, the right-most IP address in ``X-Forwarded-For`` that does not match one of the IPs or network ranges given in this option will be used as the client IP address for logging purposes.
    If all IP addresses in ``X-Forwarded-For`` match entries in this list, the left-most will be logged as the client IP address.
    See :ref:`client-ips` for more information.

``after_logout_url`` (required)
    URL to which to send the user after logout via the ``/logout`` route, if no destination URL was specified with the ``rd`` parameter.
    Normally this should be set to some top-level landing page for the protected applications.

``issuer`` (required)
    Configure the JWT issuer.

    ``iss`` (required)
        The value to use for the ``iss`` claim in issued JWTs.
        Should support either the ``/.well-known/openid-configuration`` or ``/.well-known/jwks.json`` routes to get public key information.
        Gafaelfawr will provide the ``/.well-known/jwks.json`` route internally.

    ``key_id`` (required)
        JWT ``kid`` to use when signing tokens.

    ``aud`` (required)
        Values for the ``aud`` claim in issued JWTs.
        By convention these should be URLs.
        Must have the following keys.

        ``default`` (required)
            The default ``aud`` claim.

        ``internal`` (required)
            The internal ``aud`` claim, used instead of ``default`` if the ``audience`` GET parameter to the ``/auth`` route is set and its value matches the value of this key.

    ``key_file`` (required)
        File containing the RSA private key (in PEM encoding) to use for signing JWTs.

    ``exp_minutes`` (optional, default 1440)
        The expiration period of newly-issued JWTs, in minutes.
        The default is one day.

    ``influxdb_secret_file`` (optional)
        File containing the shared secret for issuing InfluxDB tokens.
        If not set, issuance of InfluxDB tokens will be disabled.

    ``influxdb_username`` (optional)
        If set, force the username in all InfluxDB tokens to this value rather than the authenticated username of the user requesting a token.

``github`` (optional)
    Configure GitHub authentication.
    Users who go to the ``/login`` route will be sent to GitHub for authentication, and their token created based on their GitHub user metadata.

    ``client_id`` (required)
        The GitHub OAuth client ID.

    ``client_secret_file`` (required)
        File containing the GitHub OAuth client secret.

``oidc`` (optional)
    Configure OpenID Connect authentication.
    Users who go to the ``/login`` route will be sent to an OpenID Connect provider for authentication.
    Their token will then be reissued based on the token issued by the OpenID Connect provider.
    This support has only been tested with CILogon.

    ``client_id`` (required)
        The client ID registered with the OpenID Connect provider.

    ``client_secret_file`` (required)
        File containing the client secret registered with the OpenID Connect provider, used to retrieve the ID token for the user after authentication.

    ``login_url`` (required)
        The URL at the OpenID Connect provider to which to send the user to initiate authentication.

    ``login_params`` (optional)
        Additional parameters, as a dict, to send in the login URL.

    ``redirect_url`` (required)
        The URL to which the OpenID Connect provider should send the user after successful authentication.
        This must be the full URL of the ``/login`` route of Gafaelfawr.

    ``token_url`` (required)
        The URL at the OpenID Connect provider from which to request an ID token after authentication.

    ``scopes`` (optional)
        Scopes to request from the OpenID Connect provider.  The ``openid`` scope will be added automatically and does not need to be specified.

    ``issuer`` (required)
        The ``iss`` claim value for JWTs signed by the OpenID Connect provider.
        Must support either the ``/.well-known/openid-configuration`` or ``/.well-known/jwks.json`` routes to get public key information.

    ``audience`` (required)
        The ``aud`` claim value for JWTs signed by the OpenID Connect provider.

    ``key_ids`` (optional)
        Supported ``kid`` values for this issuer.
        If given, only JWTs signed by one of the ``kid`` values listed in this configuration key will be verified and all others will be rejected.
        If omitted, any ``kid`` value matching a key that can be retrieved from the OpenID Connect provider's JWKS URL will be accepted.

``oidc_server_secrets_file`` (optional)
    File defining the clients allowed to use Gafaelfawr as an OpenID Connect server.
    The contents of this file must be a list of objects in JSON format.
    Each object in the list must have two keys: ``id`` and ``secret``.
    ``id`` is the value sent by an OpenID Connect client as the ``client_id``.
    ``secret`` is the corresponding ``client_secret`` value for that client.
    See :ref:`openid-connect` for more details.

``known_scopes`` (optional)
    A dict whose keys are known scope names and whose values are human-language descriptions of that scope.
    Used only to construct the web page where a user can create a new API token with a specific set of scopes.

``group_mapping`` (optional)
    A dict whose keys are names of scopes and whose values are lists of names of groups (as found in the ``name`` attribute of the values of an ``isMemberOf`` claim in a JWT).
    When a JWT from an external issuer is reissued with the native JWT issuer, a ``scope`` claim will be added.
    The value of this claim will be all scopes for which the user is a member (according to the ``isMemberOf`` claim) of at least one of the corresponding groups.
    For example, given a configuration like:

    .. code-block:: yaml

       group_mapping:
           "admin": ["foo", "bar"]

    and a token claim of:

    .. code-block:: json

       {"isMemberOf": [{"name": "other"}, {"name": "bar"}]}

    a ``scope`` claim of ``admin`` will be added to a reissued token.

    This setting will also be used for authorization checking in the ``/auth`` route.
    Any scope claims constructed from the group membership will be added to a ``scope`` claim present in the JWT before checking if the user has an appropriate scope to be allowed access to the underlying route.

    If GitHub authentication is in use, a user's groups will be based on their GitHub team memberships.
    See :ref:`github-groups` for more information.

``username_claim`` (optional, default ``uid``)
    The token claim to use as the authenticated user's username.

``uid_claim`` (optional, defualt ``uidNumber``)
    The token claim to use as the authenticated user's UID.

Examples
========

See `gafaelfawr-github.yaml <https://github.com/lsst-sqre/gafaelfawr/blob/master/examples/gafaelfawr-github.yaml>`__ and `gafaelfawr-oidc.yaml <https://github.com/lsst-sqre/gafaelfawr/blob/master/examples/gafaelfawr-oidc.yaml>`__ for example configuration files.
The first configures GitHub authentication.
The second OpenID Connect.

See `gafaelfawr-dev.yaml <https://github.com/lsst-sqre/gafaelfawr/blob/master/examples/gafaelfawr-dev.yaml>`__ for a configuration file designed for a development server running on localhost.
**WARNING**: Do not use this configuration for anything other than a local development server.
It contains published secrets available to anyone on the Internet.
