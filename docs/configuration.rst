######################
Configuration settings
######################

JWT Authorizer uses `Dynaconf`_ for configuration, so configuration settings can be provided in a large number of ways.
The recommended approach is to use a YAML file.
By default, the file ``/etc/jwt-authorizer/authorizer.yaml`` is loaded as configuration settings.
This path can be overridden via the ``--settings`` option to the ``jwt_authorizer run`` command.

.. _Dynaconf: https://dynaconf.readthedocs.io/en/latest/

When configuring JWT Authorizer to run in Kubernetes, consider defining your settings as the value of a ``authorizer.yaml`` key in a config map, and then mounting that config map at ``/etc/jwt-authorizer`` in the pod.

See the `Dynaconf`_ documentation for more details, including how to override specific settings with environment variables.

.. _settings:

Settings
========

.. warning::
   The names of these configuration settings will change in a future release.
   Some little-used configuration settings will be deleted.

Some settings are nested, in which case the parent setting takes a dict value.
The description of that setting will specify whether there is a fixed set of child keys for related settings, or a more general collection of key/value pairs.

``realm`` (required)
    The authentication realm indicated in the ``WWW-Authenticate`` header returned as part of a 401 error when a user is not already authenticated.

``www_authenticate`` (optional, default ``Bearer``)
    The type of authentication to request in the ``WWW-Authenticate`` header returned as part of a 401 error.
    Must be either ``Bearer`` or ``Basic``.

``loglevel`` (optional)
    The Python log level to use, in string form.
    This is not currently used.

``no_authorize`` (optional, default ``False``)
    Disable authorization checks.
    Any valid token will be accepted regardless of the requested scopes.

``no_verify`` (optional, default ``False``)
    Disable token verification.
    The signature on the token will not be verified, thus allowing anyone to claim to have any identity and scope.
    Totally insecure, useful only for testing.

``set_user_headers`` (optional, default ``True``)
    On the authentication endpoint, extract the username, email, UID, and group list from the token if available and set headers containing that information for the application that is being authenticated.

``session_secret`` (required)
    The secret used to encrypt the JWT Authorizer session cookie.
    Must be a Fernet key generated with :py:meth:`cryptography.fernet.Fernet.generate_key`.

``jwt_username_key`` (optional, default ``uid``)
    The token claim to use as the authenticated user's username.

``jwt_uid_key`` (optional, defualt ``uidNumber``)
    The token claim to use as the authenticated user's UID.

``github`` (optional)
    Configure GitHub authentication.
    Users who go to the ``/login`` route will be sent to GitHub for authentication, and their token created based on their GitHub user metadata.

    ``client_id`` (required)
        The GitHub OAuth client ID.

    ``client_secret`` (required)
        The GitHub OAuth client secret.
        ``client_secret_file`` may be set instead of ``client_secret``, in which case it specifies the path to a file containing the secret.

``oauth2_store_session`` (required)
    Configure the oauth2_proxy session store.
    Used to create sessions that can be consumed by a patched version of oauth2_proxy.
    These settings must match the oauth2_proxy configuration.

    ``ticket_prefix`` (required)
        The prefix on issued tickets, which must also match the name of the oauth2_proxy session cookie.

    ``redis_url`` (required)
        URL to the Redis used to store encrypted oauth2_proxy sessions and sets of user-issued tokens.

    ``oauth2_proxy_secret`` (required)
        Secret used to encrypt the components of the oauth2_proxy sessions stored in Redis.
        Must match the oauth2_proxy configuration.
        Must be a 256-bit key encoded in URL-safe base64 encoding.
        ``oauth2_proxy_secret_file`` may be set instead of ``oauth2_proxy_secret``, in which case it specifies the path to a file containing the secret.

``oauth2_jwt`` (required)
    Configure the JWT issuer.

    ``iss`` (required)
        The value to use for the ``iss`` claim in issued JWTs.
        Must be a URL, and must support either the ``/.well-known/openid-configuration`` or ``/.well-known/jwks.json`` routes to get public key information.
        Must match an ``issuer`` key whose data matches the rest of these settings.

    ``key_id`` (required)
        JWT ``kid`` to use when signing tokens.
        Must match a member of the ``issuer_key_ids`` list in the corresponding issuer configuration.

    ``aud`` (required)
        Values for the ``aud`` claim in issued JWTs.
        By convention these should be URLs.
        Must have the following keys.

        ``default`` (required)
            The default ``aud`` claim.

        ``internal`` (required)
            The internal ``aud`` claim, used instead of ``default`` if the ``audience`` GET parameter to the ``/auth`` route is set and its value matches the value of this key.

    ``key`` (required)
        The RSA private key (in PEM encoding) to use for signing JWTs.
        ``key_file`` may be set instead of ``key``, in which case it specifies the path to a file containing the key.

``oauth2_jwt_exp`` (optional, default 1440)
    The expiration period of newly-issued JWTs, in minutes.
    The default is one day.

``issuers`` (required)
    Must contain a key matching the ``iss`` claim for all supported JWT issuers, including one for the JWT issuer configured with ``oauth2_jwt``.
    The key must also be a URL that supports either the ``/.well-known/openid-configuration`` or ``/.well-known/jwks.json`` routes to get public key information.
    The following subkeys must be set.

    ``audience`` (required)
        The ``aud`` claim value for JWTs signed with this issuer.
        May either be a single value or a list of possible values.
        For the issuer entry for the JWT issuer configured with ``oauth2_jwt``, list both the default and internal ``aud`` claims.

    ``issuer_key_ids`` (required)
        Supported ``kid`` values for this issuer.
        Only JWTs signed by one of the ``kid`` values listed in this configuration key can be verified.
        All others will be rejected.

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

``known_capabilities`` (optional)
    A dict whose keys are known scope names and whose values are human-language descriptions of that scope.
    Used only to construct the web page where a user can create a new API token with a specific set of scopes.

Examples
========

See `authorizer.yaml <https://github.com/lsst/jwt_authorizer/blob/master/example/authorizer.yaml>`__ for an example configuration file.

See `dev.yaml <https://github.com/lsst/jwt_authorizer/blob/master/example/dev.yaml>`__ for a configuration file designed for a development server running on localhost.
**WARNING**: Do not use this configuration for anything other than a local development server.
It contains published secrets available to anyone on the Internet.
