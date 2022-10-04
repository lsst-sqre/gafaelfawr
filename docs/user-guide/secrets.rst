.. _vault-secrets:

#############
Vault secrets
#############

Gafaelfawr uses secrets stored in `Vault`_ and uses `Vault Secrets Operator`_ to materialize those secrets in Kubernetes.
The Phalanx installer expects a Vault secret named ``gafaelfawr`` in the relevant Science Platform environment containing the following keys:

``bootstrap-token``
    A Gafaelfawr token created with ``gafaelfawr generate-token`` (:doc:`CLI command <cli>`).
    Used to create service tokens, initialize admins, and do other privileged operations.
    See :ref:`bootstrapping` for more information.

``cilogon-client-secret``
    The CILogon secret, obtained during client registration as described above.
    This is only required if you're using CILogon for authentication.

``database-password``
    The password to use for the PostgreSQL database.
    This should be set to a long, randomly-generated alphanumeric string.

``github-client-secret`` (optional)
    The GitHub secret, obtained when creating the OAuth App as described above.
    This is only required if you're using GitHub for authentication.

``ldap-password`` (optional)
    The password used for simple binds to the LDAP server used as a source of data about users.
    Only used if LDAP lookups are enabled.
    See :ref:`ldap-groups` for more information.

``oidc-client-secret`` (optional)
    The secret for an OpenID Connect authentication provider.
    This is only required if you're using generic OpenID Connect for authentication.

``oidc-server-secrets`` (optional)
    Only used if the Helm chart parameter ``config.oidcServer.enabled`` is set to true.
    The JSON representation of the OpenID Connect clients.
    Must be a JSON list of objects, each of which must have ``id`` and ``secret`` keys corresponding to the ``client_id`` and ``client_secret`` parameters sent by OpenID Connect clients.
    See :ref:`openid-connect` for more information.

``redis-password``
    The password to use for Redis authentication.
    This should be set to a long, randomly-generated alphanumeric string.

``session-secret``
    Encryption key for the Gafaelfawr session cookie.
    Generate with ``gafaelfawr generate-session-secret`` (:doc:`CLI command <cli>`).

``signing-key`` (optional)
    Only used if the Helm chart parameter ``config.oidcServer.enabled`` is set to true.
    The PEM-encoded RSA private key used to sign internally-issued JWTs.
    Generate with ``gafaelfawr generate-key`` (:doc:`CLI command <cli>`).

``slack-webhook`` (optional)
    Only used if the Helm chart parameter ``config.slackAlerts`` is set to true.
    The Slack incoming webhook URL to which to post alerts.
    See :ref:`slack-alerts` for more information.
