##################
Installation guide
##################

Gafaelfawr was written to run inside a Kubernetes environment.
While there is nothing intrinsic in Gafaelfawr that would prevent it from working in some other environment, only installation on Kubernetes has been documented or tested.

Prerequisites
=============

The `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__ must already be configured and working.
Gafaelfawr expects TLS termination to be done by the ingress controller.

The instructions below assume that you will use Vault_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets as Kubernetes secrets.
The Gafaelfawr Helm chart requires this.

.. _Vault: https://vaultproject.io/
.. _Vault Secrets Operator: https://github.com/ricoberger/vault-secrets-operator

Client configuration
====================

GitHub
------

If you will be using GitHub as the authentication provider, you will need to create a GitHub OAuth app for Gafaelfawr and obtain a client ID and secret.
To get these values, go to Settings > Developer Settings for either a GitHub user or an organization, go into OAuth Apps, and create a new application.
The callback URL should be the ``/login`` route under the hostname you will use for your Gafaelfawr deployment.

CILogon
-------

If you will use CILogon as the authentication provider, you will need to register with CILogon to get a client ID and secret.

1. Go to the `registration page <https://cilogon.org/oauth2/register>`__.
2. Enter the client name.
   For Rubin Observatory deployments, include "Rubin Observatory LSP" in the name.
3. Enter the contact email.
   You will be notified at this email when the client is registered.
4. Enter the top page of the LSP deployment as the home URL.
   For example: ``https://lsst-lsp-instance.example.com``
5. Enter the ``/login`` route as the callback URL.
   For example: ``https://lsst-lsp-instance.example.com/login``
6. Leave the public client box unchecked.
7. Select the following scopes:
   - email
   - org.cilogin.userinfo
   - profile
   You will need some additional custom configuration, but you will have to request that via email since it isn't available on the registration page.
8. Enter one day (86400 seconds) as the refresh token lifetime.

Submit that information.
You will get a client ID and secret.
This will not work immediately; you will need to wait for the CILogon team to register the client.

After you have gotten email confirming that your client has been registered, reply to that email and request that the client configuration be copied from the client ``cilogon:/client_id/6ca7b54ac075b65bccb9c885f9ba4a75``.
This will add the scope that releases group and UID information from LDAP.

.. _vault-secrets:

Vault secrets
=============

The standard Helm chart for Gafaelfawr (described below) assumes that you will use `Vault`_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets in Kubernetes.
If you are using it, create a Vault secret with the following keys:

``cilogon-client-secret``
    The CILogon secret, obtained during client registration as described above.
    This is not required if you are using GitHub authentication.

``github-client-secret``
    The GitHub secret, obtained when creating the OAuth App as described above.
    This is not required if you are using CILogin authentication.

``influxdb-secret`` (optional)
    The shared secret to use for issuing InfluxDB tokens.
    See :ref:`influxdb` for more information.

``oidc-server-secrets`` (optional)
    Only used if the Helm chart parameter ``oidc_server.enabled`` is set to true.
    The JSON representation of the OpenID Connect clients.
    Must be a JSON list of objects, each of which must have ``id`` and ``secret`` keys corresponding to the ``client_id`` and ``client_secret`` parameters sent by OpenID Connect clients.
    See :ref:`openid-connect` for more information.

``redis-password``
    The password to use for Redis authentication.
    This should be set to a long, randomly-generated alphanumeric string.

``session-secret``
    Encryption key for the Gafaelfawr session cookie.
    Generate with :py:meth:`cryptography.fernet.Fernet.generate_key`.

``signing-key``
    The PEM-encoded RSA private key used to sign internally-issued JWTs.
    Generate with ``gafaelfawr generate-key``.

You will reference the path to this secret in Vault when configuring the Helm chart later.

If you are not using the standard Helm chart, you can use Kubernetes secrets directly or use Vault secrets with a different naming or organization.
You will specify the paths to the secrets in the Gafaelfawr configuration, as documented at :ref:`settings`.

.. _helm-settings:

Helm deployment
===============

There is a Helm chart for Gafaelfawr named ``gafaelfawr`` available from the `Rubin Observatory charts repository <https://lsst-sqre.github.io/charts/>`__.
The Helm chart only supports GitHub or CILogon as identity providers.
To use that chart, you will need to provide a ``values.yaml`` file with the following keys under a ``gafaelfawr`` key:

``host`` (required)
    The FQDN of the host under which Gafaelfawr is running.
    The ``/auth``, ``/login``, ``/logout``, ``/oauth2/callback``, and ``/.well-known/jwks.json`` routes will be claimed under this host by the Gafaelfawr ingress configuration.
    If ``oidc_server.enabled`` is set to true, the ``/.well-known/openid-configuration`` will also be claimed.
    This setting will be used to derive multiple other URLs, such as the issuer.

``ingress.host`` (optional)
    The host-based virtual host under which to create the ingress routes.
    Normally this should be set to the same thing as ``host``.
    However, you may wish to leave it unset if you want all routes to be configured with the ``*`` virtual host.

``image`` (optional)
    The Docker image to use for the Gafaelfawr application.
    Takes the following subkeys:

    ``repository`` (optional)
        The name of the Docker repository from which to pull an image.
        Defaults to the official release repository.

    ``tag`` (optional)
        The version of image to use.
        If not set, defaults to the image corresponding to the ``appVersion`` metadata property of the chart, which is normally the latest stable release.

    ``pullPolicy`` (optional)
        Kubernetes pull policy for the image.
        Defaults to ``Always``.

``redis_claim`` (optional)
    The name of a persistent volume claim to use for Redis storage.
    If not given, Redis will use ``emptyDir``, which is ephemeral storage that will be cleared on every pod restart (thus invalidating all user authentication sessions and user-issued tokens).

``vault_secrets_path`` (required)
    The path in Vault for the Vault secret containing the secret keys described in :ref:`vault-secrets`.

``proxies`` (optional)
    A list of network blocks that should be treated as internal to the cluster and therefore ignored when analyzing ``X-Forwarded-For`` to find the true client IP.
    If not set, defaults to the `RFC 1918 private address spaces <https://tools.ietf.org/html/rfc1918>`__.
    See :ref:`client-ips` and the ``proxies`` documentation in :ref:`settings` for more information.

``loglevel`` (optional)
    The Python logging level.
    Set to one of the (all-caps) string log level values from the Python :py:mod:`logging` module.

``issuer.exp_minutes`` (optional)
    The lifetime (in minutes) of the issued JWTs and thus the user's authentication session.
    The default is 1440 (one day).

``issuer.influxdb.enabled`` (optional)
    Whether to enable InfluxDB token issuance.
    If this is set to true, the Vault secret for Gafaelfawr must contain an ``influxdb-secret`` key.

``issuer.influxdb.username`` (optional)
    If set, force the username in all InfluxDB tokens to this value rather than the authenticated username of the user requesting a token.
    Only applicable if InfluxDB token issuance is enabled.

``github.client_id``
    The client ID for the GitHub OAuth App if using GitHub as the identity provider.
    Only set either this or ``cilogon.client_id``.

``cilogon.client_id``
    The client ID for CILogon if using CILogon as the identity provider.
    Only set either this or ``github.client_id``.

``cilogon.redirect_url``
    The full redirect URL for CILogon if using CILogon as the identity provider.
    Set this if you need to change the redirect URL to the ``/oauth2/callback`` route instead of the ``/login`` route.

``cilogon.login_params``
    A mapping of additional parameters to send to the CILogon authorize route.
    Can be used to set parameters like ``skin`` or ``selected_idp``.
    See the `CILogon OIDC documentation <https://www.cilogon.org/oidc>`__ for more information.

``oidc_server.enabled``
    Set this to true to enable the OpenID Connect server.
    If this is set to true, the Vault secret for Gafaelfawr must contain a ``oidc-server-secrets`` key.

``known_scopes``
    Mapping of scope names to descriptions.
    This is used to populate the new token creation page.
    It is copied directly to the ``known_scopes`` configuration setting documented in :ref:`settings`.
    The ``admin:token`` scope used internally by Gafaelfawr for token administrators must be included.

``group_mapping``
    Mapping of scope names to lists of groups that provide that scope.
    When GitHub is used as the provider, group membership will be synthesized from GitHub team membership.
    See :ref:`github-groups` for more information.
    When an OpenID Connect provider such as CILogon is used as the provider, group membership will be taken from the ``isMemberOf`` claim of the token returned by the provider.

``kubernetes`` (optional)
    Configuration for Gafaelfawr's Kubernetes secret management support.

    ``service_secrets``
        A list of Kubernetes secrets that Gafaelfawr should manage.
        These secrets will be used to store service tokens.
        See :ref:`kubernetes-service-secrets` for more information.
        Each element of the list should have the following keys:

        ``secret_name``
            The name of the secret.

        ``secret_namespace``
            The namespace in which to put the secret.

        ``service``
            The name of the service for which to create a token.

        ``scopes`` (optional)
            A list of scopes the token should have.
            If not provided, the token will have no scopes.

For an example, see `the configuration for the LSST Science Platform deployments <https://github.com/lsst-sqre/lsp-deploy/blob/master/services/gafaelfawr>`__.

The Helm chart will generate a Gafaelfawr configuration file via a ``ConfigMap`` resource.
See :ref:`settings` if you need to understand that configuration file or fine-tune its settings.

Administrators
==============

Gafaelfawr has a concept of token administrators.
Those users can add and remove other administrators and can create a service or user token for any user.
Currently, this capability is only available via the API, not the UI.

If a username is marked as a token administrator, that user will be automatically granted the ``admin:token`` scope when they authenticate (via either GitHub or OpenID Connect), regardless of their group membership.
They can then choose whether to delegate that scope to any user tokens they create.

The initial set of administrators can be added with the ``initial_admins`` configuration option (see :ref:`settings`) or via the bootstrap token.

Bootstrapping
-------------

Gafaelfawr can be configured with a special token, called the bootstrap token.
This token must be generated with ``gafaelfawr generate-token`` and then set via the ``bootstrap_token`` configuration option (see :ref:`settings`).
It can then be used with API calls as a bearer token in the ``Authenticate`` header.

The bootstrap token acts like the token of a service or user with the ``admin:token`` scope, but can only access specific routes, namely ``/auth/api/v1/tokens`` and those under ``/auth/api/v1/admins``.
