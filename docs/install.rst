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
To get these values, go to Settings → Developer Settings for either a GitHub user or an organization, go into OAuth Apps, and create a new application.
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
   For example: ``https://lsp-instance.example.com``
5. Enter the ``/login`` route as the callback URL.
   For example: ``https://lsp-instance.example.com/login``
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
To use that chart, you will need to provide a ``values.yaml`` file with the following keys.

``affinity`` (optional)
    Affinity configuration for the Gafaelfawr pod.

``config.cilogon.clientId``
    The client ID for CILogon if using CILogon as the identity provider.
    Only set either this or ``config.github.clientId``.

``config.cilogon.redirectUrl`` (optional)
    The full redirect URL for CILogon if using CILogon as the identity provider.
    Set this if you need to change the redirect URL to the ``/oauth2/callback`` route instead of the ``/login`` route.

``config.cilogon.loginParams`` (optional)
    A mapping of additional parameters to send to the CILogon authorize route.
    Can be used to set parameters like ``skin`` or ``selected_idp``.
    See the `CILogon OIDC documentation <https://www.cilogon.org/oidc>`__ for more information.

``config.host`` (required)
    The FQDN of the host under which Gafaelfawr is running.
    This setting will be used to derive multiple other URLs, such as the issuer.

``config.github.clientId``
    The client ID for the GitHub OAuth App if using GitHub as the identity provider.
    Only set either this or ``cilogon.client_id``.

``config.groupMapping`` (required)
    Mapping of scope names to lists of groups that provide that scope.
    When GitHub is used as the provider, group membership will be synthesized from GitHub team membership.
    See :ref:`github-groups` for more information.
    When an OpenID Connect provider such as CILogon is used as the provider, group membership will be taken from the ``isMemberOf`` claim of the token returned by the provider.
    This must be set to have a reasonably usable system.

``config.issuer.expMinutes`` (optional)
    The lifetime (in minutes) of the issued JWTs and thus the user's authentication session.
    The default is 1440 (one day).

``config.issuer.influxdb.enabled`` (optional)
    Whether to enable InfluxDB token issuance.
    If this is set to true, the Vault secret for Gafaelfawr must contain an ``influxdb-secret`` key.

``config.issuer.influxdb.username`` (optional)
    If set, force the username in all InfluxDB tokens to this value rather than the authenticated username of the user requesting a token.
    Only applicable if InfluxDB token issuance is enabled.

``config.knownScopes``
    Mapping of scope names to descriptions.
    This is used to populate the new token creation page.
    It is copied directly to the ``known_scopes`` configuration setting documented in :ref:`settings`.
    The ``admin:token`` and ``user:token`` scopes used internally by Gafaelfawr for token administrators must be included.
    The default list of known scopes are those used by the Rubin Science Platform components.

``config.kubernetes.service_secrets`` (optional)
    A list of Kubernetes secrets that Gafaelfawr should manage.
    These secrets will be used to store service tokens.
    See :ref:`kubernetes-service-secrets` for more information.
    Each element of the list should have the following keys:

    ``secretName``
        The name of the secret.

    ``secretNamespace``
        The namespace in which to put the secret.

    ``service``
        The name of the service for which to create a token.

    ``scopes`` (optional)
        A list of scopes the token should have.
        If not provided, the token will have no scopes.

``config.loglevel`` (optional)
    The Python logging level.
    Set to one of the (all-caps) string log level values from the Python :py:mod:`logging` module.

``config.oidcServer.enabled``
    Set this to true to enable the OpenID Connect server.
    If this is set to true, the Vault secret for Gafaelfawr must contain a ``oidc-server-secrets`` key.

``config.proxies`` (optional)
    A list of network blocks that should be treated as internal to the cluster and therefore ignored when analyzing ``X-Forwarded-For`` to find the true client IP.
    If not set, defaults to the `RFC 1918 private address spaces <https://tools.ietf.org/html/rfc1918>`__.
    See :ref:`client-ips` and the ``proxies`` documentation in :ref:`settings` for more information.

``fullnameOverride`` (optional)
    Override the chart name used to name resources.

``image.pullPolicy`` (optional)
    The pull policy to use for the Docker image.
    Defaults to ``IfNotPresent``.

``image.repository`` (optional)
    The name of the Docker repository from which to pull an image.
    Defaults to the official release repository.

``image.tag`` (optional)
    The version of image to use.
    If not set, defaults to the image corresponding to the ``appVersion`` metadata property of the chart, which is normally the latest stable release.

``imagePullSecrets`` (optional)
    A list of Kubernetes secret names used as Docker secrets when pulling images.

``ingress.enabled`` (optional)
    Whether to define an ingress for Gafaelfawr.
    Defaults to true.

``ingress.annotations`` (optional)
    Additional annotations to add to the ingress definition.

``ingress.host`` (optional)
    The host-based virtual host under which to create the ingress routes.
    Normally this should be set to the same thing as ``config.host``.
    However, you may wish to leave it unset if you want all routes to be configured with the ``*`` virtual host.
    The ``/auth``, ``/login``, ``/logout``, ``/oauth2/callback``, and ``/.well-known/jwks.json`` routes will be claimed under this host by the Gafaelfawr ingress configuration.
    If ``oidcServer.enabled`` is set to true, the ``/.well-known/openid-configuration`` will also be claimed.

``ingress.tls`` (optional)
    TLS configuration for the ingress.
    If multiple ingresses share the same hostname, only one of them needs TLS configuration.

``nameOverride`` (optional)
    Override the chart name used in ``app.kubernetes.io/name`` annotations.

``nodeSelector`` (optional)
    Kubernetes node selector for where to locate the Gafaelfawr pod.

``podAnnotations`` (optional)
    Additional annotations to attach to the Gafaelfawr pod.

``replicaCount`` (optional)
    How many instances of Gafaelfawr to spawn.
    Defaults to 1.

``redis.affinity`` (optional)
    Affinity configuration for the Gafaelfawr Redis pod.

``redis.image.repository`` (optional)
    The repository from which to get Redis images.
    Defaults to ``redis`` (at Docker Hub).

``redis.image.tag`` (optional)
    The Redis image to use.

``redis.image.pullPolicy`` (optional)
    The Kubernetes pull policy to use for the Redis image.
    Defaults to ``IfNotPresent``

``redis.nodeSelector`` (optional)
    Node selection criteria for the Gafaelfawr Redis pod.

``redis.persistence.enabled`` (optional)
    Whether to enable persistent volumes for Redis.
    If set to true, dynamic provisioning will be used for a persistent volume store for Redis, using the other configuration options below, unless ``redis.persistence.volumeClaimName`` is set.
    If set to false, Redis will use ``emptyDir``, which is ephemeral storage that will be cleared on every pod restart (thus invalidating all user authentication sessions and user-issued tokens).
    This setting is only suitable for testing and development.
    Defaults to true.

``redis.persistence.size`` (optional)
    The size of persistent volume to request.
    Defaults to ``1Gi`` (1 GiB).

``redis.persistence.storageClass`` (optional)
    The storage class of persistent volume to request.
    Defaults to the empty string, which will use the default storage class.

``redis.persistence.accessMode`` (optional)
    The access mode of persistent volume to request.
    Defaults to ``ReadWriteOnce``.

``redis.persistence.volumeClaimName`` (optional)
    The name of a persistent volume claim to use for Redis storage.
    This overrides any other persistence settings except ``redis.persistence.enabled`` and uses an existing ``PersistentVolumeClaim`` by name.
    That ``PersistentVolumeClaim`` must be created and managed outside of the Gafaelfawr chart.

``redis.podAnnotations`` (optional)
    Pod annotations for the Gafaelfawr Redis pod.

``redis.tolerations`` (optional)
    List of tolerations for the Gafaelfawr Redis pod.

``resources`` (optional)
    Resource requests and limits for the Gafaelfawr container.

``tolerations`` (optional)
    List of tolerations for the Gafaelfawr pod.

``vaultSecretsPath`` (required)
    The path in Vault for the Vault secret containing the secret keys described in :ref:`vault-secrets`.

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
