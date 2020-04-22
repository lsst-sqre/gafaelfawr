#######################
Kubernetes installation
#######################

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

``session-secret``
    Encryption key for the Gafaelfawr session cookie.
    Generate with :py:meth:`cryptography.fernet.Fernet.generate_key`.

``signing-key``
    The PEM-encoded RSA private key used to sign internally-issued JWTs.
    Generate with ``gafaelfawr generate-key``.

You will reference the path to this secret in Vault when configuring the Helm chart later.

If you are not using the standard Helm chart, you can use Kubernetes secrets directly or use Vault secrets with a different naming or organization.
You will specify the paths to the secrets in the Gafaelfawr configuration, as documented at :ref:`settings`.

Helm deployment
===============

There is a Helm chart for Gafaelfawr named ``gafaelfawr`` available from the `Rubin Observatory charts repository <https://lsst-sqre.github.io/charts/>`__.
The Helm chart only supports GitHub or CILogon as identity providers.
To use that chart, you will need to provide a ``values.yaml`` file with the following keys under a ``gafaelfawr`` key:

``host`` (required)
    The FQDN of the host under which Gafaelfawr is running.
    The ``/auth``, ``/login``, ``/oauth2/callback``, and ``/.well-known/jwks.json`` routes will be claimed under this host by the Gafaelfawr ingress configuration.
    This setting will be used to derive multiple other URLs, such as the issuer.

``ingress.host`` (optional)
    The host-based virtual host under which to create the ingress routes.
    Normally this should be set to the same thing as ``host``.
    However, you may wish to leave it unset if you want all routes to be configured with the ``*`` virtual host.

``image`` (optional)
    The Docker image to use for the Gafaelfawr application.
    If not set, defaults to the image corresponding to the ``appVersion`` metadata property of the chart, which is normally the latest stable release.

``redis_claim`` (optional)
    The name of a persistent volume claim to use for Redis storage.
    If not given, Redis will use ``emptyDir``, which is ephemeral storage that will be cleared on every pod restart (thus invalidating all user authentication sessions and user-issued tokens).

``vault_secrets.path`` (required)
    The path in Vault for the Vault secret containing the secret keys described in :ref:`vault-secrets`.

``user_scope`` (required)
    The token scope to require before allowing access to the ``/auth/tokens`` route, which allows the user to issue and revoke their own tokens.

``config.loglevel`` (optional)
    The Python logging level.
    Set to one of the (all-caps) string log level values from the Python :py:mod:`logging` module.

``config.session_length`` (optional)
    The lifetime (in minutes) of the issued JWTs and thus the user's authentication session.
    The default is 1440 (one day).

``config.github.client_id``
    The client ID for the GitHub OAuth App if using GitHub as the identity provider.
    Only set either this or ``cilogon.client_id``.

``config.cilogon.client_id``
    The client ID for CILogon if using CILogon as the identity provider.
    Only set either this or ``github.client_id``.

``config.known_scopes``
    Mapping of scope names to descriptions.
    This is used to populate the new token creation page.
    It is copied directly to the ``known_scopes`` configuration setting documented in :ref:`settings`.

``config.group_mapping``
    Mapping of scope names to lists of groups that provide that scope.
    Tokens from an OpenID Connect provider such as CILogon that include groups in an ``isMemberOf`` claim will be granted scopes based on this mapping.

For an example, see `the configuration for the LSST Science Platform deployments <https://github.com/lsst-sqre/lsp-deploy/blob/master/services/gafaelfawr>`__.

Application configuration
=========================

Protecting a service
--------------------

Authentication and authorization for a service are configured via annotations on the ingress for that service.
The typical annotations for a web application used via a web browser are:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-request-redirect: $request_uri
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/oauth2/sign_in"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?scope=<scope>"

Replace ``<hostname>`` with the hostname of the ingress on which the Gafaelfawr routes are configured, and ``<scope>`` with the name of the scope that should be required in order to visit this site.

This will send a request to the Gafaelfawr ``/auth`` route for each request.
It will find the user's authentication token, check that it is valid, and check that the user has the required scope.
If the user is not authenticated, they will be redirected to the sign-in URL configured here, which in turn will either send the user to CILogon or to GitHub to authenticate.
If the user is already authenticated but does not have the desired scope, they will receive a 403 error.

If the user authenticates and authorizes successfully, the request will be sent to the application.
Included in the request will be an ``X-Auth-Request-Token`` header containing the user's JWT.
This will be a reissued token signed by Gafaelfawr.

.. _auth-config:

Configuring authentication
--------------------------

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

``audience`` (optional)
    May be set to the value of the ``issuer.aud.internal`` configuration parameter, in which case a new token will be issued from the user's token with all the same claims but with that audience.
    This newly-issued token will be returned in the ``X-Auth-Request-Token`` header instead of the user's regular token.
    The intent of this feature is to send an audience-restricted version of a token to an internal service, which may use it to make subrequests to other internal services but should not be able to make requests to public-facing services.

These parameters must be URL-encoded as GET parameters to the ``/auth`` route.

.. _auth-headers:

Additional authentication headers
---------------------------------

The following headers may be requested by the application by adding them to the ``nginx.ingress.kubernetes.io/auth-response-headers`` annotation for the ingress rule.
The value of that annotation is a comma-separated list of desired headers.

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
----------------

A JWKS for the Gafaelfawr token issuer is available via the ``/.well-known/jwks.json`` route.
An application may use that URL to retrieve the public key of Gafaelfawr and use it to verify the token signature.
