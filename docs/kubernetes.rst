#######################
Kubernetes installation
#######################

Prerequisites
=============

The `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__ must already be configured and working.
JWT Authorizer expects TLS termination to be done by the ingress controller.

The instructions below assume that you will use Vault_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets as Kubernetes secrets.

.. _Vault: https://vaultproject.io/
.. _Vault Secrets Operator: https://github.com/ricoberger/vault-secrets-operator

OpenID or OAuth client configuration
====================================

GitHub
------

If you will be using GitHub as the authentication provider, you will need to create a GitHub OAuth app for JWT Authorizer and obtain a client ID and secret.
To get these values, go to Settings > Developer Settings for either a GitHub user or an organization, go into OAuth Apps, and create a new application.
The callback URL should be the ``/login`` route under the hostname you will use for your JWT Authorizer deployment.

CILogon
-------

.. warning::
   These instructions are for the oauth2_proxy integration.
   They will be replaced with instructions for the native OpenID Connect implementation in the future.

If you will use CILogon as the authentication provider, you will need to register with CILogon to get a client ID and secret.

1. Go to the `registration page <https://cilogon.org/oauth2/register>`__.
2. Enter the client name.
   For Rubin Observatory deployments, include "Rubin Observatory LSP" in the name.
3. Enter the contact email.
   You will be notified at this email when the client is registered.
4. Enter the top page of the LSP deployment as the home URL.
   For example, ``https://lsst-lsp-instance.example.com``.
5. Enter the oauth2_proxy URL as the callback URL.
   Also add the ``/login`` route for a future implementation without oauth2_proxy.
   For example, you might enter both:
   - ``https://lsst-lsp-instance.example.com/oauth2/callback``
   - ``https://lsst-lsp-instance.example.com/login``
6. Leave the public client box unchecked.
7. Select the following scopes:
   - email
   - org.cilogin.userinfo
   - profile
   You will eventually need the voPerson scope as well, but you will have to request that via email since it isn't available on the registration page.
8. Enter one day (86400 seconds) as the refresh token lifetime.

Submit that information.
You will get a client ID and secret.
This will not work immediately; you will need to wait for the CILogon team to register the client.

After you have gotten email confirming that your client has been registered, reply to that email and request that the client configuration be copied from the client ``cilogon:/client_id/6ca7b54ac075b65bccb9c885f9ba4a75``.
This will add the voPerson scope.

Vault secrets
=============

The standard Helm chart for JWT Authorizer (described below) assumes that you will use `Vault`_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets in Kubernetes.
Create a Vault secret with the following keys:

``oauth2_proxy_client_secret.txt``
    The CILogon secret, obtained during client registration as described above.
    Only used by oauth2_proxy.

``oauth2_proxy_cookie_secret.txt``
    The secret key used to encrypt the oauth2_proxy session.
    Shared between JWT Authorizer and oauth2_proxy.
    Should be a 256-bit secret key encoded in URL-safe base64.

``session_secret.txt``
    Encryption key for the JWT Authorizer session cookie.
    Generate with :py:meth:`cryptography.fernet.Fernet.generate_key`.

``signing_key.pem``
    The PEM-encoded RSA private key used to sign internally-issued JWTs.
    Generate with ``openssl genrsa -out signing_key.pem 2048``.

You will reference the path to this secret in Vault when configuring the Helm chart later.

Helm deployment
===============

There is a Helm chart for JWT Authorizer named ``authnz`` available from the `Rubin Observatory charts repository <https://lsst-sqre.github.io/charts/>`__.

.. note::
   Documentation for the Helm chart is coming in a future release.
   In the meantime, see `values.yaml <https://github.com/lsst-sqre/charts/blob/master/authnz/values.yaml>`__ for some hints on configuration.

For an example, see `the configuration for the LSST Science Platform deployments <https://github.com/lsst-sqre/lsp-deploy/blob/master/services/authnz>`__.

Application configuration
=========================

Protecting a service
--------------------

Authentication and authorization for a service are configured via annotations on the ingress for that service.
For CILogon, the typical annotations for a web application used via a web browser are:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-request-redirect: $request_uri
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/oauth2/sign_in"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?capability=<capability>"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      error_page 403 = "https://<hostname>/oauth2/start?rd=$escaped_request_uri";

Authentication and authorization using GitHub is similar, but somewhat simpler since oauth2_proxy is not involved.
The typical annotations for a web application used via a web browser are:

.. code-block:: yaml

   annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-signin: "https://<hostname>/login?rd=$escaped_request_uri"
    nginx.ingress.kubernetes.io/auth-url: "https://<hostname>/auth?capability=<capability>"

In both cases, replace ``<hostname>`` with the hostname of the ingress on which the JWT Authorizer routes are configured, and ``<capability>`` with the name of the scope that should be required in order to visit this site.

This will send a request to the JWT Authorizer ``/auth`` route for each request.
It will find the user's authentication token, check that it is valid, and check that the user has the required scope.
If the user is not authenticated, they will be redirected to the sign-in URL configured here, which in turn will either send the user to CILogon or to GitHub to authenticate.
For the CILogon configuration, if the user does not have the required scope, they will also be sent to reauthenticate.
(This is not ideal since it creates a redirect loop if the user cannot obtain that capability.)
The GitHub configuration will return a proper 403 error.

If the user authenticates and authorizes successfully, the request will be sent to the application.
Included in the request will be an ``X-Auth-Request-Token`` header containing the user's JWT.
This will be a reissued token signed by JWT Authorizer.

Configuring authentication
--------------------------

The URL in the ``nginx.ingress.kubernetes.io/auth-url`` annotation accepts several parameters to customize the authentication request.

``capability``
    The scope claim that the client JWT must have.
    May be given multiple times.
    The interpretation of multiple values is determined by the ``satisfy`` parameter.

``satisfy``
    May be set to ``any`` or ``all``.
    Optional, defaults to ``all``.
    If set to ``all``, the client must have a claim listing every scope specified in the ``capability`` parameters.
    If set to ``any``, the client need only have one of the scopes specified in the ``capability`` parameters.

``audience``
    May be set to the internal audience of JWT Authorizer to request a reissued token scoped to the internal audience.

These parameters must be URL-encoded as GET parameters to the ``/auth`` route.

Additional authentication headers
---------------------------------

The following headers may be requested by the application by adding them to the ``nginx.ingress.kubernetes.io/auth-response-headers`` annotation for the ingress rule.
The value of that annotation is a comma-separated list of desired headers.

``X-Auth-Request-Email``
    If enabled and the claim is available, this will be set based on the ``email`` claim in the token.

``X-Auth-Request-User``
    If enabled and the claim is available, this will be set from token based on the ``jwt_username_key`` setting (by default, the ``uid`` claim).

``X-Auth-Request-Uid``
    If enabled and the claim is available, this will be set from token based on the ``jwt_uid_key`` setting (by default, the ``uidNumber`` claim).

``X-Auth-Request-Groups``
    If the token lists groups in an ``isMemberOf`` claim, the names of the groups will be returned, comma-separated, in this header.

``X-Auth-Request-Token``
    If enabled, the encoded token will be sent.

``X-Auth-Request-Token-Ticket``
    When a ticket is available for the token, we will return it under this header.
    Do not rely on this behavior or setting.
    The ticket is often not available.

``X-Auth-Request-Token-Capabilities``
    If the token has capabilities in the ``scope`` claim, they will be returned in this header.

``X-Auth-Request-Token-Capabilities-Accepted``
    A space-separated list of token scopes the reliant resource accepts.
    This is configured in the ``nginx.ingress.kubernetes.io/auth-url`` annotation via the ``capabilities`` parameter.

``X-Auth-Request-Token-Capabilities-Satisfy``
    The strategy the reliant resource uses to determine whether a token satisfies the capability requirements.
    It will be either ``any`` or ``all``.
    This is configured in the ``nginx.ingress.kubernetes.io/auth-url`` annotation via the ``satisfy`` parameter.

Verifying tokens
----------------

A JWKS for the JWT Authorizer token issuer is available via the ``/.well-known/jwks.json`` route.
An application may use that URL to retrieve the public key of JWT Authorizer and use it to verify the token signature.
