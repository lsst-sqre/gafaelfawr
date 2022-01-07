##################
Installation guide
##################

Gafaelfawr was written to run inside a Kubernetes environment.
While there is nothing intrinsic in Gafaelfawr that would prevent it from working in some other environment, only installation on Kubernetes has been documented or tested.

Prerequisites
=============

The `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__ must already be configured and working.
Gafaelfawr only supports that ingress controller.
Gafaelfawr also expects TLS termination to be done by the ingress controller.

A PostgreSQL database is required but not provided by the Helm chart.
You must provision this database and configure it as described below.
Google Cloud SQL (including the Google Cloud SQL Auth Proxy) is supported.

Redis is also required for storage, but the Gafaelfawr Helm chart will configure and deploy a private Redis server for this purpose.
However, you will need to configure persistent storage for that Redis server for any non-test deployment, which means that the Kubernetes cluster must provide persistent storage.

Gafaelfawr requires use of Vault_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets as Kubernetes secrets.

.. _Vault: https://vaultproject.io/
.. _Vault Secrets Operator: https://github.com/ricoberger/vault-secrets-operator

Client configuration
====================

.. _github-config:

GitHub
------

If you will be using GitHub as the authentication provider, you will need to create a GitHub OAuth app for Gafaelfawr and obtain a client ID and secret.
To get these values, go to Settings → Developer Settings for either a GitHub user or an organization, go into OAuth Apps, and create a new application.
The callback URL should be the ``/login`` route under the hostname you will use for your Gafaelfawr deployment.

.. _cilogon-config:

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

Other OpenID Connect provider
-----------------------------

Gafaelfawr supports client authentication using an arbitrary OpenID Connect provider, as long as the provider supports a ``response_type`` of ``code``, a ``grant_type`` of ``authorization_code``, accepts a ``client_secret`` for authentication, and returns tokens that contain a username and numeric UID.
You will need the following information from the OpenID Connect provider:

- Client ID that Gafaelfawr will use to authenticate
- Client secret corresponding to that client ID
- JWT audience corresponding to that client ID
- Authorization endpoint URL (where the user is sent to authorize Gafaelafwr)
- Token endpoint URL (from which Gafaelfawr retrieves a token after authentication)
- JWT issuer URL
- List of scopes to request from the OpenID Connect provider

.. _vault-secrets:

Vault secrets
=============

The standard Helm chart for Gafaelfawr (described below) assumes that you will use `Vault`_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets in Kubernetes.
If you are using it, create a Vault secret with the following keys:

``bootstrap-token``
    A Gafaelfawr token created with ``gafaelfawr generate-token``.
    Used to create service tokens, initialize admins, and do other privileged operations.
    See :ref:`bootstrapping` for more information.

``cilogon-client-secret``
    The CILogon secret, obtained during client registration as described above.
    This is only required if you're using CILogon for authentication.

``database-password``
    The password to use for the PostgreSQL database.
    This should be set to a long, randomly-generated alphanumeric string.

``github-client-secret``
    The GitHub secret, obtained when creating the OAuth App as described above.
    This is only required if you're using GitHub for authentication.

``influxdb-secret`` (optional)
    The shared secret to use for issuing InfluxDB tokens.
    See :ref:`influxdb` for more information.
    You can omit this if you don't need InfluxDB token support.

``oidc-client-secret``
    The secret for an OpenID Connect authentication provider.
    This is only required if you're using generic OpenID Connect for authentication.

``oidc-server-secrets`` (optional)
    Only used if the Helm chart parameter ``oidcServer.enabled`` is set to true.
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

.. _helm-settings:

Helm deployment
===============

The supported way of deploying Gafaelfawr is to use the Helm chart in the `Rubin Observatory charts repository <https://lsst-sqre.github.io/charts/>`__.
The Helm chart only supports GitHub or CILogon as identity providers.

To use that chart, you will need to provide a ``values.yaml`` file or otherwise set various Helm values.
Below are the most-commonly-used settings.
For a complete reference, see `the Helm chart documentation <https://github.com/lsst-sqre/charts/tree/master/charts/gafaelfawr>`__.

For examples, see `the configuration for the LSST Science Platform deployments <https://github.com/lsst-sqre/lsp-deploy/blob/master/services/gafaelfawr>`__.

.. _basic-settings:

Basic settings
--------------

Set the path in Vault where the Gafaelfawr secret is stored:

.. code-block:: yaml

   vaultSecretsPath: "secret/path/in/vault"

Set the URL to the PostgreSQL database that Gafaelfawr will use:

.. code-block:: yaml

   config:
     databaseUrl: "postgresql://gafaelfawr@example.com/gafaelfawr"

Do not include the password in the URL; instead, put the password in the ``database-password`` key in the Vault secret.
If you are using Cloud SQL with the Cloud SQL Auth Proxy (see :ref:`cloudsql`), use ``localhost`` for the hostname portion.

Set the hostname that Gafaelfawr will be protecting:

.. code-block:: yaml

   config:
     host: "hostname.example.com"
   ingress:
     host: "hostname.example.com"

You can omit ``ingress.host`` if you aren't using named virtual hosts and want all routes to be registered for ``*``.
The ``/auth``, ``/login``, ``/logout``, ``/oauth2/callback``, and ``/.well-known/jwks.json`` routes will be claimed under this host (or under ``*`` if it is not given) by the Gafaelfawr ingress configuration.
If ``config.oidcServer.enabled`` is set to true, the ``/.well-known/openid-configuration`` route will also be claimed.

If you need to configure TLS options or annotations for the ingress, use ``ingress.annotations`` and ``ingress.tls``.
The syntax is the same as the ``metadata.annotations`` and ``spec.tls`` attributes of a Kubernetes ``Ingress`` resource.

To add additional information to the error page from a failed login, set ``config.errorFooter`` to a string.
This string will be embedded verbatim, inside a ``<p>`` tag, in all login error messages.
It may include HTML and will not be escaped.
This is a suitable place to direct the user to support information or bug reporting instructions.

Consider increasing the number of Gafaelfawr processes to run.
This improves robustness and performance scaling.
Production deployments should use at least two replicas.

.. code-block:: yaml

   replicaCount: 2

Finally, you may want to define the initial set of administrators:

.. code-block:: yaml

   config:
     initialAdmins:
       - "username"
       - "otheruser"

This makes the users ``username`` and ``otheruser`` (as authenticated by the upstream authentication provider configured below) admins, meaning that they can create, delete, and modify any authentication tokens.
This value is only used when initializing a new Gafaelfawr database that does not contain any admins.
Setting this is optional; you can instead use the bootstrap token (see :ref:`bootstrapping`) to perform any administrative actions through the API.

.. _providers:

Authentication provider
-----------------------

Configure GitHub, CILogon, or OpenID Connect as the upstream provider.

GitHub
^^^^^^

.. code-block:: yaml

   config:
     github:
       clientId: "<github-client-id>"

using the GitHub client ID from :ref:`github-config`.

CILogon
^^^^^^^

.. code-block:: yaml

   config:
     cilogon:
       clientId: "<cilogon-client-id>"

using the CILogon client ID from :ref:`cilogon-config`.

CILogon has some additional options under ``config.cilogon`` that you may want to set:

``config.cilogon.redirectUrl``
    The full redirect URL for CILogon if using CILogon as the identity provider.
    Set this if you need to change the redirect URL to the ``/oauth2/callback`` route instead of the ``/login`` route.

``config.cilogon.loginParams``
    A mapping of additional parameters to send to the CILogon authorize route.
    Can be used to set parameters like ``skin`` or ``selected_idp``.
    See the `CILogon OIDC documentation <https://www.cilogon.org/oidc>`__ for more information.

Generic OpenID Connect
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

   config:
     oidc:
       clientId: "<oidc-client-id>"
       audience: "<oidc-client-audience>"
       loginUrl: "<oidc-login-url>"
       tokenUrl: "<oidc-token-url>"
       issuer: "<oidc-issuer>"
       scopes:
         - "<scope-to-request>"
         - "<scope-to-request>"

There is one additional option under ``config.oidc`` that you may want to set:

``config.oidc.loginParams``
    A mapping of additional parameters to send to the login route.
    Can be used to set additional configuration options for some OpenID Connect providers.

.. _scopes:

LDAP groups
-----------

When using either CILogon or generic OpenID Connect as an authentication provider, you can choose to obtain group information from an LDAP server rather than an ``isMemberOf`` attribute inside the token.
Currently, Gafaelfawr only supports anonymous LDAP binds.

To do this, add the following configuration:

.. code-block:: yaml

   config:
     ldap:
       url: "ldaps://<ldap-server>"
       baseDn: "<base-dn-for-search>"

You may need to set the following additional options under ``config.ldap`` depending on your LDAP schema:

``config.ldap.groupObjectClass``
    The object class from which group information should be looked up.
    Default: ``posixGroup``.

``config.ldap.groupMember``
    The member attribute of that object class.
    The values must match the username returned in the token from the OpenID Connect authentication server.
    Default: ``member``.

The name of each group will be taken from the ``cn`` attribute and the numeric UID will be taken from the ``gidNumber`` attribute.

Scopes
------

Gafaelfawr takes group information from the upstream authentication provider and maps it to scopes.
Scopes are then used to restrict access to protected applications (see :ref:`protect-service`).

The list of scopes is configured via ``config.knownScopes``, which is an object mapping scope names to human-readable descriptions.
Every scope that you want to use must be listed in ``config.knownScopes``.
The default includes:

.. code-block:: yaml

   config:
     knownScopes:
       "admin:token": "Can create and modify tokens for any user"
       "user:token": "Can create and modify user tokens"

which are used internally by Gafaelfawr, plus the scopes that are used by the Rubin Science Platform.
You can add additional scopes by adding more key/value pairs to the ``config.knownScopes`` object in ``values.yaml``.

Once the scopes are configured, you will need to set up a mapping from groups to scope names.

When GitHub is used as the provider, group membership will be synthesized from GitHub team membership.
See :ref:`github-groups` for more information.
A setting for GitHub might look something like this:

.. code-block:: yaml

   config:
     groupMapping:
       "exec:admin":
         - "lsst-sqre-square"
       "exec:notebook":
         - "lsst-sqre-square"
         - "lsst-sqre-friends"
       "exec:portal":
         - "lsst-sqre-square"
         - "lsst-sqre-friends"
       "exec:user":
         - "lsst-sqre-square"
         - "lsst-sqre-friends"
       "read:tap":
         - "lsst-sqre-square"
         - "lsst-sqre-friends"

This uses groups generated from teams in the GitHub ``lsst-sqre`` organization.

When an OpenID Connect provider such as CILogon is used as the provider, group membership will be taken from the ``isMemberOf`` claim of the token returned by the provider.
The value of this claim will be all scopes for which the user is a member (according to the ``isMemberOf`` claim) of at least one of the corresponding groups.
For example, given a configuration like:

.. code-block:: yaml

   config:
     groupMapping:
       "admin": ["foo", "bar"]

and a token claim of:

.. code-block:: json

   {"isMemberOf": [{"name": "other"}, {"name": "bar"}]}

a ``scope`` claim of ``admin`` will be added to a reissued token.

Regardless of the ``config.groupMapping`` configuration, the ``user:token`` scope will be automatically added to the session token of any user authenticating via OpenID Connect or GitHub.
The ``admin:token`` scope will be automatically added to any user marked as an admin in Gafaelfawr.

Redis storage
-------------

For any Gafaelfawr deployment other than a test instance, you will want to configure persistent storage for Redis.
Otherwise, each upgrade of Gafaelfawr's Redis component will invalidate all of the tokens.

By default, the Gafaelfawr Helm chart uses auto-provisioning to create a ``PersistentVolumeClaim`` with the default storage class, requesting 1GiB of storage with the ``ReadWriteOnce`` access mode.
If this is suitable for your deployment, you can leave the configuration as is.
Otherwise, you can adjust the size (you probably won't need to make it larger; Gafaelfawr's storage needs are modest), storage class, or access mode by setting ``redis.persistence.size``, ``redis.persistence.storageClass``, and ``redis.persistence.accessMode``.

If you instead want to manage the persistent volume directly rather than using auto-provisioning, use a configuration such as:

.. code-block:: yaml

   redis:
     persistence:
       volumeClaimName: "gafaelfawr-pvc"

to point to an existing ``PersistentVolumeClaim``.
You can then create that ``PersistentVolumeClaim`` and its associated ``PersistentVolume`` via any mechanism you choose, and the volume pointed to by that claim will be mounted as the Redis volume.
Gafaelfawr uses the standard Redis Docker image, so the volume must be writable by UID 999, GID 999 (which the ``StatefulSet`` will attempt to ensure using the Kubernetes ``fsGroup`` setting).

Finally, if you do have a test installation where you don't mind invalidating all tokens whenever Redis is restarted, you can use:

.. code-block:: yaml

   redis:
     persistence:
       enabled: false

This will use an ephemeral ``emptyDir`` volume for Redis storage.

.. _cloudsql:

Cloud SQL
---------

If the PostgreSQL database that Gafaelfawr should use is a Google Cloud SQL database, Gafaelfawr supports using the Cloud SQL Auth Proxy via Workload Identity.

First, follow the `normal setup instructions for Cloud SQL Auth Proxy using Workload Identity <https://cloud.google.com/sql/docs/postgres/connect-kubernetes-engine>`__.
You do not need to create the Kubernetes service account; two service accounts will be created by the Gafaelfawr Helm chart.
The default names of those service accounts are ``gafaelfawr`` and ``gafaelfawr-tokens``, both in the ``gafaelfawr`` namespace.
These names can be overridden with the ``serviceAccount.name`` and ``tokens.serviceAccount.name`` Helm values.

Then, once you have the name of the Google service account for the Cloud SQL Auth Proxy (created in the above instructions), enable the Cloud SQL Auth Proxy sidecar in the Gafaelfawr Helm chart.
An example configuration:

.. code-block:: yaml

   cloudsql:
     enabled: true
     instanceConnectionName: "dev-7696:us-central1:dev-e9e11de2"
     serviceAccount: "gafaelfawr@dev-7696.iam.gserviceaccount.com"

Replace ``instanceConnectionName`` and ``serviceAccount`` with the values for your environment.
You will still need to set ``config.databaseUrl`` and the ``database-password`` key in the Vault secret with appropriate values, but use ``localhost`` for the hostname in ``config.databaseUrl``.

As mentioned in the Google documentation, the Cloud SQL Auth Proxy does not support IAM authentication to the database, only password authentication, and IAM authentication is not recommended for connection pools for long-lived processes.
Gafaelfawr therefore doesn't support IAM authentication to the database.

.. _helm-proxies:

Logging and proxies
-------------------

The default logging level of Gafaelfawr is ``INFO``, which will log a message for every action it takes.
To change this, set ``config.loglevel``:

.. code-block:: yaml

   config:
     loglevel: "WARNING"

Valid values are ``DEBUG`` (to increase the logging), ``INFO`` (the default), ``WARNING``, or ``ERROR``.

Gafaelfawr is meant to be deployed behind an NGINX proxy server.
In order to accurately log the IP address of the client, instead of the IP address of the proxy server, it must know what IP ranges correspond to possible proxy servers rather than clients.
Set this with ``config.proxies``:

.. code-block:: yaml

   config:
     proxies:
       - "192.0.2.0/24"

If not set, defaults to the `RFC 1918 private address spaces <https://tools.ietf.org/html/rfc1918>`__.
See :ref:`client-ips` for more information.

OpenID Connect server
---------------------

Gafaelfawr can act as an OpenID Connect identity provider for relying parties inside the Kubernetes cluster.
To enable this, set ``config.oidcServer.enabled`` to true.
If this is set, ``oidc-server-secrets`` must be set in the Gafaelfawr Vault secret.
See :ref:`openid-connect` for more information.

InfluxDB tokens
---------------

To enable issuing of InfluxDB tokens, set ``config.issuer.influxdb.enabled``.
To force all InfluxDB tokens to be issued with the same username, instead of the username requesting the token, set ``config.issuer.influxdb.username``.
For example:

.. code-block:: yaml

   config:
     issuer:
       influxdb:
         enabled: true
         username: "influxdbuser"

If this is set, ``influxdb-secret`` must be set in the Vault secret.
See :ref:`influxdb` for more information.

Administrators
==============

Gafaelfawr has a concept of token administrators.
Those users can add and remove other administrators and can create a service or user token for any user.
Currently, this capability is only available via the API, not the UI.

If a username is marked as a token administrator, that user will be automatically granted the ``admin:token`` scope when they authenticate (via either GitHub or OpenID Connect), regardless of their group membership.
They can then choose whether to delegate that scope to any user tokens they create.

The initial set of administrators can be added with the ``config.initialAdmins`` Helm variable (see :ref:`basic-settings`) or via the bootstrap token.

.. _bootstrapping:

Bootstrapping
-------------

Gafaelfawr can be configured with a special token, called the bootstrap token.
This token must be generated with ``gafaelfawr generate-token`` and then stored in the ``bootstrap-token`` key of the Gafaelfawr Vault secret.
See :ref:`vault-secrets` for more details.
It can then be used with API calls as a bearer token in the ``Authenticate`` header.

The bootstrap token acts like the token of a service or user with the ``admin:token`` scope, but can only access specific routes, namely ``/auth/api/v1/tokens`` and those under ``/auth/api/v1/admins``.
