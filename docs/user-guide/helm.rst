.. _helm-settings:

##################
Helm configuration
##################

Gafaelfawr is configured as a Phalanx_ application, using the Helm chart in `the Phalanx repository <https://github.com/lsst-sqre/phalanx/tree/main/applications/gafaelfawr/>`__.
You will need to provide a ``values-<environment>.yaml`` file for your Phalanx environment.
Below are the most-commonly-used settings.

For a complete reference, see the `Gafaelfawr application documentation <https://phalanx.lsst.io/applications/gafaelfawr/index.html>`__.
For examples, see the other ``values-<environment>.yaml`` files in that directory.

In the below examples, the full key hierarchy is shown for each setting.
For example:

.. code-block:: yaml

   config:
     cilogon:
       test: true

When writing a ``values-<environment>.yaml`` chart, you should coalesce all settings so that each level of the hierarchy appears only once.
For example, there should be one top-level ``config:`` key and all parameters that start with ``config.`` should go under that key.

.. _basic-settings:

Basic settings
==============

Database
--------

Set the URL to the PostgreSQL database that Gafaelfawr will use:

.. code-block:: yaml

   config:
     databaseUrl: "postgresql://gafaelfawr@example.com/gafaelfawr"

Do not include the password in the URL; instead, put the password in the ``database-password`` key in the Vault secret.
If you are using Cloud SQL with the Cloud SQL Auth Proxy (see :ref:`cloudsql`), use ``localhost`` for the hostname portion.

Alternately, if Gafaelfawr should use the cluster-internal PostgreSQL service, omit the ``config.databaseUrl`` setting and instead add:

.. code-block:: yaml

   config:
     internalDatabase: true

This option is primarily for test and development deployments and is not recommended for production use.

Error pages
-----------

To add additional information to the error page from a failed login, set ``config.errorFooter`` to a string.
This string will be embedded verbatim, inside a ``<p>`` tag, in all login error messages.
It may include HTML and will not be escaped.
This is a suitable place to direct the user to support information or bug reporting instructions.

Scaling
-------

Consider increasing the number of Gafaelfawr processes to run.
This improves robustness and performance scaling.
Production deployments should use at least two replicas.

.. code-block:: yaml

   replicaCount: 2

Token lifetime
--------------

Change the token lifetime by setting ``config.tokenLifetimeMinutes``.
The default is 1380 (23 hours).

.. code-block:: yaml

   config:
     tokenLifetimeMinutes: 43200  # 30 days

This setting will also affect the lifetime of tokens issued by the OpenID Connect server, if enabled.

Administrators
--------------

You may want to define the initial set of administrators:

.. code-block:: yaml

   config:
     initialAdmins:
       - "username"
       - "otheruser"

This makes the users ``username`` and ``otheruser`` (as authenticated by the upstream authentication provider configured below) admins, meaning that they can create, delete, and modify any authentication tokens.
This value is only used when initializing a new Gafaelfawr database that does not contain any admins.
Setting this is optional; you can instead use the bootstrap token (see :ref:`bootstrapping`) to perform any administrative actions through the API.

Resource requests and limits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every component of Gafaelfawr defines Kubernetes resource requests and limits.
Look for the ``resources`` key at the top level of the chart and in the portions of the chart for the underlying Gafaelfawr components.

The default limits and requests were set based on a fairly lightly loaded deployment that uses OpenID Connect as the authentication provider and LDAP for user metadata.
For a heavily-loaded environment, you may need to increase the resource requests to reflect the expected resource consumption of your instance of Gafaelfawr and allow Kubernetes to do better scheduling.
You will hopefully not need to increase the limits, which are generous.

.. _providers:

Authentication provider
=======================

Configure GitHub, CILogon, or OpenID Connect as the upstream provider.

GitHub
------

.. code-block:: yaml

   config:
     github:
       clientId: "<github-client-id>"

using the GitHub client ID from :ref:`github-config`.

When GitHub is used as the provider, group membership will be synthesized from GitHub team membership.
See :ref:`github-groups` for more information.

CILogon
-------

.. code-block:: yaml

   config:
     cilogon:
       clientId: "<cilogon-client-id>"

using the CILogon client ID from :ref:`cilogon-config`.

When CILogon is used as the provider, group membership should normally be obtained from LDAP (see :ref:`LDAP groups <ldap-groups>`).
However, it optionally can be obtained from information embedded in the OpenID Connect ID token.
To do the latter, CILogon (generally via COmanage) should be configured to add a token claim in the following format:

.. code-block:: json

   {"isMemberOf": [
       {"name": "one-group", "id": 1344},
       {"name": "other-group", "id": 3718},
   ]}

The name of the claim can be overridden with ``config.cilogon.groupsClaim`` as discussed below.

CILogon has some additional options under ``config.cilogon`` that you may want to set:

``config.cilogon.loginParams``
    A mapping of additional parameters to send to the CILogon authorize route.
    Can be used to set parameters like ``skin`` or ``selected_idp``.
    See the `CILogon OIDC documentation <https://www.cilogon.org/oidc>`__ for more information.

``config.cilogon.enrollmentUrl``
    If a username was not found for the CILogon unique identifier, redirect the user to this URL.
    This is intended for deployments using CILogon with COmanage for identity management.
    The enrollment URL will normally be the initial URL for a COmanage user-initiated enrollment flow.

``config.cilogon.gidClaim``
    The claim of the OpenID Connect ID token from which to take the primary GID.
    Only used if :ref:`GID lookup in LDAP <ldap-user>` is not configured.
    The default is to not obtain a primary GID from the token.

``config.cilogon.uidClaim``
    The claim of the OpenID Connect ID token from which to take the numeric UID.
    Only used if :ref:`UID lookup in LDAP <ldap-user>` is not configured.
    The default is ``uidNumber``.

``config.cilogon.groupsClaim``
    The claim of the OpenID Connect ID token from which to take the group membership information.
    Only used if :ref:`LDAP groups <ldap-groups>` are not configured.
    The default is ``isMemberOf``.

``config.cilogon.usernameClaim``
    The claim of the OpenID Connect ID token from which to take the username.
    The default is ``uid``.

Generic OpenID Connect
----------------------

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

Group information from the user can come from either LDAP (see :ref:`LDAP groups <ldap-groups>`) or from a claim in the OpenID Connect ID token.
For the latter option, the claim should preferrably have the following format:

.. code-block:: json

   {"isMemberOf": [
       {"name": "one-group", "id": 1344},
       {"name": "other-group", "id": 3718},
   ]}

The name of the claim can be overridden with ``config.oidc.groupsClaim`` as discussed below.
Optionally, the value of the claim can be a simple list of group names instead of a structure including the GIDs, but in this case Gafaelfawr will not have access to the GID information and will not be able to provide it to protected services.

If group names in the token claim start with a slash, the name is canonicalized by removing the slash.
Keycloak tends to mangle group names in this way.

.. warning::

   Prefer to use LDAP for user metadata and group information instead of using token attributes.
   We have encountered numerous problems and severe limitations with obtaining user metadata from OpenID Connect tokens.

   As one specific example, it does not appear to be possible to use OpenID Connect tokens issued by LDAP-backed Keycloak to provide group membership information with GIDs.
   Keycloak does not appear to be capable of associating group names with GID information from the group tree of an LDAP server.
   The best it can do is provide uncorrelated lists of group names and GIDs, which is not sufficient for Gafaelfawr's needs.
   If you are using Keycloak plus LDAP, giving Gafaelfawr direct access to LDAP for user metadata and using Keycloak only for authentication is *strongly recommended*.

There are some additional options under ``config.oidc`` that you may want to set:

``config.oidc.loginParams``
    A mapping of additional parameters to send to the login route.
    Can be used to set additional configuration options for some OpenID Connect providers.

``config.oidc.enrollmentUrl``
    If a username was not found for the unique identifier in the ``sub`` claim of the OpenID Connect ID token, redirect the user to this URL.
    This could, for example, be a form where the user can register for access to the deployment, or a page explaining how a user can get access.

``config.oidc.gidClaim``
    The claim of the OpenID Connect ID token from which to take the primary GID.
    Only used if :ref:`GID lookup in LDAP <ldap-user>` is not configured.
    The default is to not obtain a primary GID from the token.

``config.oidc.uidClaim``
    The claim of the OpenID Connect ID token from which to take the numeric UID.
    Only used if :ref:`UID lookup in LDAP <ldap-user>` is not configured.
    The default is ``uidNumber``.

``config.cilogon.groupsClaim``
    The claim of the OpenID Connect ID token from which to take the group membership information.
    Only used if :ref:`LDAP groups <ldap-groups>` are not configured.
    The default is ``isMemberOf``.

    Be aware that although Gafaelfawr can parse a simple list of groups and will provide that information via its token information endpoints, this is not sufficient for the Notebook Aspect of the Science Platform.
    The OpenID Connect provider must be capable of generating structured group information, including both the group name and the GID, in the format Gafaelfawr expects.
    If this is not possible (and it usually is not), use LDAP instead.

``config.oidc.usernameClaim``
    The claim of the OpenID Connect ID token from which to take the username.
    The default is ``uid``.

.. _ldap:

LDAP
====

The preferred way for Gafaelfawr to get metadata about users (full name, email address, group membership, UID and GID, etc.) when using CILogon or OpenID Connect is from an LDAP server.
If the GitHub authentication provider is used, this information instead comes from GitHub and LDAP is not supported.

If LDAP is enabled, group membership is always taken from LDAP (see :ref:`ldap-groups`) instead of the ID token from the upstream authentication provider.
Other information about the user may also be retrieved from LDAP if configured (see :ref:`ldap-user`).

.. warning::

   If you are using CILogon or OpenID Connect as the authentication provider and have an LDAP server available, it is *strongly recommended* to use LDAP as the source of both user and group metadata rather than trying to use OpenID Connect token data.
   Using CILogon or OpenID Connect only for authentication and retrieving all additional information from LDAP is the most heavily tested and lowest-friction Gafaelfawr configuration apart from the GitHub support.

LDAP authentication
-------------------

.. note::

   This section describes how the Gafaelfawr service itself authenticates to the LDAP server.
   Users are never authenticated using LDAP.
   User authentication always uses OpenID Connect or GitHub.

Gafaelfawr supports anonymous binds, simple binds (username and password), or Kerberos GSSAPI binds.

To use anonymous binds (the default), just specify the URL of the LDAP server with no additional bind configuration.

.. code-block:: yaml

   config:
     ldap:
       url: "ldaps://<ldap-server>"

To use simple binds, also specify the DN of the user to bind as.
If this is set, ``ldap-password`` must be set in the Gafaelfawr Vault secret to the password to use with the simple bind.

.. code-block:: yaml

   config:
     ldap:
       url: "ldaps://<ldap-server>"
       userDn: "<bind-dn-of-user>"

To use Kerberos GSSAPI binds, provide a ``krb5.conf`` file that contains the necessary information to connect to your Kerberos server.
Normally at least ``default_realm`` should be set.
Including a full copy of your standard ``/etc/krb5.conf`` file should work.
If this is set, ``ldap-keytab`` must be set in the Gafaelfawr Vault secret to the contents of a Kerberos keytab file to use for authentication to the LDAP server.

.. code-block:: yaml

   config:
     ldap:
       url: "ldaps://<ldap-server>"
       kerberosConfig: |
         [libdefaults]
           default_realm = EXAMPLE.ORG

         [realms]
           EXAMPLE.ORG = {
             kdc = kerberos.example.org
             kdc = kerberos-1.example.org
             kdc = kerberos-2.example.org
             default_domain = example.org
           }

.. _ldap-groups:

LDAP groups
-----------

To obtain user group information from LDAP, add the following configuration:

.. code-block:: yaml

   config:
     ldap:
       groupBaseDn: "<base-dn-for-search>"

You may need to set the following additional options under ``config.ldap`` depending on your LDAP schema:

``config.ldap.groupObjectClass``
    The object class from which group information should be looked up.
    Default: ``posixGroup``.

``config.ldap.groupMemberAttr``
    The member attribute of that object class.
    The values must match the username returned in the token from the OpenID Connect authentication server, or (if ``config.ldap.groupSearchByDn`` is set) the user DN formed from that username and the configuration options described in :ref:`ldap-user`.
    Default: ``member``.

``config.ldap.groupSearchByDn``
    If set to true, rather than expecting the membership attribute to contain bare usernames, expect it to contain full user DNs.
    This is the configuration used by most LDAP servers.
    Construct the user DN by combining the username with the values of ``config.ldap.userSearchAttr`` (as the attribute name for the first DN component containing the username) and ``config.ldap.userBaseDn`` (for the rest of the DN).
    If this is set, ``config.ldap.userBaseDn`` must also be set.
    Default: ``false``, mostly for backward compatibility reasons.

``config.ldap.addUserGroup``
    If set to ``true``, add an additional group to the user's group membership with a name equal to their username and a GID equal to their UID (provided they have a UID; if not, no group is added).
    Use this in environments with user private groups that do not appear in LDAP.
    In order to safely use this option, the GIDs of regular groups must be disjoint from user UIDs so that the user's UID can safely be used as the GID of this synthetic group.
    Default: ``false``.

The name of each group will be taken from the ``cn`` attribute and the GID will be taken from the ``gidNumber`` attribute.

.. _ldap-user:

LDAP user information
---------------------

By default, Gafaelfawr takes the user's name, email, and numeric UID from the upstream provider via the ``name``, ``mail``, and ``uidNumber`` claims in the ID token.
If LDAP is used for group information, this data, plus the primary GID, can instead be obtained from LDAP.
To do this, add the following configuration:

.. code-block:: yaml

   config:
     ldap:
       userBaseDn: "<base-dn-for-search>"

By default, this will get the name (from the ``displayName`` attribute) and the email (from the ``mail`` attribute) from LDAP instead of the ID token.
If either have multiple values, the first one will be used.

To also obtain the numeric UID from LDAP, add ``uidAttr: "uidNumber"`` to the LDAP configuration.
(Replace ``uidNumber`` with some other attribute if your LDAP directory stores the numeric UID elsewhere.)
As with the other attributes, if this attribute has multiple values, the first one will be used.

To obtain the primary GID from LDAP, add ``gidAttr: "gidNumber"`` to the LDAP configuration.
(Replace ``gidNumber`` with some other attribute if your LDAP directory stores the primary GID elsewhere.)
As with the other attributes, if this attribute has multiple values, the first one will be used.
If this GID does not match the GID of any of the user's groups, the corresponding group will be looked up in LDAP by GID and added to the user's group list.
This handles LDAP configurations where only supplemental group memberships are recorded in LDAP, and the primary group membership is recorded only via the user's GID.
If this configuration is not given but user private groups is enabled with ``addUserGroup: true``, the primary GID will be set to the same as the UID (which is the GID of the synthetic user private group).
Otherwise, the primary GID will be left unset.

You may need to set the following additional options under ``config.ldap`` depending on your LDAP schema:

``config.ldap.emailAttr``
    The attribute from which to get the user's email address.
    Default: ``mail``.

``config.ldap.nameAttr``
    The attribute from which to get the user's full name.
    This attribute should hold the whole name that should be used, not just a surname or family name (which are not universally valid concepts anyway).
    Default: ``displayName``.

``config.ldap.userSearchAttr``
    The attribute holding the username, used to find the user's entry.
    Default: ``uid``.

Firestore UID/GID assignment
============================

Gafaelfawr can manage UID and GID assignment internally, using `Google Firestore <https://cloud.google.com/firestore>`__ as the storage mechanism.
This only works with Open ID Connect authentication, and :ref:`Cloud SQL <cloudsql>` must also be enabled.
The same service account used for Cloud SQL must have read/write permissions to Firestore.

When this support is enabled, Gafaelfawr ignores any UID and GID information from the tokens issued by the upstream OpenID Connect provider and from LDAP, and instead assigns UIDs and GIDs to users and groups by name the first time that a given username or group name is seen.
UIDs and GIDs are never reused.
They are assigned from the ranges documented in :dmtn:`225`.

To enable use of Firestore for UID/GID assignment, add the following configuration:

.. code-block:: yaml

   config:
     firestore:
       project: "<google-project-id>"

Set ``<google-project-id>`` to the name of the Google project for the Firestore data store.
(Best practice is to make a dedicated project solely for Firestore, since there can only be one Firestore instance per Google project.)

.. _forgerock:

ForgeRock Identity Management GID queries
=========================================

Gafaelfawr can get the GID corresponding to a group from a ForgeRock Identity Management server.
Only GIDs, not UIDs, can be looked up this way.
When using this configuration, UIDs should be present in the OpenID Connect claim from the upstream authentication system.

When this support is enabled, the GID for each group found in the token issued by the OpenID Connect provider during login will be looked up in a ForgeRock Identity Management server.
Specifically, Gafaelfawr will query the ``groups`` collection of the ``freeipa`` component.
The request will be authenticated with HTTP Basic authentication.

To enable this support, add the following configuration:

.. code-block:: yaml

   config:
     forgerock:
       url: "<url-of-forgerock-server>"
       username: "<username>"

Set ``<url-of-forgerock-server>`` to the base URL of the ForgeRock Identity Management REST API.
``/system/freeipa/groups`` will be added to find the ``groups`` collection.

``<username>`` should be the username used for HTTP Basic authentication.
The corresponding password must be set in the ``forgerock-password`` field of the Gafaelfawr Vault secret (see :ref:`vault-secrets`).

GID lookups in ForgeRock Identity Management is only supported in conjunction with OpenID Connect authentication.

.. _scopes:

Scopes
======

Gafaelfawr takes group information from the upstream authentication provider or from LDAP and maps it to scopes.
Scopes are then used to restrict access to protected services (see :ref:`ingress`).

For a list of scopes used by the Rubin Science Platform, which may also be useful as an example for other deployments, see :dmtn:`235`.

The list of scopes is configured via ``config.knownScopes``, which is an object mapping scope names to human-readable descriptions.
Every scope that you want to use must be listed in ``config.knownScopes``.
The default includes:

.. code-block:: yaml

   config:
     knownScopes:
       "admin:token": "Can create and modify tokens for any user"
       "user:token": "Can create and modify user tokens"

which are used internally by Gafaelfawr, plus the scopes that are used by the Rubin Science Platform.
You can add additional scopes by adding more key/value pairs to the ``config.knownScopes`` object in ``values-<environment>.yaml``.

Once the scopes are configured, you will need to set up a mapping from groups to scope names using the ``groupMapping`` setting.
This is a dictionary of scope names to lists of groups that provide that scope.

The group can be given in one of two ways: either a simple string giving the name of the group (used for CILogon and OpenID Connect authentication providers), or the GitHub organization and team specified with the following syntax:

.. code-block:: yaml

   github:
     organization: "lsst-sqre"
     team: "friends"

Both ``organization`` and ``team`` must be given.
It is not possible to do access control based only on organizational membership.

The value of ``organization`` must be the ``login`` attribute of the organization, and the value of ``team`` must be the ``slug`` attribute of the team.
(Generally the latter is the name of the team converted to lowercase with spaces and other special characters replaced with ``-``.)

A complete setting for GitHub might look something like this:

.. code-block:: yaml

   config:
     groupMapping:
       "admin:token":
         - github:
             organization: "lsst-sqre"
             team: "square"
       "exec:notebook":
         - github:
             organization: "lsst-sqre"
             team: "square"
         - github:
             organization: "lsst-sqre"
             team: "friends"
       "exec:portal":
         - github:
             organization: "lsst-sqre"
             team: "square"
         - github:
             organization: "lsst-sqre"
             team: "friends"
       "read:tap":
         - github:
             organization: "lsst-sqre"
             team: "square"
         - github:
             organization: "lsst-sqre"
             team: "friends"

Be aware that Gafaelfawr will convert these organization and team pairs to group names internally, and applications will see only the converted group names.
See :ref:`github-groups` for more information.

When CILogon or generic OpenID Connect are used as the providers, the group information may come from either LDAP or claims in the OpenID Connect ID token.
Either way, that group membership will then be used to determine scopes via the ``groupMapping`` configuration.
For those authentication providers, the group names are simple strings.
For example, given a configuration like:

.. code-block:: yaml

   config:
     groupMapping:
       "exec:admin": ["foo", "bar"]

and a token claim of:

.. code-block:: json

   {"isMemberOf": [{"name": "other"}, {"name": "bar"}]}

a ``scope`` claim of ``exec:admin`` will be added to the token.

Regardless of the ``config.groupMapping`` configuration, the ``user:token`` scope will be automatically added to the session token of any user authenticating via OpenID Connect or GitHub.
The ``admin:token`` scope will be automatically added to any user marked as an admin in Gafaelfawr.

Quotas
======

Gafaelfawr supports calculating user quotas based on group membership and providing quota information through its API.
These quotas are not enforced by Gafaelfawr.

To configure quotas, set a base quota for all users, and then optionally add additional quota for members of specific groups.
Here is an example:

.. code-block:: yaml

   config:
     quota:
       default:
         api:
           datalinker: 1000
         notebook:
           cpu: 2.0
           memory: 4.0
       groups:
         g_developers:
           notebook:
             cpu: 8.0
             memory: 4.0

API quotas are in requests per 15 minutes.
Notebook quotas are in CPU equivalents and GiB of memory.

Therefore, the above example sets an API quota for the ``datalinker`` service of 1000 requests per 15 minutes, and a default quota for user notebooks of 2.0 CPU equivalents and 4.0GiB of memory.
Users who are members of the ``g_developers`` group get an additional 4.0GiB of memory for their notebooks.

The keys for API quotas are names of services.
This is the same name the service should use in the ``config.delegate.internal.service`` key of a ``GafaelfawrIngress`` resource (see :ref:`ingress`) or the ``delegate_to`` argument to the ``/auth`` route in a manually-configured ingress (see :ref:`manual-ingress`).
If a service name has no corresponding quota setting, access to that service will be unrestricted.

All group stanzas matching the group membership of a user are added to the ``default`` quota, and the results are reported as the quota for that user by the user information API.

Members of specific groups cannot be granted unrestricted access to an API service since a missing key for a service instead means that this group contributes no additional quota for that service.
Instead, grant effectively unlimited access by granting a very large quota number.

Redis storage
=============

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
=========

If the PostgreSQL database that Gafaelfawr should use is a Google Cloud SQL database, Gafaelfawr supports using the Cloud SQL Auth Proxy via Workload Identity.

First, follow the `normal setup instructions for Cloud SQL Auth Proxy using Workload Identity <https://cloud.google.com/sql/docs/postgres/connect-kubernetes-engine>`__.
You do not need to create the Kubernetes service account; two service accounts will be created by the Gafaelfawr Helm chart.
The names of those service accounts are ``gafaelfawr`` and ``gafaelfawr-tokens``, both in Gafaelfawr's Kubernetes namespace (by default, ``gafaelfawr``).

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

.. _helm-additional-hosts:

Additional hosts
================

Currently, Gafaelfawr only supports full interactive authentication on a single fully-qualified domain name, which must also be the primary FQDN for that Rubin Science Platform deployment.
However, it optionally can support token authentication on additional hostnames.

To do this, add the following setting:

.. code-block:: yaml

   ingress:
     additionalHosts:
       - another-host.example.com

Gafaelfawr will then take over the ``/auth`` route of all of those additional hosts.
TLS configuration must be handled by some other ingress.
The Gafaelfawr Kubernets ingress will not configure TLS for additional hosts even though Gafaelfawr requires TLS.

Only token authentication will be supported for those hostnames, and therefore ingresses using those secondary hostnames should never set ``config.loginRedirect`` to true (see :ref:`login-redirect`).

.. _helm-proxies:

Logging and proxies
===================

The default logging level of Gafaelfawr is ``info``, which will log a message for every action it takes.
To change this, set ``config.logLevel``:

.. code-block:: yaml

   config:
     logLevel: "warning"

Valid values are ``debug`` (to increase the logging), ``info`` (the default), ``warning``, or ``error``.
These values can be specified in any case.

Gafaelfawr is deployed behind a proxy server.
In order to accurately log the IP address of the client, instead of the IP address of the proxy server, it must know what IP ranges correspond to possible proxy servers rather than clients.
Set this with ``config.proxies``:

.. code-block:: yaml

   config:
     proxies:
       - "192.0.2.0/24"

If not set, defaults to the `RFC 1918 private address spaces <https://datatracker.ietf.org/doc/html/rfc1918>`__.
See :ref:`client-ips` for more details.

.. _slack-alerts:

Slack alerts
============

Gafaelfawr can optionally report uncaught exceptions to Slack.
To enable this, set ``config.slackAlerts``:

.. code-block:: yaml

   config:
     slackAlerts: true

You will also have to set the ``slack-webhook`` key in the Gafaelfawr secret to the URL of the incoming webhook to use to post these alerts.

Maintenance
===========

Timing
^^^^^^

Gafaelfawr uses two Kubernetes ``CronJob`` resources to perform periodic maintenance and consistency checks on its data stores.

The maintenance job records history and deletes active entries for expired tokens, and truncates history tables as needed.
By default, it is run hourly at five minutes past the hour.
Its schedule can be set with ``config.maintenance.maintenanceSchedule`` (a `cron schedule expression`_).

The audit job looks for data inconsistencies and reports them to Slack.
:ref:`Slack alerts <slack-alerts>` must be configured.
By default, it runs once a day at 03:00 in the time zone of the Kubernetes cluster.
Its schedule can be set with ``config.maintenance.auditSchedule`` (a `cron schedule expression`_).

.. _cron schedule expression: https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-syntax

Time limits
^^^^^^^^^^^

By default, Gafaelfawr allows its maintenance and audit jobs five minutes to run, and cleans up any completed jobs older than one day.
Kubernetes also deletes completed and failed jobs as necessary to maintain a cap on the number retained, which normally overrides the cleanup timing for the maintenance job that runs hourly.

To change the time limit for maintenance jobs (if, for instance, you have a huge user database or your database is very slow), set ``config.maintenance.deadlineSeconds`` to the length of time jobs are allowed to run for.
To change the retention time for completed jobs, set ``config.maintenance.cleanupSeconds`` to the maximum lifetime of a completed job.

OpenID Connect server
=====================

Gafaelfawr can act as an OpenID Connect identity provider for relying parties inside the Kubernetes cluster.
To enable this, set ``config.oidcServer.enabled`` to true.
If this is set, ``oidc-server-secrets`` and ``signing-key`` must be set in the Gafaelfawr Vault secret.
See :ref:`openid-connect` for more information.
