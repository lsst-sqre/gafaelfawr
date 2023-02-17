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

Set the URL to the PostgreSQL database that Gafaelfawr will use:

.. code-block:: yaml

   config:
     databaseUrl: "postgresql://gafaelfawr@example.com/gafaelfawr"

Do not include the password in the URL; instead, put the password in the ``database-password`` key in the Vault secret.
If you are using Cloud SQL with the Cloud SQL Auth Proxy (see :ref:`cloudsql`), use ``localhost`` for the hostname portion.

To add additional information to the error page from a failed login, set ``config.errorFooter`` to a string.
This string will be embedded verbatim, inside a ``<p>`` tag, in all login error messages.
It may include HTML and will not be escaped.
This is a suitable place to direct the user to support information or bug reporting instructions.

Consider increasing the number of Gafaelfawr processes to run.
This improves robustness and performance scaling.
Production deployments should use at least two replicas.

.. code-block:: yaml

   replicaCount: 2

Change the token lifetime by setting ``config.tokenLifetimeMinutes``.
The default is 1380 (23 hours).

.. code-block:: yaml

   config:
     tokenLifetimeMinutes: 43200  # 30 days

This setting will also affect the lifetime of tokens issued by the OpenID Connect server, if enabled.

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
This was required to support at least one Keycloak installation.

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

``config.oidc.usernameClaim``
    The claim of the OpenID Connect ID token from which to take the username.
    The default is ``uid``.

.. _ldap-groups:

LDAP groups
===========

When using either CILogon or generic OpenID Connect as an authentication provider, you can choose to obtain group information from an LDAP server rather than an ``isMemberOf`` attribute inside the token.

To do this, add the following configuration:

.. code-block:: yaml

   config:
     ldap:
       url: "ldaps://<ldap-server>"
       groupBaseDn: "<base-dn-for-search>"

You may need to set the following additional options under ``config.ldap`` depending on your LDAP schema:

``config.ldap.userDn``
    The DN of the user to bind as.
    Gafaelfawr currently only supports simple binds.
    If this is set, ``ldap-password`` must be set in the Gafaelfawr Vault secret to the password to use with the simple bind.

``config.ldap.groupObjectClass``
    The object class from which group information should be looked up.
    Default: ``posixGroup``.

``config.ldap.groupMemberAttr``
    The member attribute of that object class.
    The values must match the username returned in the token from the OpenID Connect authentication server.
    Default: ``member``.

``config.ldap.addUserGroup``
    If set to ``true``, add an additional group to the user's group membership with a name equal to their username and a GID equal to their UID (provided they have a UID; if not, no group is added).
    Use this in environments with user private groups that do not appear in LDAP.
    In order to safely use this option, the GIDs of regular groups must be disjoint from user UIDs so that the user's UID can safely be used as the GID of this synthetic group.
    Default: ``false``.

The name of each group will be taken from the ``cn`` attribute and the GID will be taken from the ``gidNumber`` attribute.

.. _ldap-user:

LDAP user information
=====================

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

.. _scopes:

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

.. _helm-proxies:

Logging and proxies
===================

The default logging level of Gafaelfawr is ``INFO``, which will log a message for every action it takes.
To change this, set ``config.loglevel``:

.. code-block:: yaml

   config:
     loglevel: "WARNING"

Valid values are ``DEBUG`` (to increase the logging), ``INFO`` (the default), ``WARNING``, or ``ERROR``.

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

Maintenance timing
==================

Gafaelfawr uses two Kubernetes ``CronJob`` resources to perform periodic maintenance and consistency checks on its data stores.

The maintenance job records history and deletes active entries for expired tokens, and truncates history tables as needed.
By default, it is run hourly at five minutes past the hour.
Its schedule can be set with ``config.maintenance.maintenanceSchedule`` (a `cron schedule expression`_).

The audit job looks for data inconsistencies and reports them to Slack.
:ref:`Slack alerts <slack-alerts>` must be configured.
By default, it runs once a day at 03:00 in the time zone of the Kubernetes cluster.
Its schedule can be set with ``config.maintenance.auditSchedule`` (a `cron schedule expression`_).

.. _cron schedule expression: https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-syntax

OpenID Connect server
=====================

Gafaelfawr can act as an OpenID Connect identity provider for relying parties inside the Kubernetes cluster.
To enable this, set ``config.oidcServer.enabled`` to true.
If this is set, ``oidc-server-secrets`` and ``signing-key`` must be set in the Gafaelfawr Vault secret.
See :ref:`openid-connect` for more information.
