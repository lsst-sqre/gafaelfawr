.. _helm-settings:

##################
Helm configuration
##################

Gafaelfawr is configured as a Phalanx_ application, using the Helm chart in `the Phalanx repository <https://github.com/lsst-sqre/phalanx/tree/main/applications/gafaelfawr/>`__.
You will need to provide a :file:`values-{environment}.yaml` file for your Phalanx environment.
For examples, see the other :file:`values-{environment}.yaml` files in that directory.

In the below examples, the full key hierarchy is shown for each setting.
For example:

.. code-block:: yaml

   config:
     cilogon:
       test: true

When writing a :file:`values-{environment}.yaml` chart, you should coalesce all settings so that each level of the hierarchy appears only once.
For example, there should be one top-level ``config:`` key and all parameters that start with ``config.`` should go under that key.

You should also read the `Gafaelfawr application documentation <https://phalanx.lsst.io/applications/gafaelfawr/index.html>`__.
In particular, when bootstrapping a new Phalanx environment, see the `Gafaelfawr bootstrapping instructions <https://phalanx.lsst.io/applications/gafaelfawr/bootstrap.html>`__.

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

To enable database schema creation or upgrades, add:

.. code-block:: yaml

   config:
     upgradeSchema: true

This will enable a Helm pre-install and pre-upgrade hook that will initialize or update the database schema before the rest of Gafaelfawr is installed or updated.
This setting should be left off by default and only enabled when you know you want to initialize the database from scratch or update the schema.
When updating the schema of an existing installation, all Gafaelfawr components should be stopped before syncing Gafaelfawr.
See `the Phalanx documentation <https://phalanx.lsst.io/applications/gafaelfawr/manage-schema.html>`__ for step-by-step instructions.

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

Change the token lifetime by setting ``config.tokenLifetime``.
The default is 30 days.

.. code-block:: yaml

   config:
     tokenLifetime: 23h

Supported interval suffixes are ``w`` (weeks), ``d`` (days), ``h`` (hours), ``m`` (minutes), and ``s`` (seconds).
Several values can be specified together.
For example, ``1d6h23m`` specifies a token lifetime of one day, six hours, and 23 minutes.

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
----------------------------

Every component of Gafaelfawr defines Kubernetes resource requests and limits.
Look for the ``resources`` key at the top level of the chart and in the portions of the chart for the underlying Gafaelfawr components.

The default limits and requests were set based on a fairly lightly loaded deployment that uses OpenID Connect as the authentication provider and LDAP for user metadata.
For a heavily-loaded environment, you may need to increase the resource requests to reflect the expected resource consumption of your instance of Gafaelfawr and allow Kubernetes to do better scheduling.
You will hopefully not need to increase the limits, which are generous.

Authentication realm
--------------------

The default authentication realm for ``WWW-Authenticate`` headers, which is displayed as part of the HTTP Basic Authentication prompt in browsers, is the hostname of the Phalanx environment in which Gafaelfawr is installed.
This default can be overridden by setting ``config.realm``.

Base internal URL
-----------------

Gafaelfawr needs to know the internal cluster DNS domain when creating ``Ingress`` resources from ``GafaelfawrIngress`` resources.
By default, Gafaelfawr assumes that the cluster DNS domain is ``svc.cluster.local`` and the address to Gafaelfawr can be constructed by adding the name of the service and the name of the Gafaelfawr deployment namespace to the front of that domain.
If your cluster sets it to something else (by using the ``--cluster-domain`` flag, for example), or if you are running Gafaelfawr in a vCluster but running the ingress outside of that vCluster, you will need to override the internal URL to Gafaelfawr by setting ``config.baseInternalUrl``.

.. code-block:: yaml

   config:
     baseInternalUrl: "http://gafaelfawr.gafaelfawr.svc.example.com:8080"

The first component of the host name is the name of the ``Service`` resource and therefore must be ``gafaelfawr``.
Always use a port of 8080.

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

CILogon support assumes that COmanage is being used as the identity management system.
Additional information about the authenticated user will be obtained from LDAP (see :ref:`ldap`).

CILogon has some additional options under ``config.cilogon`` that you may want to set:

``config.cilogon.loginParams``
    A mapping of additional parameters to send to the CILogon authorize route.
    Can be used to set parameters like ``skin`` or ``selected_idp``.
    See the `CILogon OIDC documentation <https://www.cilogon.org/oidc>`__ for more information.

``config.cilogon.enrollmentUrl``
    If a username was not found for the CILogon unique identifier, redirect the user to this URL.
    This is intended for deployments using CILogon with COmanage for identity management.
    The enrollment URL will normally be the initial URL for a COmanage user-initiated enrollment flow.

``config.cilogon.usernameClaim``
    The claim of the OpenID Connect ID token from which to take the username.
    The default is ``username``.

Generic OpenID Connect
----------------------

Gafaelfawr should be able to support most OpenID Connect servers as sources of authentication.
This support has primarily been tested with Keycloak_.

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

Additional information for the user must come from LDAP (see :ref:`ldap`).

There are some additional options under ``config.oidc`` that you may want to set:

``config.oidc.loginParams``
    A mapping of additional parameters to send to the login route.
    Can be used to set additional configuration options for some OpenID Connect providers.

``config.oidc.enrollmentUrl``
    If a username was not found for the unique identifier in the ``sub`` claim of the OpenID Connect ID token, redirect the user to this URL.
    This could, for example, be a form where the user can register for access to the deployment, or a page explaining how a user can get access.

``config.oidc.usernameClaim``
    The claim of the OpenID Connect ID token from which to take the username.
    The default is ``uid``.

.. _ldap:

LDAP
====

When using OpenID Connect (either CILogon or generic), metadata about users (full name, email address, group membership, UID and GID, etc.) must come from an LDAP server.
If the GitHub authentication provider is used, this information instead comes from GitHub and LDAP is not supported.

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

Gafaelfawr must be told what the base DN of the group tree in LDAP is so that it can find a user's group membership.

.. code-block:: yaml

   config:
     ldap:
       groupBaseDn: "<base-dn-for-search>"

You may need to set the following additional options under ``config.ldap`` depending on your LDAP schema:

By default, the GID number of the group is taken from the ``gidNumber`` attribute of the group.
If :ref:`Firestore support <firestore>` is enabled, the GIDs in LDAP are ignored and Gafaelfawr allocates GIDs from Firestore instead.

``config.ldap.groupObjectClass``
    The object class from which group information should be looked up.
    Default: ``posixGroup``.

``config.ldap.groupMemberAttr``
    The member attribute of that object class.
    The values must match the username returned in the token from the OpenID Connect authentication server, or (if ``config.ldap.groupSearchByDn`` is set) the user DN formed from that username and the configuration options described in :ref:`ldap-user`.
    Default: ``member``.

``config.ldap.groupSearchByDn``
    By default, Gafaelfawr searches the ``config.ldap.groupMemberAttr`` attribute for the user's DN (formed by combining the username with ``config.ldap.userSearchAttr`` (as the attribute name for the first DN component containing the username) and ``config.ldap.userBaseDn`` (for the rest of the DN).
    This is the configuration used by most LDAP servers.
    If this option is set to false, the group tree is searched for the bare username instead.

``config.ldap.addUserGroup``
    If set to true, add an additional group to the user's group membership with a name equal to their username and a GID equal to their UID (provided they have a UID; if not, no group is added).
    Use this in environments with user private groups that do not appear in LDAP.
    In order to safely use this option, the GIDs of regular groups must be disjoint from user UIDs so that the user's UID can safely be used as the GID of this synthetic group.
    Default: false.

The name of each group will be taken from the ``cn`` attribute and the GID will be taken from the ``gidNumber`` attribute.

.. _ldap-user:

LDAP user information
---------------------

For any authentication mechanism other than GitHub, Gafaelfawr looks up the user's name, email, and, optionally, the numeric UID and GID in LDAP.
Name and email are optional and allowed to be missing.
To do this, Gafaelfawr must be told the base DN of the user tree in LDAP:

.. code-block:: yaml

   config:
     ldap:
       userBaseDn: "<base-dn-for-search>"

By default, this will get the name from the ``displayName`` attribute, the email (from the ``mail`` attribute, the UID from the ``uidNumber`` attribute, and the primary GID from the ``gidNumber`` attribute.
These attribute names be overridden; see below.
If any have multiple values, the first one will be used.

If this GID does not match the GID of any of the user's groups, the corresponding group will be looked up in LDAP by GID and added to the user's group list.
This handles LDAP configurations where only supplemental group memberships are recorded in LDAP, and the primary group membership is recorded only via the user's GID.

If ``config.ldap.gidAttr`` is set to null or the primary GID is missing from LDAP, but user private groups is enabled with ``addUserGroup: true``, the primary GID will be set to the same as the UID.
This is the same as the GID of the synthetic user private group.
Otherwise, the primary GID will be left unset, which may break applications that require a primary GID.

If :ref:`Firestore support <firestore>` is enabled, the UID and GID in LDAP are ignored and Gafaelfawr allocates UIDs and GIDs from Firestore instead.

You may need to set the following additional options under ``config.ldap`` depending on your LDAP schema:

``config.ldap.emailAttr``
    The attribute from which to get the user's email address.
    Set to null to not look up email addresses.
    Default: ``mail``.

``config.ldap.gidAttr``
    The attribute holding the user's primary GID number.
    Set to null to not look up primary GID numbers from LDAP, although be aware that some services may require a primary GID.
    This attribute is only used if :ref:`Firestore <firestore>` is not used for UID and GID assignment and ``config.ldap.addUserGroup`` is not set.
    Default: ``gidNumber``.

``config.ldap.nameAttr``
    The attribute from which to get the user's full name.
    This attribute should hold the whole name that should be used, not just a surname or family name (which are not universally valid concepts anyway).
    Set to null to not look up full names.
    Default: ``displayName``.

``config.ldap.uidAttr``
    The attribute holding the user's UID number.
    This can be set to null if UIDs should instead come from :ref:`Firestore <firestore>`.
    Default: ``uidNumber``.

``config.ldap.userSearchAttr``
    The attribute holding the username, used to find the user's entry.
    If ``config.ldap.groupSearchByDn`` is true (the default), this should also be the attribute used to construct the user DN.
    Default: ``uid``.

.. _firestore:

Firestore UID/GID assignment
============================

Gafaelfawr can manage UID and GID assignment internally, using `Google Firestore <https://cloud.google.com/firestore>`__ as the storage mechanism.
:ref:`Cloud SQL <cloudsql>` must also be enabled.
The same service account used for Cloud SQL must have read/write permissions to Firestore.

When this support is enabled, Gafaelfawr ignores any UID and GID information from GitHub or LDAP, and instead assigns UIDs and GIDs to users and groups by name the first time that a given username or group name is seen.
UIDs and GIDs are never reused.
They are assigned from the ranges documented in :dmtn:`225`.

To enable use of Firestore for UID/GID assignment, add the following configuration:

.. code-block:: yaml

   config:
     firestore:
       project: "<google-project-id>"

Set ``<google-project-id>`` to the name of the Google project for the Firestore data store.
(Best practice is to make a dedicated project solely for Firestore, since there can only be one Firestore instance per Google project.)

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

When CILogon or generic OpenID Connect are used as the providers, the group information comes from LDAP.
That group membership will then be used to determine scopes via the ``groupMapping`` configuration.
For those authentication providers, the group names are simple strings.
For example, suppose the Gafaelfawr configuration reads:

.. code-block:: yaml

   config:
     groupMapping:
       "exec:admin": ["foo", "bar"]

A user who is a member of the ``bar`` and ``other`` groups will have the ``exec:admin`` scope added to their token when it is issued.

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
             cpu: 0.0
             memory: 4.0
        g_limited:
          notebook:
            cpu: 0.0
            memory: 0.0
            spawn: false
      bypass:
        - "g_admins"

API quotas are in requests per 15 minutes.
Notebook quotas are in CPU equivalents and GiB of memory.
If spawn is set to false, users should not be allowed to spawn a new user notebook.
Members of groups listed in ``bypass`` ignore all quota restrictions.

The above example sets an API quota for the ``datalinker`` service of 1000 requests per 15 minutes, and a default quota for user notebooks of 2.0 CPU equivalents and 4.0GiB of memory.
Users who are members of the ``g_developers`` group get an additional 4.0GiB of memory for their notebooks.
Users who are members of the ``g_limited`` group are not allowed to spawn notebooks.
(Note that the CPU and memory quota additions must be specified, even if they are zero.)
Users who are members of the ``g_admins`` group ignore all quota restrictions.

The keys for API quotas are names of services.
This is the same name the service should use in the ``config.service`` key of a ``GafaelfawrIngress`` resource (see :ref:`ingress`).
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
The names of those service accounts are ``gafaelfawr`` and ``gafaelfawr-operator``, both in Gafaelfawr's Kubernetes namespace (by default, ``gafaelfawr``).

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

Alerts, metrics, and tracing
============================

.. _config-metrics:

Metrics
-------

Gafaelfawr can export events and metrics to Sasquatch_, the metrics system for Rubin Observatory.
Metrics reporting is disabled by default.
To enable it, set ``config.metrics.enabled`` to true:

.. code-block:: yaml

   config:
     metrics:
       enabled: true

Gafaelfawr will then use the Kafka user ``gafaelfawr`` to authenticate to Kafka and push various events.
For a list of all of the events Gafaelfawr exports, see :doc:`metrics`.

There are some additional configuration settings, which normally will not need to be changed:

``config.metrics.application``
    Name of the application under which to log metrics.
    Default: ``gafaelfawr``

``config.metrics.events.topicPrefix``
    The prefix for events topics.
    Generally the only reason to change this is if you're experimenting with new events in a development environment.
    Default: ``lsst.square.metrics.events``

``config.metrics.schemaManager.registryUrl``
    URL to the Confluent-compatible Kafka schema registry, used to register the schemas for events during startup.
    Default: Use the Sasquatch schema registry in the local cluster.

``config.metrics.schemaManager.suffix``
    Suffix to add to all registered subjects.
    This avoids conflicts with existing registered schemas and may be useful when experimenting with possible event schema changes that are not backwards-compatible.
    Default: no suffix

.. _slack-alerts:

Slack alerts
------------

Gafaelfawr can optionally report uncaught exceptions to Slack.
To enable this, set ``config.slackAlerts``:

.. code-block:: yaml

   config:
     slackAlerts: true

You will also have to set the ``slack-webhook`` key in the Gafaelfawr secret to the URL of the incoming webhook to use to post these alerts.

Sentry
------

Gafaelfawr can optionally report uncaught exceptions, traces, and performance information to Sentry_.
To enable this, set ``config.enableSentry``:

.. code-block:: yaml

   config:
     enableSentry: true

You will also have to set the ``sentry-dsn`` key in the Gafaelfawr secret to the URL to which the telemetry will be sent.

Maintenance
===========

Timing
------

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
-----------

By default, Gafaelfawr allows its maintenance and audit jobs five minutes to run, and cleans up any completed jobs older than one day.
Kubernetes also deletes completed and failed jobs as necessary to maintain a cap on the number retained, which normally overrides the cleanup timing for the maintenance job that runs hourly.

To change the time limit for maintenance jobs (if, for instance, you have a huge user database or your database is very slow), set ``config.maintenance.deadlineSeconds`` to the length of time jobs are allowed to run for.
To change the retention time for completed jobs, set ``config.maintenance.cleanupSeconds`` to the maximum lifetime of a completed job.

.. _helm-oidc-server:

OpenID Connect server
=====================

Gafaelfawr can act as an OpenID Connect identity provider for relying parties inside the Kubernetes cluster.
To enable this, set ``config.oidcServer.enabled`` to true.
If this is set, ``oidc-server-secrets`` and ``signing-key`` must be set in the Gafaelfawr Vault secret.

Gafaelfawr can provide an OpenID Connect ID token claim listing the data releases to which the user has access.
To do so, it must be configured with a mapping of group names to data releases to which membership in that group grants access.
This is done via the ``config.oidcServer.dataRightsMapping`` setting.
For example:

.. code-block:: yaml

   config:
     oidcServer:
       dataRightsMapping:
         g_users:
           - "dp0.1"
           - "dp0.2"
           - "dp0.3"
         g_preview:
           - "dp0.1"

This configuration indicates members of the ``g_preview`` group have access to the ``dp0.1`` release and members of the ``g_users`` group have access to all of ``dp0.1``, ``dp0.2``, and ``dp0.3``.
Users have access to the union of data releases across all of their group memberships.

See :ref:`openid-connect` for more information.
See :dmtn:`253` for how this OpenID Connect support can be used by International Data Access Centers.

The following additional options customize the behavior of the OpenID Connect server:

``config.oidcServer.issuer``
    The issuer identity (the ``iss`` claim in JWTs).
    Default: The base URL of the Phalanx environment.

``config.oidcServer.keyId``
    The key ID of the signing key (the ``kid`` claim in JWTs).
    Default: ``gafaelfawr``
