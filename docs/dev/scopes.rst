######
Scopes
######

Overview
========

Gafaelfawr makes all authorization decisions based on scopes.
Each token has zero or more scopes associated with it.
Protected services indicate which scopes are required to access that service via the scope parameter on the ``/ingress/auth`` route.
When users create their own tokens, they can choose which scopes to delegate to the user token to restrict its power.

Scopes are derived from the user's group membership as determined by their OpenID Connect claims (if OpenID Connect authentication is used), their GitHub team memberships (if GitHub authentication is used), or their LDAP group membership (if LDAP is configured).
The mapping of groups to scopes is controlled by the ``config.groupMappings`` Helm chart value.
See :ref:`scopes` for more information.

The list of supported scopes and their human-readable descriptions are configured in the ``config.knownScopes`` Helm configuration setting.
The human-readable descriptions are used in Squareone_.

For more details on how scopes are used in the Rubin Science Platform, see :dmtn:`235`.

Reserved scopes
===============

Gafaelfawr reserves scopes beginning with ``admin:`` and ``user:`` for internal use by the identity management system.
Currently, three scopes in that reserved namespace are used:

* ``admin:token`` grants token administrator powers.
  Users authenticated with a token with this scope can view, create, modify, and delete tokens for any user.
  Administrators are automatically granted this scope when they authenticate.
  The bootstrap token (configured with the ``bootstrap-token`` Kubernetes secret) is automatically granted ``admin:token`` scope.
* ``admin:userinfo`` grants access to the :samp:`/auth/api/v1/users/{username}` route, which allows retrieval of user information from LDAP (and Firestore if configured) for arbitrary usernames without having a delegated token for that user.
* ``user:token`` grants the ability to view and delete all tokens for the same user, and create and modify user tokens for that user.
  All session tokens are automatically granted this scope.

Scope inheritance
=================

Users normally begin with a session token, which is created based on OpenID Connect or GitHub authentication.
Session tokens are assigned scopes based on the user's group membership.
Reserved scopes may be automatically added based on the criteria described above.

Service tokens created by token administrators may be created with any known scope.

When a user creates a user token, they may optionally add any scope that is held by the token they use to create the user token.
When an administrator creates a user token, they may create it with any known scope.

Notebook tokens automatically get the same list of scopes as the token that triggered the creation of a notebook token.

Internal tokens get no scopes by default.
Scopes can be added to internal tokens if requested via the ``delegate_scope`` parameter to the ``/ingress/auth`` route.
The resulting internal token will have scopes equal to the intersection of the list in ``delegate_scope`` and the scopes present in the authenticating token.
This means the delegated token may have no scopes if the authenticating token doesn't have any of the requested scopes.
If the protected service wants to be assured of having a given scope in its delegated internal token, it must also make that scope mandatory for access by listing it in ``scope``.

Scope naming
============

A scope name may contain any alphanumeric ASCII character or colon (``:``), hyphen (``-``), underscore (``_``), or period (``.``).
Beyond that, scopes are arbitrary labels.
Each installation can define whatever scopes it wishes.

However, the best practice recommendation is to use either ``<system>:<component>`` or ``<verb>:<data-class>`` naming for scopes.
``admin:token`` is an example of the former.
``exec:notebook`` or ``read:tap`` are examples of the latter.
