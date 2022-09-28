##############
Administrators
##############

Gafaelfawr has a concept of token administrators.
Those users can add and remove other administrators and can create a service or user token for any user.
Currently, this capability is only available via the API, not the UI.

If a username is marked as a token administrator, that user will be automatically granted the ``admin:token`` scope when they authenticate (via either GitHub or OpenID Connect), regardless of their group membership.
They can then choose whether to delegate that scope to any user tokens they create.

The initial set of administrators can be added with the ``config.initialAdmins`` Helm variable (see :ref:`basic-settings`) or via the bootstrap token.

.. _bootstrapping:

Bootstrapping
=============

Gafaelfawr can be configured with a special token, called the bootstrap token.
This token must be generated with ``gafaelfawr generate-token`` and then stored in the ``bootstrap-token`` key of the Gafaelfawr Vault secret.
See :ref:`vault-secrets` for more details.
It can then be used with API calls as a bearer token in the ``Authenticate`` header.

The bootstrap token acts like the token of a service or user with the ``admin:token`` scope, but can only access specific routes, namely ``/auth/api/v1/tokens`` and those under ``/auth/api/v1/admins``.
