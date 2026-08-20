:og:description: Learn how to bootstrap the Gafaelfawr server.

.. _bootstrapping:

#############
Bootstrapping
#############

Normally, administrative Gafaelfawr actions should be done by a user, possibly via a user token they created, with appropriate ``admin:token``, ``admin:oidc``, or ``admin:userinfo`` scopes, depending on what APIs they want to use.
However, assignment of scopes to users depends on the user information source, which may prevent access to Gafaelfawr APIs if the user information service is down or misconfigured.

Gafaelfawr can be configured with a special token, called the bootstrap token.
This token must be generated with :command:`gafaelfawr generate-token` and then stored in the ``bootstrap-token`` key of the Gafaelfawr Vault secret.
See :ref:`vault-secrets` for more details.
It can then be used with API calls as a bearer token in the ``Authenticate`` header.

The bootstrap token acts like the token of a service or user with the ``admin:token`` scope, but can only access specific routes, namely ``/auth/api/v1/tokens``.
This allows it to be used to create user tokens for arbitrary users and with arbitrary scopes, including privileged scopes such as ``admin:token``
Those tokens can then be used to access all of the Gafaelfawr API regardless of the state of the user information service.
