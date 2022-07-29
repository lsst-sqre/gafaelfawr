########################
Authentication providers
########################

Gafaelfawr supports two choices of authentication provider: GitHub and OpenID Connect.
The authentication provider is chosen based on whether the ``config.github.clientId``, ``config.cilogon.clientId``, or ``config.oidc.clientId`` settings are present.
See :ref:`providers` for more information.

The username obtained from the authentication provider must meet the requirements specified in :dmtn:`225`.

OpenID Connect
==============

When configured to use an OpenID Connect provider (either CILogon or generic OpenID Connect), Gafaelfawr obtains the ID token from the provider after authentication and then stores key pieces of data from it as the underlying data of a token.

- Username is taken from the claim set in the ``config.cilogon.usernameClaim`` or ``config.oidc.usernameClaim`` setting.
- UID (unless LDAP or Firestore are used for UIDs) is taken from the claim set in the ``config.cilogon.uidClaim`` or ``config.oidc.uidClaim`` setting and is converted to a number.
- Name (unless LDAP is used) is taken from the ``name`` claim if it exists.
- Email address (unless LDAP is used) is taken from the ``email`` claim if it exists.
- Groups (unless LDAP is used) are taken from the ``isMemberOf`` claim if it exists.

The scope of the token will be based on the group membership and the ``config.groupMapping`` Helm chart value.
See :ref:`scopes` for more details.

Registration with the OpenID Connect provider must be done in advance, outside of Gafaelfawr.
Refresh tokens are not used.

GitHub
======

The token created after GitHub authentication is based on information retrieved from the GitHub API.
The username will be taken from the ``login`` value returned by the ``/user`` API route, forced to lowercase.
The UID will be taken from the ``id`` value returned by the ``/user`` API route.
The name will be taken from the ``name`` value returned by the ``/user`` API route.
The email address will be taken from the address tagged primary in the addresses returned by the ``/user/emails`` API route.
The group membership will be taken from the user's team membership.
See :ref:`github-groups` for more details.
The scope of the token will be based on the group membership and the ``config.groupMapping`` configuration setting.

LDAP and Firestore are not supported as sources of user metadata when GitHub is used as an authentication provider.

.. _github-groups:

Groups from GitHub
------------------

Gafaelfawr synthesizes groups from GitHub teams.
Each team membership that an authenticated user has on GitHub (and releases through the GitHub OAuth authentication) will be mapped to a group.
The default group name is ``<organization>-<team-slug>`` where ``<organization>`` is the ``login`` attribute (forced to lowercase) of the organization containing the team and ``<team-slug>`` is the ``slug`` attribute of the team.
These values are retrieved through the ``/user/teams`` API route.
The ``slug`` attribute is constructed by GitHub based on the name.
It's a canonicalization of the name that removes case differences and replaces special characters like space with a dash.

Since group names are limited to 32 characters, if that name is longer than 32 characters, it will be truncated and made unique.
The full, long group name will be hashed (with SHA-256), and truncated at 25 characters, and then a dash and the first six characters of the URL-safe-base64-encoded hash will be appended.

The GID for each group will be the ``id`` of the team.
