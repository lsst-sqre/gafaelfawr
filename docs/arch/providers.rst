########################
Authentication providers
########################

Gafaelfawr supports two choices of authentication provider: GitHub and OpenID Connect.
The authentication provider is chosen based on whether the ``config.github.clientId`` or ``config.cilogon.clientId`` settings are present.
See :ref:`providers` for more information.

Gafaelfawr uses the authentication provider to determine the numeric UID of the user.
Be aware that changing from one authentication provider to another will likely result in UID changes for all users.
Gafaelfawr itself does not care and will pass along the new values, but protected applications that use those values may be surprised by a change.

The username obtained from the authentication provider must meet the following requirements:

* Only lowercase alphanumeric characters (GitHub usernames will be automatically lowercased) or hyphen
* May not start or end with a hyphen
* May not have two consecutive hyphens

These are the same requirements GitHub imposes.

OpenID Connect
==============

When configured to use an OpenID Connect provider, Gafaelfawr obtains the ID token from the provider after authentication and then stores key pieces of data from it as the underlying data of a token.

- Username is taken from the claim identified by the ``username_claim`` setting.
- UID is taken from the claim identified by the ``uid_claim`` setting and is converted to a number.
- Name is taken from the ``name`` claim if it exists.
- Email address is taken from the ``email`` claim if it exists.
- Groups are taken from the ``isMemberOf`` claim if it exists.
- The scope of the token will be based on the group membership from ``isMemberOf`` and the ``config.groupMapping`` Helm chart value.
  See :ref:`scopes` for more details.

Registration with the OpenID Connect provider must be done in advance, outside of Gafaelfawr.
Refresh tokens are not used.

GitHub
======

GitHub does not issue JWTs, so the token created after GitHub authentication is based on information retrieved from the GitHub API.
The username will be taken from the ``login`` value returned by the ``/user`` API route, forced to lowercase.
The UID will be taken from the ``id`` value returned by the ``/user`` API route.
The name will be taken from the ``name`` value returned by the ``/user`` API route.
The email address will be taken from the address tagged primary in the addresses returned by the ``/user/emails`` API route.
The group membership will be taken from the user's team membership.
See :ref:`github-groups` for more details.
The scope of the token will be based on the group membership and the ``group_mapping`` configuration setting.

.. _github-groups:

Groups from GitHub
------------------

Gafaelfawr synthesizes groups from GitHub teams.
Each team membership that an authenticated user has on GitHub (and releases through the GitHub OAuth authentication) will be mapped to a group in the ``isMemberOf`` claim.
The default group name is ``<organization>-<team-slug>`` where ``<organization>`` is the ``login`` attribute (forced to lowercase) of the organization containing the team and ``<team-slug>`` is the ``slug`` attribute of the team.
These values are retrieved through the ``/user/teams`` API route.
The ``slug`` attribute is constructed by GitHub based on the name.
It's a canonicalization of the name that removes case differences and replaces special characters like space with a dash.

Since group names are limited to 32 characters, if that name is longer than 32 characters, it will be truncated and made unique.
The full, long group name will be hashed (with SHA-256), and truncated at 25 characters, and then a dash and the first six characters of the URL-safe-base64-encoded hash will be appended.

The ``id`` attribute for each group will be the ``id`` of the team.
It's not clear from the GitHub API whether this value is globally unique.
Hopefully it will be.
