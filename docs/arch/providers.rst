########################
Authentication providers
########################

Gafaelfawr supports two choices of authentication provider: GitHub and OpenID Connect.
The authentication provider is chosen based on whether the ``github`` or ``oidc`` settings are present.
See :ref:`settings` for more information.

OpenID Connect
==============

When configured to use an OpenID Connect provider, Gafaelfawr obtains the ID token from the provider after authentication and then uses that token as the basis of a newly-issued token.
All claims will be copied from the ID token with the exception of:

- ``aud``, ``iss``, ``jti``, and ``act`` claims will be copied into a newly-created ``act`` claim and replaced with new values for the local issuer.
- ``iss`` and ``exp`` claims will be replaced.
  ``exp`` (expiration) will be set based on the issuer configuration settings.
  The expiration of the token from the OpenID Connect provider will be ignored.
- The ``scope`` claim will be dropped.
  If ``isMemberOf`` is set, a new scope claim will be created based on the ``group_mapping`` configuration setting.
  See :ref:`settings` for more details.

Registration with the OpenID Connect provider must be done in advance, outside of Gafaelfawr.
Refresh tokens are not used.

GitHub
======

GitHub does not issue JWTs, so the JWT created after GitHub authentication is based on information retrieved from the GitHub API.
In addition to the standard JWT claims, the following information is included:

``email``
    The ``email`` attribute returned by the ``/user`` API route.
``isMemberOf``
    A list of objects with ``name`` and ``id`` attributes corresponding to the user's team memberships.
    ``name`` is a string and ``id`` is a number.
    See :ref:`github-groups` for more details.
``sub``
    The ``login`` attribute returned by the ``/user`` API route, forced to lowercase.
``uid``
    The ``login`` attribute returned by the ``/user`` API route, forced to lowercase.
``uidNumber``
    The ``id`` attribute returned by the ``/user`` API route, converted to a string.
    The hope is that this is suitable for a unique UID.

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

The ``id`` attribute for each group in the ``isMemberOf`` claim will be the ``id`` of the team.
It's not clear from the GitHub API whether this value is globally unique.
Hopefully it will be.
