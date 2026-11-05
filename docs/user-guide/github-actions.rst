.. _github-actions:

#############################
GitHub Actions token exchange
#############################

Gafaelfawr can exchange the OpenID Connect ID token that GitHub issues to a GitHub Actions job for a short-lived Gafaelfawr token.
A workflow can then call services in the Phalanx environment without storing a long-lived Gafaelfawr token as a GitHub Actions secret.
See :sqr:`120` for the design.

Which repositories may do this, what scopes they receive, and how long the token lives are governed by a registry of GitHub projects.
A project binds a set of constraints on the claims of the GitHub ID token to a bot username and a token policy.
Token administrators manage the registry through the admin API described on this page.

.. note::

   The exchange endpoint that workflows call to obtain a token is not yet available.
   This page will be extended with instructions for workflows when it is.

Configure Gafaelfawr
====================

Set ``config.githubTokenExchange.enabled`` to true in the Gafaelfawr Helm values.
For the available settings, including the audience and the maximum token lifetime, see :ref:`helm-github-token-exchange`.
Each Phalanx environment has its own registry, so a repository that needs tokens in two environments must be registered in both.

.. _github-actions-register:

Register a GitHub project
=========================

Projects are registered via ``POST`` of a JSON object to the ``/auth/api/v1/github/projects`` route.
The GitHub Actions token exchange must be enabled for that route to be available.
The token or cookie used to authenticate to this route must have the ``admin:token`` scope, the same scope required to create service tokens for arbitrary bot users.
The bootstrap token may also be used.

The body of the registration request contains the following fields:

``repository``
    The GitHub repository as ``owner/name``.
    This is matched case-insensitively against the ``repository`` claim of the ID token.
    The repository must be public, since Gafaelfawr looks it up through the GitHub API without credentials.

``scopes``
    The maximum scopes a token minted for this project may carry, as a list of strings.
    Each must be a scope known to this Gafaelfawr installation.
    ``admin:`` scopes are reserved and may not be granted.
    The list may be empty for a project whose tokens are used only for identity.

``username`` (optional)
    The bot username for which tokens are minted.
    It must begin with ``bot-gh-`` and otherwise be a valid Gafaelfawr username.
    If omitted, the username is derived from the repository as ``bot-gh-<owner>-<repo>``, lowercased, with any character that is not a letter or digit replaced with a hyphen.
    Several projects may share one username, which is intended for several projects for the same repository with different policies.
    If the derived username is already used by a project for a different repository, registration is refused and an explicit username must be given.

``workflow`` (optional)
    The workflow file that may obtain tokens, compared against the path part of the ``job_workflow_ref`` claim.
    Give either ``.github/workflows/<file>`` for a workflow in the project repository, or ``<owner>/<repo>/.github/workflows/<file>`` for a reusable workflow in another repository.
    If omitted, any workflow matches.

``environment`` (optional)
    The GitHub Actions environment name, compared against the ``environment`` claim.
    If set, tokens from jobs that do not use that environment never match.
    If omitted, any environment matches.

``ref`` (optional)
    The Git ref, compared against the ``ref`` claim.
    Give either an exact value such as ``refs/heads/main`` or a prefix ending in ``/`` such as ``refs/tags/``.
    If omitted, any ref matches, including pull request refs.

``max_lifetime`` (optional)
    The maximum lifetime of a minted token, as a number of seconds or an ISO 8601 duration such as ``PT1H``.
    It may not exceed the maximum lifetime configured for the token exchange.
    If omitted, it defaults to one hour or the configured maximum, whichever is shorter.

``uid``, ``gid``, ``groups`` (optional)
    Identity attributes to store with minted tokens, as for service tokens created through the admin token API.
    They matter only where a service resolves the caller's identity through Gafaelfawr's user information routes and the bot user has no entry in the identity source of the environment.

``enabled`` (optional)
    Whether the project may match tokens.
    Defaults to true.
    A disabled project is kept but never matches.

``description`` (optional)
    A human-readable, free-form description of this project.
    Provide enough information to help someone reviewing the registry several years in the future.

``requested_by`` (optional)
    An opaque identifier of the person on whose behalf the project was created, as ``<source>:<identifier>``, such as ``slack:U024BE7LH`` or ``gafaelfawr:someuser``.
    It is recorded and can be used as a filter when listing projects but is never interpreted.

Unset constraints match anything, so a project with only a repository accepts every workflow, event, and branch of that repository.
Set the narrowest constraints the use case allows.
A project that publishes something, for example, should pin the workflow and restrict the ref to ``refs/heads/main`` or to ``refs/tags/``.

For example, to register a project for documentation builds of the SQR-062 technote, restricted to the ``docs.yaml`` workflow on the default branch:

.. code-block:: json

   {
     "description": "Documentation builds for SQR-062",
     "repository": "lsst-sqre/sqr-062",
     "workflow": ".github/workflows/docs.yaml",
     "ref": "refs/heads/main",
     "scopes": ["write:docverse"],
     "max_lifetime": "PT1H"
   }

On successful registration, the response has status 201, a ``Location`` header with the URL of the new project, and a body containing the stored project.
In addition to the fields of the request, the stored project has the following fields:

``id``
    The unique identifier of the project.
    It is used in the URLs of the admin API and recorded on every token minted for the project.

``username``
    The resolved bot username, whether given explicitly or derived from the repository.

``repository_id``, ``repository_owner_id``
    The numeric GitHub IDs of the repository and its owner, looked up when the project was registered.
    They are compared against the corresponding claims at every exchange, so the project keeps trusting the original repository even if it is renamed or its name is later reused by someone else.
    Check them against the intended repository.

``template``
    The name of the project template the project was provisioned from, or null for projects registered through this route.

``created``, ``created_by``, ``modified``, ``modified_by``
    When the project was created and last modified, and the username of the token that made each change.

Durations in responses are always ISO 8601.

At most one project may match a given ID token, so registration is refused with status 409 if the project is enabled and its constraints overlap those of an existing enabled project for the same repository.
Two projects overlap when a token could satisfy both: for each of ``workflow``, ``environment``, and ``ref``, the constraint is unset in at least one of them, the values are equal, or one ref is a prefix of the other.
The error names the conflicting project.
To give one repository a general policy and a narrower one, register disjoint projects, for example one for ``refs/pull/`` and another for ``refs/heads/main``.
If the repository lookup fails because GitHub is unavailable or the anonymous API rate limit was exceeded, registration is refused with status 502 and should be retried later; the same applies when modifying a project's ``repository``.

List and inspect projects
=========================

``GET /auth/api/v1/github/projects`` returns every registered project, ordered by ID.
The results can be limited with the query parameters ``repository`` (compared case-insensitively), ``username``, ``template``, and ``requested_by``, which combine when several are given.
``GET /auth/api/v1/github/projects/{id}`` returns one project.
Both routes require the ``admin:token`` scope.

Modify a project
================

Any field of the registration request can be changed with a ``PATCH`` request to ``/auth/api/v1/github/projects/{id}`` containing only the fields to change.
The pinned ``repository_id`` and ``repository_owner_id`` follow the repository and cannot be set directly, and ``template`` cannot be changed through this API.
A request that changes nothing leaves the project untouched, including its modification time, and is not recorded in the project history.
Setting an optional field to null clears it.
Setting ``username`` to null derives it from the repository again.
Changing ``repository`` looks up its numeric IDs again but keeps the username unless it is also changed, since the bot identity should not move when the repository is renamed.
Changes to the constraints are checked for overlap with other enabled projects as on registration.

Setting ``enabled`` to false revokes every outstanding token minted for the project.
Other changes, such as to the scopes or constraints, do not affect tokens already minted.
To make a tightened policy take effect at once, disable and then re-enable the project.

Delete a project
================

A ``DELETE`` request to ``/auth/api/v1/github/projects/{id}`` deletes the project, revokes every outstanding token minted for it, and responds with status 204.

Audit history
=============

Every change to the registry is recorded in the ``github_project_history`` table of the Gafaelfawr database, in the same style as the token change history: the action, the acting administrator, the time, the client IP address, and the project before and after the change.
Tokens revoked by disabling or deleting a project are recorded in the token change history with the administrator who made the change as the actor.

See the :doc:`REST API documentation </api/rest>` for more information.
