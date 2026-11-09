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
A service such as Templatebot can also create projects of an administrator-defined shape from a project template, under a narrower scope, as described in :ref:`github-actions-provisioning`.
Workflow authors obtain tokens as described in :ref:`github-actions-workflow`.

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
    The name of the project template the project was provisioned from (see :ref:`github-actions-provisioning`), or null for projects registered through this route.

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

.. _github-actions-provisioning:

Provision projects from templates
=================================

Most projects in the registry are for technotes, which are created by Templatebot in response to a Slack request rather than by hand.
Templatebot must create the project for a new repository before its first documentation build runs, but giving it ``admin:token`` would let a compromise of Templatebot control every identity in the environment.
Instead, an administrator defines a project template that fixes every field of a project except the repository, and Templatebot creates projects from that template with a token holding only the ``admin:github-oidc-provision`` scope.

Define a project template
-------------------------

Templates are created via ``POST`` of a JSON object to the ``/auth/api/v1/github/project-templates`` route, which requires the ``admin:token`` scope like the other registry routes.
The body of the request contains the following fields:

``name``
    The identifier of the template, used in URLs and by provisioners, such as ``technote``.
    It must consist of lowercase letters, digits, and hyphens.
    The name cannot be changed once the template is created.

``owners``
    The GitHub organizations or users whose repositories may be provisioned from this template, as a list of logins.
    Each is looked up through the GitHub API when the template is created or the list is changed, and its numeric ID is pinned alongside its name.
    A repository may be provisioned only if its owner matches an entry by name and by ID, so that an organization deleted and re-registered under the same name by someone else is not trusted.

``repository_pattern`` (optional)
    A regular expression that the name of the repository, without its owner, must match in full to be provisioned from this template.
    The match is case-insensitive, since GitHub repository names are.
    For example, ``^[a-z]+-[0-9]{3,}$`` matches the names of technote repositories.
    If omitted, any repository name is allowed.

``workflow``, ``environment``, ``ref`` (optional)
    Constraints copied into every project provisioned from the template, with the same meaning and forms as for a project.
    A ``workflow`` of the form ``.github/workflows/<file>`` is relative to the provisioned repository.

``scopes``, ``max_lifetime``, ``uid``, ``gid``, ``groups``
    The token policy copied into every project provisioned from the template, with the same meaning and restrictions as for a project.
    ``max_lifetime`` defaults as for a project if omitted.

``enabled`` (optional)
    Whether the template may be used to provision projects.
    Defaults to true.
    Projects already provisioned from a disabled template are unaffected.

``description`` (optional)
    A human-readable, free-form description of this template.

For example, a template for technotes pins the reusable workflow that every technote repository calls, leaves ``ref`` unset because an edition is published for every branch and pull request, and grants the documentation scopes:

.. code-block:: json

   {
     "name": "technote",
     "description": "Documentation builds for technotes created by Templatebot",
     "owners": ["lsst-dm", "lsst", "lsst-sqre", "lsst-sqre-testing"],
     "repository_pattern": "^[a-z]+-[0-9]{3,}$",
     "workflow": "lsst-sqre/rubin-sphinx-technote-workflows/.github/workflows/ci.yaml",
     "scopes": ["write:docverse", "exec:linkcheck"],
     "max_lifetime": "PT1H"
   }

On success, the response has status 201, a ``Location`` header with the URL of the new template, and a body containing the stored template, in which each owner is an object with ``name`` and ``id`` fields.
Templates are listed with ``GET /auth/api/v1/github/project-templates``, retrieved with ``GET /auth/api/v1/github/project-templates/{name}``, and modified with a ``PATCH`` request to that URL containing only the fields to change, as for projects.
Changing ``owners`` looks up only the owners that were not already in the list and keeps the pinned IDs of those that remain.
Changing a template affects only projects provisioned afterwards.
A fleet-wide change, such as a new path for the reusable workflow, is made by a token administrator with a script that lists the template's projects (using the ``template`` filter of the project list route) and patches each one.

A ``DELETE`` request to ``/auth/api/v1/github/project-templates/{name}`` deletes the template, provided that no project records it.
Otherwise the request fails with status 409 and a message giving the number of such projects, so that the ``template`` field of a project always names a template that exists.
A template whose projects should remain is retired by disabling it instead.

Changes to templates are recorded in the project history table alongside changes to projects.

Provision a project
-------------------

A provisioner creates a project from a template with a ``POST`` of a JSON object to ``/auth/api/v1/github/project-templates/{name}/projects``.
This is the only registry route that accepts the ``admin:github-oidc-provision`` scope; ``admin:token`` also satisfies it, since token administrators can do everything a provisioner can.
The body contains the following fields:

``repository``
    The GitHub repository as ``owner/name``, which must be public.

``description``, ``requested_by`` (optional)
    As for a project registered directly.
    Templatebot sets ``requested_by`` to the Slack user who asked for the technote, as ``slack:<user ID>``.

Gafaelfawr checks that the template is enabled, looks up the repository on GitHub as the project registration route does, and checks that its owner is in the template's ``owners`` list by name and by pinned ID and that its name matches ``repository_pattern`` if the template has one.
It then creates the project exactly as the registration route would from a request carrying the template's fields and the given repository: the username is always derived as ``bot-gh-<owner>-<repo>``, the repository IDs are pinned, overlap with existing projects is checked, and ``created_by`` and the actor in the project history are the provisioner, not the person named in ``requested_by``.
The project records the template's name in its ``template`` field.
The response is the same 201 document the registration route returns.

A provisioner cannot choose a username, scopes, constraints, or lifetime, and cannot read, modify, or delete projects or templates.
The most it can do is extend a policy an administrator wrote to a repository an administrator allowed, and it still takes write access to that repository to obtain a token.

The route is idempotent, since Templatebot may retry after a failure.
If a project for the same repository already exists and records the same template, the route returns that project with status 200 and no ``Location`` header, without changing it.
A project for the same repository created directly or from a different template conflicts as usual, with status 409 naming the conflicting project.

The provisioning errors are:

- 404 if the template does not exist.
- 409 with type ``template_disabled`` if the template is disabled.
- 422 with type ``repository_not_allowed`` if the repository owner is not allowed by the template or the repository name does not match its pattern.
  The message names the owner or repository name from the request but does not disclose the template's owners or pattern.
- 422 with type ``unknown_repository`` if the repository does not exist or is not public.
- 502 if GitHub could not be contacted, in which case the request should be retried.

Set up a provisioner
--------------------

To let a service provision projects, add ``admin:github-oidc-provision`` to ``config.knownScopes`` in the Gafaelfawr Helm values and create a service token for the service with that scope, normally as a ``GafaelfawrServiceToken`` resource in the service's Helm chart.
Because the scope begins with ``admin:``, it may not be granted to a project or template, so no GitHub workflow can obtain a token that provisions projects.
Like the registry, templates and the provisioning route exist per Phalanx environment, and a service token is valid only in the environment that issued it.


.. _github-actions-workflow:

Use the exchange from a workflow
================================

From a workflow author's point of view, obtaining a token is two steps: ask GitHub for an ID token with the right audience, and post that ID token to Gafaelfawr.
The job must have the ``id-token: write`` permission.
Grant it at the job level rather than the workflow level, so that other jobs in the workflow cannot mint tokens.

The audience must be the exact base URL of the Phalanx environment, without a trailing slash, unless the administrators of that environment have configured a different audience.
Gafaelfawr in each environment accepts only its own audience, so a workflow that talks to services in two environments requests two ID tokens and performs two exchanges.

As shell steps, the exchange looks like this:

.. code-block:: yaml

   jobs:
     upload:
       runs-on: ubuntu-latest
       permissions:
         id-token: write
         contents: read
       steps:
         - uses: actions/checkout@v5

         - name: Get a Gafaelfawr token
           id: gafaelfawr
           shell: bash
           run: |
             id_token=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
               "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://roundtable.lsst.cloud" | jq -r .value)
             token=$(curl -sSf -X POST https://roundtable.lsst.cloud/auth/api/v1/github/token \
               --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
               --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
               --data-urlencode "subject_token=$id_token" \
               --data-urlencode "scope=write:docverse" | jq -r .access_token)
             echo "::add-mask::$token"
             echo "token=$token" >> "$GITHUB_OUTPUT"

         - name: Upload to Docverse
           uses: lsst-sqre/docverse-upload@v1
           with:
             token: ${{ steps.gafaelfawr.outputs.token }}

The ``::add-mask::`` line keeps the minted token out of the job log.
Nothing in the repository's secrets is used.

The minted token is a Gafaelfawr token of type ``github`` for the bot user of the matching project.
In every other respect it behaves like a service token: it is presented as a bearer token, it carries the scopes shown in the reply, and it expires after the project's maximum lifetime.
It can be inspected and deleted through the token admin interfaces under the bot username like any other token, but it cannot be modified.

Reusable workflows
------------------

If a project constrains the workflow, the constraint is compared against the ``job_workflow_ref`` claim of the ID token.
For a job that calls a reusable workflow, that claim names the reusable workflow's file, not the calling workflow.
A project for such a job must therefore pin the reusable workflow, which for a workflow hosted in another repository means giving its full ``<owner>/<repo>/.github/workflows/<file>`` path as described in :ref:`github-actions-register`, while the project's ``repository`` is still the calling repository.
The exchange reports the ``job_workflow_ref`` of the token in every rejection for a token that matched no project, so a mismatch is easy to spot.

The exchange request
--------------------

The exchange endpoint is ``POST /auth/api/v1/github/token`` and follows the OAuth 2.0 token exchange grammar of :rfc:`8693`.
It requires no Gafaelfawr authentication; the GitHub ID token is the credential.
The request is form-encoded with the following parameters:

``grant_type``
    Must be ``urn:ietf:params:oauth:grant-type:token-exchange``.

``subject_token``
    The GitHub ID token.

``subject_token_type``
    Must be ``urn:ietf:params:oauth:token-type:id_token``.

``scope`` (optional)
    A space-separated list of scopes for the minted token.
    It must be a subset of the scopes of the matching project; a request for a scope outside that set is rejected rather than silently narrowed, so that a misconfigured workflow fails visibly.
    If omitted, the token receives every scope of the project.
    An empty ``scope`` is treated as omitted, but one containing only whitespace is rejected.

The other :rfc:`8693` parameters (``resource``, ``audience``, ``requested_token_type``, ``actor_token``, and ``actor_token_type``) are not supported and are rejected if present.
There is no parameter for the lifetime; the token always receives the project's maximum lifetime, capped by the maximum configured for the environment.

A successful response has status 200, carries ``Cache-Control: no-store``, and has a JSON body such as:

.. code-block:: json

   {
     "access_token": "gt-vHj2M0OdtGVmwq3vz0u4iw.vk_fmBhUSsFndqRgvSi9ow",
     "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
     "token_type": "Bearer",
     "expires_in": 3600,
     "scope": "write:docverse"
   }

``access_token`` is the Gafaelfawr token, ``expires_in`` is its remaining lifetime in seconds, and ``scope`` is the space-separated list of scopes it carries.

Errors have status 400 and an OAuth 2.0 error document with ``error`` and ``error_description`` fields:

``invalid_request``
    The request is malformed: a required parameter is missing, ``subject_token_type`` is not supported, ``scope`` contains only whitespace, or an unsupported parameter is present.

``unsupported_grant_type``
    ``grant_type`` is not token exchange.

``invalid_grant``
    The ID token failed verification, or it verified but matched no enabled project.
    The description names the check that failed.
    For a token that matched no project, it gives the repository and its IDs, the ``job_workflow_ref``, the ref, and the environment from the token, so that the author can compare them against the project's constraints.
    It never describes the projects that did not match.

``invalid_scope``
    A requested scope is not allowed by the matching project.
    The description names the refused scopes.

If the exchange is not enabled in the environment, the response has status 404.
If GitHub's signing keys cannot be retrieved, so that the ID token cannot be verified, the response has status 502 with the error ``temporarily_unavailable`` and should be retried.

Audit history
=============

Every change to the registry is recorded in the ``github_project_history`` table of the Gafaelfawr database, in the same style as the token change history: the action, the acting administrator or provisioner, the time, the client IP address, and the project or template before and after the change.
Entries for changes to a template and for projects provisioned from it both record the template's name, so the history of a template includes everything it has produced.
Tokens revoked by disabling or deleting a project are recorded in the token change history with the administrator who made the change as the actor.

Every token minted by the exchange is recorded in the token change history with the ``github`` token type, the project ID, the bot username as the actor, and the address of the GitHub Actions runner.
The history can be filtered by type through the ``token_type`` query parameter of ``/auth/api/v1/history/token-changes``, so every token the exchange has ever minted can be listed in one query.
In addition, each exchange is logged and emits a ``github_token_exchange`` metrics event carrying the project ID, the bot username, the token key, and the ``repository``, ``job_workflow_ref``, ``ref``, ``environment``, ``event_name``, ``actor``, ``run_id``, ``run_attempt``, and ``jti`` claims of the ID token.
This is enough to find, for any token, exactly which workflow run obtained it and who triggered that run.

See the :doc:`REST API documentation </api/rest>` for more information.
