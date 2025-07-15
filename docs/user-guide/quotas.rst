################
Quota management
################

As part of its function as the authorization service for the Rubin Science Platform, Gafaelfawr also tracks user quotas and enforces API quotas.
Base quotas and additional quota increments by group are configured in :ref:`Gafaelfawr's Helm chart <helm-quota>`.
These quotas can be temporarily overridden by using the Gafaelfawr REST API.

Types of quota
==============

Gafaelfawr tracks two types of quota for each user: API quotas and notebook quotas.
The notebook quotas are only calculated in Gafaelfawr and must be queried and enforced by some other system (normally Nublado_).

API quotas
----------

An API quota limits a user to a number of requests in each one minute interval.
After one minute, the user's usage resets and they get their full quota again.

Every named service has a separate API quota.
This quota may not exist, in which case requests to that service are not rate limited.
All requests on behalf of a user count against that user's quota, whether they are made directly by the user or indirectly by another service on behalf of the user.

The scope of a "named service" for API quota purposes is the ``config.service`` key of a ``GafaelfawrIngress`` resource (see :doc:`gafaelfawringress`).
Every ``GafaelfawrIngress`` with the same ``config.service`` value consumes the API quota by the same name.

If a user is not subject to any quota for a particular service, no quota-related HTTP headers will be present in the response.
If a quota is in place, multiple ``X-RateLimit-*`` headers will be set.
See :ref:`headers-rate-limit` for more details.
These headers are based on the rate limiting used by GitHub.

If the user exceeds their quota, subsequent requests will be rejected with an HTTP 429 response code.
That response will include the same ``X-RateLimit-*`` headers, as well as the HTTP-standard ``Retry-After`` header, which specifies the time at which the user's quota will reset.

Blocking a service
^^^^^^^^^^^^^^^^^^

Setting the API quota to zero is a special case.
This is treated as an administrative block of the accesses to the service that it affects, and all requests are rejected with a 403 error (not a 429 error).

This is normally only useful when done in quota overrides (see :ref:`quota-overrides`).

Notebook quotas
---------------

The user's notebook quota controls the maximum number of CPU equivalents and the maximum amount of memory that a user's notebook can use.
The notebook quota also includes a boolean flag, ``spawn``, which controls whether that user should be able to spawn new notebooks.

Notebook quotas are only calculated by Gafaelfawr, not tracked.
Normally, they are enforced by Nublado_.

.. _quota-overrides:

Overriding quotas
=================

Gafaelfawr supports temporary quota overrides.
This is done via the following REST API:

``GET /auth/api/v1/quota-overrides``
    Retrieves the current quota overrides in JSON format.
    Returns 404 if there are no quota overrides.

``PUT /auth/api/v1/quota-overrides``
    Creates or replaces the quota overrides.
    The body should be in JSON format.
    There is no ``PATCH`` API; the complete override configuration has to be provided.

``DELETE /auth/api/v1/quota-overrides``
    Delete the quota overrides.
    Returns 404 if there are no quota overrides and 204 on success.

These routes require a token with ``admin:token`` scope.

The body sent via ``PUT`` and returned by ``GET`` is the same format as the ``config.quota`` key for the Gafaelfawr configuration except in JSON format.

Quota overrides, unlike group quotas, are not additive.
Instead, they override (as in the name) any quota from the default or group sections.
If the quota override configuration generates a notebook quota or an API quota for a particular service, the default and group quota information for notebooks or that API are ignored completely.
Otherwise, the normal quota default and group quota information applies.
