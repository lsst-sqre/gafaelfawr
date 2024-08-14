#######
Metrics
#######

Gafaelfawr optionally supports exporting metrics to an OpenTelemetry_ collector.
To enable this support, see :ref:`config-metrics`.

All metrics are logged with a service name of ``gafaelfawr``.

If metrics collection is enabled, the following metrics will currently be logged.
More metrics will likely be added in the future.

Frontend metrics
================

The following metrics are logged with the meter name of ``frontend``:

login.attempts (counter)
    Count of times Gafaelfawr sends a user to the identity provider to authenticate, not including duplicate redirects when the user already has an authentication in progress.
    Duplicates are suppressed by not counting redirects if the ``state`` attribute of the user's cookie is already set.

login.enrollment (counter)
    Count of the times Gafaelfawr redirects a user to the enrollment flow.

login.failures (counter)
    Count of the times a login fails at the Gafaelfawr end, meaning that either something went wrong in Gafaelfawr itself, with the request to the remote authentication service, or via an error reported by the remote authentication service.
    This does not count cases where the authentication service never returns the user to us.
    It also does not count redirects to the enrollment flow.

login.successes (counter)
    Count of the times Gafaelfawr successfully authenticates a user and creates a new session.
    The username will be attached as the ``username`` attribute.

login.success_time (gauge)
    Total elapsed time in floating point seconds from when Gafaelfawr redirected the user for authentication to when the user successfully authenticated.
    The username will be attached as the ``username`` attribute.

request.auth (counter)
    Count of successful authentication attempts to a service.
    Currently, this only counts authentications to a service that requests delegated tokens.
    The username is attached as the ``username`` attribute and the service name is attached as the ``service`` attribute.

State metrics
=============

The following metrics are logged by the Gafaelfawr maintenance cron job with the meter name of ``state``.

sessions.active_users (gauge)
    Number of users with unexpired sessions.

user_tokens.active
    Number of active (unexpired) user tokens.
