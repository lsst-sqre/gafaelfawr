#######
Metrics
#######

Gafaelfawr optionally supports exporting events to Sasquatch_.
To enable this support, see :ref:`config-metrics`.

By default, metrics are logged with an application name of ``gafaelfawr`` and a topic prefix of ``lsst.square.metrics.events``.

If event exporting is enabled, the following events will currently be logged.
More events will likely be added in the future.

Frontend metrics
================

The following events are logged by the Gafaelfawr frontend:

auth
    A user was successfully authenticated to a service.
    The username is present as the ``username`` tag.
    The service name is present as the ``service`` tag, if known.

login_attempt
    Gafaelfawr sent a user to the identity provider to authenticate, not including duplicate redirects when the user already has an authentication in progress.
    Duplicates are suppressed by not counting redirects if the ``state`` attribute of the user's cookie is already set.

login_enrollment
    Gafaelfawr redirected a user to the enrollment flow.

login_failure
    A login failed at the Gafaelfawr end, meaning that either something went wrong in Gafaelfawr itself, with the request to the remote authentication service, or via an error reported by the remote authentication service.
    This does not count cases where the authentication service never returns the user to us.
    It also does not count redirects to the enrollment flow.

login_successe
    Gafaelfawr successfully authenticated a user and created a new session.
    The username is present as the ``username`` tag.
    The length of time from initial redirect to successful authentication is present as the ``elapsed`` field, as a float number of seconds.

State metrics
=============

The following metrics are logged by the Gafaelfawr maintenance cron job.
These are also logged as events, since current Rubin Observatory infrastructure only supports events, but they are actually metrics and will switch to a metrics system once one is available.

active_user_sessions
    Number of users with unexpired sessions, sent in the ``count`` field.

active_user_tokens
    Number of active (unexpired) user tokens, sent in the ``count`` field.
