#######
Logging
#######

Gafaelfawr uses structlog to log all messages in JSON.
Most routes will log a single message at the ``INFO`` log level (the default) on success.
The ``/login`` route does a bit more work and will log more messages.
More detailed logging is available at the ``DEBUG`` level, including a snapshot of Gafaelfawr's configuration on initial startup.
User errors are logged at the ``WARNING`` level.

Log attributes
==============

The main log message will be in the ``event`` attribute of each log message.
If this message indicates an error with supplemental information, the additional details of the error will be in the ``error`` attribute.

The following attributes will be added to each log message, in addition to the default attributes added by :py:mod:`structlog`:

``logger``
    Always set to ``gafaelfawr``.

``method``
    The HTTP method of the request.

``path``
    The path portion of the HTTP request.

``remote``
    The remote IP address making the request.
    This will be taken from ``X-Forwarded-For`` if available, since Gafaelfawr is designed to be run behind a Kubernetes NGINX ingress.

``request_id``
    A unique UUID for each request.
    This can be used to correlate multiple messages logged from a single request.

``user_agent``
    The ``User-Agent`` header of the incoming request.
    This can be helpful in finding requests from a particular user or investigating problems with specific web browsers.

All authenticated routes add the following attributes once the user's token has been located and verified:

``scope``
    The ``scope`` claim of the user's token.

``token``
    The ``jti`` claim of the token.

``user``
    The username claim of the token (configured via the ``username_claim`` configuration parameter).

The ``/auth`` route adds the following attributes:

``auth_uri``
    The URL being authenticated.
    This is the URL (withough the scheme and host) of the original request that Gafaelfawr is being asked to authenticate via a subrequest.
    This will be ``NONE`` if the request was made directly to the ``/auth`` endpoint (which should not happen in normal usage, but may happen during testing).

``required_scope``
    The list of scopes required, taken from the ``scope`` query parameter

``satisfy``
    The authorization strategy, taken from the ``satisfy`` query parameter.

The ``/login`` route adds the following attributes:

``return_url``
    The URL to which the user will be sent after successful authentication.
