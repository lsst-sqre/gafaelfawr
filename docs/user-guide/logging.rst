#######
Logging
#######

Gafaelfawr uses structlog_ (via Safir_) to log all its internal messages in JSON.
It is run via uvicorn_, which also logs all requests in the standard Apache log format.
Interesting events that are not obvious from the access logging done by uvicorn are logged at the ``INFO`` level.
User errors are logged at the ``WARNING`` level.
Gafaelfawr or other identity management errors are logged at the ``ERROR`` level.

Log attributes
==============

The main log message will be in the ``event`` attribute of each log message.
If this message indicates an error with supplemental information, the additional details of the error will be in the ``error`` attribute.

Gafaelfawr will add some consistent attributes to log messages, in addition to the default attributes `added by Safir <https://safir.lsst.io/user-guide/logging.html>`__.
All authenticated routes add the following attributes once the user's token has been located and verified:

``scopes``
    The scopes of the authentication token.

``token``
    The key of the authentication token.

``token_source``
    Where the token was found.
    Chosen from ``cookie`` (found in the session cookie), ``bearer`` (provided as a bearer token in an ``Authorization`` header), or ``basic-username`` or ``basic-password`` (provided as the username or password in an HTTP Basic ``Authorization`` header).

``user``
    The username of the token.

The ``/ingress/auth`` route adds the following attributes:

``auth_uri``
    The URL being authenticated.
    This is the URL of the original request that Gafaelfawr is being asked to authenticate via a subrequest.

``quota``
    Information about the API quota, if there is any.
    If set, this will be a dictionary with three keys: ``limit``, set to the API quota limit applied to this user and service; ``used``, set to the number of requests in the current quota interval; and ``reset``, set to the time at which the current quota interval ends.

``required_scope``
    The list of scopes required, taken from the ``scope`` query parameter

``satisfy``
    The authorization strategy, taken from the ``satisfy`` query parameter.

``service``
    The name of the underlying service, if known.

The ``/login`` route adds the following attributes:

``return_url``
    The URL to which the user will be sent after successful authentication.

Routes that create or modify tokens will log the new details of the token in some or all of the following attributes:

``token_expires``
    The expiration time of the token, in ISO 8601 format but with the ``T`` separator replaced with a space.

``token_key``
    The key of the new token.

``token_name``
    The name of the token.

``token_scopes``
    The scopes of the newly-created token (not to be confused with ``scopes``, which are the scopes of the token used to authenticate the request).

``token_service``
    The service for which this delegated token was created, used only for internal tokens.

``token_userinfo``
    User identity information stored with the token.
    This information will override any information coming from external sources, such as LDAP or Firestore.
    It is a dictionary, with possible keys including ``name``, ``email``, ``uid``, ``gid``, and ``groups``.

``token_username``
    The username of the new token.
    This is often omitted when a user is creating a token for themselves, and the username of the token therefore matches ``user``.
