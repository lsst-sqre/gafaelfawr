"""Constants for Gafaelfawr."""

from datetime import timedelta

__all__ = [
    "ACTOR_REGEX",
    "ALGORITHM",
    "BOT_USERNAME_REGEX",
    "CHANGE_HISTORY_RETENTION",
    "CONFIG_PATH",
    "COOKIE_NAME",
    "CURSOR_REGEX",
    "GID_MIN",
    "GID_MAX",
    "GROUPNAME_REGEX",
    "HTTP_TIMEOUT",
    "ID_CACHE_SIZE",
    "KUBERNETES_WATCH_TIMEOUT",
    "KUBERNETES_TIMER_DELAY",
    "KUBERNETES_TOKEN_INTERVAL",
    "LDAP_CACHE_SIZE",
    "LDAP_CACHE_LIFETIME",
    "LDAP_TIMEOUT",
    "MINIMUM_LIFETIME",
    "NGINX_SNIPPET",
    "OIDC_AUTHORIZATION_LIFETIME",
    "REDIS_BACKOFF_START",
    "REDIS_BACKOFF_MAX",
    "REDIS_RETRIES",
    "SCOPE_REGEX",
    "TOKEN_CACHE_SIZE",
    "UID_BOT_MIN",
    "UID_BOT_MAX",
    "UID_USER_MIN",
    "USERNAME_REGEX",
]

ALGORITHM = "RS256"
"""JWT algorithm to use for all tokens."""

CHANGE_HISTORY_RETENTION = timedelta(days=365)
"""Retention of old token change history entries."""

CONFIG_PATH = "/etc/gafaelfawr/gafaelfawr.yaml"
"""Default configuration path."""

COOKIE_NAME = "gafaelfawr"
"""Name of the state cookie."""

HTTP_TIMEOUT = 20.0
"""Timeout (in seconds) for outbound HTTP requests to auth providers."""

KUBERNETES_WATCH_TIMEOUT = 10 * 60
"""Timeout (in seconds) for the Kubernetes operator watch operation.

If this is not set, Kopf attempts to connect without a timeout. This sometimes
triggers a bug in Kubernetes where the server stops responding without closing
the connection (see https://github.com/nolar/kopf/issues/585). Instead, set an
explicit timeout.

This is the timeout sent to the Kubernetes server and is supposed to be
handled on the server side. A client-side timeout will be set for one minute
longer than this timeout in case the server doesn't handle its timeout
properly.
"""

KUBERNETES_TIMER_DELAY = 5
"""How long (in seconds) to delay timers after startup and changes.

Gafaelfawr uses a Kopf_ timer to periodically re-check service tokens stored
in secrets and regenerate them if needed.  This timer can conflict with the
update handler if changes were made to the ``GafaelfawrServiceToken`` object
while the operator was not running.  Wait this long after startup and after
any detected change to the object before processing it with the timer to try
to avoid that conflict.

This could be longer for production operation, but the test suite needs to
wait for at least this long to test timer operation, so this is a compromise.
"""

KUBERNETES_TOKEN_INTERVAL = 60 * 60
"""How frequently (in seconds) to validate service tokens stored in secrets."""

LDAP_TIMEOUT = 5.0
"""Timeout (in seconds) for LDAP queries."""

MINIMUM_LIFETIME = timedelta(minutes=5)
"""Minimum expiration lifetime for a token."""

NGINX_SNIPPET = """\
auth_request_set $auth_www_authenticate $upstream_http_www_authenticate;
auth_request_set $auth_status $upstream_http_x_error_status;
auth_request_set $auth_error_body $upstream_http_x_error_body;
error_page 403 = @autherror;
"""
"""Code snippet to put into NGINX configuration for each ingress."""

OIDC_AUTHORIZATION_LIFETIME = 60 * 60
"""How long (in seconds) an authorization code is good for."""

REDIS_BACKOFF_START = 0.2
"""How long (in seconds) to initially wait after a Redis failure.

Exponential backoff will be used for subsequent retries, up to
`REDIS_BACKOFF_MAX` total delay.
"""

REDIS_BACKOFF_MAX = 1.0
"""Maximum delay (in seconds) to wait after a Redis failure."""

REDIS_RETRIES = 10
"""How many times to try to connect to Redis before giving up."""

# The following constants define per-process cache sizes.

ID_CACHE_SIZE = 10000
"""How many UID or GID values to cache in memory."""

TOKEN_CACHE_SIZE = 5000
"""How many internal or notebook tokens to cache in memory."""

LDAP_CACHE_SIZE = 1000
"""Maximum numbr of entries in LDAP caches."""

LDAP_CACHE_LIFETIME = 5 * 60
"""Lifetime of the LDAP caches in seconds."""

# The following constants define the limits of UID and GID ranges when
# Gafaelfawr is doing UID and GID assignment.

UID_BOT_MIN = 100000
"""Minimum UID for bot users."""

UID_BOT_MAX = 199999
"""Maximum UID for bot users."""

UID_USER_MIN = 3000000
"""Minimum UID for users."""

GID_MIN = 2000000
"""Minimum GID for groups."""

GID_MAX = 2999999
"""Maximum gid for groups."""

# The following constants are used for field validation.  Minimum and maximum
# length are handled separately.

BOT_USERNAME_REGEX = "^bot-[a-z0-9](?:[a-z0-9]|-[a-z0-9])*$"
"""Regex matching a valid username that is also a bot user."""

CURSOR_REGEX = "^p?[0-9]+_[0-9]+$"
"""Regex matching a valid cursor."""

GROUPNAME_REGEX = "^[a-zA-Z][a-zA-Z0-9._-]*$"
"""Regex matching all valid group names."""

SCOPE_REGEX = "^[a-zA-Z0-9:._-]+$"
"""Regex matching a valid scope."""

USERNAME_REGEX = (
    "^[a-z0-9](?:[a-z0-9]|-[a-z0-9])*[a-z](?:[a-z0-9]|-[a-z0-9])*$"
)
"""Regex matching all valid usernames."""

ACTOR_REGEX = f"{USERNAME_REGEX}|^<[a-z]+>$"
"""Regex matching all valid actors (including ``<bootstrap>``)."""
