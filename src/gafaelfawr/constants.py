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
    "GID_MAX",
    "GID_MIN",
    "GITHUB_ACTIONS_ISSUER",
    "GITHUB_ACTIONS_JWKS_MIN_REFRESH",
    "GITHUB_ACTIONS_JWT_LEEWAY",
    "GITHUB_API_URL",
    "GITHUB_BOT_USERNAME_PREFIX",
    "GITHUB_BOT_USERNAME_REGEX",
    "GITHUB_PROJECT_DEFAULT_LIFETIME",
    "GITHUB_REPOSITORY_REGEX",
    "GROUPNAME_REGEX",
    "HTTP_TIMEOUT",
    "ID_CACHE_SIZE",
    "KUBERNETES_TIMER_DELAY",
    "KUBERNETES_TOKEN_INTERVAL",
    "KUBERNETES_WATCH_TIMEOUT",
    "LDAP_CACHE_LIFETIME",
    "LDAP_CACHE_SIZE",
    "LDAP_TIMEOUT",
    "MINIMUM_LIFETIME",
    "NGINX_SNIPPET",
    "OAUTH_ACCESS_TOKEN_TYPE",
    "OAUTH_ID_TOKEN_TYPE",
    "OAUTH_TOKEN_EXCHANGE_GRANT_TYPE",
    "OIDC_AUTHORIZATION_LIFETIME",
    "REDIS_BACKOFF_MAX",
    "REDIS_BACKOFF_START",
    "REDIS_EPHEMERAL_POOL_SIZE",
    "REDIS_PERSISTENT_POOL_SIZE",
    "REDIS_POOL_TIMEOUT",
    "REDIS_RETRIES",
    "REDIS_TIMEOUT",
    "SCOPE_REGEX",
    "TOKEN_CACHE_SIZE",
    "UID_BOT_MAX",
    "UID_BOT_MIN",
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

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
"""Issuer (``iss`` claim) of GitHub Actions ID tokens.

This is fixed rather than configurable because the GitHub Actions token
exchange only supports GitHub.com, not GitHub Enterprise Server.
"""

GITHUB_ACTIONS_JWKS_MIN_REFRESH = timedelta(minutes=1)
"""Minimum interval between key refreshes prompted by unknown key IDs.

A GitHub Actions ID token naming a key ID that is not in the cached key set
prompts a refresh of the keys, since GitHub rotates its signing keys. Without
a limit, anyone could force a request to GitHub for each token they send to
the token exchange. Within this interval after a refresh, tokens naming
unknown key IDs are rejected without refreshing the keys again. Expiry of the
cached keys after the configured cache lifetime always forces a refresh.
"""

GITHUB_ACTIONS_JWT_LEEWAY = 30
"""Clock skew (in seconds) allowed when checking GitHub Actions ID tokens.

Applied to the ``nbf`` and ``iat`` claims when verifying a GitHub Actions ID
token presented to the token exchange. The ``exp`` claim is checked strictly.
"""

GITHUB_API_URL = "https://api.github.com"
"""Base URL of the GitHub REST API, used to pin repository IDs."""

GITHUB_BOT_USERNAME_PREFIX = "bot-gh-"
"""Required prefix of the bot username of a GitHub project.

Tokens minted by the GitHub Actions token exchange are issued to the bot user
of the matching project. The prefix makes an identity minted from GitHub
recognizable wherever a username appears.
"""

GITHUB_PROJECT_DEFAULT_LIFETIME = timedelta(hours=1)
"""Default maximum lifetime of tokens minted for a GitHub project.

Used when a project is created without a maximum lifetime. Capped by the
configured maximum lifetime of the GitHub Actions token exchange, which may
be shorter than this.
"""

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

NGINX_RESPONSE_HEADERS = (
    "Authorization",
    "Cookie",
    "X-Auth-Request-Email",
    "X-Auth-Request-Service",
    "X-Auth-Request-Token",
    "X-Auth-Request-User",
)
"""Headers to lift from the Gafaelfawr response to the backend request.

Any of these headers in the incoming request will be overwritten with the
versions of these headers returned by the Gafaelfawr auth subrequest, or
deleted entirely if the subrequest doesn't return one of these headers.
"""

NGINX_SNIPPET = """\
auth_request_set $auth_error_body $upstream_http_x_error_body;
auth_request_set $auth_ratelimit_limit $upstream_http_x_ratelimit_limit;
auth_request_set $auth_ratelimit_remaining\
 $upstream_http_x_ratelimit_remaining;
auth_request_set $auth_ratelimit_reset $upstream_http_x_ratelimit_reset;
auth_request_set $auth_ratelimit_resource $upstream_http_x_ratelimit_resource;
auth_request_set $auth_ratelimit_used $upstream_http_x_ratelimit_used;
auth_request_set $auth_retry_after $upstream_http_retry_after;
auth_request_set $auth_www_authenticate $upstream_http_www_authenticate;
auth_request_set $auth_status $upstream_http_x_error_status;
more_set_headers "X-RateLimit-Limit: $auth_ratelimit_limit";
more_set_headers "X-RateLimit-Remaining: $auth_ratelimit_remaining";
more_set_headers "X-RateLimit-Reset: $auth_ratelimit_reset";
more_set_headers "X-RateLimit-Resource: $auth_ratelimit_resource";
more_set_headers "X-RateLimit-Used: $auth_ratelimit_used";
error_page 403 = @autherror;
"""
"""Code snippet to put into NGINX configuration for each ingress."""

OAUTH_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
"""Token type identifier for access tokens, from RFC 8693.

Returned as the ``issued_token_type`` of a successful GitHub Actions token
exchange.
"""

OAUTH_ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
"""Token type identifier for OpenID Connect ID tokens, from RFC 8693.

The only ``subject_token_type`` accepted by the GitHub Actions token
exchange, since the subject token is always a GitHub Actions ID token.
"""

OAUTH_TOKEN_EXCHANGE_GRANT_TYPE = (
    "urn:ietf:params:oauth:grant-type:token-exchange"
)
"""Grant type of an OAuth 2.0 token exchange request, from RFC 8693."""

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

REDIS_EPHEMERAL_POOL_SIZE = 25
"""Size of the ephemeral Redis connection pool."""

REDIS_PERSISTENT_POOL_SIZE = 25
"""Size of the persistent Redis connection pool."""

REDIS_POOL_TIMEOUT = 30
"""Seconds to wait for a connection from the pool before giving up."""

REDIS_TIMEOUT = 5
"""Timeout in seconds for a Redis network operation (including connecting)."""

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

GITHUB_BOT_USERNAME_REGEX = "^bot-gh-[a-z0-9](?:[a-z0-9]|-[a-z0-9])*$"
"""Regex matching a valid bot username for a GitHub project."""

GITHUB_REPOSITORY_REGEX = (
    "^[a-zA-Z0-9](?:[a-zA-Z0-9]|-[a-zA-Z0-9])*/[a-zA-Z0-9._-]+$"
)
"""Regex matching a GitHub repository as ``owner/name``."""

GROUPNAME_REGEX = (
    "^([a-zA-Z]|[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z])[a-zA-Z0-9._-]*$"
)
"""Regex matching all valid group names."""

SCOPE_REGEX = "^[a-zA-Z0-9:._-]+$"
"""Regex matching a valid scope."""

USERNAME_REGEX = (
    "^[a-z0-9](?:[a-z0-9]|-[a-z0-9])*[a-z](?:[a-z0-9]|-[a-z0-9])*$"
)
"""Regex matching all valid usernames."""

ACTOR_REGEX = f"{USERNAME_REGEX}|^<[a-z]+>$"
"""Regex matching all valid actors (including ``<bootstrap>``)."""
