"""Constants for Gafaelfawr."""

ALGORITHM = "RS256"
"""JWT algorithm to use for all tokens."""

COOKIE_NAME = "gafaelfawr"
"""Name of the state cookie."""

HTTP_TIMEOUT = 20.0
"""Timeout (in seconds) for outbound HTTP requests to auth providers."""

LDAP_TIMEOUT = 5.0
"""Timeout (in seconds) for LDAP queries."""

MINIMUM_LIFETIME = 5 * 60
"""Minimum expiration lifetime for a token in seconds."""

OIDC_AUTHORIZATION_LIFETIME = 60 * 60
"""How long (in seconds) an authorization code is good for."""

SETTINGS_PATH = "/etc/gafaelfawr/gafaelfawr.yaml"
"""Default configuration path."""

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

USERNAME_REGEX = "^[a-z0-9](?:[a-z0-9]|-[a-z0-9])*$"
"""Regex matching all valid usernames."""

ACTOR_REGEX = f"{USERNAME_REGEX}|^<[a-z]+>$"
"""Regex matching all valid actors (including ``<bootstrap>``)."""
