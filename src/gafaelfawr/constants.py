"""Constants for Gafaelfawr."""

ALGORITHM = "RS256"
"""JWT algorithm to use for all tokens."""

COOKIE_NAME = "gafaelfawr"
"""Name of the state cookie."""

MINIMUM_LIFETIME = 5 * 60
"""Minimum expiration lifetime for a token in seconds."""

OIDC_AUTHORIZATION_LIFETIME = 60 * 60
"""How long (in seconds) an authorization code is good for."""

SETTINGS_PATH = "/etc/gafaelfawr/gafaelfawr.yaml"
"""Default configuration path."""

USERNAME_REGEX = "^[a-z0-9._-]+$"
"""Regex matching all valid usernames."""
