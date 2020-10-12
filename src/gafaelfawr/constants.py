"""Constants for Gafaelfawr."""

ALGORITHM = "RS256"
"""JWT algorithm to use for all tokens."""

CONFIG_PATH = "/etc/gafaelfawr/gafaelfawr.yaml"
"""Default configuration path."""

OIDC_AUTHORIZATION_LIFETIME = 60 * 60
"""How long (in seconds) an authorization code is good for."""
