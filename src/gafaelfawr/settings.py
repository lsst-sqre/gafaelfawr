"""Model for the Gafaelfawr configuration settings file.

Gafaelfawr has two internal configuration containers: `Settings` and
`~gafaelfawr.config.Config`.  Config is in the correct structure for internal
use by the Gafaelfawr code.  Settings, defined here, is the data model used to
parse and validate the on-disk configuration file.  Settings is then converted
to Config for internal use.

This separation allows the configuration file to be structured and simplified
for human writability.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from pydantic import AnyHttpUrl, BaseModel, IPvAnyNetwork, validator

__all__ = [
    "GitHubSettings",
    "IssuerSettings",
    "IssuerAudienceSettings",
    "OIDCSettings",
    "Settings",
]


class IssuerAudienceSettings(BaseModel):
    """pydantic model of issuer audience configuration."""

    default: str
    """Default aud (audience) field in issued tokens."""

    internal: str
    """Internal aud (audience) field in issued tokens."""


class IssuerSettings(BaseModel):
    """pydantic model of issuer configuration."""

    iss: str
    """iss (issuer) field in issued tokens."""

    key_id: str
    """kid (key ID) header field in issued tokens."""

    aud: IssuerAudienceSettings
    """aud (audience) possibilities for issued tokens."""

    key_file: str
    """File containing RSA private key for signing issued tokens."""

    exp_minutes: int = 1440  # 1 day
    """Number of minutes into the future that a token should expire."""

    influxdb_secret_file: Optional[str] = None
    """File containing shared secret for issuing InfluxDB tokens."""

    influxdb_username: Optional[str] = None
    """The username to set in all InfluxDB tokens."""


class GitHubSettings(BaseModel):
    """pydantic model of GitHub configuration."""

    client_id: str
    """Client ID of the GitHub App."""

    client_secret_file: str
    """File containing secret for the GitHub App."""


class OIDCSettings(BaseModel):
    """pydantic model of OpenID Connect configuration."""

    client_id: str
    """Client ID for talking to the OpenID Connect provider."""

    client_secret_file: str
    """File containing secret for talking to the OpenID Connect provider."""

    login_url: AnyHttpUrl
    """URL to which to send the user to initiate authentication."""

    login_params: Dict[str, str] = {}
    """Additional parameters to the login URL."""

    redirect_url: AnyHttpUrl
    """Return URL to which the authentication provider should send the user.

    This should be the full URL of the /login route of Gafaelfawr.
    """

    token_url: AnyHttpUrl
    """URL at which to redeem the authentication code for a token."""

    scopes: List[str] = []
    """Scopes to request from the authentication provider.

    The ``openid`` scope will always be added and does not need to be
    specified.
    """

    issuer: str
    """Expected issuer of the ID token."""

    audience: str
    """Expected audience of the ID token."""

    key_ids: List[str] = []
    """List of acceptable kids that may be used to sign the ID token."""


class Settings(BaseModel):
    """pydantic model of Gafaelfawr settings file.

    This describes the settings file as parsed from disk.  This model will be
    converted to a `~gafaelfawr.config.Config` dataclass for internal use so
    that some settings can be duplicated, rewritten, or parsed into internal
    formats for later convenience.

    Several fields use an empty dictionary or empty list as a default value.
    Due to a quirk in how Python handles empty dict and list constructors, the
    caller must be careful to never modify those fields and instead treat the
    value as read-only.
    """

    realm: str
    """Realm for HTTP authentication."""

    loglevel: str = "INFO"
    """Logging level."""

    session_secret_file: str
    """File containing encryption secret for session cookie and store."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    redis_password_file: Optional[str] = None
    """File containing the password to use when connecting to Redis."""

    proxies: Optional[List[IPvAnyNetwork]]
    """Trusted proxy IP netblocks in front of Gafaelfawr.

    If this is set to a non-empty list, it will be used as the trusted list of
    proxies when parsing ``X-Forwarded-For`` for the ``/auth`` route.  IP
    addresses from that header will be discarded from the right side when they
    are within a netblock in this list until a non-matching IP is reached or
    there is only one IP left, and then that IP will be used as the remote IP
    for logging purposes.  This will allow logging of accurate client IP
    addresses.
    """

    after_logout_url: AnyHttpUrl
    """Default URL to which to send the user after logging out."""

    username_claim: str = "uid"
    """Name of claim to use as the username."""

    uid_claim: str = "uidNumber"
    """Name of claim to use as the UID."""

    issuer: IssuerSettings
    """Settings for the internal token issuer."""

    github: Optional[GitHubSettings] = None
    """Settings for the GitHub authentication provider."""

    oidc: Optional[OIDCSettings] = None
    """Settings for the OpenID Connect authentication provider."""

    oidc_server_secrets_file: Optional[str] = None
    """Path to file containing OpenID Connect client secrets in JSON."""

    known_scopes: Dict[str, str] = {}
    """Known scopes (the keys) and their descriptions (the values)."""

    group_mapping: Dict[str, List[str]] = {}
    """Mappings of scopes to lists of groups that provide them."""

    @validator("loglevel")
    def valid_loglevel(cls, v: str) -> str:
        level = getattr(logging, v, None)
        if not level:
            raise ValueError("invalid logging level")
        return v

    @validator("oidc", always=True)
    def exactly_one_provider(
        cls, v: Optional[OIDCSettings], values: Dict[str, object]
    ) -> Optional[OIDCSettings]:
        """Ensure either github or oidc is set, not both."""
        if v and "github" in values and values["github"]:
            raise ValueError("both github and oidc settings present")
        if not v and ("github" not in values or not values["github"]):
            raise ValueError("neither github nor oidc settings present")
        return v
