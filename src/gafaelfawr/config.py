"""Configuration for Gafaelfawr."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dynaconf import LazySettings

from gafaelfawr.keypair import RSAKeyPair

if TYPE_CHECKING:
    from typing import Dict, List, Optional

__all__ = [
    "Config",
    "Configuration",
    "GitHubConfig",
    "IssuerConfig",
    "OIDCConfig",
]


@dataclass
class Configuration:
    """Configuration for Gafaelfawr.

    Notes
    -----
    This is a temporary hack to allow use of Safir to handle logging.  It
    needs to be unified with the main Config struct.
    """

    name: str = os.getenv("SAFIR_NAME", "gafaelfawr")
    """The application's name, which doubles as the root HTTP endpoint path.

    Set with the ``SAFIR_NAME`` environment variable.
    """

    profile: str = os.getenv("SAFIR_PROFILE", "development")
    """Application run profile: "development" or "production".

    Set with the ``SAFIR_PROFILE`` environment variable.
    """

    logger_name: str = os.getenv("SAFIR_LOGGER", "gafaelfawr")
    """The root name of the application's logger.

    Set with the ``SAFIR_LOGGER`` environment variable.
    """

    log_level: str = os.getenv("SAFIR_LOG_LEVEL", "INFO")
    """The log level of the application's logger.

    Set with the ``SAFIR_LOG_LEVEL`` environment variable.
    """


@dataclass
class GitHubConfig:
    """Metadata for GitHub authentication.

    Some configuration parameters are duplicated from the main application
    configuration so that all of the configuration for the GitHub provider is
    encapsulated here.
    """

    client_id: str
    """Client ID of the GitHub App."""

    client_secret: str
    """Secret for the GitHub App."""

    username_claim: str
    """Name of claim in which to store the username."""

    uid_claim: str
    """Name of claim in which to store the UID."""


@dataclass
class OIDCConfig:
    """Configuration for OpenID Connect authentication."""

    client_id: str
    """Client ID for talking to the OpenID Connect provider."""

    client_secret: str
    """Secret for talking to the OpenID Connect provider."""

    login_url: str
    """URL to which to send the user to initiate authentication."""

    login_params: Dict[str, str]
    """Additional parameters to the login URL."""

    redirect_url: str
    """Return URL to which the authentication provider should send the user.

    This should be the full URL of the /login route of Gafaelfawr.
    """

    token_url: str
    """URL at which to redeem the authentication code for a token."""

    scopes: List[str]
    """Scopes to request from the authentication provider.

    The ``openid`` scope will always be added and does not need to be
    specified.
    """

    issuer: str
    """Expected issuer of the ID token."""

    audience: str
    """Expected audience of the ID token."""

    key_ids: List[str]
    """List of acceptable kids that may be used to sign the ID token."""


@dataclass
class IssuerConfig:
    """Configuration for how to issue tokens."""

    iss: str
    """iss (issuer) field in issued tokens."""

    kid: str
    """kid (key ID) header field in issued tokens."""

    aud: str
    """Default aud (audience) field in issued tokens."""

    aud_internal: str
    """Internal aud (audience) field in issued tokens."""

    keypair: RSAKeyPair
    """RSA key pair for signing and verifying issued tokens."""

    exp_minutes: int
    """Number of minutes into the future that a token should expire."""


@dataclass
class Config:
    """Configuration for Gafaelfawr."""

    realm: str
    """Realm for HTTP authentication."""

    loglevel: Optional[str]
    """Log level, chosen from the string levels supported by logging."""

    session_secret: str
    """Secret used to encrypt the session cookie and session store."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    after_logout_url: str
    """Default URL to which to send the user after logging out."""

    issuer: IssuerConfig
    """Configuration for internally-issued tokens."""

    github: Optional[GitHubConfig]
    """Configuration for GitHub authentication."""

    oidc: Optional[OIDCConfig]
    """Configuration for OpenID Connect authentication."""

    known_scopes: Dict[str, str]
    """Known scopes (the keys) and their descriptions (the values)."""

    group_mapping: Dict[str, List[str]]
    """Mapping of a scope to a list of groups receiving that scope.

    Used to determine the scope for a reissued token based on the group
    memberships indicated in that token.
    """
    username_claim: str
    """Token claim from which to take the username."""

    uid_claim: str
    """Token claim from which to take the UID."""

    @classmethod
    def from_dynaconf(cls, settings: LazySettings) -> Config:
        """Construction a Config object from Dynaconf settings.

        Parameters
        ----------
        settings : `dynaconf.LazySettings`
            Dynaconf settings.

        Returns
        -------
        config : `Config`
            The corresponding Config object.
        """
        keypair = RSAKeyPair.from_pem(
            cls._load_secret(settings["ISSUER.KEY_FILE"])
        )
        issuer_config = IssuerConfig(
            iss=settings["ISSUER.ISS"],
            kid=settings["ISSUER.KEY_ID"],
            aud=settings["ISSUER.AUD.DEFAULT"],
            aud_internal=settings["ISSUER.AUD.INTERNAL"],
            keypair=keypair,
            exp_minutes=settings["ISSUER.EXP_MINUTES"],
        )

        session_secret = cls._load_secret(
            settings["SESSION_SECRET_FILE"]
        ).decode()

        github = None
        if settings.get("GITHUB.CLIENT_ID"):
            client_secret = cls._load_secret(
                settings["GITHUB.CLIENT_SECRET_FILE"]
            ).decode()
            github = GitHubConfig(
                client_id=settings["GITHUB.CLIENT_ID"],
                client_secret=client_secret,
                username_claim=settings["USERNAME_CLAIM"],
                uid_claim=settings["UID_CLAIM"],
            )

        oidc = None
        if settings.get("OIDC.LOGIN_URL"):
            client_secret = cls._load_secret(
                settings["OIDC.CLIENT_SECRET_FILE"]
            ).decode()
            oidc = OIDCConfig(
                client_id=settings["OIDC.CLIENT_ID"],
                client_secret=client_secret,
                login_url=settings["OIDC.LOGIN_URL"],
                login_params=settings.get("OIDC.LOGIN_PARAMS", {}),
                redirect_url=settings["OIDC.REDIRECT_URL"],
                token_url=settings["OIDC.TOKEN_URL"],
                scopes=settings.get("OIDC.SCOPES", []),
                issuer=settings["OIDC.ISSUER"],
                audience=settings["OIDC.AUDIENCE"],
                key_ids=settings.get("OIDC.KEY_IDS", []),
            )

        known_scopes = settings.get("KNOWN_SCOPES", {})

        group_mapping = {}
        if settings.get("GROUP_MAPPING"):
            for key, value in settings["GROUP_MAPPING"].items():
                assert isinstance(key, str), "group_mapping is malformed"
                assert isinstance(value, list), "group_mapping is malformed"
                group_mapping[key] = value

        return cls(
            realm=settings["REALM"],
            loglevel=settings.get("LOGLEVEL", "INFO"),
            session_secret=session_secret,
            redis_url=settings["REDIS_URL"],
            after_logout_url=settings["AFTER_LOGOUT_URL"],
            issuer=issuer_config,
            github=github,
            oidc=oidc,
            known_scopes=known_scopes,
            group_mapping=group_mapping,
            username_claim=settings["USERNAME_CLAIM"],
            uid_claim=settings["UID_CLAIM"],
        )

    def log_settings(self, logger: logging.Logger) -> None:
        """Log information about the application settings.

        Parameters
        ----------
        logger : `logging.Logger`
            The logger to use for those log messages.
        """
        logger.info("Configured realm %s", self.realm)

        if self.issuer:
            logger.info(
                "Configured token issuer: %s with key ID %s",
                self.issuer.iss,
                self.issuer.kid,
            )
            logger.info("Configured default audience: %s", self.issuer.aud)
            logger.info(
                "Configured internal audience: %s", self.issuer.aud_internal
            )
            logger.info(
                "Default JWT expiration is %d minutes", self.issuer.exp_minutes
            )

        logger.info("Configured Redis pool from URL %s", self.redis_url)

    @staticmethod
    def _load_secret(path: str) -> bytes:
        """Load a secret from a file."""
        with open(path, "rb") as fh:
            secret = fh.read().strip()
            assert len(secret), f"Secret file {path} is empty"
            return secret
