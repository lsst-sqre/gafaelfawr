"""Configuration for JWT Authorizer."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dynaconf import LazySettings

from jwt_authorizer.keypair import RSAKeyPair

if TYPE_CHECKING:
    from typing import Dict, List, Optional, Tuple

__all__ = [
    "Config",
    "Configuration",
    "GitHubConfig",
    "Issuer",
    "IssuerConfig",
    "OIDCConfig",
]


@dataclass
class Configuration:
    """Configuration for jwt_authorizer.

    Notes
    -----
    This is a temporary hack to allow use of Safir to handle logging.  It
    needs to be unified with the main Config struct.
    """

    name: str = os.getenv("SAFIR_NAME", "jwt_authorizer")
    """The application's name, which doubles as the root HTTP endpoint path.

    Set with the ``SAFIR_NAME`` environment variable.
    """

    profile: str = os.getenv("SAFIR_PROFILE", "development")
    """Application run profile: "development" or "production".

    Set with the ``SAFIR_PROFILE`` environment variable.
    """

    logger_name: str = os.getenv("SAFIR_LOGGER", "jwt_authorizer")
    """The root name of the application's logger.

    Set with the ``SAFIR_LOGGER`` environment variable.
    """

    log_level: str = os.getenv("SAFIR_LOG_LEVEL", "INFO")
    """The log level of the application's logger.

    Set with the ``SAFIR_LOG_LEVEL`` environment variable.
    """


@dataclass
class GitHubConfig:
    """Metadata for GitHub authentication."""

    client_id: str
    """Client ID of the GitHub App."""

    client_secret: str
    """Secret for the GitHub App."""


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

    This should be the full URL of the /login route of jwt_authorizer.
    """

    token_url: str
    """URL at which to redeem the authentication code for a token."""

    scopes: List[str]
    """Scopes to request from the authentication provider.

    The ``openid`` scope will always be added and does not need to be
    specified.
    """


@dataclass(eq=True, frozen=True)
class Issuer:
    """Metadata about a token issuer for validation."""

    url: str
    """URL identifying the issuer (matches iss field in tokens)."""

    audience: Tuple[str, ...]
    """Expected audience for this issuer."""

    key_ids: Tuple[str, ...]
    """List of valid key IDs this issuer uses."""


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
    """Configuration for JWT Authorizer."""

    realm: str
    """Realm for HTTP authentication."""

    loglevel: Optional[str]
    """Log level, chosen from the string levels supported by logging."""

    username_claim: str
    """Token claim from which to take the username."""

    uid_claim: str
    """Token claim from which to take the UID."""

    github: Optional[GitHubConfig]
    """Configuration for GitHub authentication."""

    oidc: Optional[OIDCConfig]
    """Configuration for OpenID Connect authentication."""

    issuer: IssuerConfig
    """Configuration for internally-issued tokens."""

    session_secret: str
    """Secret used to encrypt the session cookie and session store."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    known_capabilities: Dict[str, str]
    """Known scopes (the keys) and their descriptions (the values)."""

    group_mapping: Dict[str, List[str]]
    """Mapping of a scope to a list of groups receiving that scope.

    Used to determine the scope for a reissued token based on the group
    memberships indicated in that token.
    """

    issuers: Dict[str, Issuer]
    """Known iss (issuer) values and their metadata."""

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
            cls._load_secret(settings["OAUTH2_JWT.KEY_FILE"])
        )
        issuer_config = IssuerConfig(
            iss=settings["OAUTH2_JWT.ISS"],
            kid=settings["OAUTH2_JWT.KEY_ID"],
            aud=settings["OAUTH2_JWT.AUD.DEFAULT"],
            aud_internal=settings["OAUTH2_JWT.AUD.INTERNAL"],
            keypair=keypair,
            exp_minutes=settings["OAUTH2_JWT_EXP"],
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
            )

        known_capabilities = settings.get("KNOWN_CAPABILITIES", {})

        issuers = {}
        if settings.get("ISSUERS"):
            for url, info in settings["ISSUERS"].items():
                audience_setting = info["AUDIENCE"]
                # Support either str or list values, turning both into tuples
                # so that the Issuer class is hashable.  This will be cleaned
                # up when configuration handling is redone.
                if isinstance(audience_setting, str):
                    audience: Tuple[str, ...] = (audience_setting,)
                else:
                    audience = tuple(audience_setting)
                issuer = Issuer(
                    url=url,
                    audience=audience,
                    key_ids=tuple(info["ISSUER_KEY_IDS"]),
                )
                issuers[url] = issuer

        group_mapping = {}
        if settings.get("GROUP_MAPPING"):
            for key, value in settings["GROUP_MAPPING"].items():
                assert isinstance(key, str), "group_mapping is malformed"
                assert isinstance(value, list), "group_mapping is malformed"
                group_mapping[key] = value

        return cls(
            realm=settings["REALM"],
            loglevel=settings.get("LOGLEVEL", "INFO"),
            username_claim=settings["JWT_USERNAME_KEY"],
            uid_claim=settings["JWT_UID_KEY"],
            github=github,
            oidc=oidc,
            issuer=issuer_config,
            session_secret=session_secret,
            redis_url=settings["REDIS_URL"],
            known_capabilities=known_capabilities,
            group_mapping=group_mapping,
            issuers=issuers,
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

        for issuer in self.issuers.values():
            logger.info(
                "Configured token access for %s (audience: %s, key_ids: %s)",
                issuer.url,
                issuer.audience,
                ", ".join(issuer.key_ids),
            )
        if not self.issuers:
            logger.warning("No issuers configured")

    @staticmethod
    def _load_secret(path: str) -> bytes:
        """Load a secret from a file."""
        with open(path, "rb") as fh:
            secret = fh.read().strip()
            assert len(secret), f"Secret file {path} is empty"
            return secret
