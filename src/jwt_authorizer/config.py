"""Configuration for JWT Authorizer."""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from dynaconf import LazySettings

if TYPE_CHECKING:
    from typing import Dict, List, Optional, Tuple

__all__ = [
    "AuthenticateType",
    "Config",
    "Configuration",
    "Issuer",
    "IssuerConfig",
    "SessionStoreConfig",
]

ALGORITHM = "RS256"


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

    key: bytes
    """Private key in PEM format for signing issued tokens."""

    exp_minutes: int
    """Number of minutes into the future that a token should expire."""


@dataclass
class SessionStoreConfig:
    """Configuration for how to store and retrieve oauth2_proxy sessions."""

    ticket_prefix: str
    """Prefix for oauth2_proxy tickets (must match cookie name)."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    oauth2_proxy_secret: bytes
    """Secret used for encryption of oauth2_proxy session fields."""


class AuthenticateType(Enum):
    Basic = auto()
    Bearer = auto()


@dataclass
class Config:
    """Configuration for JWT Authorizer."""

    realm: str
    """Realm for HTTP authentication."""

    authenticate_type: AuthenticateType
    """What type of authentication to request in WWW-Authenticate."""

    loglevel: Optional[str]
    """Log level, chosen from the string levels supported by logging."""

    no_authorize: bool
    """Disable authorization."""

    no_verify: bool
    """Disable token verification."""

    set_user_headers: bool
    """Whether to set headers containing user information from the token."""

    username_key: str
    """Token field from which to take the username."""

    uid_key: str
    """Token field from which to take the UID."""

    github: Optional[GitHubConfig]
    """Configuration for GitHub authentication."""

    group_mapping: Dict[str, List[str]]
    """Mapping of a scope to a list of groups receiving that scope."""

    issuer: IssuerConfig
    """Configuration for internally-issued tokens."""

    session_secret: str
    """Secret used to encrypt the session cookie.

    This is unrelated to the oauth2_proxy sessions stored in Redis.  It is
    used to encrypt the session cookie used by jwt_authorizer to store
    temporary state.  Must be a Fernet key.
    """

    session_store: SessionStoreConfig
    """Configuration for storing oauth2_proxy sessions."""

    known_capabilities: Dict[str, str]
    """Known scopes (the keys) and their descriptions (the values)."""

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
        if settings.get("OAUTH2_JWT.KEY"):
            key = settings["OAUTH2_JWT.KEY"]
        else:
            key = cls._load_secret(settings["OAUTH2_JWT.KEY_FILE"])
        issuer_config = IssuerConfig(
            iss=settings["OAUTH2_JWT.ISS"],
            kid=settings["OAUTH2_JWT.KEY_ID"],
            aud=settings["OAUTH2_JWT.AUD.DEFAULT"],
            aud_internal=settings["OAUTH2_JWT.AUD.INTERNAL"],
            key=key,
            exp_minutes=settings["OAUTH2_JWT_EXP"],
        )

        if settings.get("SESSION_SECRET"):
            session_secret = settings["SESSION_SECRET"]
        else:
            session_secret = cls._load_secret(settings["SESSION_SECRET_FILE"])

        github = None
        if settings.get("GITHUB.CLIENT_ID"):
            if settings.get("GITHUB.CLIENT_SECRET"):
                secret = settings["GITHUB.CLIENT_SECRET"]
            else:
                secret = cls._load_secret(
                    settings["GITHUB.CLIENT_SECRET_FILE"]
                )
            github = GitHubConfig(
                client_id=settings["GITHUB.CLIENT_ID"], client_secret=secret
            )

        group_mapping = {}
        if settings.get("GROUP_MAPPING"):
            for key, value in settings["GROUP_MAPPING"].items():
                assert isinstance(key, str), "group_mapping is malformed"
                assert isinstance(value, list), "group_mapping is malformed"
                group_mapping[key] = value

        store_session_settings = settings["OAUTH2_STORE_SESSION"]
        if store_session_settings.get("OAUTH2_PROXY_SECRET"):
            secret_b64 = store_session_settings["OAUTH2_PROXY_SECRET"]
        else:
            secret_b64 = cls._load_secret(
                store_session_settings["OAUTH2_PROXY_SECRET_FILE"]
            )
        secret = base64.urlsafe_b64decode(secret_b64)
        session_store = SessionStoreConfig(
            ticket_prefix=store_session_settings["TICKET_PREFIX"],
            redis_url=store_session_settings["REDIS_URL"],
            oauth2_proxy_secret=secret,
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

        return cls(
            realm=settings["REALM"],
            authenticate_type=AuthenticateType[settings["WWW_AUTHENTICATE"]],
            loglevel=settings.get("LOGLEVEL"),
            no_authorize=settings["NO_AUTHORIZE"],
            no_verify=settings["NO_VERIFY"],
            set_user_headers=settings["SET_USER_HEADERS"],
            username_key=settings["JWT_USERNAME_KEY"],
            uid_key=settings["JWT_UID_KEY"],
            github=github,
            issuer=issuer_config,
            group_mapping=group_mapping,
            session_secret=session_secret,
            session_store=session_store,
            known_capabilities=known_capabilities,
            issuers=issuers,
        )

    def log_settings(self, logger: logging.Logger) -> None:
        """Log information about the application settings.

        Parameters
        ----------
        logger : `logging.Logger`
            The logger to use for those log messages.
        """
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

        logger.info("Configured realm %s", self.realm)
        logger.info(
            "Configured WWW-Authenticate type: %s", self.authenticate_type.name
        )

        if self.no_verify:
            logger.warning("Authentication verification is disabled")
        if self.no_authorize:
            logger.warning("Authorization is disabled")

        logger.info(
            "Configured group mapping: %s", json.dumps(self.group_mapping)
        )

        if self.session_store:
            logger.info(
                "Configured Redis pool from URL: %s with prefix: %s",
                self.session_store.redis_url,
                self.session_store.ticket_prefix,
            )

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
