"""Configuration for Gafaelfawr."""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import yaml

from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.settings import Settings

if TYPE_CHECKING:
    from ipaddress import _BaseNetwork
    from typing import Any, FrozenSet, Mapping, Optional, Tuple

__all__ = [
    "Config",
    "GitHubConfig",
    "IssuerConfig",
    "OIDCConfig",
    "SafirConfig",
    "VerifierConfig",
]


@dataclass(frozen=True)
class SafirConfig:
    """Safir configuration for Gafaelfawr.

    These configuration settings are used by the Safir middleware.
    """

    log_level: str
    """The log level of the application's logger.

    Takes the first value of the following that is set:

    - The ``SAFIR_LOG_LEVEL`` environment variable.
    - The ``loglevel`` Gafaelfawr configuration setting.
    - ``INFO``
    """

    name: str = os.getenv("SAFIR_NAME", "gafaelfawr")
    """The application's name, which doubles as the root HTTP endpoint path.

    Set with the ``SAFIR_NAME`` environment variable.
    """

    profile: str = os.getenv("SAFIR_PROFILE", "production")
    """Application run profile: "development" or "production".

    Set with the ``SAFIR_PROFILE`` environment variable.
    """

    logger_name: str = os.getenv("SAFIR_LOGGER", "gafaelfawr")
    """The root name of the application's logger.

    Set with the ``SAFIR_LOGGER`` environment variable.
    """


@dataclass(frozen=True)
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

    group_mapping: Mapping[str, FrozenSet[str]]
    """Mapping of group names to the set of scopes that group grants."""

    username_claim: str
    """Token claim from which to take the username."""

    uid_claim: str
    """Token claim from which to take the UID."""


@dataclass(frozen=True)
class VerifierConfig:
    """Configuration for how to verify tokens."""

    iss: str
    """iss (issuer) field in issued tokens."""

    aud: str
    """Default aud (audience) field in issued tokens."""

    aud_internal: str
    """Internal aud (audience) field in issued tokens."""

    keypair: RSAKeyPair
    """RSA key pair for signing and verifying issued tokens."""

    username_claim: str
    """Token claim from which to take the username."""

    uid_claim: str
    """Token claim from which to take the UID."""

    oidc_iss: Optional[str]
    """Expected issuer of the ID token from an OpenID Connect provider."""

    oidc_aud: Optional[str]
    """Expected audience of the ID token an OpenID Connect provider."""

    oidc_kids: Tuple[str, ...]
    """List of acceptable kids that may be used to sign the ID token."""


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class OIDCConfig:
    """Configuration for OpenID Connect authentication."""

    client_id: str
    """Client ID for talking to the OpenID Connect provider."""

    client_secret: str
    """Secret for talking to the OpenID Connect provider."""

    login_url: str
    """URL to which to send the user to initiate authentication."""

    login_params: Mapping[str, str]
    """Additional parameters to the login URL."""

    redirect_url: str
    """Return URL to which the authentication provider should send the user.

    This should be the full URL of the /login route of Gafaelfawr.
    """

    token_url: str
    """URL at which to redeem the authentication code for a token."""

    scopes: Tuple[str, ...]
    """Scopes to request from the authentication provider.

    The ``openid`` scope will always be added and does not need to be
    specified.
    """

    issuer: str
    """Expected issuer of the ID token."""

    audience: str
    """Expected audience of the ID token."""

    key_ids: Tuple[str, ...]
    """List of acceptable kids that may be used to sign the ID token."""


@dataclass(frozen=True)
class Config:
    """Configuration for Gafaelfawr.

    Some configuration parameters from the settings file are copied into
    multiple configuration dataclasses.  This allows the configuration for
    each internal component to be self-contained and unaware of the
    configuration of the rest of the application.
    """

    realm: str
    """Realm for HTTP authentication."""

    session_secret: str
    """Secret used to encrypt the session cookie and session store."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    redis_password: Optional[str]
    """Password for the Redis server that stores sessions."""

    proxies: Tuple[_BaseNetwork, ...]
    """Trusted proxy IP netblocks in front of Gafaelfawr.

    If this is set to a non-empty list, it will be used as the trusted list of
    proxies when parsing ``X-Forwarded-For`` for the ``/auth`` route.  IP
    addresses from that header will be discarded from the right side when they
    match an entry in this list until a non-matching IP is reached or there is
    only one IP left, and then that IP will be used as the remote IP for
    logging purposes.  This will allow logging of accurate client IP
    addresses.
    """

    after_logout_url: str
    """Default URL to which to send the user after logging out."""

    issuer: IssuerConfig
    """Configuration for internally-issued tokens."""

    verifier: VerifierConfig
    """Configuration for the token verifier."""

    github: Optional[GitHubConfig]
    """Configuration for GitHub authentication."""

    oidc: Optional[OIDCConfig]
    """Configuration for OpenID Connect authentication."""

    known_scopes: Mapping[str, str]
    """Known scopes (the keys) and their descriptions (the values)."""

    safir: SafirConfig
    """Configuration for the Safir middleware."""

    @classmethod
    def from_file(cls, path: str, **overrides: Any) -> Config:
        """Construct a Config object from a settings file.

        Parameters
        ----------
        path : `str`
            Path to the settings file in YAML.
        **overrides : `typing.Any`
            Settings that override settings read from the configuration file.

        Returns
        -------
        config : `Config`
            The corresponding Config object.
        """
        with open(path, "r") as f:
            raw_settings = yaml.safe_load(f)
        raw_settings.update(overrides)
        settings = Settings.parse_obj(raw_settings)

        # Load the secrets from disk.
        key = cls._load_secret(settings.issuer.key_file)
        keypair = RSAKeyPair.from_pem(key)
        session_secret = cls._load_secret(settings.session_secret_file)
        redis_password = None
        if settings.redis_password_file:
            path = settings.redis_password_file
            redis_password = cls._load_secret(path).decode()
        if settings.github:
            path = settings.github.client_secret_file
            github_secret = cls._load_secret(path).decode()
        if settings.oidc:
            path = settings.oidc.client_secret_file
            oidc_secret = cls._load_secret(path).decode()

        # The group mapping in the settings maps a scope to a list of groups
        # that provide that scope.  This may be conceptually easier for the
        # person writing the configuration, but for our purposes we want a map
        # from a group name to a set of scopes that group provides.
        #
        # Reconstruct the group mapping in the form in which we want to use it
        # internally.
        group_mapping = defaultdict(set)
        for scope, groups in settings.group_mapping.items():
            for group in groups:
                group_mapping[group].add(scope)
        group_mapping_frozen = {
            k: frozenset(v) for k, v in group_mapping.items()
        }

        # Build the Config object.
        issuer_config = IssuerConfig(
            iss=settings.issuer.iss,
            kid=settings.issuer.key_id,
            aud=settings.issuer.aud.default,
            aud_internal=settings.issuer.aud.internal,
            keypair=keypair,
            exp_minutes=settings.issuer.exp_minutes,
            group_mapping=group_mapping_frozen,
            username_claim=settings.username_claim,
            uid_claim=settings.uid_claim,
        )
        verifier_config = VerifierConfig(
            iss=settings.issuer.iss,
            aud=settings.issuer.aud.default,
            aud_internal=settings.issuer.aud.internal,
            keypair=keypair,
            username_claim=settings.username_claim,
            uid_claim=settings.uid_claim,
            oidc_iss=settings.oidc.issuer if settings.oidc else None,
            oidc_aud=settings.oidc.audience if settings.oidc else None,
            oidc_kids=tuple(settings.oidc.key_ids if settings.oidc else []),
        )
        github_config = None
        if settings.github:
            github_config = GitHubConfig(
                client_id=settings.github.client_id,
                client_secret=github_secret,
                username_claim=settings.username_claim,
                uid_claim=settings.uid_claim,
            )
        oidc_config = None
        if settings.oidc:
            oidc_config = OIDCConfig(
                client_id=settings.oidc.client_id,
                client_secret=oidc_secret,
                login_url=str(settings.oidc.login_url),
                login_params=settings.oidc.login_params,
                redirect_url=str(settings.oidc.redirect_url),
                token_url=str(settings.oidc.token_url),
                scopes=tuple(settings.oidc.scopes),
                issuer=settings.oidc.issuer,
                audience=settings.oidc.audience,
                key_ids=tuple(settings.oidc.key_ids),
            )
        log_level = os.getenv("SAFIR_LOG_LEVEL", settings.loglevel)
        return cls(
            realm=settings.realm,
            session_secret=session_secret.decode(),
            redis_url=settings.redis_url,
            redis_password=redis_password,
            proxies=tuple(settings.proxies if settings.proxies else []),
            after_logout_url=str(settings.after_logout_url),
            issuer=issuer_config,
            verifier=verifier_config,
            github=github_config,
            oidc=oidc_config,
            known_scopes=settings.known_scopes or {},
            safir=SafirConfig(log_level=log_level),
        )

    def log_settings(self, logger: logging.Logger) -> None:
        """Log information about the application settings.

        Parameters
        ----------
        logger : `logging.Logger`
            The logger to use for those log messages.
        """
        logger.debug("Configured realm %s", self.realm)
        logger.debug("Configured Redis pool at URL %s", self.redis_url)
        logger.debug(
            "Configured landing page after logout: %s", self.after_logout_url
        )
        if self.proxies:
            proxies = ", ".join([str(p) for p in self.proxies])
            logger.debug("Configured trusted proxy IPs: %s", proxies)
        logger.debug(
            "Configured token issuer %s, key ID %s, audience %s and %s"
            " (internal), expiration %d minutes",
            self.issuer.iss,
            self.issuer.kid,
            self.issuer.aud,
            self.issuer.aud_internal,
            self.issuer.exp_minutes,
        )
        logger.debug(
            "Configured %s as username claim", self.issuer.username_claim
        )
        logger.debug("Configured %s as UID claim", self.issuer.uid_claim)
        if self.github:
            logger.debug(
                "Configured GitHub authentication with client ID %s",
                self.github.client_id,
            )
        elif self.oidc:
            logger.debug(
                "Configured OpenID Connect authentication: client ID %s,"
                " login URL %s, token URL %s, redirect URL %s",
                self.oidc.client_id,
                self.oidc.login_url,
                self.oidc.token_url,
                self.oidc.redirect_url,
            )

    @staticmethod
    def _load_secret(path: str) -> bytes:
        """Load a secret from a file."""
        with open(path, "rb") as fh:
            secret = fh.read().strip()
            assert len(secret), f"Secret file {path} is empty"
            return secret
