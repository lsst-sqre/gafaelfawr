"""Configuration for Gafaelfawr.

There are two, mostly-parallel models defined here.  The ones ending in
``Settings`` are the pydantic models used to read the settings file from disk,
the root of which is `Settings`.  This is then processed and broken up into
configuration dataclasses for various components and then exposed to the rest
of Gafaelfawr as the `Config` object.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import _BaseNetwork
from typing import Dict, FrozenSet, List, Mapping, Optional, Tuple

import yaml
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    BaseSettings,
    IPvAnyNetwork,
    validator,
)
from safir.logging import configure_logging

from .constants import SCOPE_REGEX, USERNAME_REGEX
from .keypair import RSAKeyPair
from .models.token import Token

__all__ = [
    "Config",
    "FirestoreConfig",
    "FirestoreSettings",
    "GitHubConfig",
    "GitHubSettings",
    "LDAPConfig",
    "LDAPSettings",
    "OIDCConfig",
    "OIDCClient",
    "OIDCServerConfig",
    "OIDCServerSettings",
    "OIDCSettings",
    "Settings",
]


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

    enrollment_url: Optional[AnyHttpUrl] = None
    """URL to which the user should be redirected if not enrolled.

    If LDAP username lookup is configured (using ``ldap.username_base_dn``)
    and the user could not be found, redirect the user, after login, to this
    URL so that they can register.
    """

    scopes: List[str] = []
    """Scopes to request from the authentication provider.

    The ``openid`` scope will always be added and does not need to be
    specified.
    """

    issuer: str
    """Expected issuer of the ID token."""

    audience: str
    """Expected audience of the ID token."""

    username_claim: str = "uid"
    """Name of claim to use as the username."""

    uid_claim: str = "uidNumber"
    """Name of claim to use as the UID."""

    gid_claim: Optional[str] = None
    """Name of claim to use as the primary GID."""

    groups_claim: str = "isMemberOf"
    """Name of claim to use for the group membership."""


class LDAPSettings(BaseModel):
    """pydantic model of LDAP configuration."""

    url: str
    """LDAP server URL.

    Use the ``ldaps`` scheme if you're using TLS.  Only anonymous binds are
    supported.
    """

    user_dn: Optional[str] = None
    """Simple bind user DN for the LDAP server."""

    password_file: Optional[str] = None
    """File containing simple bind password for the LDAP server."""

    group_base_dn: str
    """Base DN to use when executing an LDAP search for user groups."""

    group_object_class: str = "posixGroup"
    """LDAP group object class.

    Usually ``posixGroup``, as specified in :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    group_member_attr: str = "member"
    """LDAP group member attribute.

    ``memberuid`` in :rfc:`2307` and ``member`` in `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    user_base_dn: Optional[str] = None
    """Base DN to use to search for user information.

    If set, the base DN used to search for the user record, from which other
    information such as full name, email, and (if configured) numeric UID will
    be retrieved.
    """

    user_search_attr: str = "uid"
    """Search attribute for finding the user record.

    This attribute must hold the username of the user that Gafaelfawr knows
    them by.  Used if ``user_base_dn`` is set.  The default is ``uid``, which
    is the LDAP convention for the attribute holding the username.
    """

    name_attr: Optional[str] = "displayName"
    """LDAP full name attribute.

    The attribute from which the user's full name will be taken, or `None` to
    not look up full names.  This should normally be ``displayName``, but
    sometimes it may be desirable to use a different name attribute.  This
    should hold the whole name that should be used by the Science Platform,
    not just a surname or family name (which are not universally valid
    concepts anyway).
    """

    email_attr: Optional[str] = "mail"
    """LDAP email attribute.

    The attribute from which the user's email address should be taken, or
    `None` to not look up email addresses.  This should normally be
    ``mail``.
    """

    uid_attr: Optional[str] = None
    """LDAP UID attribute.

    If set, the user's UID will be taken from this sttribute.  If UID lookups
    are desired, this should usually be ``uidNumber``, as specified in
    :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    gid_attr: Optional[str] = None
    """LDAP GID attirbute.

    If set, the user's primary GID will be taken from this sttribute.  If GID
    lookups are desired, this should usually be ``gidNumber``, as specified in
    :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.  If
    not set, the primary GID will match the UID if ``add_user_group`` is true,
    and otherwise will not be set.
    """

    add_user_group: bool = False
    """Whether to synthesize a user private group with GID matching UID.

    If set to `True`, synthesize a group for the user whose name and GID
    matches the username and UID, adding it to the group list without
    requiring it to appear in LDAP.
    """


class FirestoreSettings(BaseModel):
    """pydantic model of Firestore configuration."""

    project: str
    """Project containing the Firestore collections."""


class OIDCServerSettings(BaseModel):
    """pydantic model of issuer configuration."""

    issuer: str
    """iss (issuer) field in issued tokens."""

    key_id: str
    """kid (key ID) header field in issued tokens."""

    audience: str
    """aud (audience) field in issued tokens."""

    key_file: str
    """File containing RSA private key for signing issued tokens."""

    secrets_file: str
    """Path to file containing OpenID Connect client secrets in JSON."""


class Settings(BaseSettings):
    """pydantic model of Gafaelfawr settings file.

    This describes the settings file as parsed from disk.  This model will be
    converted to a `Config` dataclass for internal use so that some settings
    can be duplicated, rewritten, or parsed into internal formats for later
    convenience.

    Several fields use an empty dictionary or empty list as a default value.
    Due to a quirk in how Python handles empty dict and list constructors, the
    caller must be careful to never modify those fields and instead treat the
    value as read-only.  In practice, this isn't much of a concern since this
    object is only used to convert to a `Config` object.
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

    database_url: str
    """URL for the PostgreSQL database."""

    database_password_file: Optional[str] = None
    """File containing the password for the PostgreSQL database."""

    bootstrap_token_file: Optional[str] = None
    """File containing the bootstrap authentication token.

    This token can be used with specific routes in the admin API to change the
    list of admins and create service and user tokens.
    """

    token_lifetime_minutes: int = 1380  # 23 hours
    """Number of minutes into the future that a token should expire."""

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

    github: Optional[GitHubSettings] = None
    """Settings for the GitHub authentication provider."""

    oidc: Optional[OIDCSettings] = None
    """Settings for the OpenID Connect authentication provider."""

    ldap: Optional[LDAPSettings] = None
    """Settings for the LDAP-based group lookups with OIDC provider."""

    firestore: Optional[FirestoreSettings] = None
    """Settings for Firestore-based UID/GID assignment."""

    oidc_server: Optional[OIDCServerSettings] = None
    """Settings for the internal OpenID Connect server."""

    initial_admins: List[str]
    """Initial token administrators to configure when initializing database."""

    known_scopes: Dict[str, str] = {}
    """Known scopes (the keys) and their descriptions (the values)."""

    group_mapping: Dict[str, List[str]] = {}
    """Mappings of scopes to lists of groups that provide them."""

    error_footer: Optional[str] = None
    """HTML to add (inside ``<p>``) to login error pages."""

    slack_webhook_file: Optional[str] = None
    """File containing the Slack webhook to which to post alerts."""

    @validator("initial_admins", each_item=True)
    def _validate_initial_admins(cls, v: str) -> str:
        if not re.match(USERNAME_REGEX, v):
            raise ValueError("invalid username")
        return v

    @validator("known_scopes")
    def _valid_known_scopes(cls, v: Dict[str, str]) -> Dict[str, str]:
        for scope in v.keys():
            if not re.match(SCOPE_REGEX, scope):
                raise ValueError(f"invalid scope {scope}")
        for required in ("admin:token", "user:token"):
            if required not in v:
                raise ValueError(f"required scope {scope} missing")
        return v

    @validator("loglevel")
    def _valid_loglevel(cls, v: str) -> str:
        level = getattr(logging, v, None)
        if not level:
            raise ValueError("invalid logging level")
        return v

    @validator("oidc", always=True)
    def _exactly_one_provider(
        cls, v: Optional[OIDCSettings], values: Dict[str, object]
    ) -> Optional[OIDCSettings]:
        """Ensure either github or oidc is set, not both."""
        if v and "github" in values and values["github"]:
            raise ValueError("both github and oidc settings present")
        if not v and ("github" not in values or not values["github"]):
            raise ValueError("neither github nor oidc settings present")
        return v

    @validator("ldap", always=True)
    def _valid_ldap_config(
        cls, v: Optional[LDAPSettings], values: Dict[str, object]
    ) -> Optional[LDAPSettings]:
        """Ensure all fields are non-empty if url is non-empty."""
        if v and v.url and not v.group_base_dn:
            raise ValueError("not all required ldap fields are present")
        if v and v.user_dn and not v.password_file:
            raise ValueError("ldap.password_file required if ldap.user_dn set")
        return v

    @validator("initial_admins", pre=True)
    def _nonempty_list(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("initial_admins is empty")
        return v


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

    enrollment_url: Optional[str]
    """URL to which the user should be redirected if not enrolled.

    If LDAP username lookup is configured (using ``ldap.username_base_dn``)
    and the user could not be found, redirect the user, after login, to this
    URL so that they can register.
    """

    scopes: Tuple[str, ...]
    """Scopes to request from the authentication provider.

    The ``openid`` scope will always be added and does not need to be
    specified.
    """

    issuer: str
    """Expected issuer of the ID token."""

    audience: str
    """Expected audience of the ID token."""

    username_claim: str
    """Token claim from which to take the username."""

    uid_claim: str
    """Token claim from which to take the UID."""

    gid_claim: Optional[str]
    """Token claim from which to take the primary GID."""

    groups_claim: str
    """Token claim from which to take the group membership."""


@dataclass(frozen=True)
class LDAPConfig:
    """Configuration for LDAP support.

    In all known implementations, ``gidNumber`` holds the numeric GID of the
    group and ``cn`` holds its name, so these are not configurable.
    """

    url: str
    """LDAP server URL.

    Use the ``ldaps`` scheme if you're using TLS.  Only anonymous binds are
    supported.
    """

    user_dn: Optional[str]
    """User DN for simple bind authentication to the LDAP server."""

    password: Optional[str]
    """Password for simple bind authentication to the LDAP server."""

    group_base_dn: str
    """Base DN to use when executing LDAP search for group membership."""

    group_object_class: str = "posixGroup"
    """LDAP group object class.

    Usually ``posixGroup``, as specified in :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    group_member_attr: str = "member"
    """LDAP group member attribute.

    ``memberuid`` in :rfc:`2307` and ``member`` in `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    user_base_dn: Optional[str] = None
    """Base DN to use to search for user information.

    If set, the base DN used to search for the user record, from which other
    information such as full name, email, and (if configured) numeric UID will
    be retrieved.
    """

    user_search_attr: str = "uid"
    """Search attribute for finding the user record.

    This attribute must hold the username of the user that Gafaelfawr knows
    them by.  Used if ``user_base_dn`` is set.  The default is ``uid``, which
    is the LDAP convention for the attribute holding the username.
    """

    name_attr: Optional[str] = "displayName"
    """LDAP full name attribute.

    The attribute from which the user's full name will be taken, or `None` to
    not look up full names.  This should normally be ``displayName``, but
    sometimes it may be desirable to use a different name attribute.  This
    should hold the whole name that should be used by the Science Platform,
    not just a surname or family name (which are not universally valid
    concepts anyway).
    """

    email_attr: Optional[str] = "mail"
    """LDAP email attribute.

    The attribute from which the user's email address should be taken, or
    `None` to not look up email addresses.  This should normally be
    ``mail``.
    """

    uid_attr: Optional[str] = None
    """LDAP UID attribute.

    If set, the user's UID will be taken from this sttribute.  If UID lookups
    are desired, this should usually be ``uidNumber``, as specified in
    :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    gid_attr: Optional[str] = None
    """LDAP GID attirbute.

    If set, the user's primary GID will be taken from this sttribute.  If GID
    lookups are desired, this should usually be ``gidNumber``, as specified in
    :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.  If
    not set, the primary GID will match the UID if ``add_user_group`` is true,
    and otherwise will not be set.
    """

    add_user_group: bool = False
    """Whether to synthesize a user private group with GID matching UID.

    If set to `True`, synthesize a group for the user whose name and GID
    matches the username and UID, adding it to the group list without
    requiring it to appear in LDAP.
    """


@dataclass(frozen=True)
class FirestoreConfig:
    """Configuration for Firestore-based UID/GID assignment."""

    project: str
    """Project containing the Firestore collections."""


@dataclass(frozen=True)
class OIDCClient:
    """Configuration for a single OpenID Connect client of our server."""

    client_id: str
    """Unique identifier of the client."""

    client_secret: str
    """Secret used to authenticate this client."""


@dataclass(frozen=True)
class OIDCServerConfig:
    """Configuration for the OpenID Connect server."""

    issuer: str
    """iss (issuer) field in issued tokens."""

    key_id: str
    """kid (key ID) header field in issued tokens."""

    audience: str
    """aud (audience) field in issued tokens."""

    keypair: RSAKeyPair
    """RSA key pair for signing and verifying issued tokens."""

    lifetime: timedelta
    """Lifetime of issued tokens."""

    clients: Tuple[OIDCClient, ...]
    """Supported OpenID Connect clients."""


@dataclass(frozen=True)
class Config:
    """Configuration for Gafaelfawr.

    The internal representation of the configuration, created from the
    `Settings` model.

    Some configuration parameters from the settings file are copied into
    multiple configuration dataclasses.  This allows the configuration for
    each internal component to be self-contained and unaware of the
    configuration of the rest of the application.
    """

    realm: str
    """Realm for HTTP authentication."""

    session_secret: str
    """Secret used to encrypt the session cookie and session store."""

    database_url: str
    """URL for the PostgreSQL database."""

    database_password: Optional[str]
    """Password for the PostgreSQL database."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    redis_password: Optional[str]
    """Password for the Redis server that stores sessions."""

    bootstrap_token: Optional[Token]
    """Bootstrap authentication token.

    This token can be used with specific routes in the admin API to change the
    list of admins and create service and user tokens.
    """

    token_lifetime: timedelta
    """Maximum lifetime of session, notebook, and internal tokens."""

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

    github: Optional[GitHubConfig]
    """Configuration for GitHub authentication."""

    ldap: Optional[LDAPConfig]
    """Configuration for LDAP."""

    firestore: Optional[FirestoreConfig]
    """Settings for Firestore-based UID/GID assignment."""

    oidc: Optional[OIDCConfig]
    """Configuration for OpenID Connect authentication."""

    oidc_server: Optional[OIDCServerConfig]
    """Configuration for the OpenID Connect server."""

    known_scopes: Mapping[str, str]
    """Known scopes (the keys) and their descriptions (the values)."""

    group_mapping: Mapping[str, FrozenSet[str]]
    """Mapping of group names to the set of scopes that group grants."""

    initial_admins: Tuple[str, ...]
    """Initial token administrators to configure when initializing database."""

    error_footer: Optional[str] = None
    """HTML to add (inside ``<p>``) to login error pages."""

    slack_webhook: Optional[str] = None
    """Slack webhook to which to post alerts."""

    @classmethod
    def from_file(cls, path: str) -> Config:
        """Construct a Config object from a settings file.

        Parameters
        ----------
        path : `str`
            Path to the settings file in YAML.

        Returns
        -------
        config : `Config`
            The corresponding Config object.
        """
        with open(path, "r") as f:
            raw_settings = yaml.safe_load(f)
        settings = Settings.parse_obj(raw_settings)

        # Build the GitHub configuration if needed.
        github_config = None
        if settings.github:
            path = settings.github.client_secret_file
            github_secret = cls._load_secret(path).decode()
            github_config = GitHubConfig(
                client_id=settings.github.client_id,
                client_secret=github_secret,
            )

        # Build the OpenID Connect configuration if needed.
        oidc_config = None
        if settings.oidc:
            path = settings.oidc.client_secret_file
            enrollment_url = None
            if settings.oidc.enrollment_url:
                enrollment_url = str(settings.oidc.enrollment_url)
            oidc_secret = cls._load_secret(path).decode()
            oidc_config = OIDCConfig(
                client_id=settings.oidc.client_id,
                client_secret=oidc_secret,
                login_url=str(settings.oidc.login_url),
                login_params=settings.oidc.login_params,
                redirect_url=str(settings.oidc.redirect_url),
                token_url=str(settings.oidc.token_url),
                enrollment_url=enrollment_url,
                scopes=tuple(settings.oidc.scopes),
                issuer=settings.oidc.issuer,
                audience=settings.oidc.audience,
                username_claim=settings.oidc.username_claim,
                uid_claim=settings.oidc.uid_claim,
                gid_claim=settings.oidc.gid_claim,
                groups_claim=settings.oidc.groups_claim,
            )

        # Build LDAP configuration if needed.
        ldap_config = None
        if settings.ldap and settings.ldap.url:
            ldap_password = None
            if settings.ldap.password_file:
                path = settings.ldap.password_file
                ldap_password = cls._load_secret(path).decode()
            ldap_config = LDAPConfig(
                url=settings.ldap.url,
                user_dn=settings.ldap.user_dn,
                password=ldap_password,
                group_base_dn=settings.ldap.group_base_dn,
                group_object_class=settings.ldap.group_object_class,
                group_member_attr=settings.ldap.group_member_attr,
                user_base_dn=settings.ldap.user_base_dn,
                user_search_attr=settings.ldap.user_search_attr,
                name_attr=settings.ldap.name_attr,
                email_attr=settings.ldap.email_attr,
                uid_attr=settings.ldap.uid_attr,
                gid_attr=settings.ldap.gid_attr,
                add_user_group=settings.ldap.add_user_group,
            )

        # Build Firestore configuration if needed.
        firestore_config = None
        if settings.firestore:
            firestore_config = FirestoreConfig(
                project=settings.firestore.project
            )

        # Build the OpenID Connect server configuration if needed.
        oidc_server_config = None
        if settings.oidc_server:
            oidc_key = cls._load_secret(settings.oidc_server.key_file)
            oidc_keypair = RSAKeyPair.from_pem(oidc_key)
            path = settings.oidc_server.secrets_file
            oidc_secrets_json = cls._load_secret(path).decode()
            oidc_secrets = json.loads(oidc_secrets_json)
            oidc_clients = tuple(
                (
                    OIDCClient(client_id=c["id"], client_secret=c["secret"])
                    for c in oidc_secrets
                )
            )
            oidc_server_config = OIDCServerConfig(
                issuer=settings.oidc_server.issuer,
                key_id=settings.oidc_server.key_id,
                audience=settings.oidc_server.audience,
                keypair=oidc_keypair,
                lifetime=timedelta(minutes=settings.token_lifetime_minutes),
                clients=oidc_clients,
            )

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

        # Build the top-level configuration.
        session_secret = cls._load_secret(settings.session_secret_file)
        bootstrap_token = None
        if settings.bootstrap_token_file:
            path = settings.bootstrap_token_file
            bootstrap_token_str = cls._load_secret(path).decode()
            bootstrap_token = Token.from_str(bootstrap_token_str)
        redis_password = None
        if settings.redis_password_file:
            path = settings.redis_password_file
            redis_password = cls._load_secret(path).decode()
        database_password = None
        if settings.database_password_file:
            path = settings.database_password_file
            database_password = cls._load_secret(path).decode()
        slack_webhook = None
        if settings.slack_webhook_file:
            path = settings.slack_webhook_file
            slack_webhook = cls._load_secret(path).decode()
        config = cls(
            realm=settings.realm,
            session_secret=session_secret.decode(),
            database_url=settings.database_url,
            database_password=database_password,
            redis_url=settings.redis_url,
            redis_password=redis_password,
            bootstrap_token=bootstrap_token,
            token_lifetime=timedelta(minutes=settings.token_lifetime_minutes),
            proxies=tuple(settings.proxies if settings.proxies else []),
            after_logout_url=str(settings.after_logout_url),
            github=github_config,
            oidc=oidc_config,
            ldap=ldap_config,
            firestore=firestore_config,
            oidc_server=oidc_server_config,
            known_scopes=settings.known_scopes or {},
            group_mapping=group_mapping_frozen,
            initial_admins=tuple(settings.initial_admins),
            error_footer=settings.error_footer,
            slack_webhook=slack_webhook,
        )

        # Configure logging.  Some Safir applications allow customization of
        # these parameters, but Gafaelfawr only allows customizing the log
        # level.
        configure_logging(
            profile="production",
            log_level=settings.loglevel,
            name="gafaelfawr",
            add_timestamp=True,
        )

        # Return the completed configuration.
        return config

    @staticmethod
    def _load_secret(path: str) -> bytes:
        """Load a secret from a file."""
        with open(path, "rb") as fh:
            secret = fh.read().strip()
            assert len(secret), f"Secret file {path} is empty"
            return secret
