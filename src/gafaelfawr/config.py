"""Configuration for Gafaelfawr.

There are two, mostly-parallel models defined here.  The ones ending in
``Settings`` are the pydantic models used to read the configuration file from
disk, the root of which is `Settings`.  This is then processed and broken up
into configuration dataclasses for various components and then exposed to the
rest of Gafaelfawr as the `Config` object.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Annotated, Self
from uuid import UUID

import yaml
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    UrlConstraints,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel
from pydantic_core import Url
from safir.logging import LogLevel, configure_logging

from .constants import SCOPE_REGEX, USERNAME_REGEX
from .keypair import RSAKeyPair
from .models.token import Token
from .util import group_name_for_github_team

__all__ = [
    "Config",
    "FirestoreConfig",
    "FirestoreSettings",
    "GitHubConfig",
    "GitHubGroup",
    "GitHubGroupTeam",
    "GitHubSettings",
    "HttpsUrl",
    "LDAPConfig",
    "LDAPSettings",
    "NotebookQuota",
    "NotebookQuotaSettings",
    "OIDCConfig",
    "OIDCClient",
    "OIDCServerConfig",
    "OIDCServerSettings",
    "OIDCSettings",
    "Quota",
    "QuotaGrant",
    "QuotaGrantSettings",
    "QuotaSettings",
    "Settings",
]

HttpsUrl = Annotated[
    Url,
    UrlConstraints(
        allowed_schemes=["https"], host_required=True, max_length=2083
    ),
]


class GitHubSettings(BaseModel):
    """pydantic model of GitHub configuration."""

    client_id: str
    """Client ID of the GitHub App."""

    client_secret_file: Path
    """File containing secret for the GitHub App."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class OIDCSettings(BaseModel):
    """pydantic model of OpenID Connect configuration."""

    client_id: str
    """Client ID for talking to the OpenID Connect provider."""

    client_secret_file: Path
    """File containing secret for talking to the OpenID Connect provider."""

    login_url: AnyHttpUrl
    """URL to which to send the user to initiate authentication."""

    login_params: dict[str, str] = Field(
        {},
        title="Additional login parameters",
        description="Additional parameters to the login URL",
    )

    redirect_url: AnyHttpUrl
    """Return URL to which the authentication provider should send the user.

    This should be the full URL of the /login route of Gafaelfawr.
    """

    token_url: AnyHttpUrl
    """URL at which to redeem the authentication code for a token."""

    enrollment_url: AnyHttpUrl | None = None
    """URL to which the user should be redirected if not enrolled.

    If LDAP username lookup is configured (using ``ldap.username_base_dn``)
    and the user could not be found, redirect the user, after login, to this
    URL so that they can register.
    """

    scopes: list[str] = Field(
        [],
        title="Scopes to request",
        description=(
            "Scopes to request from the authentication provider. The"
            " ``openid`` scope will always be added and does not need to be"
            " specified."
        ),
    )

    issuer: str
    """Expected issuer of the ID token."""

    audience: str
    """Expected audience of the ID token."""

    username_claim: str = "uid"
    """Name of claim to use as the username."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class LDAPSettings(BaseModel):
    """pydantic model of LDAP configuration."""

    url: str
    """LDAP server URL.

    Use the ``ldaps`` scheme if you're using TLS.  Only anonymous binds are
    supported.
    """

    user_dn: str | None = None
    """Simple bind user DN for the LDAP server."""

    use_kerberos: bool = False
    """Whether to use Kerberos GSSAPI binds.

    If both this and ``user_dn`` are set, simple binds take precedence. This
    allows triggering all of the other Kerberos handling while still using
    simple binds instead of GSSAPI binds, to make testing easier.
    """

    password_file: Path | None = None
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

    group_search_by_dn: bool = False
    """Whether to search for group membership by user DN.

    By default, Gafaelfawr locates user group memberships by searching for an
    attribute in the group tree containing the bare username. If this option
    is set to `True`, the username is turned into a user DN using
    ``user_base_dn`` and ``user_search_attr`` and group memberships are
    instead retrieved by searching for ``group_member_attr`` attributes
    containing that DN.

    The default is `False` for backwards-compatibility reasons and because
    setting the LDAP user attributes is optional, but most LDAP servers are
    organized this way. The default may be changed to `True` in a future
    release.

    If set to `True`, ``user_base_dn`` must be set.
    """

    user_base_dn: str
    """Base DN to use to search for user information.

    The base DN used to search for the user record, from which other
    information such as full name, email, numeric UID, and (if configured)
    numeric GID will be retrieved.
    """

    user_search_attr: str = "uid"
    """Search attribute for finding the user record.

    This attribute must hold the username of the user that Gafaelfawr knows
    them by.  Used if ``user_base_dn`` is set.  The default is ``uid``, which
    is the LDAP convention for the attribute holding the username. This should
    also be the attribute used to make up the DN of a user, since it is used
    by ``group_search_by_dn``.
    """

    name_attr: str | None = "displayName"
    """LDAP full name attribute.

    The attribute from which the user's full name will be taken, or `None` to
    not look up full names. This should normally be ``displayName``, but
    sometimes it may be desirable to use a different name attribute. This
    should hold the whole name that should be used by the Science Platform,
    not just a surname or family name (which are not universally valid
    concepts anyway).
    """

    email_attr: str | None = "mail"
    """LDAP email attribute.

    The attribute from which the user's email address should be taken, or
    `None` to not look up email addresses. This should normally be ``mail``.
    """

    uid_attr: str | None = "uidNumber"
    """LDAP UID attribute.

    If set, the user's UID will be taken from this sttribute. This should
    usually be ``uidNumber``, as specified in :rfc:`2307` and `RFC 2307bis`_.
    If not set, Firestore must be configured.
    """

    gid_attr: str | None = "gidNumber"
    """LDAP GID attirbute.

    If set, the user's primary GID will be taken from this sttribute. This
    should usually be ``gidNumber``, as specified in :rfc:`2307` and `RFC
    2307bis`_. If not set, the primary GID will match the UID if
    ``add_user_group`` is true, and otherwise will not be set.
    """

    add_user_group: bool = False
    """Whether to synthesize a user private group with GID matching UID.

    If set to `True`, synthesize a group for the user whose name and GID
    matches the username and UID, adding it to the group list without
    requiring it to appear in LDAP.
    """

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    @model_validator(mode="after")
    def _validate_password_file(self) -> Self:
        """Ensure fields are non-empty if url is non-empty."""
        if self.user_dn and not self.password_file:
            raise ValueError("password_file required if user_dn set")
        return self


class FirestoreSettings(BaseModel):
    """pydantic model of Firestore configuration."""

    project: str
    """Project containing the Firestore collections."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class OIDCServerSettings(BaseModel):
    """pydantic model of issuer configuration."""

    issuer: HttpsUrl
    """iss (issuer) field in issued tokens."""

    key_id: str
    """kid (key ID) header field in issued tokens."""

    key_file: Path
    """File containing RSA private key for signing issued tokens."""

    secrets_file: Path
    """Path to file containing OpenID Connect client secrets in JSON."""

    data_rights_mapping: dict[str, list[str]] = Field(
        {},
        title="Group to data rights mapping",
        description=(
            "Mapping of group names to keywords for data releases, indicating"
            " membership in that group grants access to that data release."
            " Used to construct the ``data_rights`` claim, which can be"
            " requested by asking for the ``rubin`` scope."
        ),
        examples=[{"g_users": ["dp0.1", "dp0.2", "dp0.3"]}],
    )

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class NotebookQuotaSettings(BaseModel):
    """Quota settings for the Notebook Aspect."""

    cpu: float
    """Maximum number of CPU equivalents."""

    memory: float
    """Maximum memory usage in GiB."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class QuotaGrantSettings(BaseModel):
    """One grant of quotas.

    There may be one of these per group, as well as a default one, in the
    overall quota configuration.
    """

    api: dict[str, int] = Field(
        {},
        title="Service quotas",
        description=(
            "Mapping of service names to quota of requests per 15 minutes"
        ),
    )

    notebook: NotebookQuotaSettings | None = None
    """Quota settings for the Notebook Aspect."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class QuotaSettings(BaseModel):
    """Quota settings."""

    default: QuotaGrantSettings
    """Default quotas for all users."""

    groups: dict[str, QuotaGrantSettings] = Field(
        {},
        title="Quota grants by group",
        description="Additional quota grants by group name",
    )

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class GitHubGroupTeam(BaseModel):
    """Specification for a GitHub team."""

    organization: str
    """Name of the organization."""

    team: str
    """Slug of the team within that organization."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    def __str__(self) -> str:
        return group_name_for_github_team(self.organization, self.team)


class GitHubGroup(BaseModel):
    """An individual GitHub team."""

    github: GitHubGroupTeam
    """Details of the GitHub team."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    def __str__(self) -> str:
        return str(self.github)


class Settings(BaseModel):
    """pydantic model of Gafaelfawr configuration file.

    This describes the configuration file as parsed from disk.  This model
    will be converted to a `Config` dataclass for internal use so that some
    settings can be duplicated, rewritten, or parsed into internal formats for
    later convenience.

    Several fields use an empty dictionary or empty list as a default value.
    Due to a quirk in how Python handles empty dict and list constructors, the
    caller must be careful to never modify those fields and instead treat the
    value as read-only.  In practice, this isn't much of a concern since this
    object is only used to convert to a `Config` object.
    """

    realm: str
    """Realm for HTTP authentication."""

    log_level: LogLevel = LogLevel.INFO
    """Logging level."""

    session_secret_file: Path
    """File containing encryption secret for session cookie and store."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    redis_password_file: Path | None = None
    """File containing the password to use when connecting to Redis."""

    database_url: str
    """URL for the PostgreSQL database."""

    database_password_file: Path | None = None
    """File containing the password for the PostgreSQL database."""

    bootstrap_token_file: Path | None = None
    """File containing the bootstrap authentication token.

    This token can be used with specific routes in the admin API to change the
    list of admins and create service and user tokens.
    """

    token_lifetime_minutes: int = 1380  # 23 hours
    """Number of minutes into the future that a token should expire."""

    proxies: list[IPv4Network | IPv6Network] | None = None
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

    error_footer: str | None = None
    """HTML to add (inside ``<p>``) to login error pages."""

    slack_webhook_file: Path | None = None
    """File containing the Slack webhook to which to post alerts."""

    cadc_base_uuid: UUID | None = None
    """Namespace UUID used to generate UUIDs for CADC-compatible auth."""

    github: GitHubSettings | None = None
    """Settings for the GitHub authentication provider."""

    oidc: OIDCSettings | None = None
    """Settings for the OpenID Connect authentication provider."""

    ldap: LDAPSettings | None = None
    """Settings for the LDAP-based group lookups with OIDC provider."""

    firestore: FirestoreSettings | None = None
    """Settings for Firestore-based UID/GID assignment."""

    oidc_server: OIDCServerSettings | None = None
    """Settings for the internal OpenID Connect server."""

    quota: QuotaSettings | None = None
    """Quota for users."""

    initial_admins: list[str]
    """Initial token administrators to configure when initializing database."""

    known_scopes: dict[str, str] = Field(
        {},
        title="Known scopes",
        description=(
            "Known scopes (the keys) and their descriptions (the values)"
        ),
    )

    group_mapping: dict[str, list[str | GitHubGroup]] = Field(
        {},
        title="Scope to group mapping",
        description="Mappings of scopes to lists of groups that provide them",
    )

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    @field_validator("initial_admins")
    @classmethod
    def _validate_initial_admins(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("initial_admins is empty")
        for admin in v:
            if not re.match(USERNAME_REGEX, admin):
                raise ValueError(f"invalid username {admin}")
        return v

    @field_validator("known_scopes")
    @classmethod
    def _valid_known_scopes(cls, v: dict[str, str]) -> dict[str, str]:
        for scope in v:
            if not re.match(SCOPE_REGEX, scope):
                raise ValueError(f"invalid scope {scope}")
        for required in ("admin:token", "user:token"):
            if required not in v:
                raise ValueError(f"required scope {required} missing")
        return v

    @model_validator(mode="after")
    def _validate_userinfo(self) -> Self:
        """Ensure user information sources are configured properly."""
        if not self.github and not self.oidc:
            msg = "One of GitHub or OpenID Connect must be configured"
            raise ValueError(msg)
        if self.github and self.oidc:
            raise ValueError("GitHub and OpenID Connect cannot both be used")
        if self.github and self.ldap:
            raise ValueError("LDAP cannot be used with GitHub authentication")
        if self.oidc and not self.ldap:
            msg = "LDAP must be configured if OpenID Connect is used"
            raise ValueError(msg)
        if self.ldap:
            if not self.ldap.uid_attr and not self.firestore:
                msg = "ldap.uidAttr must be set unless Firestore is used"
                raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
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


@dataclass(frozen=True, slots=True)
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

    enrollment_url: str | None
    """URL to which the user should be redirected if not enrolled.

    If LDAP username lookup is configured (using ``ldap.username_base_dn``)
    and the user could not be found, redirect the user, after login, to this
    URL so that they can register.
    """

    scopes: tuple[str, ...]
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


@dataclass(frozen=True, slots=True)
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

    user_dn: str | None
    """User DN for simple bind authentication to the LDAP server."""

    password: str | None
    """Password for simple bind authentication to the LDAP server."""

    use_kerberos: bool
    """Whether to use Kerberos GSSAPI binds.

    If both this and ``user_dn`` are set, simple binds take precedence. This
    allows triggering all of the other Kerberos handling while still using
    simple binds instead of GSSAPI binds, to make testing easier.
    """

    group_base_dn: str
    """Base DN to use when executing LDAP search for group membership."""

    group_object_class: str
    """LDAP group object class."""

    group_member_attr: str
    """LDAP group member attribute."""

    group_search_by_dn: bool
    """Whether to search for group membership by user DN.

    By default, Gafaelfawr locates user group memberships by searching for an
    attribute in the group tree containing the bare username. If this option
    is set to `True`, the username is turned into a user DN using
    ``user_base_dn`` and ``user_search_attr`` and group memberships are
    instead retrieved by searching for ``group_member_attr`` attributes
    containing that DN.
    """

    user_base_dn: str
    """Base DN to use to search for user information.

    If set, the base DN used to search for the user record, from which other
    information such as full name, email, and (if configured) numeric UID will
    be retrieved.
    """

    user_search_attr: str
    """Search attribute for finding the user record.

    This attribute must hold the username of the user that Gafaelfawr knows
    them by.  Used if ``user_base_dn`` is set.  The default is ``uid``, which
    is the LDAP convention for the attribute holding the username.
    """

    name_attr: str | None
    """LDAP full name attribute.

    The attribute from which the user's full name will be taken, or `None` to
    not look up full names.  This should normally be ``displayName``, but
    sometimes it may be desirable to use a different name attribute.  This
    should hold the whole name that should be used by the Science Platform,
    not just a surname or family name (which are not universally valid
    concepts anyway).
    """

    email_attr: str | None
    """LDAP email attribute.

    The attribute from which the user's email address should be taken, or
    `None` to not look up email addresses.  This should normally be
    ``mail``.
    """

    uid_attr: str | None
    """LDAP UID attribute.

    If set, the user's UID will be taken from this sttribute.  If UID lookups
    are desired, this should usually be ``uidNumber``, as specified in
    :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.
    """

    gid_attr: str | None
    """LDAP GID attirbute.

    If set, the user's primary GID will be taken from this sttribute.  If GID
    lookups are desired, this should usually be ``gidNumber``, as specified in
    :rfc:`2307` and `RFC 2307bis
    <https://datatracker.ietf.org/doc/html/draft-howard-rfc2307bis-02>`__.  If
    not set, the primary GID will match the UID if ``add_user_group`` is true,
    and otherwise will not be set.
    """


@dataclass(frozen=True, slots=True)
class FirestoreConfig:
    """Configuration for Firestore-based UID/GID assignment."""

    project: str
    """Project containing the Firestore collections."""


@dataclass(frozen=True, slots=True)
class OIDCClient:
    """Configuration for a single OpenID Connect client of our server."""

    client_id: str
    """Unique identifier of the client."""

    client_secret: str
    """Secret used to authenticate this client."""

    return_uri: str
    """Acceptable return URL when authenticating users for this client."""


@dataclass(frozen=True, slots=True)
class OIDCServerConfig:
    """Configuration for the OpenID Connect server."""

    issuer: str
    """iss (issuer) field in issued tokens."""

    key_id: str
    """kid (key ID) header field in issued tokens."""

    keypair: RSAKeyPair
    """RSA key pair for signing and verifying issued tokens."""

    lifetime: timedelta
    """Lifetime of issued tokens."""

    clients: tuple[OIDCClient, ...]
    """Supported OpenID Connect clients."""

    data_rights_mapping: Mapping[str, frozenset[str]]
    """Mapping of group names to keywords for data releases.

    Indicates that membership in the given group grants access to that set of
    data releases. Used to construct the ``data_rights`` claim, which can be
    requested by asking for the ``rubin`` scope.
    """


@dataclass(frozen=True, slots=True)
class NotebookQuota:
    """Quota settings for the Notebook Aspect."""

    cpu: float
    """Maximum number of CPU equivalents."""

    memory: float
    """Maximum memory usage in GiB."""


@dataclass(frozen=True, slots=True)
class QuotaGrant:
    """One grant of quotas.

    There may be one of these per group, as well as a default one, in the
    overall quota configuration.
    """

    api: Mapping[str, int]
    """Mapping of service names to quota of requests per 15 minutes."""

    notebook: NotebookQuota | None
    """Quota settings for the Notebook Aspect."""


@dataclass(frozen=True, slots=True)
class Quota:
    """Quota settings."""

    default: QuotaGrant
    """Default quotas for all users."""

    groups: Mapping[str, QuotaGrant]
    """Additional quota grants by group name."""


@dataclass(frozen=True, slots=True)
class Config:
    """Configuration for Gafaelfawr.

    The internal representation of the configuration, created from the
    `Settings` model.

    Some configuration parameters from the configuration file are copied into
    multiple configuration dataclasses.  This allows the configuration for
    each internal component to be self-contained and unaware of the
    configuration of the rest of the application.
    """

    realm: str
    """Realm for HTTP authentication."""

    log_level: LogLevel
    """Level for logging."""

    session_secret: str
    """Secret used to encrypt the session cookie and session store."""

    redis_url: str
    """URL for the Redis server that stores sessions."""

    redis_password: str | None
    """Password for the Redis server that stores sessions."""

    database_url: str
    """URL for the PostgreSQL database."""

    database_password: str | None
    """Password for the PostgreSQL database."""

    bootstrap_token: Token | None
    """Bootstrap authentication token.

    This token can be used with specific routes in the admin API to change the
    list of admins and create service and user tokens.
    """

    token_lifetime: timedelta
    """Maximum lifetime of session, notebook, and internal tokens."""

    proxies: tuple[IPv4Network | IPv6Network, ...]
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

    error_footer: str | None
    """HTML to add (inside ``<p>``) to login error pages."""

    slack_webhook: str | None
    """Slack webhook to which to post alerts."""

    cadc_base_uuid: UUID | None
    """Namespace UUID used to generate UUIDs for CADC-compatible auth."""

    add_user_group: bool
    """Whether to synthesize a user private group with GID matching UID.

    If set to `True`, synthesize a group for the user whose name and GID
    matches the username and UID, adding it to the group list without
    requiring it to appear in LDAP.
    """

    github: GitHubConfig | None
    """Configuration for GitHub authentication."""

    oidc: OIDCConfig | None
    """Configuration for OpenID Connect authentication."""

    ldap: LDAPConfig | None
    """Configuration for LDAP."""

    firestore: FirestoreConfig | None
    """Settings for Firestore-based UID/GID assignment."""

    oidc_server: OIDCServerConfig | None
    """Configuration for the OpenID Connect server."""

    quota: Quota | None
    """Quota for users."""

    initial_admins: tuple[str, ...]
    """Initial token administrators to configure when initializing database."""

    known_scopes: Mapping[str, str]
    """Known scopes (the keys) and their descriptions (the values)."""

    group_mapping: Mapping[str, frozenset[str]]
    """Mapping of group names to the set of scopes that group grants."""

    @classmethod
    def from_file(cls, path: Path) -> Self:  # noqa: PLR0912,PLR0915,C901
        """Construct a Config object from a configuration file.

        Parameters
        ----------
        path
            Path to the configuration file in YAML.

        Returns
        -------
        Config
            The corresponding `Config` object.
        """
        with path.open("r") as f:
            settings = Settings.model_validate(yaml.safe_load(f))

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
            )

        # Build LDAP configuration if needed.
        add_user_group = settings.github is not None
        ldap_config = None
        if settings.ldap:
            ldap_password = None
            if settings.ldap.password_file:
                path = settings.ldap.password_file
                ldap_password = cls._load_secret(path).decode()
            ldap_config = LDAPConfig(
                url=settings.ldap.url,
                user_dn=settings.ldap.user_dn,
                password=ldap_password,
                use_kerberos=settings.ldap.use_kerberos,
                group_base_dn=settings.ldap.group_base_dn,
                group_object_class=settings.ldap.group_object_class,
                group_member_attr=settings.ldap.group_member_attr,
                group_search_by_dn=settings.ldap.group_search_by_dn,
                user_base_dn=settings.ldap.user_base_dn,
                user_search_attr=settings.ldap.user_search_attr,
                name_attr=settings.ldap.name_attr,
                email_attr=settings.ldap.email_attr,
                uid_attr=settings.ldap.uid_attr,
                gid_attr=settings.ldap.gid_attr,
            )
            add_user_group = settings.ldap.add_user_group

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
                OIDCClient(
                    client_id=c["id"],
                    client_secret=c["secret"],
                    return_uri=c["return_uri"],
                )
                for c in oidc_secrets
            )
            data_rights_mapping = {
                g: frozenset(r)
                for g, r in settings.oidc_server.data_rights_mapping.items()
            }
            oidc_server_config = OIDCServerConfig(
                issuer=str(settings.oidc_server.issuer),
                key_id=settings.oidc_server.key_id,
                keypair=oidc_keypair,
                lifetime=timedelta(minutes=settings.token_lifetime_minutes),
                clients=oidc_clients,
                data_rights_mapping=data_rights_mapping,
            )

        # Build the quota configuration if needed.
        quota = None
        if settings.quota:
            notebook = None
            if settings.quota.default.notebook:
                notebook_default = settings.quota.default.notebook
                notebook = NotebookQuota(**notebook_default.model_dump())
            default = QuotaGrant(
                api=settings.quota.default.api, notebook=notebook
            )
            group_quota = {}
            for group, grant in settings.quota.groups.items():
                notebook = None
                if grant.notebook:
                    notebook = NotebookQuota(**grant.notebook.model_dump())
                frozen_grant = QuotaGrant(api=grant.api, notebook=notebook)
                group_quota[group] = frozen_grant
            quota = Quota(default=default, groups=group_quota)

        # The group mapping in the settings maps a scope to a list of groups
        # that provide that scope. This may be conceptually easier for the
        # person writing the configuration, but for our purposes we want a map
        # from a group name to a set of scopes that group provides. Groups may
        # also be GitHubTeamName objects instead of strings, and we need to
        # convert them here.
        #
        # Reconstruct the group mapping in the form in which we want to use it
        # internally.
        group_mapping = defaultdict(set)
        for scope, groups in settings.group_mapping.items():
            for group_or_team in groups:
                group_mapping[str(group_or_team)].add(scope)
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
        return cls(
            realm=settings.realm,
            log_level=settings.log_level,
            session_secret=session_secret.decode(),
            redis_url=settings.redis_url,
            redis_password=redis_password,
            database_url=settings.database_url,
            database_password=database_password,
            bootstrap_token=bootstrap_token,
            token_lifetime=timedelta(minutes=settings.token_lifetime_minutes),
            proxies=tuple(settings.proxies if settings.proxies else []),
            after_logout_url=str(settings.after_logout_url),
            error_footer=settings.error_footer,
            slack_webhook=slack_webhook,
            cadc_base_uuid=settings.cadc_base_uuid,
            add_user_group=add_user_group,
            github=github_config,
            oidc=oidc_config,
            ldap=ldap_config,
            firestore=firestore_config,
            oidc_server=oidc_server_config,
            quota=quota,
            initial_admins=tuple(settings.initial_admins),
            known_scopes=settings.known_scopes or {},
            group_mapping=group_mapping_frozen,
        )

    def configure_logging(self) -> None:
        """Configure logging based on the Gafaelfawr configuration."""
        configure_logging(name="gafaelfawr", log_level=self.log_level)

    @staticmethod
    def _load_secret(path: Path) -> bytes:
        """Load a secret from a file."""
        secret = path.read_bytes().rstrip(b"\n")
        if len(secret) == 0:
            raise ValueError(f"Secret file {path} is empty")
        return secret
