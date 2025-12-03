"""Configuration for Gafaelfawr.

Gafaelfawr is primarily configured by a YAML file injected into the pod that
contains a copy of the ``config`` key of the Helm chart values. However, many
settings are based on Phalanx global settings or secrets, and those are
injected via environment variables.

Every part of the configuration that accepts environment variables uses the
same prefix for simplicity in the Helm chart. Only the settings with explicit
``validation_alias`` settings support configuration via environment variable.
There is unfortunately no way to disable environment variable support for the
other settings that should always come from the configuration file.

Order of fields in the configuration models should match the order of the
fields in Gafaelfawr's :file:`values.yaml` file, although there will be more
settings here since some settings are only injected via environment variables
and cannot be set in the config.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Annotated, Any, NotRequired, Self, TypedDict, override
from urllib.parse import quote

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    SecretStr,
    UrlConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel
from pydantic_core import Url
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from safir.logging import LogLevel, configure_logging
from safir.metrics import MetricsConfiguration
from safir.pydantic import EnvAsyncPostgresDsn, EnvRedisDsn, HumanTimedelta

from .constants import MINIMUM_LIFETIME, SCOPE_REGEX, USERNAME_REGEX
from .exceptions import InvalidTokenError
from .keypair import RSAKeyPair
from .models.quota import QuotaConfig
from .models.token import Token
from .util import group_name_for_github_team

HttpsUrl = Annotated[
    Url,
    UrlConstraints(
        allowed_schemes=["https"], host_required=True, max_length=2083
    ),
]
"""URL type that accepts only ``https`` URLs."""

LdapDsn = Annotated[
    Url, UrlConstraints(allowed_schemes=["ldap", "ldaps"], host_required=True)
]
"""DSN for connecting to an LDAP server."""

__all__ = [
    "CamelCaseSettings",
    "Config",
    "CookieParameters",
    "EnvFirstSettings",
    "FirestoreConfig",
    "GitHubConfig",
    "GitHubGroup",
    "GitHubGroupTeam",
    "HttpsUrl",
    "LDAPConfig",
    "OIDCClient",
    "OIDCConfig",
    "OIDCServerConfig",
    "QuotaConfig",
]


class CamelCaseSettings(BaseSettings):
    """Base class for Pydantic settings supporting camel-case.

    This base class also forbids all extra attributes. It should be used as
    the base class (possibly indirectly) for all Gafaelfawr configuration
    models that support environment variable overrides.
    """

    model_config = SettingsConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )


class EnvFirstSettings(CamelCaseSettings):
    """Base class for Pydantic settings with environment overrides.

    Classes that inherit from this base class will prioritize environment
    variables over arguments to the class constructor.
    """

    @override
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Override the sources of settings.

        Deactivate :file:`.env` and secret file support, since Phalanx doesn't
        use them. Allow environment variables to override init parameters,
        since init parameters come from the YAML configuration file and we
        want environment variables to take precedent.

        Ideally, this code would use Pydantic's ``YamlConfigSettingsSource``,
        but unfortunately it currently doesn't support overriding the path to
        the configuration file dynamically, which is required by the test
        suite.
        """
        return (env_settings, init_settings)


class GitHubConfig(EnvFirstSettings):
    """Configuration for the GitHub authentication provider."""

    client_id: str = Field(
        ...,
        title="GitHub client ID",
        description="Client ID of the GitHub OAuth App",
    )

    client_secret: SecretStr = Field(
        ...,
        title="GitHub client secret",
        description="Secret for the GitHub OAuth App",
        validation_alias=AliasChoices(
            "GAFAELFAWR_GITHUB_CLIENT_SECRET", "clientSecret"
        ),
    )


class OIDCConfig(EnvFirstSettings):
    """Configuration for a generic OpenID Connect authentication provider."""

    client_id: str = Field(
        ...,
        title="OpenID Connect client ID",
        description="Client ID for talking to the OpenID Connect provider",
    )

    client_secret: SecretStr = Field(
        ...,
        title="OpenID Connect client secret",
        description="Secret for talking to the OpenID Connect provider",
        validation_alias=AliasChoices(
            "GAFAELFAWR_OIDC_CLIENT_SECRET", "clientSecret"
        ),
    )

    # This must come after client_id due to its custom validator.
    audience: str = Field(
        ...,
        title="ID token audience",
        description=(
            "Value of audience (``aud``) claim to expect. If not set, defaults"
            " to the client ID."
        ),
    )

    login_url: HttpUrl = Field(
        ...,
        title="User login URL",
        description="URL to which to send the user to initiate authentication",
    )

    login_params: dict[str, str] = Field(
        {},
        title="Additional login parameters",
        description="Additional parameters to the login URL",
    )

    redirect_url: HttpUrl = Field(
        ...,
        title="Return URL after authentication",
        description=(
            "Where the user should be sent after authentication. This must"
            " match the URL registered with CILogon. It should be the full"
            " URL of the ``/login`` route."
        ),
        validation_alias=AliasChoices(
            "GAFAELFAWR_REDIRECT_URL", "redirectUrl"
        ),
    )

    token_url: HttpUrl = Field(
        ...,
        title="OpenID Connect token endpoint",
        description=(
            "URL from which to redeem the authentication code for a token"
        ),
    )

    enrollment_url: HttpUrl | None = Field(
        None,
        title="Enrollment URL",
        description=(
            "If LDAP username lookup is configured (using"
            " ``ldap.username_base_dn``) and the user could not be found,"
            " redirect the user, after login, to this URL so that they can"
            " register"
        ),
    )

    issuer: str = Field(
        ...,
        title="Expected issuer",
        description="Expected issuer claim (``iss``) of the ID token",
    )

    scopes: list[str] = Field(
        [],
        title="Scopes to request",
        description=(
            "Scopes to request from the authentication provider. The"
            " ``openid`` scope will always be added and does not need to be"
            " specified."
        ),
    )

    username_claim: str = Field(
        "uid",
        title="Claim containing username",
        description="OpenID Connect ID token claim containing the username",
    )

    @field_validator("audience", mode="before")
    @classmethod
    def _validate_audience(cls, v: str | None, info: ValidationInfo) -> str:
        if v is None:
            return info.data["client_id"]
        return v


class CILogonConfig(EnvFirstSettings):
    """Configuration for the CILogon authentication provider."""

    client_id: str = Field(
        ...,
        title="CILogon client ID",
        description="Client ID for talking to CILogon",
    )

    client_secret: SecretStr = Field(
        ...,
        title="CILogon client secret",
        description="Secret for talking to CILogon",
        validation_alias=AliasChoices(
            "GAFAELFAWR_CILOGON_CLIENT_SECRET", "clientSecret"
        ),
    )

    enrollment_url: HttpUrl | None = Field(
        None,
        title="Enrollment URL",
        description=(
            "If LDAP username lookup is configured (using"
            " ``ldap.username_base_dn``) and the user could not be found,"
            " redirect the user, after login, to this URL so that they can"
            " register"
        ),
    )

    test: bool = Field(
        False,
        title="Use test CILogon",
        description=(
            "If true, use the test CILogon service instead of the production"
            " service"
        ),
    )

    login_params: dict[str, str] = Field(
        {},
        title="Additional login parameters",
        description="Additional parameters to the login URL",
    )

    redirect_url: HttpUrl = Field(
        ...,
        title="Return URL after authentication",
        description=(
            "Where the user should be sent after authentication. This must"
            " match the URL registered with CILogon. It should be the full"
            " URL of the ``/login`` route."
        ),
        validation_alias=AliasChoices(
            "GAFAELFAWR_REDIRECT_URL", "redirectUrl"
        ),
    )

    username_claim: str = Field(
        "username",
        title="Claim containing username",
        description="OpenID Connect ID token claim containing the username",
    )

    def to_oidc_config(self) -> OIDCConfig:
        """Convert to an OpenID Connect configuration.

        The Helm chart for Gafaelfawr separates CILogon from generic OpenID
        Config so that the configuration doesn't have to explicitly configure
        URLs and other parameters that are always the same for CILogon.
        Internally, though, Gafaelfawr treats them both as OpenID Connect
        configurations. This method generates the OpenID Connect configuration
        that will be used by the rest of Gafaelfawr.

        Returns
        -------
        OIDCConfig
            Corresponding OpenID Connect configuration.
        """
        host = "test.cilogon.org" if self.test else "cilogon.org"
        base_url = f"https://{host}"

        # Do not include redirect_url here, since the OIDCConfig model will
        # pull it from the environment and complain about extra inputs if it's
        # also specified in the constructor.
        return OIDCConfig.model_validate(
            {
                "audience": self.client_id,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "enrollment_url": self.enrollment_url,
                "login_url": f"{base_url}/authorize",
                "login_params": self.login_params,
                "token_url": f"{base_url}/oauth2/token",
                "issuer": base_url,
                "scopes": ["email", "org.cilogon.userinfo"],
                "username_claim": self.username_claim,
            }
        )


class LDAPConfig(EnvFirstSettings):
    """Configuration for LDAP support.

    In all known implementations, ``gidNumber`` holds the numeric GID of the
    group and ``cn`` holds its name, so these are not configurable.
    """

    url: LdapDsn = Field(
        ...,
        title="LDAP server URL",
        description=(
            "URL of LDAP server to query for user information. Not supported"
            " when GitHub is used as the authentication provider."
        ),
    )

    user_dn: str | None = Field(
        None,
        title="Simple bind DN for LDAP queries",
        description=(
            "DN of user to bind as with simple bind when querying the LDAP"
            " server. If neither this nor ``use_kerberos`` are set, Gafaelfawr"
            " will do an anonymous bind."
        ),
    )

    password: SecretStr | None = Field(
        None,
        title="Simple bind password",
        description=(
            "Password for simple bind authentication to the LDAP server."
            " Only used if ``user_dn`` is set."
        ),
        validation_alias="GAFAELFAWR_LDAP_PASSWORD",
    )

    kerberos_config: str | None = Field(
        None,
        title="Kerberos configuration for GSS-API",
        description=(
            "Contents of a :file:`/etc/krb5.conf` file to use for Kerberos"
            " GSS-API binds to the LDAP server. This setting is not used"
            " directly by the Gafaelfawr code. It is handled in the wrapper"
            " script for container setup. However, ``use_kerberos`` is set"
            " to true if this setting is not `None`."
        ),
    )

    use_kerberos: bool = Field(
        False,
        title="Whether to bind with GSS-API",
        description=(
            "If set to true, authenticate to LDAP with Kerberos GSS-API."
            " If both this and ``user_dn`` are set, simple binds take"
            " precedence. This allows triggering all of the other Kerberos"
            " handling while still using simple binds instead of GSSAPI"
            " binds, to make testing easier. This is set based on whether"
            " ``kerberos_config`` is set."
        ),
    )

    group_base_dn: str = Field(
        ...,
        title="Base DN for group lookups",
        description=(
            "Base DN to use when executing an LDAP search for user groups"
        ),
    )

    group_object_class: str = Field(
        "posixGroup",
        title="LDAP group object class",
        description=(
            "Object class to search for in the group tree. Usually"
            " ``posixGroup``, as specified in :rfc:`2307` and `RFC 2307bis`_."
        ),
    )

    group_member_attr: str = Field(
        "member",
        title="LDAP attribute holding group members",
        description=(
            "The LDAP attribute in the group tree that contains the list of"
            " members, either as simple usernames or, if"
            " ``group_search_by_dn`` is set, the user DN. Usually ``member``"
            " as specified in `RFC 2307bis`_."
        ),
    )

    group_search_by_dn: bool = Field(
        True,
        title="Search for groups by user DN",
        description=(
            "Whether to search for groups by user DN or only username. If this"
            " option is set to true, the username is transformed into a DN"
            " using ``user_base_dn`` and ``user_search_attr``, and that DN is"
            " the target of the ``group_member_attr`` search."
        ),
    )

    user_base_dn: str = Field(
        ...,
        title="Base DN for user lookups",
        description=(
            "The base DN used to search for the user record, from which other"
            " information such as full name, email, numeric UID, and numeric"
            " GID will be retrieved."
        ),
    )

    user_search_attr: str = Field(
        "uid",
        title="Search attribute for users",
        description=(
            "This attribute must hold the username of the user provided in"
            " the OpenID Connect ID token. The default is ``uid``, which is"
            " the LDAP convention for the attribute holding the username."
            " This should also be the attribute used to make up the DN of a"
            " user if ``group_search_by_dn`` is enabled."
        ),
    )

    name_attr: str | None = Field(
        "displayName",
        title="LDAP full name attribute",
        description=(
            "The attribute from which the user's full name will be taken, or"
            " `None` to not look up full names. This should normally be"
            " ``displayName``, but sometimes it may be desirable to use a"
            " different name attribute such as ``gecos``. This should hold"
            " the whole name that should be used by Gafaelfawr, not just a"
            " surname or family name (which are not universally valid"
            " concepts anyway)."
        ),
    )

    email_attr: str | None = Field(
        "mail",
        title="LDAP email attribute",
        description=(
            "The attribute from which the user's email address should be"
            " taken, or `None` to not look up email addresses. This should"
            " normally be ``mail``."
        ),
    )

    uid_attr: str | None = Field(
        "uidNumber",
        title="LDAP UID attribute",
        description=(
            "The attribute from which the user's numeric UID will be taken."
            " This should usually be ``uidNumber`` as specified in :rfc:`2307`"
            " and `RFC 2307bis`_. If Firestore is enabled, this may be set to"
            " null to not attempt UID lookups."
        ),
    )

    gid_attr: str | None = Field(
        "gidNumber",
        title="LDAP GID attirbute",
        description=(
            "The attribute from which the user's primary GID should be taken,"
            " or `None` to not look up primary GIDs. This should usually be"
            " be ``gidNumber``, as specified in :rfc:`2307` and "
            " `RFC 2307bis`_."
        ),
    )

    add_user_group: bool = Field(
        False,
        title="Synthesize user private groups",
        description=(
            "If set to true, synthesize a group for the user whose name and"
            " GID matches the username and UID, adding it to the group list"
            " without requiring it to appear in LDAP"
        ),
    )

    @model_validator(mode="after")
    def _validate_password(self) -> Self:
        """Ensure fields are non-empty if url is non-empty."""
        if self.user_dn and not self.password:
            raise ValueError("password required if userDn is set")
        return self

    @model_validator(mode="after")
    def _validate_use_kerberos(self) -> Self:
        """Set ``use_kerberos`` if ``kerberos_config`` is set."""
        if self.kerberos_config:
            self.use_kerberos = True
        return self


class FirestoreConfig(BaseModel):
    """Configuration for Firestore-based UID/GID assignment."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    project: str = Field(
        ...,
        title="Firestore GCP project",
        description="Project containing the Firestore collections",
    )


class OIDCClient(BaseModel):
    """Configuration for a single OpenID Connect client of our server.

    Unlike the other configuration models, this model parses the value of a
    secret rather than the Helm values file and does not support camel-case.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        ..., title="Client ID", description="Unique identifier of the client"
    )

    secret: SecretStr = Field(
        ...,
        title="Client secret",
        description="Secret used to authenticate this client",
    )

    return_uri: HttpUrl = Field(
        ...,
        title="Return URL",
        description=(
            "Acceptable return URL when authenticating users for this client"
        ),
    )


class OIDCServerConfig(EnvFirstSettings):
    """Configuration for the OpenID Connect server."""

    enabled: bool = Field(
        False,
        title="Enable OpenID Connect server",
        description="Whether to enable the internal OpenID Connect server",
    )

    issuer: HttpsUrl = Field(
        ...,
        title="Token issuer",
        description="Issuer (``iss``) claim in issued JWT tokens",
        validation_alias="GAFAELFAWR_OIDC_SERVER_ISSUER",
    )

    key: SecretStr = Field(
        ...,
        title="RSA private key",
        description="RSA private key used to sign issued JWTs",
        validation_alias="GAFAELFAWR_OIDC_SERVER_KEY",
    )

    key_id: str = Field(
        "gafaelfawr",
        title="Token key ID",
        description=(
            "Key ID (``kid``) claim in issued JWT tokens, which will also"
            " be used to provide the key from the metadata endpoints. Note"
            " that Gafaelfawr does not (yet) support key rotation, so while"
            " this key ID can be changed, Gafaelfawr has no mechanism to"
            " serve the old key as well as the new one with different key"
            " IDs."
        ),
    )

    clients: list[OIDCClient] = Field(
        ...,
        title="OpenID Connect clients",
        description="Registered OpenID Connect clients",
        validation_alias="GAFAELFAWR_OIDC_SERVER_CLIENTS",
    )

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

    _keypair: RSAKeyPair
    """RSA key pair created from ``key``."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        key = self.key.get_secret_value().encode()
        self._keypair = RSAKeyPair.from_pem(key)

    @property
    def keypair(self) -> RSAKeyPair:
        """RSA key pair used for signing JWTs."""
        return self._keypair


class GitHubGroupTeam(BaseModel):
    """Specification for a GitHub team."""

    model_config = ConfigDict(extra="forbid")

    organization: str = Field(..., title="Name of the organization")

    team: str = Field(..., title="Slug of the team")

    @override
    def __str__(self) -> str:
        return group_name_for_github_team(self.organization, self.team)


class GitHubGroup(BaseModel):
    """An individual GitHub team."""

    model_config = ConfigDict(extra="forbid")

    github: GitHubGroupTeam = Field(..., title="Details of the GitHub team")

    @override
    def __str__(self) -> str:
        return str(self.github)


class CookieParameters(TypedDict):
    """Settings passed to `fastapi.Response.set_cookie` to set cookies."""

    domain: NotRequired[str]
    httponly: bool
    secure: bool


class SentryConfig(CamelCaseSettings):
    """Sentry configuration for Gafaelfawr.

    This configuration is not used internally, but has to be present in the
    model so that we can forbid unknown configuration settings. Otherwise,
    Phalanx wouldn't be able to use the full ``config`` key of the Helm values
    as the configuration file.
    """

    enabled: bool = Field(False, title="Whether to send exceptions to Sentry")
    traces_sample_rate: float = Field(
        0.0,
        title="Sentry trace sample rate",
        description="The percentage of traces to be sent to sentry.",
        ge=0.0,
        le=1.0,
    )


class Config(EnvFirstSettings):
    """Configuration for Gafaelfawr."""

    after_logout_url: HttpUrl = Field(
        ...,
        title="Destination URL after logout",
        description="Default URL to which to send the user after logging out",
        validation_alias=AliasChoices(
            "GAFAELFAWR_AFTER_LOGOUT_URL", "afterLogoutUrl"
        ),
    )

    allow_subdomains: bool = Field(
        False,
        title="Allow subdomains",
        description=(
            "Allow authenticated ingresses in subdomains of the base URL."
            " This requires use of domain-scoped cookies instead of host"
            " cookies and therefore requires every subdomain of the domain"
            " in the base URL be under the full control of Gafaelfawr."
            " Otherwise, enabling this may cause cookies to leak and"
            " compromise the security of the protected applications."
        ),
    )

    base_url: HttpUrl = Field(
        ...,
        title="Base URL",
        description="Base URL for user-facing routes such as ``/login``",
        validation_alias=AliasChoices("GAFAELFAWR_BASE_URL", "baseUrl"),
    )

    base_internal_url: HttpUrl = Field(
        ...,
        title="Internal base URL",
        description=(
            "Base URL for internal-only routes such as ``/ingress/auth``"
        ),
        validation_alias=AliasChoices(
            "GAFAELFAWR_BASE_INTERNAL_URL", "baseInternalUrl"
        ),
    )

    bootstrap_token: SecretStr = Field(
        ...,
        title="Bootstrap token",
        description=(
            "File containing the bootstrap authentication token. This token"
            " can be used with specific routes in the admin API to change the"
            " list of admins and create service and user tokens."
        ),
        validation_alias=AliasChoices(
            "GAFAELFAWR_BOOTSTRAP_TOKEN", "bootstrapToken"
        ),
    )

    database_url: EnvAsyncPostgresDsn = Field(
        ...,
        title="Database DSN",
        description="DSN for the PostgreSQL database",
        validation_alias=AliasChoices(
            "GAFAELFAWR_DATABASE_URL", "databaseUrl"
        ),
    )

    database_password: SecretStr = Field(
        ...,
        title="Database password",
        description="Password for the PostgreSQL database",
        validation_alias=AliasChoices(
            "GAFAELFAWR_DATABASE_PASSWORD", "databasePassword"
        ),
    )

    error_footer: str | None = Field(
        None,
        title="HTML for error pages",
        description="HTML to add (inside ``<p>``) to login error pages",
    )

    internal_database: bool = Field(
        False,
        title="Use a cluster-internal database",
        description=(
            "Whether to use a cluster-internal database. This setting is only"
            " used by Helm, not by Gafaelfawr itself."
        ),
    )

    log_level: LogLevel = Field(
        LogLevel.INFO,
        title="Logging level",
        description="Python logging level",
    )

    metrics: MetricsConfiguration = Field(
        title="Metrics configuration",
        description="Configuration for reporting metrics to Kafka",
    )

    proxies: list[IPv4Network | IPv6Network] | None = Field(
        None,
        title="Trusted incoming proxy netblocks",
        description=(
            "If this is set to a non-empty list, it will be used as the"
            " trusted list of proxies when parsing the ``X-Forwarded-For``"
            " HTTP header in incoming requests. IP addresses from that"
            " header will be discarded from the right side when they are"
            " within a netblock in this list until a non-matching IP is"
            " reached or there is only one IP left, and then that IP will be"
            " used as the remote IP for logging purposes. This allows"
            " logging of accurate client IP addresses."
        ),
    )

    redis_ephemeral_url: EnvRedisDsn = Field(
        ...,
        title="Ephemeral Redis DSN",
        description="DSN for the Redis server that stores ephemeral data",
        validation_alias=AliasChoices(
            "GAFAELFAWR_REDIS_EPHEMERAL_URL", "redisEphemeralUrl"
        ),
    )

    redis_persistent_url: EnvRedisDsn = Field(
        ...,
        title="Persistent Redis DSN",
        description="DSN for the Redis server that stores tokens",
        validation_alias=AliasChoices(
            "GAFAELFAWR_REDIS_PERSISTENT_URL", "redisPersistentUrl"
        ),
    )

    redis_password: SecretStr | None = Field(
        None,
        title="Redis password",
        description="Password for both Redis servers",
        validation_alias=AliasChoices(
            "GAFAELFAWR_REDIS_PASSWORD", "redisPassword"
        ),
    )

    sentry: SentryConfig | None = Field(None, title="Sentry configuration")

    session_secret: SecretStr = Field(
        ...,
        title="Session encryption key",
        description="Fernet encryption key used for session cookie and store",
        validation_alias=AliasChoices(
            "GAFAELFAWR_SESSION_SECRET", "sessionSecret"
        ),
    )

    slack_alerts: bool = Field(
        False,
        title="Enable Slack alerts",
        description=(
            "Whether to enable Slack alerts. If true, ``slack_webhook`` must"
            " also be set."
        ),
    )

    slack_webhook: SecretStr | None = Field(
        None,
        title="Slack webhook for alerts",
        description="If set, alerts will be posted to this Slack webhook",
        validation_alias=AliasChoices(
            "GAFAELFAWR_SLACK_WEBHOOK", "slackWebhook"
        ),
    )

    token_lifetime: HumanTimedelta = Field(
        timedelta(days=30),
        title="Session token lifetime",
        description="Lifetime of newly-created session tokens",
    )

    update_schema: bool = Field(
        False,
        title="Update SQL schema",
        description=(
            "This setting is interpreted by Helm and triggers a SQL schema"
            " update via a Helm hook. It is not used by Gafaelfawr directly."
        ),
    )

    github: GitHubConfig | None = Field(
        None,
        title="GitHub configuration",
        description="Configuration for the GitHub authentication provider",
    )

    cilogon: CILogonConfig | None = Field(
        None,
        title="CILogon configuration",
        description="Configuration for the CILogon authentication provider",
    )

    oidc: OIDCConfig | None = Field(
        None,
        title="OpenID Connect configuration",
        description=(
            "Configuration for the OpenID Connect authentication provider"
        ),
    )

    ldap: LDAPConfig | None = Field(
        None,
        title="LDAP configuration",
        description="Configuration for retrieving user information from LDAP",
    )

    firestore: FirestoreConfig | None = Field(
        None,
        title="Firestore configuration",
        description="Configuration for UID/GID allocation using Firestore",
    )

    oidc_server: OIDCServerConfig | None = Field(
        None,
        title="OpenID Connect server configuration",
        description=(
            "Configuration for Gafaelfawr's internal OpenID Connect server"
        ),
    )

    quota: QuotaConfig | None = Field(
        None,
        title="Quota for users",
        description="Rules for assigning quota to users",
    )

    initial_admins: list[str] = Field(
        [],
        title="Initial administrators",
        description=(
            "List of usernames to mark as admins during database"
            " initialization"
        ),
    )

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

    _group_to_scopes: dict[str, frozenset[str]]
    """Internal cached mapping of scopes to groups from ``group_mapping``."""

    @field_validator("bootstrap_token")
    @classmethod
    def _validate_bootstrap_token(cls, v: SecretStr) -> SecretStr:
        try:
            Token.from_str(v.get_secret_value())
        except InvalidTokenError as e:
            raise ValueError(str(e)) from e
        return v

    @field_validator("initial_admins")
    @classmethod
    def _validate_initial_admins(cls, v: list[str]) -> list[str]:
        if not v:
            return v
        for admin in v:
            if not re.match(USERNAME_REGEX, admin):
                raise ValueError(f"invalid username {admin}")
        return v

    @field_validator("known_scopes")
    @classmethod
    def _validate_known_scopes(cls, v: dict[str, str]) -> dict[str, str]:
        for scope in v:
            if not re.match(SCOPE_REGEX, scope):
                raise ValueError(f"invalid scope {scope}")
        for required in ("admin:token", "admin:userinfo", "user:token"):
            if required not in v:
                raise ValueError(f"required scope {required} missing")
        return v

    @field_validator("token_lifetime")
    @classmethod
    def _validate_token_lifetime(cls, v: timedelta) -> timedelta:
        """Ensure the token lifetime is longer than minimal lifetime."""
        limit = MINIMUM_LIFETIME + MINIMUM_LIFETIME
        if v < limit:
            raise ValueError(f"must be longer than {limit.total_seconds}s")
        return v

    @model_validator(mode="before")
    @classmethod
    def _validate_optional(cls, data: Any) -> Any:
        """Remove sub-models that are not configured.

        Due to how the Helm :file:`values.yaml` file is documented, the
        setting that's used as a signal to enable or disable that section of
        the configuration will always be present. If it's set to an empty
        string, remove that section of the configuration.
        """
        if not isinstance(data, dict):
            return data
        for key, needed in (
            ("cilogon", "clientId"),
            ("github", "clientId"),
            ("oidc", "clientId"),
            ("ldap", "url"),
            ("firestore", "project"),
            ("oidcServer", "enabled"),
            ("quota", "default"),
        ):
            if data.get(key) is not None and not data[key].get(needed):
                del data[key]
        return data

    @model_validator(mode="after")
    def _validate_scopes(self) -> Self:
        """Ensure all assigned scopes are listed in ``known_scopes``."""
        for scope in self.group_mapping:
            if scope not in self.known_scopes:
                msg = f"Scope {scope} assigned but not in knownScopes"
                raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_userinfo(self) -> Self:
        """Ensure user information sources are configured properly."""
        # Convert CILogon configuration to OpenID Connect configuration.
        if self.cilogon and self.oidc:
            msg = "Only one of GitHub, CILogon, or OpenID Connect may be used"
            raise ValueError(msg)
        if self.cilogon:
            self.oidc = self.cilogon.to_oidc_config()
            self.cilogon = None

        # Check that exactly one authentication provider is configured.
        if not self.github and not self.oidc:
            raise ValueError("No authentication provider configured")
        if self.github and self.oidc:
            msg = "Only one of GitHub, CILogon, or OpenID Connect may be used"
            raise ValueError(msg)

        # Chck that the LDAP configuration is consistent.
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

    @classmethod
    def from_file(cls, path: Path) -> Self:
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
            return cls.model_validate(yaml.safe_load(f))

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

        # The group mapping in the settings maps a scope to a list of groups
        # that provide that scope. This is conceptually easier for the person
        # writing the configuration, but Gafaelfawr internally wants a map
        # from a group name to a set of scopes that group provides. Groups may
        # also be GitHubTeamName objects instead of strings, but all lookups
        # are done by strings, so we need to convert them to their string
        # form.
        group_to_scopes = defaultdict(set)
        for scope, groups in self.group_mapping.items():
            for group_or_team in groups:
                group_to_scopes[str(group_or_team)].add(scope)
        self._group_to_scopes = {
            k: frozenset(v) for k, v in group_to_scopes.items()
        }

    @property
    def add_user_group(self) -> bool:
        """Whether to add a synthetic private user group."""
        return bool(self.github or (self.ldap and self.ldap.add_user_group))

    @property
    def base_hostname(self) -> str:
        """Realm to use for HTTP authentication."""
        # HttpUrl guarantees that the host is not None, but this is not
        # reflected in the type system so we have to check for mypy purposes.
        if not self.base_url.host:
            raise RuntimeError("baseUrl does not contain a hostname")
        return self.base_url.host

    @property
    def cookie_parameters(self) -> CookieParameters:
        """Parameters to pass to `fastapi.Response.set_cookie`."""
        parameters = CookieParameters(secure=True, httponly=True)
        if self.allow_subdomains:
            parameters["domain"] = self.base_hostname
        return parameters

    @property
    def redis_rate_limit_url(self) -> str:
        """Redis DSN to use for rate limiting.

        The limits_ package requires the Redis DSN in a specific format with
        the password already included.
        """
        host = self.redis_ephemeral_url.host
        port = self.redis_ephemeral_url.port
        netloc = f"{host}:{port}" if port else host
        path = self.redis_ephemeral_url.path
        if self.redis_password:
            password = quote(self.redis_password.get_secret_value(), safe="")
            return f"async+redis://:{password}@{netloc}{path}"
        else:
            return f"async+redis://{netloc}{path}"

    def configure_logging(self) -> None:
        """Configure logging based on the Gafaelfawr configuration."""
        configure_logging(name="gafaelfawr", log_level=self.log_level)

    def get_scopes_for_group(self, group: str) -> frozenset[str]:
        """Return the scopes granted by a given group membership.

        Parameters
        ----------
        group
            Name of the group.

        Returns
        -------
        frozenset of str
            Scopes granted by that group membership. This will be the empty
            set if the group was not recognized.
        """
        return self._group_to_scopes.get(group) or frozenset()

    def is_hostname_allowed(self, hostname: str | None) -> bool:
        """Check whether a hostname is within the Gafaelfawr domain.

        Numerous places in Gafaelfawr want to allow only hostnames that fall
        within the base domain of Gafaelfawr. If subdomains are disabled, the
        hostname must match the base hostname exactly. If subdomains are
        allowed, the hostname must be a subdomain of that base domain.

        Parameters
        ----------
        hostname
            Hostname to check. `None` is allowed for typing convenience but
            is always rejected.

        Returns
        -------
        bool
            Whether that hostname is allowed for this Gafaelfawr instance.
        """
        if not hostname:
            return False
        domain = self.base_hostname
        if hostname == domain:
            return True
        return self.allow_subdomains and hostname.endswith(f".{domain}")
