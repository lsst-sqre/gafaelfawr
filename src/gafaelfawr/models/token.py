"""Representation of an authentication token and associated data."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
)
from safir.datetime import current_datetime
from safir.pydantic import normalize_datetime

from ..constants import GROUPNAME_REGEX, USERNAME_REGEX
from ..exceptions import InvalidTokenError
from ..util import normalize_scopes, random_128_bits

__all__ = [
    "AdminTokenRequest",
    "CADCUserInfo",
    "NewToken",
    "NotebookQuota",
    "Quota",
    "Token",
    "TokenBase",
    "TokenData",
    "TokenGroup",
    "TokenInfo",
    "TokenType",
    "TokenUserInfo",
    "UserTokenRequest",
    "UserTokenModifyRequest",
]


class Token(BaseModel):
    """An opaque token.

    Notes
    -----
    A token consists of two parts, a semi-public key that is used as the Redis
    key, and a secret that is only present in the token returned to the user
    and the encrypted session in Redis.

    The serialized form of a token always starts with ``gt-``, short for
    Gafaelfawr token, to make it easier to identify these tokens in logs.

    The serialized form encodes the secret in URL-safe base64 with the padding
    stripped off (because equal signs can be parsed oddly in cookies).
    """

    key: str = Field(default_factory=random_128_bits)
    secret: str = Field(default_factory=random_128_bits)

    @classmethod
    def from_str(cls, token: str) -> Self:
        """Parse a serialized token into a `Token`.

        Parameters
        ----------
        token
            The serialized token.

        Returns
        -------
        Token
            The decoded `Token`.

        Raises
        ------
        InvalidTokenError
            The provided string is not a valid token.
        """
        if not token.startswith("gt-"):
            msg = "Token does not start with gt-"
            raise InvalidTokenError(msg)
        trimmed_token = token[len("gt-") :]

        if "." not in trimmed_token:
            raise InvalidTokenError("Token is malformed")
        key, secret = trimmed_token.split(".", 1)
        if len(key) != 22 or len(secret) != 22:
            raise InvalidTokenError("Token is malformed")

        return cls(key=key, secret=secret)

    @classmethod
    def is_token(cls, token: str) -> bool:
        """Determine if a string is a Gafaelfawr token.

        Parameters
        ----------
        token
            The string to check.

        Returns
        -------
        bool
            Whether that string looks like a Gafaelfawr token.  The token
            isn't checked for validity, only format.
        """
        if not token.startswith("gt-"):
            return False
        trimmed_token = token[len("gt-") :]
        if "." not in trimmed_token:
            return False
        key, secret = trimmed_token.split(".", 1)
        return len(key) == 22 and len(secret) == 22

    def __str__(self) -> str:
        """Return the encoded token."""
        return f"gt-{self.key}.{self.secret}"


class TokenType(Enum):
    """The class of token."""

    session = "session"
    """An interactive user web session."""

    user = "user"
    """A user-generated token that may be used programmatically."""

    notebook = "notebook"
    """The token delegated to a Jupyter notebook for the user."""

    internal = "internal"
    """Service-to-service token chained from a user request.

    A service-to-service token used for internal sub-calls made as part of
    processing a user request.
    """

    service = "service"
    """Service-to-service token independent of a user request.

    A service-to-service token used for internal calls initiated by
    services, unrelated to a user request.
    """


class TokenGroup(BaseModel):
    """Information about a single group."""

    name: str = Field(
        ...,
        title="Name of the group",
        examples=["g_special_users"],
        min_length=1,
        pattern=GROUPNAME_REGEX,
    )

    id: int | None = Field(
        None,
        title="Numeric GID of the group",
        examples=[123181],
        description=(
            "Numeric GID may be unset, in which case the group still"
            " contributes to determining scopes, but may be ignored by"
            " services that require a GID. If Firestore is configured, a"
            " numeric GID will be allocated by Firestore if left unset"
            " when creating a token."
        ),
    )


class NotebookQuota(BaseModel):
    """Notebook Aspect quota information for a user."""

    cpu: float = Field(..., title="CPU equivalents", examples=[4.0])

    memory: float = Field(
        ..., title="Maximum memory use (GiB)", examples=[16.0]
    )


class Quota(BaseModel):
    """Quota information for a user."""

    api: dict[str, int] = Field(
        {},
        title="API quotas",
        description=(
            "Mapping of service names to allowed requests per 15 minutes."
        ),
        examples=[
            {
                "datalinker": 500,
                "hips": 2000,
                "tap": 500,
                "vo-cutouts": 100,
            }
        ],
    )

    notebook: NotebookQuota | None = Field(
        None, title="Notebook Aspect quotas"
    )


class TokenBase(BaseModel):
    """Base information about a token common to several representations.

    This is the information that's common to the Redis and database
    representations of the token.
    """

    username: str = Field(
        ...,
        title="Username",
        description="User to whom the token was issued",
        examples=["someuser"],
        min_length=1,
        max_length=64,
    )

    token_type: TokenType = Field(
        ...,
        description=(
            "Class of token, chosen from:\n\n"
            "* `session`: An interactive user web session\n"
            "* `user`: A user-generated token that may be used"
            " programmatically\n"
            "* `notebook`: The token delegated to a Jupyter notebook for"
            " the user\n"
            "* `internal`: A service-to-service token used for internal"
            " sub-calls made as part of processing a user request\n"
            "* `service`: A service-to-service token used for internal calls"
            " initiated by services, unrelated to a user request\n"
        ),
        title="Token type",
        examples=["session"],
    )

    scopes: list[str] = Field(
        ...,
        title="Token scopes",
        description="Scopes of the token",
        examples=[["read:all", "user:token"]],
    )

    created: datetime = Field(
        default_factory=current_datetime,
        title="Creation time",
        description="Creation timestamp of the token in seconds since epoch",
        examples=[1614986130],
    )

    expires: datetime | None = Field(
        None,
        title="Expiration time",
        description="Expiration timestamp of the token in seconds since epoch",
        examples=[1616986130],
    )

    _normalize_scopes = field_validator("scopes", mode="before")(
        normalize_scopes
    )


class TokenInfo(TokenBase):
    """Information about a token returned by the token-info endpoint.

    This is all the information about the token that's stored in the
    underlying database.  It includes some fields not present in Redis.
    """

    token: str = Field(
        ...,
        title="Token key",
        examples=["5KVApqcVbSQWtO3VIRgOhQ"],
        min_length=22,
        max_length=22,
    )

    token_name: str | None = Field(
        None,
        title="User-given name of the token",
        examples=["laptop token"],
        min_length=1,
        max_length=64,
    )

    service: str | None = Field(
        None,
        title="Service",
        description=(
            "Service to which the token was delegated.  Only present for"
            " internal tokens"
        ),
        examples=["some-service"],
        min_length=1,
        max_length=64,
    )

    last_used: datetime | None = Field(
        None,
        title="Last used",
        description="When the token was last used in seconds since epoch",
        examples=[1614986130],
    )

    parent: str | None = Field(
        None,
        title="Parent token",
        examples=["DGO1OnPohl0r3C7wqhzRgQ"],
        min_length=22,
        max_length=22,
    )

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("created", "expires", "last_used")
    def _serialize_datetime(self, time: datetime | None) -> int | None:
        return int(time.timestamp()) if time is not None else None

    _normalize_created = field_validator(
        "created", "last_used", "expires", mode="before"
    )(normalize_datetime)


class TokenUserInfo(BaseModel):
    """The information about a user stored with their token.

    If information is stored with the token, it overrides information from
    other sources such as LDAP.  Fields that should be dynamically retrieved
    from LDAP should be omitted or set to `None`.
    """

    username: str = Field(
        ...,
        title="Username",
        description="User to whom the token was issued",
        examples=["someuser"],
        min_length=1,
        max_length=64,
    )

    name: str | None = Field(
        None,
        title="Preferred full name",
        examples=["Alice Example"],
        min_length=1,
    )

    email: str | None = Field(
        None,
        title="Email address",
        examples=["alice@example.com"],
        min_length=1,
    )

    uid: int | None = Field(None, title="UID number", examples=[4123], ge=1)

    gid: int | None = Field(
        None,
        title="Primary GID",
        description=(
            "GID of primary group. If set, this will also be the GID of one of"
            " the groups of which the user is a member."
        ),
        examples=[4123],
        ge=1,
    )

    groups: list[TokenGroup] | None = Field(
        None,
        title="Groups",
        description="Groups of which the user is a member",
    )

    quota: Quota | None = Field(None, title="Quota")

    def to_userinfo_dict(self) -> dict[str, Any]:
        """Convert to a dictionary for logging purposes.

        This method converts only the `TokenUserInfo` portion of a token to a
        dictionary for logging purposes, excluding the ``username`` field
        (which is logged separately).  It's used when logging creation of
        new tokens to make a record of the user identity information included
        in the token (as opposed to retrieved dynamically from other sources
        such as LDAP or Firestore).

        Returns
        -------
        dict
            Dictionary of information, roughly equivalent to calling
            ``dict(exclude_none=True)`` on the `TokenUserInfo` object, but
            ensuring that only its data is included even if called on a
            subclass such as `TokenData`.
        """
        token_userinfo: dict[str, Any] = {}
        if self.name is not None:
            token_userinfo["name"] = self.name
        if self.email is not None:
            token_userinfo["email"] = self.email
        if self.uid is not None:
            token_userinfo["uid"] = self.uid
        if self.gid is not None:
            token_userinfo["gid"] = self.gid
        if self.groups is not None:
            token_userinfo["groups"] = [g.model_dump() for g in self.groups]
        return token_userinfo


class TokenData(TokenBase, TokenUserInfo):
    """Data about a token stored in Redis.

    This holds all the token information stored in Redis, and thus all the
    token information required to support authentication decisions and
    (currently) user information queries.  It should not be used directly as a
    response model; for that, see `TokenInfo` and `TokenUserInfo`.
    """

    token: Token = Field(..., title="Associated token")

    # These fields should not have to be reiterated since they're inherited
    # from TokenUserInfo, but the Pydantic mypy plugin has a bug that loses
    # inherited | None type information. See:
    #
    # https://github.com/pydantic/pydantic/issues/7398
    #
    # These duplicate definitions should be removed when the Pydantic mypy
    # plugin is fixed.
    name: str | None = Field(
        None,
        title="Preferred full name",
        examples=["Alice Example"],
        min_length=1,
    )
    uid: int | None = Field(None, title="UID number", examples=[4123], ge=1)
    gid: int | None = Field(
        None,
        title="Primary GID",
        description=(
            "GID of primary group. If set, this will also be the GID of one of"
            " the groups of which the user is a member."
        ),
        examples=[4123],
        ge=1,
    )
    groups: list[TokenGroup] | None = Field(
        None,
        title="Groups",
        description="Groups of which the user is a member",
    )

    @field_serializer("created", "expires")
    def _serialize_datetime(self, time: datetime | None) -> int | None:
        return int(time.timestamp()) if time is not None else None

    @classmethod
    def bootstrap_token(cls) -> Self:
        """Build authentication data for the bootstrap token.

        This token doesn't exist in the backing store, so instead synthesize a
        `~gafaelfawr.models.token.TokenData` object for it.

        Returns
        -------
        TokenData
            Artificial data for the bootstrap token.
        """
        return cls(
            token=Token(),
            username="<bootstrap>",
            token_type=TokenType.service,
            scopes=["admin:token"],
            created=current_datetime(),
        )

    @classmethod
    def internal_token(cls) -> Self:
        """Build authentication data for the internal token.

        Similar to the bootstrap token, this does not exist in the backing
        store.  It is used by background jobs internal to Gafaelfawr.

        Returns
        -------
        TokenData
            Artificial data for the bootstrap token.
        """
        return cls(
            token=Token(),
            username="<internal>",
            token_type=TokenType.service,
            scopes=["admin:token"],
            created=current_datetime(),
        )


class NewToken(BaseModel):
    """Response to a token creation request."""

    token: str = Field(
        ...,
        title="Newly-created token",
        examples=["gt-2T1RHkIi4b14JzswnXfCsQ.8t5XdPSYTrteD0pDB15zqQ"],
    )


class AdminTokenRequest(BaseModel):
    """A request to create a new token via the admin interface."""

    username: str = Field(
        ...,
        title="User for which to issue a token",
        description=(
            "The username may only contain lowercase letters, digits,"
            " and dash (`-`), and may not start or end with a dash"
        ),
        examples=["some-service"],
        min_length=1,
        max_length=64,
        pattern=USERNAME_REGEX,
    )

    token_type: TokenType = Field(
        ...,
        title="Token type",
        description=(
            "Must be either `service` or `user`"
            "\n\n"
            "* `service`: A service-to-service token used for internal calls"
            " initiated by services, unrelated to a user request\n"
            "* `user`: A user-generated token that may be used"
            " programmatically\n"
        ),
        examples=["service"],
    )

    token_name: str | None = Field(
        None,
        title="User-given name of the token",
        description="Only provide this field for a token type of `user`",
        examples=["laptop token"],
        min_length=1,
        max_length=64,
        validate_default=True,
    )

    scopes: list[str] = Field(
        default_factory=list,
        title="Token scopes",
        examples=[["read:all"]],
    )

    expires: datetime | None = Field(
        None,
        title="Token expiration",
        description=(
            "Expiration timestamp of the token in seconds since epoch, or"
            " omitted to never expire"
        ),
        examples=[1616986130],
    )

    name: str | None = Field(
        None,
        title="Preferred full name",
        description=(
            "If a value is not provided, and LDAP is configured, the full"
            " name from the LDAP entry for that username will be used"
        ),
        examples=["Service User"],
        min_length=1,
    )

    email: str | None = Field(
        None,
        title="Email address",
        description=(
            "If a value is not provided, and LDAP is configured, the email"
            " address from the LDAP entry for that username will be used"
        ),
        examples=["service@example.com"],
        min_length=1,
    )

    uid: int | None = Field(
        None,
        title="UID number",
        description=(
            "If a value is not provided, and Firestore or LDAP are"
            " configured, the UID from Firestore (preferred) or the LDAP"
            " entry for that username will be used"
        ),
        examples=[4131],
        ge=1,
    )

    gid: int | None = Field(
        None,
        title="Primary GID",
        description=(
            "GID of primary group. If set, should correspond to the id of a"
            " group of which the user is a member. If a value is not provided"
            " and LDAP is configured to add user private groups, it will be"
            " set to the same value as the UID."
        ),
        examples=[4123],
        ge=1,
    )

    groups: list[TokenGroup] | None = Field(
        None,
        title="Groups",
        description=(
            "Groups of which the user is a member. If a value is not provided,"
            " and LDAP is configured, the group membership from LDAP will be"
            " used"
        ),
    )

    @field_validator("token_type")
    @classmethod
    def _valid_token_type(cls, v: TokenType) -> TokenType:
        if v not in (TokenType.service, TokenType.user):
            raise ValueError("token_type must be service or user")
        return v

    @field_validator("token_name")
    @classmethod
    def _valid_token_name(
        cls, v: str | None, info: ValidationInfo
    ) -> str | None:
        if "token_type" not in info.data:
            # Validation already failed, so the return value doesn't matter.
            return None
        if v and info.data["token_type"] == TokenType.service:
            raise ValueError("Tokens of type service cannot have a name")
        if not v and info.data["token_type"] == TokenType.user:
            raise ValueError("Tokens of type user must have a name")
        return v


class UserTokenRequest(BaseModel):
    """The parameters of a user token that are under the user's control."""

    token_name: str = Field(
        ...,
        title="User-given name of the token",
        examples=["laptop token"],
        min_length=1,
        max_length=64,
    )

    scopes: list[str] = Field(
        default_factory=list,
        title="Token scope",
        examples=[["read:all"]],
    )

    expires: datetime | None = Field(
        None,
        title="Expiration time",
        description="Expiration timestamp of the token in seconds since epoch",
        examples=[1625986130],
    )


class UserTokenModifyRequest(BaseModel):
    """The parameters of a user token that can be changed.

    This is a separate model from `UserTokenRequest` because the
    ``token_name`` field is optional on modify requests.
    """

    token_name: str | None = Field(
        None,
        title="User-given name of the token",
        examples=["laptop token"],
        min_length=1,
        max_length=64,
    )

    scopes: list[str] | None = Field(
        None, title="Token scopes", examples=[["read:all"]]
    )

    expires: datetime | None = Field(
        None,
        title="Expiration time",
        description=(
            "Expiration timestamp of the token in seconds since epoch, or"
            " None to never expire."
        ),
        examples=[1625986130],
    )


class CADCUserInfo(BaseModel):
    """User metadata required by the CADC authentication code.

    This model is hopefully temporary and will be retired by merging the CADC
    support with the OpenID Connect support.
    """

    exp: datetime | None = Field(
        None,
        title="Expiration time",
        description=(
            "Expiration timestamp of the token in seconds since epoch. If"
            " not present, the token never expires."
        ),
        examples=[1625986130],
    )

    preferred_username: str = Field(
        ...,
        title="Username",
        description="Username of user",
        examples=["someuser"],
    )

    sub: UUID = Field(
        ...,
        title="Unique identifier",
        description=(
            "CADC code currently requires a UUID in this field. In practice,"
            " this is generated as a version 5 UUID based on a configured"
            " UUID namespace and the string representation of the user's"
            " numeric UID (thus allowing username changes if the UID is"
            " preserved."
        ),
        examples=["78410c93-841d-53b1-a353-6411524d149e"],
    )

    @field_serializer("exp")
    def _serialize_datetime(self, time: datetime | None) -> int | None:
        return int(time.timestamp()) if time is not None else None
