"""Representation of an authentication token and associated data."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

from ..constants import GROUPNAME_REGEX, USERNAME_REGEX
from ..exceptions import InvalidTokenError
from ..util import (
    current_datetime,
    normalize_datetime,
    normalize_scopes,
    random_128_bits,
)

__all__ = [
    "AdminTokenRequest",
    "NewToken",
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
    def from_str(cls, token: str) -> Token:
        """Parse a serialized token into a `Token`.

        Parameters
        ----------
        token : `str`
            The serialized token.

        Returns
        -------
        decoded_token : `Token`
            The decoded `Token`.

        Raises
        ------
        gafaelfawr.exceptions.InvalidTokenError
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

    def __str__(self) -> str:
        """Return the encoded token."""
        return f"gt-{self.key}.{self.secret}"


class TokenType(Enum):
    """The class of token.

    session
        An interactive user web session.
    user
        A user-generated token that may be used programmatically.
    notebook
        The token delegated to a Jupyter notebook for the user.
    internal
        A service-to-service token used for internal sub-calls made as part of
        processing a user request.
    service
        A service-to-service token used for internal calls initiated by
        services, unrelated to a user request.
    """

    session = "session"
    user = "user"
    notebook = "notebook"
    internal = "internal"
    service = "service"


class TokenGroup(BaseModel):
    """Information about a single group.

    This is temporary until group information is stored in a dedicated
    identity management system.
    """

    name: str = Field(
        ...,
        title="Name of the group",
        example="g_special_users",
        min_length=1,
        regex=GROUPNAME_REGEX,
    )

    id: int = Field(..., title="The numeric GID of the group", example=123181)


class TokenBase(BaseModel):
    """Base information about a token common to several representations.

    This is the information that's common to the Redis and database
    representations of the token.
    """

    username: str = Field(
        ...,
        title="Username",
        description="User to whom the token was issued",
        example="someuser",
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
        example="session",
    )

    scopes: List[str] = Field(
        ..., title="Token scopes", example=["read:all", "user:token"]
    )

    created: datetime = Field(
        default_factory=current_datetime,
        title="Creation time",
        description="Creation timestamp of the token in seconds since epoch",
        example=1614986130,
    )

    expires: Optional[datetime] = Field(
        None,
        title="Expiration time",
        description="Expiration timestamp of the token in seconds since epoch",
        example=1616986130,
    )

    _normalize_scopes = validator("scopes", allow_reuse=True, pre=True)(
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
        example="5KVApqcVbSQWtO3VIRgOhQ",
        min_length=22,
        max_length=22,
    )

    token_name: Optional[str] = Field(
        None,
        title="User-given name of the token",
        example="laptop token",
        min_length=1,
        max_length=64,
    )

    service: Optional[str] = Field(
        None,
        title="Service",
        description=(
            "Service to which the token was delegated.  Only present for"
            " internal tokens"
        ),
        example="some-service",
        min_length=1,
        max_length=64,
    )

    last_used: Optional[datetime] = Field(
        None,
        title="Last used",
        description="When the token was last used in seconds since epoch",
        example=1614986130,
    )

    parent: Optional[str] = Field(
        None,
        title="Parent token",
        example="DGO1OnPohl0r3C7wqhzRgQ",
        min_length=22,
        max_length=22,
    )

    class Config:
        orm_mode = True
        json_encoders = {datetime: lambda v: int(v.timestamp())}

    _normalize_created = validator(
        "created", "last_used", "expires", allow_reuse=True, pre=True
    )(normalize_datetime)


class TokenUserInfo(BaseModel):
    """The information about a user stored with their token.

    If information is stored with the token, it overrides information from
    other sources such as LDAP.  Fields that should be dynamically retrieved
    from LDAP should be set to `None`.
    """

    username: str = Field(
        ...,
        title="Username",
        description="User to whom the token was issued",
        example="someuser",
        min_length=1,
        max_length=64,
    )

    name: Optional[str] = Field(
        None,
        title="Preferred full name",
        example="Alice Example",
        min_length=1,
    )

    email: Optional[str] = Field(
        None,
        title="Email address",
        example="alice@example.com",
        min_length=1,
    )

    uid: Optional[int] = Field(None, title="UID number", example=4123, ge=1)

    groups: Optional[List[TokenGroup]] = Field(
        None,
        title="Groups",
        description="Groups of which the user is a member",
    )


class TokenData(TokenBase, TokenUserInfo):
    """Data about a token stored in Redis.

    This holds all the token information stored in Redis, and thus all the
    token information required to support authentication decisions and
    (currently) user information queries.  It should not be used directly as a
    response model; for that, see `TokenInfo` and `TokenUserInfo`.
    """

    token: Token = Field(..., title="Associated token")

    class Config:
        json_encoders = {datetime: lambda v: int(v.timestamp())}

    @classmethod
    def bootstrap_token(cls) -> TokenData:
        """Build authentication data for the bootstrap token.

        This token doesn't exist in the backing store, so instead synthesize a
        `~gafaelfawr.models.token.TokenData` object for it.

        Returns
        -------
        data : `gafaelfawr.models.token.TokenData`
            Artificial data for the bootstrap token.
        """
        return cls(
            token=Token(),
            username="<bootstrap>",
            token_type=TokenType.service,
            scopes=["admin:token"],
            created=datetime.now(tz=timezone.utc),
        )

    @classmethod
    def internal_token(cls) -> TokenData:
        """Build authentication data for the internal token.

        Similar to the bootstrap token, this does not exist in the backing
        store.  It is used by background jobs internal to Gafaelfawr.

        Returns
        -------
        data : `gafaelfawr.models.token.TokenData`
            Artificial data for the bootstrap token.
        """
        return cls(
            token=Token(),
            username="<internal>",
            token_type=TokenType.service,
            scopes=["admin:token"],
            created=datetime.now(tz=timezone.utc),
        )


class NewToken(BaseModel):
    """Response to a token creation request."""

    token: str = Field(
        ...,
        title="Newly-created token",
        example="gt-2T1RHkIi4b14JzswnXfCsQ.8t5XdPSYTrteD0pDB15zqQ",
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
        example="some-service",
        min_length=1,
        max_length=64,
        regex=USERNAME_REGEX,
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
        example="service",
    )

    token_name: Optional[str] = Field(
        None,
        title="User-given name of the token",
        description="Only provide this field for a token type of `user`",
        example="laptop token",
        min_length=1,
        max_length=64,
    )

    scopes: List[str] = Field(
        default_factory=list,
        title="Token scopes",
        example=["read:all"],
    )

    expires: Optional[datetime] = Field(
        None,
        title="Token expiration",
        description=(
            "Expiration timestamp of the token in seconds since epoch, or"
            " omitted to never expire"
        ),
        example=1616986130,
    )

    name: Optional[str] = Field(
        None,
        title="Preferred full name",
        description=(
            "If a value is not provided, and LDAP is configured, the full"
            " name from the LDAP entry for that username will be used"
        ),
        example="Service User",
        min_length=1,
    )

    email: Optional[str] = Field(
        None,
        title="Email address",
        description=(
            "If a value is not provided, and LDAP is configured, the email"
            " address from the LDAP entry for that username will be used"
        ),
        example="service@example.com",
        min_length=1,
    )

    uid: Optional[int] = Field(
        None,
        title="UID number",
        description=(
            "If a value is not provided, and Firestore or LDAP are"
            " configured, the UID from Firestore (preferred) or the LDAP"
            " entry for that username will be used"
        ),
        example=4131,
        ge=1,
    )

    groups: Optional[List[TokenGroup]] = Field(
        None,
        title="Groups",
        description=(
            "Groups of which the user is a member. If a value is not provided,"
            " and LDAP is configured, the group membership from LDAP will be"
            " used"
        ),
    )

    @validator("token_type")
    def _valid_token_type(cls, v: TokenType) -> TokenType:
        if v not in (TokenType.service, TokenType.user):
            raise ValueError("token_type must be service or user")
        return v

    @validator("token_name", always=True)
    def _valid_token_name(
        cls, v: Optional[str], values: Dict[str, Any]
    ) -> Optional[str]:
        if "token_type" not in values:
            # Validation already failed, so the return value doesn't matter.
            return None
        if v and values["token_type"] == TokenType.service:
            raise ValueError("Tokens of type service cannot have a name")
        if not v and values["token_type"] == TokenType.user:
            raise ValueError("Tokens of type user must have a name")
        return v


class UserTokenRequest(BaseModel):
    """The parameters of a user token that are under the user's control."""

    token_name: str = Field(
        ...,
        title="User-given name of the token",
        example="laptop token",
        min_length=1,
        max_length=64,
    )

    scopes: List[str] = Field(
        default_factory=list,
        title="Token scope",
        example=["read:all"],
    )

    expires: Optional[datetime] = Field(
        None,
        title="Expiration time",
        description="Expiration timestamp of the token in seconds since epoch",
        example=1625986130,
    )


class UserTokenModifyRequest(BaseModel):
    """The parameters of a user token that can be changed.

    This is a separate model from `UserTokenRequest` because the
    ``token_name`` field is optional on modify requests.
    """

    token_name: Optional[str] = Field(
        None,
        title="User-given name of the token",
        example="laptop token",
        min_length=1,
        max_length=64,
    )

    scopes: Optional[List[str]] = Field(
        None, title="Token scopes", example=["read:all"]
    )

    expires: Optional[datetime] = Field(
        None,
        title="Expiration time",
        description=(
            "Expiration timestamp of the token in seconds since epoch, or"
            " None to never expire."
        ),
        example=1625986130,
    )
