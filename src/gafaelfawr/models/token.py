"""Representation of an authentication token and associated data."""

import re
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, ClassVar, Self, override

from pydantic import BaseModel, Field, ValidationInfo, field_validator
from safir.database import InvalidCursorError, PaginationCursor, datetime_to_db
from safir.pydantic import UtcDatetime
from sqlalchemy import Select, SQLColumnExpression, collate, tuple_

from ..constants import USERNAME_REGEX
from ..exceptions import InvalidTokenError
from ..schema import Token as SQLToken
from ..types import Scopes, Timestamp
from ..util import random_128_bits
from .enums import SortOrder, TokenSort, TokenType
from .userinfo import Group

__all__ = [
    "AdminTokenRequest",
    "NewToken",
    "Token",
    "TokenBase",
    "TokenCreatedCursor",
    "TokenCreatedDescendingCursor",
    "TokenCursor",
    "TokenData",
    "TokenInfo",
    "TokenUserInfo",
    "TokenUsernameCursor",
    "TokenUsernameDescendingCursor",
    "UserTokenModifyRequest",
    "UserTokenRequest",
    "token_cursor_type",
]

_CURSOR_KEY_PATTERN = "[A-Za-z0-9_-]{22}"
"""Pattern matching a token key in a serialized cursor."""

_CURSOR_TIME_PATTERN = r"[0-9]+(?:\.[0-9]+)?"
"""Pattern matching a creation time in a serialized cursor."""


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
            Whether that string looks like a Gafaelfawr token. The token
            isn't checked for validity, only format.
        """
        try:
            cls.from_str(token)
        except InvalidTokenError:
            return False
        else:
            return True

    @override
    def __str__(self) -> str:
        """Return the encoded token."""
        return f"gt-{self.key}.{self.secret}"


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
        title="Token type",
        examples=["session"],
    )

    service: str | None = Field(
        None,
        title="Service",
        description=(
            "Service to which the token was delegated. Only present for"
            " internal tokens."
        ),
        examples=["some-service"],
        min_length=1,
        max_length=64,
    )

    scopes: Scopes = Field(
        ...,
        title="Token scopes",
        description="Scopes of the token",
        examples=[["read:all", "user:token"]],
    )

    created: Timestamp = Field(
        default_factory=lambda: datetime.now(tz=UTC).replace(microsecond=0),
        title="Creation time",
        description="Creation timestamp of the token in seconds since epoch",
        examples=[1614986130],
    )

    expires: Timestamp | None = Field(
        None,
        title="Expiration time",
        description="Expiration timestamp of the token in seconds since epoch",
        examples=[1616986130],
    )


class TokenInfo(TokenBase):
    """Information about a token.

    All information about the token that's stored in the underlying
    database. It includes some fields not present in Redis.
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

    last_used: Timestamp | None = Field(
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

    github_project_id: int | None = Field(
        None,
        title="GitHub project ID",
        description=(
            "ID of the GitHub project that authorized the token. Only set"
            " for tokens of type github."
        ),
        examples=[42],
    )


class TokenUserInfo(BaseModel):
    """User metadata stored with the token.

    Holds the user metadata generated by the authentication provider or the
    admin token request and stored with the token, without any supplemental
    information from LDAP or Firestore. Fields that are set will override any
    data from extenral sources. Fields set to `None` will be looked up in LDAP
    or Firestore.
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

    groups: list[Group] | None = Field(
        None,
        title="Groups",
        description="Groups of which the user is a member",
    )

    def to_userinfo_dict(self) -> dict[str, Any]:
        """Convert to a dictionary for logging purposes.

        This method converts only the `TokenUserInfo` portion of a token to a
        dictionary for logging purposes, excluding the ``username`` field
        (which is logged separately). It's used when logging creation of new
        tokens to make a record of the user identity information included in
        the token (as opposed to retrieved dynamically from other sources such
        as LDAP or Firestore).

        Returns
        -------
        dict
            Dictionary of information, roughly equivalent to calling
            ``model_dump(mode="json", exclude_none=True)`` on the
            `TokenUserInfo` object, but ensuring that only its data is
            included even if called on a subclass such as `TokenData`.
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
            token_userinfo["groups"] = [
                g.model_dump(mode="json") for g in self.groups
            ]
        return token_userinfo


class TokenData(TokenBase, TokenUserInfo):
    """Data about a token stored in Redis.

    This holds all the token information stored in Redis, and thus all the
    token information required to support authentication decisions and
    (currently) user information queries.  It should not be used directly as a
    response model; for that, see `TokenInfo` and `TokenUserInfo`.
    """

    token: Token = Field(..., title="Associated token")

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
            scopes={"admin:oidc", "admin:token"},
        )

    @classmethod
    def internal_token(cls) -> Self:
        """Build authentication data for the internal token.

        Similar to the bootstrap token, this does not exist in the backing
        store. It is used by background jobs internal to Gafaelfawr.

        Returns
        -------
        TokenData
            Artificial data for the bootstrap token.
        """
        return cls(
            token=Token(),
            username="<internal>",
            token_type=TokenType.service,
            scopes={"admin:token"},
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
            " and hyphen-minus, and may not start or end with a dash"
        ),
        examples=["some-service"],
        min_length=1,
        max_length=64,
        pattern=USERNAME_REGEX,
    )

    token_type: TokenType = Field(
        ...,
        title="Token type",
        description="Must be either ``service`` or ``user``",
        examples=["service"],
    )

    token_name: str | None = Field(
        None,
        title="User-given name of the token",
        description="Only provide this field for a token type of ``user``",
        examples=["laptop token"],
        min_length=1,
        max_length=64,
        validate_default=True,
    )

    scopes: Scopes = Field(
        set(),
        title="Token scopes",
        examples=[["read:all"]],
    )

    expires: UtcDatetime | None = Field(
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

    groups: list[Group] | None = Field(
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

    scopes: Scopes = Field(
        set(),
        title="Token scope",
        examples=[["read:all"]],
    )

    expires: UtcDatetime | None = Field(
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

    scopes: Scopes | None = Field(
        None, title="Token scopes", examples=[["read:all"]]
    )

    expires: UtcDatetime | None = Field(
        None,
        title="Expiration time",
        description=(
            "Expiration timestamp of the token in seconds since epoch, or"
            " None to never expire."
        ),
        examples=[1625986130],
    )


@dataclass
class TokenCursor(PaginationCursor[TokenInfo], metaclass=ABCMeta):
    """Pagination cursor for a listing of tokens.

    A listing of tokens can be sorted in several ways, but the sort order of
    a paginated query is a property of the cursor class rather than of a
    cursor, since the first page of results has to be sorted before any
    cursor exists. Each sort order therefore has its own subclass. Use
    `token_cursor_type` to choose the one for a requested sort order.

    Subclasses define the sort key, which must end with the token key so
    that the order is total, and the serialized form of the cursor. A
    listing in descending order reverses every column of the sort key, so
    the position of a cursor can always be applied as one row comparison.
    """

    created: datetime
    """Creation time of the token at the cursor position."""

    key: str
    """Key of the token at the cursor position."""

    descending: ClassVar[bool] = False
    """Whether the listing is sorted in descending order."""

    @override
    @classmethod
    def apply_order(cls, stmt: Select, *, reverse: bool = False) -> Select:
        columns = cls._columns()
        if cls.descending != reverse:
            return stmt.order_by(*(c.desc() for c in columns))
        else:
            return stmt.order_by(*columns)

    @override
    def apply_cursor(self, stmt: Select) -> Select:
        columns = tuple_(*self._columns())
        position = self._position()

        # A forward cursor includes the token it was built from. A previous
        # cursor excludes it and selects the tokens before it.
        if self.previous:
            if self.descending:
                return stmt.where(columns > position)
            else:
                return stmt.where(columns < position)
        elif self.descending:
            return stmt.where(columns <= position)
        else:
            return stmt.where(columns >= position)

    @override
    def invert(self) -> Self:
        return replace(self, previous=not self.previous)

    @classmethod
    @abstractmethod
    def _columns(cls) -> tuple[SQLColumnExpression[Any], ...]:
        """Return the columns of the sort key, most significant first."""

    @abstractmethod
    def _position(self) -> tuple[Any, ...]:
        """Return the value of the sort key at the cursor position."""

    @staticmethod
    def _parse_created(created: str) -> datetime:
        """Parse the creation time from a serialized cursor.

        Parameters
        ----------
        created
            Creation time in seconds since epoch.

        Returns
        -------
        datetime
            Corresponding time.

        Raises
        ------
        safir.database.InvalidCursorError
            Raised if the time is out of range.
        """
        try:
            return datetime.fromtimestamp(float(created), tz=UTC)
        except (OSError, OverflowError, ValueError) as e:
            raise InvalidCursorError(f"Cannot parse cursor: {e!s}") from e

    def _serialize_created(self) -> str:
        """Serialize the creation time for the string form of the cursor.

        Returns
        -------
        str
            Creation time in seconds since epoch, with a fractional part
            only if the time is not a whole number of seconds.
        """
        timestamp = self.created.timestamp()
        if timestamp.is_integer():
            return str(int(timestamp))
        else:
            return str(timestamp)


@dataclass
class TokenCreatedCursor(TokenCursor):
    """Cursor for tokens sorted by creation time, oldest first.

    The serialized form is the creation time in seconds since epoch and the
    token key, separated by an underscore, with a ``p`` prefix for a cursor
    for the previous page.
    """

    _REGEX: ClassVar[re.Pattern[str]] = re.compile(
        f"(?P<previous>p?)(?P<created>{_CURSOR_TIME_PATTERN})"
        f"_(?P<key>{_CURSOR_KEY_PATTERN})"
    )

    @override
    @classmethod
    def from_entry(cls, entry: TokenInfo, *, reverse: bool = False) -> Self:
        return cls(created=entry.created, key=entry.token, previous=reverse)

    @override
    @classmethod
    def from_str(cls, cursor: str) -> Self:
        match = cls._REGEX.fullmatch(cursor)
        if not match:
            msg = "Not a cursor for tokens sorted by creation time"
            raise InvalidCursorError(msg)
        return cls(
            created=cls._parse_created(match["created"]),
            key=match["key"],
            previous=bool(match["previous"]),
        )

    @override
    def __str__(self) -> str:
        previous = "p" if self.previous else ""
        return f"{previous}{self._serialize_created()}_{self.key}"

    @override
    @classmethod
    def _columns(cls) -> tuple[SQLColumnExpression[Any], ...]:
        return (SQLToken.created, SQLToken.token)

    @override
    def _position(self) -> tuple[Any, ...]:
        return (datetime_to_db(self.created), self.key)


@dataclass
class TokenCreatedDescendingCursor(TokenCreatedCursor):
    """Cursor for tokens sorted by creation time, newest first."""

    descending: ClassVar[bool] = True


@dataclass
class TokenUsernameCursor(TokenCursor):
    """Cursor for tokens sorted by username, in ascending order.

    Tokens for the same username are sorted by creation time, oldest first.
    Usernames are compared in the C collation, which is to say by code
    point, so that the order does not depend on the locale of the database.

    The serialized form is the creation time in seconds since epoch, the
    username, and the token key, separated by underscores, with a ``p``
    prefix for a cursor for the previous page. Usernames cannot contain an
    underscore, so the username ends at the last underscore but one. The
    creation time comes first, although it is not the most significant part
    of the sort key, so that a username starting with ``p`` cannot be
    mistaken for that prefix.
    """

    username: str
    """Username of the token at the cursor position."""

    _REGEX: ClassVar[re.Pattern[str]] = re.compile(
        f"(?P<previous>p?)(?P<created>{_CURSOR_TIME_PATTERN})"
        f"_(?P<username>[^_]+)_(?P<key>{_CURSOR_KEY_PATTERN})"
    )

    @override
    @classmethod
    def from_entry(cls, entry: TokenInfo, *, reverse: bool = False) -> Self:
        return cls(
            username=entry.username,
            created=entry.created,
            key=entry.token,
            previous=reverse,
        )

    @override
    @classmethod
    def from_str(cls, cursor: str) -> Self:
        match = cls._REGEX.fullmatch(cursor)
        if not match:
            msg = "Not a cursor for tokens sorted by username"
            raise InvalidCursorError(msg)
        return cls(
            username=match["username"],
            created=cls._parse_created(match["created"]),
            key=match["key"],
            previous=bool(match["previous"]),
        )

    @override
    def __str__(self) -> str:
        previous = "p" if self.previous else ""
        created = self._serialize_created()
        return f"{previous}{created}_{self.username}_{self.key}"

    @override
    @classmethod
    def _columns(cls) -> tuple[SQLColumnExpression[Any], ...]:
        return (
            collate(SQLToken.username, "C"),
            SQLToken.created,
            SQLToken.token,
        )

    @override
    def _position(self) -> tuple[Any, ...]:
        return (self.username, datetime_to_db(self.created), self.key)


@dataclass
class TokenUsernameDescendingCursor(TokenUsernameCursor):
    """Cursor for tokens sorted by username, in descending order.

    Tokens for the same username are sorted by creation time, newest first.
    """

    descending: ClassVar[bool] = True


_CURSOR_TYPES: dict[tuple[TokenSort, SortOrder], type[TokenCursor]] = {
    (TokenSort.created, SortOrder.asc): TokenCreatedCursor,
    (TokenSort.created, SortOrder.desc): TokenCreatedDescendingCursor,
    (TokenSort.username, SortOrder.asc): TokenUsernameCursor,
    (TokenSort.username, SortOrder.desc): TokenUsernameDescendingCursor,
}
"""Cursor class for each sort order of a listing of tokens."""


def token_cursor_type(sort: TokenSort, order: SortOrder) -> type[TokenCursor]:
    """Return the cursor class for a sort order of a listing of tokens.

    Parameters
    ----------
    sort
        Field by which the tokens are sorted.
    order
        Direction in which the tokens are sorted.

    Returns
    -------
    type of TokenCursor
        Cursor class that sorts tokens in that order, used both to sort the
        listing and to parse and generate its cursors.
    """
    return _CURSOR_TYPES[sort, order]
