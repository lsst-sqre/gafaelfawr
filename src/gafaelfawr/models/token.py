"""Representation of an authentication token."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field, validator

from gafaelfawr.exceptions import InvalidTokenError
from gafaelfawr.storage.base import Serializable
from gafaelfawr.util import random_128_bits

__all__ = ["TokenType"]


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
    """

    session = "session"
    user = "user"
    notebook = "notebook"
    internal = "internal"


class TokenGroup(BaseModel):
    """Information about a single group.

    This is temporary until group information is stored in a dedicated
    identity management system.
    """

    name: str = Field(..., title="The name of the group")

    id: int = Field(..., title="The numeric GID of the group")


class TokenBase(BaseModel):
    """Base information about a token common to several representations.

    This is the information that's common to the Redis and database
    representations of the token.
    """

    username: str = Field(
        ...,
        title="The user to whom the token was issued",
        min_length=1,
        max_length=64,
    )

    token_type: TokenType = Field(..., title="The type of the token")

    scopes: List[str] = Field(..., title="The scopes of the token")

    created: datetime = Field(
        ..., title="Creation timestamp of the token in seconds since epoch"
    )

    expires: Optional[datetime] = Field(
        None, title="Expiration timestamp of the token in seconds since epoch"
    )


def normalize_datetime(
    v: Optional[Union[int, datetime]]
) -> Optional[datetime]:
    """Ensure datetimes are timezone-aware."""
    if v is None:
        return v
    elif isinstance(v, int):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    elif v.tzinfo and v.tzinfo.utcoffset(v) is not None:
        return v
    else:
        return v.replace(tzinfo=timezone.utc)


class TokenInfo(TokenBase):
    """Information about a token returned by the token-info endpoint.

    This is all the information about the token that's stored in the
    underlying database.  It includes some fields not present in Redis.
    """

    token_name: Optional[str] = Field(
        None,
        title="The user-given name of the token",
        min_length=1,
        max_length=64,
    )

    last_used: Optional[datetime] = Field(
        None, title="When the token was last used in seconds since epoch"
    )

    parent: Optional[str] = Field(
        None,
        title="The parent token of this token",
        min_length=22,
        max_length=22,
    )

    class Config:
        orm_mode = True
        json_encoders = {datetime: lambda v: int(v.timestamp())}

    _normalize_created = validator("created", allow_reuse=True, pre=True)(
        normalize_datetime
    )
    _normalize_last_used = validator("last_used", allow_reuse=True, pre=True)(
        normalize_datetime
    )
    _normalize_expires = validator("expires", allow_reuse=True, pre=True)(
        normalize_datetime
    )

    @validator("scopes", pre=True)
    def _normalize_scopes(cls, v: Union[str, List[str]]) -> List[str]:
        """Convert comma-delimited scopes to a list.

        Scopes are stored in the database as a comma-delimited, sorted list.
        Convert to the list representation we want to use in Python.
        """
        if isinstance(v, str):
            return v.split(",")
        else:
            return v


class TokenUserInfo(BaseModel):
    """The information about a user stored with their token.

    This information is derived from the upstream user information.  It is
    kept here temporary until it has been replaced by a proper identity
    management system.
    """

    username: str = Field(
        ...,
        title="The user to whom the token was issued",
        min_length=1,
        max_length=64,
    )

    name: str = Field(
        ..., title="The user's preferred full name", min_length=1
    )

    uid: int = Field(..., title="The user's UID number", ge=1)

    groups: List[TokenGroup] = Field(
        [], title="The groups of which the user is a member"
    )


class TokenData(TokenBase, TokenUserInfo, Serializable):
    """Data about a token stored in Redis.

    This holds all the token information stored in Redis, and thus all the
    token information required to support authentication decisions and
    (currently) user information queries.  It should not be used directly as a
    response model; for that, see `TokenInfo` and `TokenUserInfo`.
    """

    token: Token = Field(..., title="The associated token")

    class Config:
        json_encoders = {datetime: lambda v: int(v.timestamp())}

    @classmethod
    def from_json(cls, data: str) -> TokenData:
        """Deserialize from JSON."""
        return cls.parse_raw(data)

    @property
    def lifetime(self) -> Optional[int]:
        """The object lifetime in seconds."""
        if not self.expires:
            return None
        now = datetime.now(timezone.utc)
        return int((self.expires - now).total_seconds())

    def to_json(self) -> str:
        """Serialize to JSON."""
        return self.json(exclude_none=True)
