"""Representation of an authentication token."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field, validator

from gafaelfawr.exceptions import InvalidTokenError
from gafaelfawr.storage.base import Serializable
from gafaelfawr.util import random_128_bits

__all__ = ["TokenType"]


@dataclass
class Token:
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

    key: str = field(default_factory=random_128_bits)
    secret: str = field(default_factory=random_128_bits)

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

    def encode(self) -> str:
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


class TokenData(BaseModel, Serializable):
    """Data about a token stored in Redis.

    This holds all the token information stored in Redis, and thus all the
    token information required to support authentication decisions and
    (currently) user information queries.  It should not be used directly as a
    response model; for that, see `TokenInfo` and `TokenUserInfo`.
    """

    secret: str
    """The secret portion of the token."""

    username: str
    """The user to whom the token was issued."""

    token_type: TokenType
    """The type of the token."""

    service: Optional[str]
    """The service to which the token was issued, if any."""

    scopes: List[str]
    """The scopes of the token."""

    created: datetime
    """Creation time of the token."""

    expires: Optional[datetime]
    """Expiration time of the token."""

    # The following data will eventually be handled by a separate user and
    # group service, but is included in Redis for now until such a thing
    # exists.

    name: str
    """The preferred name of the user to which the token was issued."""

    uid: int
    """The UID number of the user to which the token was issued."""

    groups: List[TokenGroup]
    """The groups of which the user is a member."""

    @classmethod
    def from_json(cls, data: str) -> TokenData:
        """Deserialize from JSON.

        Parameters
        ----------
        data : `str`
            JSON-serialized representation.

        Returns
        -------
        token_data : `TokenData`
            The corresponding `TokenData` object.
        """
        token = json.loads(data)
        expires = None
        if "expires" in token:
            expires = datetime.fromtimestamp(token["expires"], tz=timezone.utc)
        groups = [
            TokenGroup(name=g["name"], id=g["id"])
            for g in token.get("groups", [])
        ]
        return cls(
            secret=token["secret"],
            username=token["username"],
            token_type=TokenType(token["token_type"]),
            service=token.get("service"),
            scopes=token.get("scopes", []),
            created=datetime.fromtimestamp(token["created"], tz=timezone.utc),
            expires=expires,
            name=token["name"],
            uid=token["uid"],
            groups=groups,
        )

    @property
    def lifetime(self) -> Optional[int]:
        """The object lifetime in seconds."""
        if not self.expires:
            return None
        now = datetime.now(timezone.utc)
        return int((self.expires - now).total_seconds())

    def to_json(self) -> str:
        """Serialize to JSON.

        Returns
        -------
        data : `str`
            The object in JSON-serialized form.
        """
        data = {
            "secret": self.secret,
            "username": self.username,
            "token_type": self.token_type.value,
            "created": int(self.created.timestamp()),
            "name": self.name,
            "uid": self.uid,
        }
        if self.service:
            data["service"] = self.service
        if self.scopes:
            data["scopes"] = self.scopes
        if self.expires:
            data["expires"] = int(self.expires.timestamp())
        if self.groups:
            data["groups"] = [
                {"name": g.name, "id": g.id} for g in self.groups
            ]
        return json.dumps(data)


def normalize_timestamp(v: Union[int, datetime]) -> int:
    """Used to allow initializing `TokenInfo` with datetime parameters."""
    if isinstance(v, datetime):
        return int(v.replace(tzinfo=timezone.utc).timestamp())
    else:
        return v


class TokenInfo(BaseModel):
    """The information about a token returned by a token-info query."""

    token: str = Field(
        ..., title="The key part of the token", min_length=22, max_length=22
    )

    username: str = Field(
        ...,
        title="The user to whom the token was issued",
        min_length=1,
        max_length=64,
    )

    token_name: Optional[str] = Field(
        None,
        title="The user-given name of the token",
        min_length=1,
        max_length=64,
    )

    token_type: TokenType = Field(..., title="The type of the token")

    scopes: List[str] = Field(..., title="The scopes of the token")

    created: int = Field(
        ...,
        title="Creation timestamp of the token in seconds since epoch",
        ge=1,
    )

    last_used: int = Field(
        None,
        title="When the token was last used in seconds since epoch",
        ge=1,
    )

    expires: int = Field(
        None,
        title="Expiration timestamp of the token in seconds since epoch",
        ge=1,
    )

    parent: Optional[str] = Field(
        None,
        title="The parent token of this token",
        min_length=22,
        max_length=22,
    )

    class Config:
        orm_mode = True

    _normalize_created = validator("created", allow_reuse=True, pre=True)(
        normalize_timestamp
    )
    _normalize_last_used = validator("last_used", allow_reuse=True, pre=True)(
        normalize_timestamp
    )
    _normalize_expires = validator("expires", allow_reuse=True, pre=True)(
        normalize_timestamp
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
