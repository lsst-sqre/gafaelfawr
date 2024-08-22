"""Representation of a token or admin history event."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, Self, TypeVar
from urllib.parse import parse_qs, urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator
from safir.datetime import current_datetime
from starlette.datastructures import URL

from ..exceptions import InvalidCursorError
from ..pydantic import Timestamp
from ..util import normalize_ip_address, normalize_scopes
from .token import TokenType

E = TypeVar("E", bound="BaseModel")
"""Type of a history entry in a paginated list."""

__all__ = [
    "AdminChange",
    "AdminHistoryEntry",
    "E",
    "HistoryCursor",
    "PaginatedHistory",
    "TokenChange",
    "TokenChangeHistoryEntry",
]


class AdminChange(Enum):
    """Type of change made to a token admin."""

    add = "add"
    remove = "remove"


class AdminHistoryEntry(BaseModel):
    """A record of a change to the token administrators."""

    username: str = Field(
        ...,
        title="Username",
        description="Username of the token administrator that was changed",
        examples=["someadmin"],
        min_length=1,
        max_length=64,
    )

    action: AdminChange = Field(..., title="Type of change", examples=["add"])

    actor: str = Field(
        ...,
        title="Actor",
        description="Username of the person making the change",
        min_length=1,
        max_length=64,
    )

    ip_address: str | None = Field(
        None,
        title="IP address",
        description=(
            "IP address from which the change was made. Will be missing if"
            " the change was made internally by Gafaelfawr."
        ),
    )

    event_time: Timestamp = Field(
        default_factory=current_datetime,
        title="Timestamp",
        description="When the change was made",
        examples=[1614986130],
    )

    model_config = ConfigDict(from_attributes=True)

    _normalize_ip_address = field_validator("ip_address", mode="before")(
        normalize_ip_address
    )


@dataclass
class HistoryCursor:
    """Pagination cursor for history entries."""

    time: datetime
    """Time position."""

    id: int
    """Unique ID position."""

    previous: bool = False
    """Whether to search backwards instead of forwards."""

    @classmethod
    def from_str(cls, cursor: str) -> Self:
        """Build cursor from the string serialization form.

        Parameters
        ----------
        cursor
            Serialized form of the cursor.

        Returns
        -------
        HistoryCursor
            The cursor represented as an object.

        Raises
        ------
        InvalidCursorError
            Raised if the cursor is not valid.
        """
        previous = cursor.startswith("p")
        if previous:
            cursor = cursor[1:]
        try:
            time, id = cursor.split("_")
            return cls(
                time=datetime.fromtimestamp(int(time), tz=UTC),
                id=int(id),
                previous=previous,
            )
        except Exception as e:
            raise InvalidCursorError(f"Invalid cursor: {e!s}") from e

    @classmethod
    def invert(cls, cursor: HistoryCursor) -> Self:
        """Return the inverted cursor (going the opposite direction).

        Parameters
        ----------
        cursor
            Cursor to invert.

        Returns
        -------
        HistoryCursor
            The inverted cursor.
        """
        return cls(
            time=cursor.time, id=cursor.id, previous=not cursor.previous
        )

    def __str__(self) -> str:
        """Serialize to a string."""
        previous = "p" if self.previous else ""
        timestamp = str(int(self.time.timestamp()))
        return f"{previous}{timestamp}_{self.id!s}"


@dataclass
class PaginatedHistory(Generic[E]):
    """Encapsulates paginated history entries with pagination information.

    Holds a paginated list of a generic type, complete with a count and
    cursors.  Can hold any type of entry, but uses a `HistoryCursor`, so
    implicitly requires the type be one that is meaningfully paginated by that
    type of cursor.
    """

    entries: list[E]
    """The history entries."""

    count: int
    """Total available entries."""

    next_cursor: HistoryCursor | None = None
    """Cursor for the next batch of entries."""

    prev_cursor: HistoryCursor | None = None
    """Cursor for the previous batch of entries."""

    def link_header(self, base_url: URL) -> str:
        """Construct an RFC 8288 ``Link`` header for a paginated result.

        Parameters
        ----------
        base_url
            The starting URL of the current group of entries.
        """
        first_url = base_url.remove_query_params("cursor")
        header = f' <{first_url!s}>; rel="first"'
        params = parse_qs(first_url.query)
        if self.next_cursor:
            params["cursor"] = [str(self.next_cursor)]
            next_url = first_url.replace(query=urlencode(params, doseq=True))
            header += f', <{next_url!s}>; rel="next"'
        if self.prev_cursor:
            params["cursor"] = [str(self.prev_cursor)]
            prev_url = first_url.replace(query=urlencode(params, doseq=True))
            header += f', <{prev_url!s}>; rel="prev"'
        return header


class TokenChange(Enum):
    """Type of change made to a token."""

    create = "create"
    revoke = "revoke"
    expire = "expire"
    edit = "edit"


class TokenChangeHistoryEntry(BaseModel):
    """A record of a change to a token."""

    token: str = Field(
        ...,
        title="Token key",
        examples=["dDQg_NTNS51GxeEteqnkag"],
        min_length=22,
        max_length=22,
    )

    username: str = Field(
        ...,
        title="Username of the token",
        examples=["someuser"],
        min_length=1,
        max_length=64,
    )

    token_type: TokenType = Field(
        ...,
        title="Type of the token",
        examples=["user"],
    )

    token_name: str | None = Field(
        None,
        title="Name of the token",
        description=(
            "Only set for tokens of type user. If the name was changed, this"
            " will be the new name of the token."
        ),
        examples=["a token"],
    )

    parent: str | None = Field(
        None,
        title="Key of parent token of this token",
        examples=["1NOV_8aPwhCWj6rM-p1XgQ"],
    )

    scopes: list[str] = Field(
        ..., title="Scopes of the token", examples=[["read:all"]]
    )

    service: str | None = Field(
        None,
        title="Service to which the token was issued",
        description="Only set for tokens of type internal.",
        examples=["some-service"],
    )

    expires: Timestamp | None = Field(
        None,
        title="Expiration of the token",
        description=(
            "If the expiration was changed, this will be the new expiration of"
            " the token."
        ),
        examples=[1615785631],
    )

    actor: str = Field(
        ...,
        title="Username of person making the change",
        examples=["adminuser"],
        min_length=1,
        max_length=64,
    )

    action: TokenChange = Field(
        ..., title="Type of change that was made", examples=["edit"]
    )

    old_token_name: str | None = Field(
        None,
        title="Previous name of the token",
        description=(
            "This field will only be present for edit changes to user tokens"
            " that changed the token name."
        ),
        examples=["old name"],
    )

    old_scopes: list[str] | None = Field(
        None,
        title="Previous scopes of the token",
        description=(
            "This field will only be present for edit changes that changed the"
            " token scopes."
        ),
        examples=[["read:some"]],
    )

    old_expires: Timestamp | None = Field(
        None,
        title="Previous expiration of the token",
        description=(
            "This field will only be present for edit changes that changed the"
            " expiration of the token."
        ),
        examples=[1614985631],
    )

    # The first implementation tried to use an IPvAnyAddress type here for the
    # automatic validation, but the corresponding query takes either an IP
    # address or a CIDR block (so can't use the same type), and all of the
    # type conversions and calcuations made for ugly code, particularly since
    # the underlying database layer wants a string.  It turned out to be
    # easier to manually validate the query and to otherwise store and
    # manipulate strings.
    #
    # We don't gain very much from the Pydantic validation since these entries
    # are created either in code or sourced from a trusted database.
    ip_address: str | None = Field(
        None,
        title="IP address from which the change was made",
        description=(
            "May be null if the change was made internally, such as token"
            " deletion due to expiration."
        ),
        examples=["198.51.100.50"],
    )

    event_time: Timestamp = Field(
        default_factory=current_datetime,
        title="Whent he change was made",
        examples=[1614985631],
    )

    model_config = ConfigDict(from_attributes=True)

    _normalize_scopes = field_validator("scopes", "old_scopes", mode="before")(
        normalize_scopes
    )
    _normalize_ip_address = field_validator("ip_address", mode="before")(
        normalize_ip_address
    )

    def model_dump_reduced(self) -> dict[str, Any]:
        """Convert to a dictionary while suppressing some fields.

        The same as the standard Pydantic ``model_dump`` method, but excludes
        the ``old_`` fields for changes other than edits and when the edit
        doesn't change those fields.

        Returns
        -------
        dict
            Dictionary representation of the object.

        Notes
        -----
        Knowing which fields to exclude requires understanding the semantics
        of the change (particularly when deciding whether to drop
        ``old_expires``) in ways that are too complex to do with the standard
        Pydantic filtering API, hence the hand-rolled method.
        """
        v = self.model_dump()

        for field in ("token_name", "parent", "service"):
            if v[field] is None:
                del v[field]
        if v["action"] == TokenChange.edit:
            for field in ("old_scopes", "old_token_name"):
                if v[field] is None:
                    del v[field]
            if v["old_expires"] is None and v["expires"] is None:
                del v["old_expires"]
        else:
            del v["old_expires"]
            del v["old_scopes"]
            del v["old_token_name"]

        return v
