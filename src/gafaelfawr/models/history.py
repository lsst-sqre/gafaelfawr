"""Representation of a token or admin history event."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Self

from pydantic import BaseModel, Field
from safir.database import DatetimeIdCursor
from safir.datetime import current_datetime
from sqlalchemy.orm import InstrumentedAttribute

from ..schema import TokenChangeHistory as SQLTokenChangeHistory
from ..types import IpAddress, Scopes, Timestamp
from .enums import AdminChange, TokenChange, TokenType

__all__ = [
    "AdminHistoryEntry",
    "TokenChangeHistoryCursor",
    "TokenChangeHistoryEntry",
    "TokenChangeHistoryRecord",
]


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

    ip_address: IpAddress | None = Field(
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

    scopes: Scopes = Field(
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

    old_scopes: Scopes | None = Field(
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
    # the underlying database layer wants a string. It turned out to be easier
    # to manually validate the query and to otherwise store and manipulate
    # strings.
    #
    # We don't gain very much from the Pydantic validation since these entries
    # are created either in code or sourced from a trusted database.
    ip_address: IpAddress | None = Field(
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


class TokenChangeHistoryRecord(TokenChangeHistoryEntry):
    """A token change history entry populated from the database.

    This model adds the unique row ID, which is not part of the public API but
    which is required for cursors to work correctly.
    """

    id: int = Field(
        ...,
        title="Unique ID",
        description="Database unique row ID, not included in the API",
        exclude=True,
    )


@dataclass
class TokenChangeHistoryCursor(DatetimeIdCursor[TokenChangeHistoryRecord]):
    """Pagination cursor for token history entries."""

    @staticmethod
    def id_column() -> InstrumentedAttribute:
        return SQLTokenChangeHistory.id

    @staticmethod
    def time_column() -> InstrumentedAttribute:
        return SQLTokenChangeHistory.event_time

    @classmethod
    def from_entry(
        cls, entry: TokenChangeHistoryRecord, *, reverse: bool = False
    ) -> Self:
        return cls(id=entry.id, time=entry.event_time, previous=reverse)
