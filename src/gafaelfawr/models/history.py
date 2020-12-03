"""Representation of a token or admin history event."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel

__all__ = ["AdminChange", "TokenChange"]


class AdminChange(Enum):
    """Type of change made to a token admin."""

    add = "add"
    remove = "remove"


class AdminHistoryEntry(BaseModel):
    """A record of a change to the token administrators."""

    username: str
    """The username of the token administrator that was changed."""

    action: AdminChange
    """The change that was made."""

    actor: str
    """The username of the person making the change."""

    ip_address: str
    """The IP address from which the change was made."""

    event_time: datetime
    """When the change was made."""

    class Config:
        orm_mode = True


class TokenChange(Enum):
    """Type of change made to a token."""

    create = "create"
    revoke = "revoke"
    expire = "expire"
    edit = "edit"
