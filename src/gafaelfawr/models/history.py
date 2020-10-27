"""Representation of a token or admin history event."""

from __future__ import annotations

from enum import Enum

__all__ = ["AdminChange", "TokenChange"]


class AdminChange(Enum):
    """Type of change made to a token admin."""

    add = "add"
    remove = "remove"


class TokenChange(Enum):
    """Type of change made to a token."""

    create = "create"
    revoke = "revoke"
    expire = "expire"
    edit = "edit"
