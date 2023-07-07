"""Representation of a token administrator."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel

__all__ = ["Admin"]


class Admin(BaseModel):
    """A token administrator."""

    username: str
    """The username of the token administrator."""

    class Config:
        orm_mode = True
        schema_extra: ClassVar[dict[str, dict[str, str]]] = {
            "example": {"username": "adminuser"}
        }
