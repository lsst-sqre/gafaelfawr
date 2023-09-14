"""Representation of a token administrator."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["Admin"]


class Admin(BaseModel):
    """A token administrator."""

    username: str = Field(
        ...,
        title="Admin username",
        description="Username of the token administrator",
        examples=["adminuser"],
    )

    model_config = ConfigDict(from_attributes=True)
