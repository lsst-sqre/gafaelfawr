"""Models for the application metdata."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Metadata(BaseModel):
    """Metadata returned by the top-level application route."""

    name: str = Field(..., title="Application name", example="gafaelfawr")

    version: str = Field(..., title="Version", example="2.0.0")

    description: str = Field(..., title="Description", example="string")

    repository_url: str = Field(
        ..., title="Repository URL", example="https://example.com/"
    )

    documentation_url: str = Field(
        ..., title="Documentation URL", example="https://example.com/"
    )
