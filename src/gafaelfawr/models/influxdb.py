"""Models for InfluxDB support."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InfluxDBToken(BaseModel):
    """Response to a token creation request."""

    token: str = Field(
        ...,
        title="Newly-created token",
        example=(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTUwODM3NzYsIml"
            "hdCI6MTYxNDk5NzUyMCwidXNlcm5hbWUiOiJycmEifQ.EaF0WRJzoKKPHIUoc3yO"
            "zrh1RAdKn63zlwlfZbgrvFI"
        ),
    )
