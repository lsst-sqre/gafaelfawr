"""Representation of authentication-related data."""

from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = ["APILoginResponse"]


class APILoginResponse(BaseModel):
    """Response to an API login request.

    The JavaScript UI visits the ``/auth/api/v1/login`` route to get a CSRF
    token and metadata about the currently-authenticated user from the session
    cookie (which the UI doesn't have the keys to read).
    """

    csrf: str = Field(
        ...,
        title="CSRF token for subsequent requests",
        description=(
            "This token must be included in any non-GET request using cookie"
            " authentication as the value of the X-CSRF-Token header."
        ),
    )

    username: str = Field(..., title="Authenticated identity from the cookie")
