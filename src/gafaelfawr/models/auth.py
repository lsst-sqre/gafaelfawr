"""Representation of authentication-related data."""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

__all__ = ["APILoginResponse"]


class Scope(BaseModel):
    """A known token scope."""

    name: str = Field(..., title="Name of the scope")

    description: str = Field(..., title="Description of the scope")


class APIConfig(BaseModel):
    """Configuration information for the API.

    Supplemental information about the Gafaelfawr configuration that is useful
    to a UI and therefore is returned as part of a login response.
    """

    scopes: List[Scope] = Field(
        ...,
        title="All known scopes",
        description=(
            "All scopes currently recognized by the server.  Tokens may have"
            " other scopes, but new tokens may only be issued with one of"
            " these scopes."
        ),
    )


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

    scopes: List[str] = Field(
        ..., title="Access scopes for this authenticated user"
    )

    config: APIConfig = Field(
        ..., title="Additional configuration information"
    )
