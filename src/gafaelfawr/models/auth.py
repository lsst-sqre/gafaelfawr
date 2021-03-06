"""Representation of authentication-related data."""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

__all__ = ["APILoginResponse"]


class Scope(BaseModel):
    """A known token scope."""

    name: str = Field(..., title="Scope name", example="user:token")

    description: str = Field(
        ...,
        title="Scope description",
        example="Can create and modify user tokens",
    )


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
        title="CSRF token",
        description=(
            "This token must be included in any non-GET request using cookie"
            " authentication as the value of the X-CSRF-Token header."
        ),
        example="OmNdVTtKKuK_VuJsGFdrqg",
    )

    username: str = Field(
        ...,
        title="Username",
        description="Authenticated identity from the cookie",
        example="someuser",
    )

    scopes: List[str] = Field(
        ...,
        title="Access scopes",
        description="Access scopes for this authenticated user",
        example=["read:all", "user:token"],
    )

    config: APIConfig = Field(
        ...,
        title="Server configuration",
        description="Additional configuration information",
    )
