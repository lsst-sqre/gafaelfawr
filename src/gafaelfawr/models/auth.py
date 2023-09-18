"""Representation of authentication-related data."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, Field

__all__ = [
    "APIConfig",
    "APILoginResponse",
    "AuthChallenge",
    "AuthError",
    "AuthErrorChallenge",
    "AuthType",
    "Satisfy",
    "Scope",
]


class AuthType(Enum):
    """Authentication types for the WWW-Authenticate header."""

    Basic = "basic"
    """HTTP Basic Authentication (RFC 7617)."""

    Bearer = "bearer"
    """HTTP Bearer Authentication (RFC 6750)."""


class AuthError(Enum):
    """Valid authentication errors for a WWW-Authenticate header.

    Defined in RFC 6750.
    """

    invalid_request = "invalid_request"
    invalid_token = "invalid_token"
    insufficient_scope = "insufficient_scope"


@dataclass
class AuthChallenge:
    """Represents a ``WWW-Authenticate`` header for a simple challenge."""

    auth_type: AuthType
    """The authentication type (the first part of the header)."""

    realm: str
    """The value of the realm attribute."""

    def to_header(self) -> str:
        """Construct the WWW-Authenticate header for this challenge.

        Returns
        -------
        str
            Contents of the WWW-Authenticate header.
        """
        return f'{self.auth_type.name} realm="{self.realm}"'


@dataclass
class AuthErrorChallenge(AuthChallenge):
    """Represents a ``WWW-Authenticate`` header for an error challenge."""

    error: AuthError
    """Short error code."""

    error_description: str
    """Human-readable error description."""

    scope: str | None = None
    """Scope required to access this URL."""

    def to_header(self) -> str:
        """Construct the WWW-Authenticate header for this challenge.

        Returns
        -------
        str
            Contents of the WWW-Authenticate header.
        """
        if self.auth_type == AuthType.Basic:
            # Basic doesn't support error information.
            return f'{self.auth_type.name} realm="{self.realm}"'

        # Strip invalid characters from the description.
        error_description = re.sub(r'["\\]', "", self.error_description)

        info = f'realm="{self.realm}", error="{self.error.name}"'
        info += f', error_description="{error_description}"'
        if self.scope:
            info += f', scope="{self.scope}"'
        return f"{self.auth_type.name} {info}"


class Satisfy(Enum):
    """Authorization strategies.

    Controls how to do authorization when there are multiple required scopes.
    A strategy of ANY allows the request if the authentication token has any
    of the required scopes.  A strategy of ALL requires that the
    authentication token have all the required scopes.
    """

    ANY = "any"
    ALL = "all"


class Scope(BaseModel):
    """A known token scope."""

    name: str = Field(..., title="Scope name", examples=["user:token"])

    description: str = Field(
        ...,
        title="Scope description",
        examples=["Can create and modify user tokens"],
    )


class APIConfig(BaseModel):
    """Configuration information for the API.

    Supplemental information about the Gafaelfawr configuration that is useful
    to a UI and therefore is returned as part of a login response.
    """

    scopes: list[Scope] = Field(
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
            " authentication as the value of the `X-CSRF-Token` header"
        ),
        examples=["OmNdVTtKKuK_VuJsGFdrqg"],
    )

    username: str = Field(
        ...,
        title="Username",
        description="Authenticated identity from the cookie",
        examples=["someuser"],
    )

    scopes: list[str] = Field(
        ...,
        title="Access scopes",
        description="Access scopes for this authenticated user",
        examples=["read:all", "user:token"],
    )

    config: APIConfig = Field(
        ...,
        title="Server configuration",
        description="Additional configuration information",
    )
