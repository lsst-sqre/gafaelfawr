"""Representation of authentication-related data."""

from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = ["APILoginResponse"]


class APILoginResponse(BaseModel):
    """Response to an API login request.

    This is returned by the ``/auth/api/v1/login`` route, which in turn is
    used by the JavaScript frontend to verify that cookie authentication is
    present and to obtain a CSRF token.
    """

    csrf: str = Field(..., title="CSRF token to send in X-CSRF-Token header")
