"""CSRF dependencies for FastAPI.

Provides two dependencies, ``set_csrf`` and ``verify_csrf``.  The first
generates a CSRF token if needed and stores it in the encrypted state cookie.
The second verifies that a form submission contains a ``_csrf`` field that
matches the CSRF cookie stored in the state.

Depends on `~gafaelfawr.middleware.state.StateMiddleware`.
"""

from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status

from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.util import random_128_bits

__all__ = ["set_csrf", "verify_csrf"]


def set_csrf(request: Request) -> None:
    """Dependency to set a CSRF cookie in the encrypted state cookie."""
    if not request.state.cookie.csrf:
        request.state.cookie.csrf = random_128_bits()


def verify_csrf(
    x_csrf_token: Optional[str] = Header(None),
    context: RequestContext = Depends(context_dependency),
) -> None:
    """Check the provided CSRF token is correct.

    Raises
    ------
    fastapi.HTTPException
        If no CSRF token was provided or if it was incorrect, and the method
        was something other than GET or OPTIONS.
    """
    if context.request.method in ("GET", "OPTIONS"):
        return
    error = None
    if not x_csrf_token:
        error = "CSRF token required in X-CSRF-Token header"
    if x_csrf_token != context.state.csrf:
        error = "Invalid CSRF token"
    if error:
        context.logger.error("CSRF verification failed", error=error)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "loc": ["header", "X-CSRF-Token"],
                "type": "invalid_csrf",
                "msg": error,
            },
        )
