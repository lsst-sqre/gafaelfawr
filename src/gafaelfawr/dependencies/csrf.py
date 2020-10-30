"""CSRF dependencies for FastAPI.

Provides two dependencies, ``set_csrf`` and ``verify_csrf``.  The first
generates a CSRF token if needed and stores it in the encrypted state cookie.
The second verifies that a form submission contains a ``_csrf`` field that
matches the CSRF cookie stored in the state.

Depends on `~gafaelfawr.middleware.state.StateMiddleware`.
"""

from fastapi import Form, HTTPException, Request, status

from gafaelfawr.util import random_128_bits

__all__ = ["set_csrf", "verify_csrf"]


def set_csrf(request: Request) -> None:
    """Dependency to set a CSRF cookie in the encrypted state cookie."""
    if not request.state.cookie.csrf:
        request.state.cookie.csrf = random_128_bits()


def verify_csrf(request: Request, _csrf: str = Form(...)) -> None:
    """Verify the CSRF cookie on form submission.

    The form must contain a field ``_csrf``, whose contents must match the
    CSRF token in the encrypted state cookie.

    Raises
    ------
    fastapi.HTTPException
        If the CSRF token is missing or doesn't match.
    """
    expected_csrf = request.state.cookie.csrf
    if not expected_csrf:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"msg": "No CSRF in session", "type": "csrf_not_found"},
        )
    if _csrf != expected_csrf:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"msg": "No CSRF token", "type": "csrf_missing"},
        )
