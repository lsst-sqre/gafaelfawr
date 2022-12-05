"""Helper functions for managing test cookies."""

from __future__ import annotations

from httpx import AsyncClient

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token

from .constants import TEST_HOSTNAME

__all__ = [
    "clear_session_cookie",
    "set_session_cookie",
]


async def set_session_cookie(client: AsyncClient, token: Token) -> str:
    """Create a valid Gafaelfawr session.

    Add a valid Gafaelfawr session cookie to the ``httpx.AsyncClient``, use
    the login URL, and return the resulting CSRF token.

    Parameters
    ----------
    client
        The client to add the session cookie to.
    token
        The token for the client identity to use.

    Returns
    -------
    str
        The CSRF token to use in subsequent API requests.
    """
    cookie = State(token=token).to_cookie()
    client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)
    r = await client.get("/auth/api/v1/login")
    assert r.status_code == 200
    return r.json()["csrf"]


def clear_session_cookie(client: AsyncClient) -> None:
    """Delete the Gafaelfawr session token.

    Parameters
    ----------
    client
        The client from which to remove the session cookie.
    """
    del client.cookies[COOKIE_NAME]
