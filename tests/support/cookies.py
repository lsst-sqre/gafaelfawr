"""Helper functions for managing test cookies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from tests.support.constants import TEST_HOSTNAME

if TYPE_CHECKING:
    from httpx import AsyncClient

    from gafaelfawr.models.token import Token

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
    client : ``httpx.AsyncClient``
        The client to add the session cookie to.
    token : `gafaelfawr.models.token.Token`
        The token for the client identity to use.

    Returns
    -------
    csrf : `str`
        The CSRF token to use in subsequent API requests.
    """
    cookie = await State(token=token).as_cookie()
    client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)
    r = await client.get("/auth/api/v1/login")
    assert r.status_code == 200
    return r.json()["csrf"]


def clear_session_cookie(client: AsyncClient) -> None:
    """Delete the Gafaelfawr session token.

    Parameters
    ----------
    client : `httpx.AsyncClient`
        The client from which to remove the session cookie.
    """
    del client.cookies[COOKIE_NAME]
