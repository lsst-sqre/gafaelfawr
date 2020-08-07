"""Base class for authentication providers."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gafaelfawr.session import Session

__all__ = ["Provider"]


class Provider(metaclass=ABCMeta):
    """Abstract base class for authentication providers."""

    @abstractmethod
    def get_redirect_url(self, state: str) -> str:
        """Get the login URL to which to redirect the user.

        Parameters
        ----------
        state : `str`
            A random string used for CSRF protection.

        Returns
        -------
        url : `str`
            The encoded URL to which to redirect the user.
        """

    @abstractmethod
    async def create_session(self, code: str, state: str) -> Session:
        """Given the code from a successful authentication, create a session.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.

        Returns
        -------
        session : `gafaelfawr.session.Session`
            The new authentication session.

        Raises
        ------
        aiohttp.ClientResponseError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        gafaelfawr.exceptions.ProviderException
            The provider responded with an error to a request.
        """
