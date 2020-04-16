"""Base class for authentication providers."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jwt_authorizer.session import Ticket
    from jwt_authorizer.tokens import VerifiedToken

__all__ = ["Provider", "ProviderException"]


class ProviderException(Exception):
    """A provider returned an error from an API call."""


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
        pass

    @abstractmethod
    async def get_token(
        self, code: str, state: str, ticket: Ticket
    ) -> VerifiedToken:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.
        ticket : `jwt_authorizer.session.Ticket`
            The ticket to use for the new token.

        Returns
        -------
        token : `jwt_authorizer.tokens.VerifiedToken`
            Authentication token issued by the local issuer and including the
            user information from the authentication provider.

        Raises
        ------
        aiohttp.ClientResponseError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        ProviderException
            The provider responded with an error to a request.
        """
        pass
