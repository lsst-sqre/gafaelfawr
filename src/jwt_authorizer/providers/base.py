"""Base class for authentication providers."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp import ClientResponse, ClientSession
    from jwt_authorizer.issuer import TokenIssuer
    from jwt_authorizer.session import Ticket
    from jwt_authorizer.tokens import VerifiedToken
    from logging import Logger
    from typing import Dict

__all__ = ["Provider", "ProviderException"]


class ProviderException(Exception):
    """A provider returned an error from an API call."""


class Provider(metaclass=ABCMeta):
    """Abstract base class for authentication providers.

    Parameters
    ----------
    session : `aiohttp.ClientSession`
        Session to use to make HTTP requests.
    issuer : `jwt_authorizer.issuer.TokenIssuer`
        Issuer to use to generate new tokens.
    logger : `logging.Logger`
        Logger for any log messages.
    """

    def __init__(
        self, session: ClientSession, issuer: TokenIssuer, logger: Logger
    ) -> None:
        self._session = session
        self.issuer = issuer
        self.logger = logger

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

    async def http_get(
        self, url: str, *, headers: Dict[str, str], raise_for_status: bool
    ) -> ClientResponse:
        """Retrieve a URL.

        Intended for overriding by a test class to avoid actual HTTP requests.

        Parameters
        ----------
        url : `str`
            URL to retrieve.
        headers : Dict[`str`, `str`]
            Extra headers to send.
        raise_for_status : `bool`
            Whether to raise an exception for a status other than 200.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The response.
        """
        return await self._session.get(
            url, headers=headers, raise_for_status=raise_for_status
        )

    async def http_post(
        self,
        url: str,
        *,
        data: Dict[str, str],
        headers: Dict[str, str],
        raise_for_status: bool,
    ) -> ClientResponse:
        """POST to a URL.

        Intended for overriding by a test class to avoid actual HTTP requests.

        Parameters
        ----------
        url : `str`
            URL to POST to.
        data : Dict[`str`, `str`]
            Form data to send in the POST.
        headers : Dict[`str`, `str`]
            Extra headers to send.
        raise_for_status : `bool`
            Whether to raise an exception for a status other than 200.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The response.
        """
        return await self._session.post(
            url, data=data, headers=headers, raise_for_status=raise_for_status
        )
