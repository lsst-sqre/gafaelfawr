"""Base class for authentication providers."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod

from ..models.state import State
from ..models.token import TokenUserInfo

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
    async def create_user_info(
        self, code: str, state: str, session: State
    ) -> TokenUserInfo:
        """Given the code from an authentication, create the user information.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL.
        session : `gafaelfawr.models.state.State`
            The session state.  The provider may also store data used during
            logout.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            The user information corresponding to that authentication.

        Raises
        ------
        httpx.HTTPError
            An HTTP client error occurred trying to talk to the authentication
            provider.
        gafaelfawr.exceptions.ProviderException
            The provider responded with an error to a request.
        """

    @abstractmethod
    async def logout(self, session: State) -> None:
        """Called during user logout.

        The authentication provider may revoke the upstream authentication
        token or take other action during user logout.

        Parameters
        ----------
        session : `gafaelfawr.models.state.State`
            The session state before logout.
        """
