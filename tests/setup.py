"""Set up the test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.session import Session, SessionHandle
from tests.support.tokens import create_oidc_test_token, create_test_token

if TYPE_CHECKING:
    from aiohttp import ClientResponse, web
    from aiohttp.pytest_plugin.test_utils import TestClient
    from aioredis import Redis
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.tokens import Token, VerifiedToken
    from tests.support.http_session import MockClientSession
    from typing import Awaitable, Callable, List, Optional, Union


class SetupTest:
    """Utility class for test setup.

    This class wraps creating a test aiohttp application, creating a factory
    for building the JWT Authorizer components, and accessing configuration
    settings.
    """

    def __init__(
        self, app: web.Application, client: Optional[TestClient] = None
    ) -> None:
        self.app = app
        self._client = client
        self.config: Config = self.app["gafaelfawr/config"]
        self.factory: ComponentFactory = self.app["gafaelfawr/factory"]
        self.redis: Redis = self.app["gafaelfawr/redis"]

    @property
    def client(self) -> TestClient:
        """Return the test client.

        This property is a typing hack to avoid forcing all tests that want to
        use a client to assert that the client exists.  Instead, assume that
        the client is available and assert if a test accesses the client but
        didn't request it be created.
        """
        assert self._client
        return self._client

    async def create_session(
        self, *, groups: Optional[List[str]] = None, **claims: str
    ) -> SessionHandle:
        """Create a session from a new signed internal token.

        Create a signed internal token as with create_token, but immediately
        store it in a session and return the corresponding session handle.

        Parameters
        ----------
        groups : List[`str`], optional
            Group memberships the generated token should have.
        **claims : `str`, optional
            Other claims to set or override in the token.

        Returns
        -------
        handle : `gafaelfawr.session.SessionHandle`
            The new session handle.
        """
        handle = SessionHandle()
        token = self.create_token(groups=groups, jti=handle.key, **claims)
        session = Session.create(handle, token)
        session_store = self.factory.create_session_store()
        await session_store.store_session(session)
        return handle

    def create_token(
        self, *, groups: Optional[List[str]] = None, **claims: Union[str, int]
    ) -> VerifiedToken:
        """Create a signed internal token.

        Parameters
        ----------
        groups : List[`str`], optional
            Group memberships the generated token should have.
        **claims : Union[`str`, `int`], optional
            Other claims to set or override in the token.

        Returns
        -------
        token : `gafaelfawr.tokens.VerifiedToken`
            The generated token.
        """
        return create_test_token(
            self.config, groups=groups, kid="some-kid", **claims
        )

    def create_oidc_token(
        self, *, groups: Optional[List[str]] = None, **claims: str
    ) -> VerifiedToken:
        """Create a signed OpenID Connect token.

        Parameters
        ----------
        groups : List[`str`], optional
            Group memberships the generated token should have.
        **claims : `str`, optional
            Other claims to set or override in the token.

        Returns
        -------
        token : `gafaelfawr.tokens.VerifiedToken`
            The generated token.
        """
        return create_oidc_test_token(self.config, groups=groups, **claims)

    def set_oidc_token(self, token: Token) -> None:
        """Set the token that will be returned from the OIDC token endpoint.

        Parameters
        ----------
        token : `gafaelfawr.tokens.Token`
            The token.
        """
        http_session: MockClientSession = self.app["safir/http_session"]
        http_session.set_oidc_token(token)

    def set_oidc_token_response(self, response: ClientResponse) -> None:
        """Set the raw response from the OIDC token request.

        Used to test error handling.

        Parameters
        ----------
        response : `aiohttp.ClientResponse`
            The raw response to return (probably mocked).
        """
        http_session: MockClientSession = self.app["safir/http_session"]
        http_session.set_oidc_token_response(response)


# Type of the pytest fixture that builds the SetupTest object.
if TYPE_CHECKING:
    SetupTestCallable = Callable[..., Awaitable[SetupTest]]
