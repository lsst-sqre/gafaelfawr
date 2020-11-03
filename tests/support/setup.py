"""Set up the test suite."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

from asgi_lifespan import LifespanManager
from httpx import AsyncClient
from pytest_httpx import to_response

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.database import initialize_database
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.main import app
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token, TokenData, TokenType
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.session import Session, SessionHandle
from tests.support.constants import TEST_HOSTNAME
from tests.support.settings import build_settings
from tests.support.tokens import create_oidc_test_token, create_test_token

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any, AsyncIterator, Dict, List, Optional, Union

    from aioredis import Redis
    from httpx import Request
    from pytest_httpx import HTTPXMock
    from pytest_httpx._httpx_internals import Response

    from gafaelfawr.config import Config, OIDCClient
    from gafaelfawr.keypair import RSAKeyPair
    from gafaelfawr.models.token import TokenGroup
    from gafaelfawr.providers.github import GitHubUserInfo
    from gafaelfawr.tokens import Token as OldToken
    from gafaelfawr.tokens import VerifiedToken


class SetupTest:
    """Utility class for test setup.

    This class wraps creating a test FastAPI application, creating a factory
    for building the components, and accessing configuration settings.

    Notes
    -----
    This class is named SetupTest instead of TestSetup because pytest thinks
    the latter is a test case and tries to execute it.
    """

    @classmethod
    @asynccontextmanager
    async def create(
        cls, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> AsyncIterator[SetupTest]:
        """Create a new `SetupTest` instance.

        This is the only supported way to set up the test environment and
        should be called instead of calling the constructor directly.  It
        initializes and starts the application and configures an
        `httpx.AsyncClient` to talk to it.

        Parameters
        ----------
        tmp_path : `pathlib.Path`
            The path for temporary files.
        httpx_mock : `pytest_httpx.HTTPXMock`
            The mock for simulating `httpx.AsyncClient` calls.
        """
        database_url = "sqlite:///" + str(tmp_path / "gafaelfawr.sqlite")
        settings_path = build_settings(
            tmp_path, "github", database_url=database_url
        )
        config_dependency.set_settings_path(str(settings_path))
        config = config_dependency()
        initialize_database(config)
        redis_dependency.is_mocked = True
        redis = await redis_dependency(config)
        try:
            async with LifespanManager(app):
                base_url = f"https://{TEST_HOSTNAME}"
                async with AsyncClient(app=app, base_url=base_url) as client:
                    yield cls(
                        tmp_path=tmp_path,
                        httpx_mock=httpx_mock,
                        config=config,
                        redis=redis,
                        client=client,
                    )
        finally:
            await redis_dependency.close()

    def __init__(
        self,
        *,
        tmp_path: Path,
        httpx_mock: HTTPXMock,
        config: Config,
        redis: Redis,
        client: AsyncClient,
    ) -> None:
        self.tmp_path = tmp_path
        self.httpx_mock = httpx_mock
        self.config = config
        self.redis = redis
        self.client = client

    @property
    def factory(self) -> ComponentFactory:
        """Return a `~gafaelfawr.factory.ComponentFactory`.

        Build a new one each time to ensure that it picks up the current
        configuration information.

        Returns
        -------
        factory : `gafaelfawr.factory.ComponentFactory`
            Newly-created factory.
        """
        return ComponentFactory(
            config=self.config, redis=self.redis, http_client=self.client
        )

    async def add_session_token(
        self,
        *,
        username: str,
        created: datetime,
        name: str,
        uid: int,
        service: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
        groups: Optional[List[TokenGroup]] = None,
    ) -> Token:
        """Create a new token with associated data."""
        token = Token()
        data = TokenData(
            token=token,
            username=username,
            token_type=TokenType.session,
            service=service,
            scopes=scopes if scopes else [],
            created=created,
            expires=expires,
            name=name,
            uid=uid,
            groups=groups if groups else [],
        )
        token_manager = self.factory.create_token_manager()
        await token_manager.add(data)
        return token

    def configure(
        self,
        template: str = "github",
        *,
        database_url: Optional[str] = None,
        oidc_clients: Optional[List[OIDCClient]] = None,
        **settings: str,
    ) -> None:
        """Change the test application configuration.

        Parameters
        ----------
        template : `str`
            Settings template to use.
        database_url : `str`
            The URL to the database to use.
        oidc_clients : List[`gafaelfawr.config.OIDCClient`] or `None`
            Configuration information for clients of the OpenID Connect server.
        **settings : str
            Any additional settings to add to the settings file.
        """
        if not database_url:
            database_url = self.config.database_url
        settings_path = build_settings(
            self.tmp_path,
            template,
            oidc_clients,
            database_url=database_url,
            **settings,
        )
        config_dependency.set_settings_path(str(settings_path))
        self.config = config_dependency()

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
        self,
        *,
        kid: Optional[str] = None,
        groups: Optional[List[str]] = None,
        **claims: str,
    ) -> VerifiedToken:
        """Create a signed OpenID Connect token.

        Parameters
        ----------
        kid : `str`, optional
            Key ID for the token header.  Defaults to the first key in the
            key_ids configuration for the OpenID Connect provider.
        groups : List[`str`], optional
            Group memberships the generated token should have.
        **claims : `str`, optional
            Other claims to set or override in the token.

        Returns
        -------
        token : `gafaelfawr.tokens.VerifiedToken`
            The generated token.
        """
        if not kid:
            assert self.config.oidc
            kid = self.config.oidc.key_ids[0]
        return create_oidc_test_token(
            self.config, kid, groups=groups, **claims
        )

    async def github_login(self, userinfo: GitHubUserInfo) -> None:
        """Simulate a GitHub login and create a session.

        This method is used by tests to populate a valid session handle in the
        test client's cookie-based session so that other tests that require an
        existing authentication can be run.

        Parameters
        ----------
        userinfo : `gafaelfawr.providers.github.GitHubUserInfo`
            User information to use to synthesize GitHub API responses.
        """
        # Simulate the initial authentication request.
        self.set_github_token_response("some-code", "some-github-token")
        r = await self.client.get(
            "/login",
            params={"rd": "https://example.com"},
            allow_redirects=False,
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)

        # Simulate the return from GitHub, which will set the authentication
        # cookie.
        self.set_github_userinfo_response("some-github-token", userinfo)
        r = await self.client.get(
            "/login",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 307

    async def login(self, token: VerifiedToken) -> None:
        """Create a valid Gafaelfawr session cookie.

        Add a valid Gafaelfawr session cookie to the `httpx.AsyncClient`.

        Parameters
        ----------
        token : `gafaelfawr.tokens.VerifiedToken`
            The token for the client identity to use.
        """
        handle = SessionHandle()
        session = Session.create(handle, token)
        session_store = self.factory.create_session_store()
        await session_store.store_session(session)
        state = State(handle=handle)
        cookie = state.as_cookie()
        self.client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)

    def set_github_userinfo_response(
        self, token: str, userinfo: GitHubUserInfo
    ) -> None:
        """Set the GitHub user information to return from the GitHub API.

        Parameters
        ----------
        token : `str`
            The token that the client must send.
        userinfo : `gafaelfawr.providers.github.GitHubUserInfo`
            User information to use to synthesize GitHub API responses.
        """
        assert self.config.github

        def callback(request: Request, ext: Dict[str, Any]) -> Response:
            assert request.headers["Authorization"] == f"token {token}"
            assert request.method == "GET"
            if str(request.url) == GitHubProvider._USER_URL:
                return to_response(
                    json={
                        "login": userinfo.username,
                        "id": userinfo.uid,
                        "name": userinfo.name,
                    }
                )
            elif str(request.url) == GitHubProvider._TEAMS_URL:
                teams = []
                for team in userinfo.teams:
                    data = {
                        "slug": team.slug,
                        "id": team.gid,
                        "organization": {"login": team.organization},
                    }
                    teams.append(data)
                return to_response(json=teams)
            elif str(request.url) == GitHubProvider._EMAILS_URL:
                return to_response(
                    json=[
                        {"email": "otheremail@example.com", "primary": False},
                        {"email": userinfo.email, "primary": True},
                    ]
                )
            else:
                assert False, f"unexpected request for {request.url}"

        self.httpx_mock.add_callback(callback)

    def set_github_token_response(self, code: str, token: str) -> None:
        """Set the token that will be returned GitHub token endpoint.

        Parameters
        ----------
        code : `str`
            The code that Gafaelfawr must send.
        token : `str`
            The token to return, which will be expected by the user info
            endpoings.
        """

        def callback(request: Request, ext: Dict[str, Any]) -> Response:
            assert self.config.github
            assert str(request.url) == GitHubProvider._TOKEN_URL
            assert request.method == "POST"
            assert request.headers["Accept"] == "application/json"
            assert parse_qs(request.read().decode()) == {
                "client_id": [self.config.github.client_id],
                "client_secret": [self.config.github.client_secret],
                "code": [code],
                "state": [ANY],
            }
            return to_response(
                json={
                    "access_token": token,
                    "scope": ",".join(GitHubProvider._SCOPES),
                    "token_type": "bearer",
                }
            )

        self.httpx_mock.add_callback(callback)

    def set_oidc_configuration_response(
        self, keypair: RSAKeyPair, kid: Optional[str] = None
    ) -> None:
        """Register the callbacks for upstream signing key configuration.

        Parameters
        ----------
        keypair : `gafaelfawr.keypair.RSAKeyPair`
            The key pair used to sign the token, which will be used to
            register the keys callback.
        kid : `str`, optional
            Key ID for the key.  If not given, defaults to the first key ID in
            the configured key_ids list.
        """
        assert self.config.oidc
        iss = self.config.oidc.issuer
        config_url = urljoin(iss, "/.well-known/openid-configuration")
        jwks_url = urljoin(iss, "/jwks.json")
        oidc_kid = kid if kid else self.config.oidc.key_ids[0]
        jwks = keypair.public_key_as_jwks(oidc_kid)

        self.httpx_mock.add_response(
            url=config_url, method="GET", json={"jwks_uri": jwks_url}
        )
        self.httpx_mock.add_response(
            url=jwks_url, method="GET", json={"keys": [jwks]}
        )

    def set_oidc_token_response(self, code: str, token: OldToken) -> None:
        """Set the token that will be returned from the OIDC token endpoint.

        Parameters
        ----------
        code : `str`
            The code that Gafaelfawr must send.
        token : `gafaelfawr.tokens.Token`
            The token.
        """

        def callback(request: Request, ext: Dict[str, Any]) -> Response:
            assert self.config.oidc
            if str(request.url) != self.config.oidc.token_url:
                assert request.method == "GET"
                return to_response(status_code=404)
            assert request.method == "POST"
            assert request.headers["Accept"] == "application/json"
            assert parse_qs(request.read().decode()) == {
                "grant_type": ["authorization_code"],
                "client_id": [self.config.oidc.client_id],
                "client_secret": [self.config.oidc.client_secret],
                "code": [code],
                "redirect_uri": [self.config.oidc.redirect_url],
            }
            return to_response(
                json={"id_token": token.encoded, "token_type": "Bearer"}
            )

        self.httpx_mock.add_callback(callback)
