"""Set up the test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

from aiohttp import ClientSession
from aioresponses import CallbackResult
from cachetools import TTLCache

from gafaelfawr.factory import ComponentFactory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.session import Session, SessionHandle
from tests.support.tokens import create_oidc_test_token, create_test_token

if TYPE_CHECKING:
    from typing import Any, Awaitable, Callable, List, Optional, Union

    from aiohttp import web
    from aiohttp.pytest_plugin.test_utils import TestClient
    from aioredis import Redis
    from aioresponses import aioresponses

    from gafaelfawr.config import Config
    from gafaelfawr.providers.github import GitHubUserInfo
    from gafaelfawr.tokens import Token, VerifiedToken


class SetupTest:
    """Utility class for test setup.

    This class wraps creating a test aiohttp application, creating a factory
    for building the JWT Authorizer components, and accessing configuration
    settings.
    """

    def __init__(
        self,
        app: web.Application,
        responses: aioresponses,
        client: Optional[TestClient] = None,
    ) -> None:
        self.app = app
        self.responses = responses
        self._client = client
        self.config: Config = self.app["gafaelfawr/config"]
        self.redis: Redis = self.app["gafaelfawr/redis"]
        self.factory = ComponentFactory(
            config=self.config,
            redis=self.redis,
            key_cache=TTLCache(maxsize=16, ttl=600),
            http_session=ClientSession(),
        )

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
        self.set_github_token_response("some-code", "some-github-token")
        self.set_github_userinfo_response("some-github-token", userinfo)

        # Simulate the initial authentication request.
        r = await self.client.get(
            "/login",
            params={"rd": f"https://{self.client.host}"},
            allow_redirects=False,
        )
        assert r.status == 303
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)

        # Simulate the return from GitHub, which will set the authentication
        # cookie.
        r = await self.client.get(
            "/login",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status == 303

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

        def user_handler(url: str, **kwargs: Any) -> CallbackResult:
            assert kwargs["headers"] == {"Authorization": f"token {token}"}
            response = {
                "login": userinfo.username,
                "id": userinfo.uid,
                "name": userinfo.name,
            }
            return CallbackResult(payload=response, status=200)

        def teams_handler(url: str, **kwargs: Any) -> CallbackResult:
            assert kwargs["headers"] == {"Authorization": f"token {token}"}
            response = []
            for team in userinfo.teams:
                data = {
                    "slug": team.slug,
                    "id": team.gid,
                    "organization": {"login": team.organization},
                }
                response.append(data)
            return CallbackResult(payload=response, status=200)

        def emails_handler(url: str, **kwargs: Any) -> CallbackResult:
            assert kwargs["headers"] == {"Authorization": f"token {token}"}
            response = [
                {"email": "otheremail@example.com", "primary": False},
                {"email": userinfo.email, "primary": True},
            ]
            return CallbackResult(payload=response, status=200)

        self.responses.get(GitHubProvider._USER_URL, callback=user_handler)
        self.responses.get(GitHubProvider._TEAMS_URL, callback=teams_handler)
        self.responses.get(GitHubProvider._EMAILS_URL, callback=emails_handler)

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
        assert self.config.github

        def handler(url: str, **kwargs: Any) -> CallbackResult:
            assert self.config.github
            assert kwargs["headers"] == {"Accept": "application/json"}
            assert kwargs["data"] == {
                "client_id": self.config.github.client_id,
                "client_secret": self.config.github.client_secret,
                "code": code,
                "state": ANY,
            }
            response = {
                "access_token": token,
                "scope": ",".join(GitHubProvider._SCOPES),
                "token_type": "bearer",
            }
            return CallbackResult(payload=response, status=200)

        self.responses.post(GitHubProvider._TOKEN_URL, callback=handler)

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

        self.responses.get(config_url, payload={"jwks_uri": jwks_url})
        self.responses.get(jwks_url, payload={"keys": [jwks]})

    def set_oidc_token_response(self, code: str, token: Token) -> None:
        """Set the token that will be returned from the OIDC token endpoint.

        Parameters
        ----------
        code : `str`
            The code that Gafaelfawr must send.
        token : `gafaelfawr.tokens.Token`
            The token.
        """
        assert self.config.oidc

        def handler(url: str, **kwargs: Any) -> CallbackResult:
            assert self.config.oidc
            assert kwargs["headers"] == {"Accept": "application/json"}
            assert kwargs["data"] == {
                "grant_type": "authorization_code",
                "client_id": self.config.oidc.client_id,
                "client_secret": self.config.oidc.client_secret,
                "code": code,
                "redirect_uri": self.config.oidc.redirect_url,
            }
            response = {
                "id_token": token.encoded,
                "token_type": "Bearer",
            }
            return CallbackResult(payload=response, status=200)

        self.responses.post(self.config.oidc.token_url, callback=handler)


# Type of the pytest fixture that builds the SetupTest object.
if TYPE_CHECKING:
    SetupTestCallable = Callable[..., Awaitable[SetupTest]]
