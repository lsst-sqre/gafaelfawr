"""Set up the test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY, Mock
from urllib.parse import urljoin

from aiohttp import ClientResponse
from cachetools import TTLCache

from gafaelfawr.factory import ComponentFactory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.session import Session, SessionHandle
from tests.support.tokens import create_oidc_test_token, create_test_token

if TYPE_CHECKING:
    from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

    from aiohttp import web
    from aiohttp.pytest_plugin.test_utils import TestClient
    from aioredis import Redis

    from gafaelfawr.config import Config
    from gafaelfawr.providers.github import GitHubUserInfo
    from gafaelfawr.tokens import Token, VerifiedToken
    from tests.support.http_session import MockClientSession


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
        self.redis: Redis = self.app["gafaelfawr/redis"]
        self.factory = ComponentFactory(
            config=self.config,
            redis=self.redis,
            key_cache=TTLCache(maxsize=16, ttl=600),
            http_session=self.app["safir/http_session"],
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

    @property
    def http_session(self) -> MockClientSession:
        """Return the mock ClientSession used for outbound calls."""
        return self.app["safir/http_session"]

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

        def user_handler(
            headers: Dict[str, str], raise_for_status: bool
        ) -> ClientResponse:
            assert headers == {"Authorization": f"token {token}"}
            assert raise_for_status
            response = {
                "login": userinfo.username,
                "id": userinfo.uid,
                "name": userinfo.name,
            }
            return self._build_json_response(response)

        def teams_handler(
            headers: Dict[str, str], raise_for_status: bool
        ) -> ClientResponse:
            assert headers == {"Authorization": f"token {token}"}
            assert raise_for_status
            response = []
            for team in userinfo.teams:
                data = {
                    "slug": team.slug,
                    "id": team.gid,
                    "organization": {"login": team.organization},
                }
                response.append(data)
            return self._build_json_response(response)

        def emails_handler(
            headers: Dict[str, str], raise_for_status: bool
        ) -> ClientResponse:
            assert headers == {"Authorization": f"token {token}"}
            assert raise_for_status
            response = [
                {"email": "otheremail@example.com", "primary": False},
                {"email": userinfo.email, "primary": True},
            ]
            return self._build_json_response(response)

        self.http_session.add_get_handler(
            GitHubProvider._USER_URL, user_handler
        )
        self.http_session.add_get_handler(
            GitHubProvider._TEAMS_URL, teams_handler
        )
        self.http_session.add_get_handler(
            GitHubProvider._EMAILS_URL, emails_handler
        )

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

        def handler(
            data: Dict[str, str],
            headers: Dict[str, str],
            raise_for_status: bool,
        ) -> ClientResponse:
            assert self.config.github
            assert raise_for_status
            assert headers == {"Accept": "application/json"}
            assert data == {
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
            return self._build_json_response(response)

        self.http_session.add_post_handler(GitHubProvider._TOKEN_URL, handler)

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

        def config_handler(
            headers: Dict[str, str], raise_for_status: bool
        ) -> ClientResponse:
            return self._build_json_response({"jwks_uri": jwks_url})

        def jwks_handler(
            headers: Dict[str, str], raise_for_status: bool
        ) -> ClientResponse:
            jwks = keypair.public_key_as_jwks(oidc_kid)
            return self._build_json_response({"keys": [jwks]})

        self.http_session.add_get_handler(config_url, config_handler)
        self.http_session.add_get_handler(jwks_url, jwks_handler)

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

        def handler(
            data: Dict[str, str],
            headers: Dict[str, str],
            raise_for_status: bool,
        ) -> ClientResponse:
            assert self.config.oidc
            assert headers == {"Accept": "application/json"}
            assert data == {
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
            return self._build_json_response(response)

        self.http_session.add_post_handler(self.config.oidc.token_url, handler)

    @staticmethod
    def _build_json_response(response: Any) -> ClientResponse:
        """Build a successful aiohttp client response."""
        r = Mock(spec=ClientResponse)
        r.json.return_value = response
        r.status = 200
        return r


# Type of the pytest fixture that builds the SetupTest object.
if TYPE_CHECKING:
    SetupTestCallable = Callable[..., Awaitable[SetupTest]]
