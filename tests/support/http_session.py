"""Mock aiohttp ClientSession for testing."""

from __future__ import annotations

import sys
from asyncio import Future
from typing import TYPE_CHECKING
from unittest.mock import ANY, Mock
from urllib.parse import urljoin

from aiohttp import ClientResponse, ClientSession

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.providers.github import GitHubProvider
from gafaelfawr.util import number_to_base64
from tests.support.tokens import create_oidc_test_token

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from typing import Any, Dict, List, Optional

__all__ = ["MockClientSession"]


class MockClientSession(Mock):
    """Mock `aiohttp.ClientSession`.

    Intercepts get and post calls and constructs return values based on test
    configuration data.

    Parameters
    ----------
    config : `tests.support.config.ConfigForTests`
        Test configuration used to determine the mocked responses.
    """

    def __init__(self) -> None:
        super().__init__(spec=ClientSession)
        self.config: Optional[Config] = None

    def set_config(self, config: Config) -> None:
        """Set the configuration, used to synthesize responses.

        This must be called before the session is used.

        Parameters
        ----------
        config : `gafaelfawr.config.Config`
            The application configuration.
        """
        self.config = config

    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = False,
    ) -> ClientResponse:
        """Mock retrieving a URL via GET.

        Parameters
        ----------
        url : `str`
            URL to retrieve.
        headers : Dict[`str`, `str`], optional
            Extra headers sent by the client.
        raise_for_status : `bool`, optional
            Whether to raise an exception for a status other than 200.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The mocked response, which implements status and json().
        """
        if url == GitHubProvider._USER_URL:
            assert headers == {"Authorization": "token some-github-token"}
            assert raise_for_status
            return self._build_json_response(self._github_user_data())
        elif url == GitHubProvider._TEAMS_URL:
            assert headers == {"Authorization": "token some-github-token"}
            assert raise_for_status
            return self._build_json_response(self._github_teams_data())
        elif url == GitHubProvider._EMAILS_URL:
            assert headers == {"Authorization": "token some-github-token"}
            assert raise_for_status
            return self._build_json_response(self._github_emails_data())
        elif url == self._openid_url():
            jwks_uri = "https://example.com/jwks.json"
            return self._build_json_response({"jwks_uri": jwks_uri})
        elif url == "https://example.com/jwks.json":
            return self._build_json_response(self._build_keys("orig-kid"))
        else:
            r = Mock(spec=ClientResponse)
            r.status = 404
            return r

    async def post(
        self,
        url: str,
        *,
        data: Dict[str, str],
        headers: Dict[str, str],
        raise_for_status: bool = False,
    ) -> ClientResponse:
        """Mock POST to a URL.

        Parameters
        ----------
        url : `str`
            URL to retrieve.
        data : Dict[`str`, `str`]
            Form data sent in the POST.
        headers : Dict[`str`, `str`]
            Extra headers sent by the client.
        raise_for_status : `bool`, optional
            Whether to raise an exception for a status other than 200.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The mocked response, which implements status and json().
        """
        assert self.config
        assert headers == {"Accept": "application/json"}
        if url == GitHubProvider._TOKEN_URL:
            assert raise_for_status
            return self._build_json_response(self._github_token_post(data))
        elif self.config.oidc and url == self.config.oidc.token_url:
            return self._build_json_response(self._oidc_token_post(data))
        else:
            r = Mock(spec=ClientResponse)
            r.status = 404
            return r

    @staticmethod
    def _build_json_response(result: Any) -> ClientResponse:
        """Build a successful aiohttp client response.

        This is more complicated than it will eventually need to be to work
        around the lack of an AsyncMock in Python 3.7.  The complexity can be
        removed when we require a minimum version of Python 3.8.
        """
        r = Mock(spec=ClientResponse)
        if sys.version_info[0] == 3 and sys.version_info[1] < 8:
            future: Future[Any] = Future()
            future.set_result(result)
            r.json.return_value = future
        else:
            r.json.return_value = result
        r.status = 200
        return r

    def _build_keys(self, kid: str) -> Dict[str, Any]:
        """Generate the JSON-encoded keys structure for a keypair."""
        assert self.config
        public_numbers = self.config.issuer.keypair.public_numbers()
        e = number_to_base64(public_numbers.e).decode()
        n = number_to_base64(public_numbers.n).decode()
        return {"keys": [{"alg": ALGORITHM, "e": e, "n": n, "kid": kid}]}

    def _github_user_data(self) -> Dict[str, Any]:
        """Return data for a GitHub user.

        Eventually this will be configurable.
        """
        return {
            "login": "githubuser",
            "id": 123456,
            "name": "GitHub User",
        }

    def _github_teams_data(self) -> List[Dict[str, Any]]:
        """Return teams data for a GitHub user.

        Eventually this will be configurable.
        """
        return [
            {"slug": "a-team", "id": 1000, "organization": {"login": "org"}},
            {
                "slug": "other-team",
                "id": 1001,
                "organization": {"login": "org"},
            },
            {
                "slug": "team-with-very-long-name",
                "id": 1002,
                "organization": {"login": "other-org"},
            },
        ]

    def _github_emails_data(self) -> List[Dict[str, Any]]:
        """Return emails data for a GitHub user.

        Eventually this will be configurable.
        """
        return [
            {"email": "otheremail@example.com", "primary": False},
            {"email": "githubuser@example.com", "primary": True},
        ]

    def _openid_url(self) -> str:
        """Return a OpenID Connect configuration retrieval URL.

        Returns
        -------
        url : `str`
            The well-known URL to the OpenID Connect configuration for that
            issuer.
        """
        base_url = "https://upstream.example.com/"
        return urljoin(base_url, "/.well-known/openid-configuration")

    def _github_token_post(self, data: Dict[str, str]) -> Dict[str, str]:
        """Handle a POST requesting a GitHub token.

        Check the provided data against our expectations and return the
        contents of the reply.
        """
        assert self.config
        assert self.config.github
        assert data == {
            "client_id": self.config.github.client_id,
            "client_secret": self.config.github.client_secret,
            "code": "some-code",
            "state": ANY,
        }
        return {
            "access_token": "some-github-token",
            "scope": ",".join(GitHubProvider._SCOPES),
            "token_type": "bearer",
        }

    def _oidc_token_post(self, data: Dict[str, str]) -> Dict[str, str]:
        """Handle a POST to get an ID token from OpenID Connect.

        Check the provided data against our expectations and return the
        contents of the reply.
        """
        assert self.config
        assert self.config.oidc
        assert data == {
            "grant_type": "authorization_code",
            "client_id": self.config.oidc.client_id,
            "client_secret": self.config.oidc.client_secret,
            "code": "some-code",
            "redirect_uri": self.config.oidc.redirect_url,
        }
        token = create_oidc_test_token(self.config, groups=["admin"])
        return {
            "id_token": token.encoded,
            "token_type": "Bearer",
        }
