"""GitHub API mocks for testing."""

from __future__ import annotations

import base64
import json
import uuid
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs

from httpx import Response

from gafaelfawr.providers.github import GitHubProvider

if TYPE_CHECKING:
    from typing import Optional

    import respx
    from httpx import Request

    from gafaelfawr.config import GitHubConfig
    from gafaelfawr.providers.github import GitHubUserInfo

__all__ = ["mock_github"]


class MockGitHub:
    """Pretends to be the GitHub API for testing.

    The methods of this object should be installed as respx mock side effects
    using `mock_github`.

    Parameters
    ----------
    config : `gafaelfawr.config.GitHubConfig`
        Configuration of the GitHub provider.
    code : `str`
        The code that Gafaelfawr must send to redeem for a token.
    user_info : `gafaelfawr.providers.github.GitHubUserInfo`
        User information to use to synthesize GitHub API responses.
    paginate_teams : `bool`
        Whether to paginate the team results.
    expect_revoke : `bool`
        Whether to expect a revocation of the token after returning all user
        information.
    """

    def __init__(
        self,
        respx_mock: respx.Router,
        config: GitHubConfig,
        code: str,
        user_info: GitHubUserInfo,
        paginate_teams: bool,
        expect_revoke: bool,
    ) -> None:
        self.respx_mock = respx_mock
        self.config = config
        self.code = code
        self.token: Optional[str] = None
        self.user_info = user_info
        self.paginate_teams = paginate_teams
        self.expect_revoke = expect_revoke

    def delete_token(self, request: Request) -> Response:
        assert self.token, "Must obtain GitHub token first"
        assert request.headers["Accept"] == "application/json"
        basic_auth_raw = f"{self.config.client_id}:{self.config.client_secret}"
        basic_auth = base64.b64encode(basic_auth_raw.encode()).decode()
        assert request.headers["Authorization"] == f"Basic {basic_auth}"
        assert json.loads(request.read().decode()) == {
            "access_token": self.token
        }
        return Response(status_code=204)

    def get_emails(self, request: Request) -> Response:
        assert self.token, "Must obtain GitHub token first"
        assert request.headers["Authorization"] == f"token {self.token}"
        return Response(
            200,
            json=[
                {"email": "otheremail@example.com", "primary": False},
                {"email": self.user_info.email, "primary": True},
            ],
        )

    def get_teams(self, request: Request) -> Response:
        assert self.token, "Must obtain GitHub token first"
        assert request.headers["Authorization"] == f"token {self.token}"
        teams = [
            {
                "slug": t.slug,
                "id": t.gid,
                "organization": {"login": t.organization},
            }
            for t in self.user_info.teams
        ]

        # Determine if the next request should be a request to revoke the
        # token.
        if self.expect_revoke:
            if not self.paginate_teams or request.url.query == b"page=2":
                client_id = self.config.client_id
                url_template = GitHubProvider._GRANT_URL_TMPL
                grant_url = url_template.format(client_id=client_id)
                self.respx_mock.delete(grant_url).mock(
                    side_effect=self.delete_token
                )

        # Return the appropriate response.
        if self.paginate_teams:
            assert len(teams) > 2
            if request.url.query == b"page=2":
                link = f'<{GitHubProvider._TEAMS_URL}>; rel="prev"'
                return Response(200, json=teams[2:], headers={"Link": link})
            else:
                link = f'<{GitHubProvider._TEAMS_URL}?page=2>; rel="next"'
                return Response(200, json=teams[:2], headers={"Link": link})
        else:
            return Response(200, json=teams)

    def get_user(self, request: Request) -> Response:
        assert self.token, "Must obtain GitHub token first"
        assert request.headers["Authorization"] == f"token {self.token}"
        return Response(
            200,
            json={
                "login": self.user_info.username,
                "id": self.user_info.uid,
                "name": self.user_info.name,
            },
        )

    def post_token(self, request: Request) -> Response:
        assert request.headers["Accept"] == "application/json"
        assert parse_qs(request.read().decode()) == {
            "client_id": [self.config.client_id],
            "client_secret": [self.config.client_secret],
            "code": [self.code],
            "state": [ANY],
        }
        self.token = str(uuid.uuid4())
        return Response(
            200,
            json={
                "access_token": self.token,
                "scope": ",".join(GitHubProvider._SCOPES),
                "token_type": "bearer",
            },
        )


def mock_github(
    respx_mock: respx.Router,
    config: GitHubConfig,
    code: str,
    user_info: GitHubUserInfo,
    *,
    paginate_teams: bool = False,
    expect_revoke: bool = False,
) -> None:
    """Set up the mocks for a GitHub userinfo call.

    Parameters
    ----------
    respx_mock : `respx.Router`
        The mock router.
    config : `gafaelfawr.config.GitHubConfig`
        Configuration of the GitHub provider.
    code : `str`
        The code that Gafaelfawr must send to redeem a token.
    user_info : `gafaelfawr.providers.github.GitHubUserInfo`
        User information to use to synthesize GitHub API responses.
    paginate_teams : `bool`, optional
        Whether to paginate the team results.  Default: `False`
    expect_revoke : `bool`, optional
        Whether to expect a revocation of the token after returning all user
        information.  Default: `False`
    """
    mock = MockGitHub(
        respx_mock, config, code, user_info, paginate_teams, expect_revoke
    )
    token_url = GitHubProvider._TOKEN_URL
    respx_mock.post(token_url).mock(side_effect=mock.post_token)
    emails_url = GitHubProvider._EMAILS_URL
    respx_mock.get(emails_url).mock(side_effect=mock.get_emails)
    teams_url = GitHubProvider._TEAMS_URL
    respx_mock.get(url__startswith=teams_url).mock(side_effect=mock.get_teams)
    respx_mock.get(GitHubProvider._USER_URL).mock(side_effect=mock.get_user)