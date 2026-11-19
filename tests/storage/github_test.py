"""Tests for GitHub repository and owner lookups."""

import pytest
import respx
from httpx import Response

from gafaelfawr.constants import GITHUB_API_URL
from gafaelfawr.exceptions import (
    GitHubError,
    GitHubWebError,
    UnknownGitHubOwnerError,
    UnknownGitHubRepositoryError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.models.github import GitHubRepository
from gafaelfawr.models.github_project import GitHubOwner
from gafaelfawr.storage.github import GitHubStorage

from ..support.github import mock_github_owners, mock_github_repositories


@pytest.mark.asyncio
async def test_get_repository(
    factory: Factory, respx_mock: respx.Router
) -> None:
    storage = GitHubStorage(
        http_client=factory._context.http_client, logger=factory._logger
    )
    expected = GitHubRepository(
        full_name="lsst-sqre/SQR-062", id=123456, owner_id=654321
    )
    mock = mock_github_repositories(respx_mock, [expected])

    # The name as GitHub reports it is returned regardless of the case in
    # the request.
    assert await storage.get_repository("lsst-sqre/sqr-062") == expected
    assert await storage.get_repository("LSST-SQRE/SQR-062") == expected
    assert mock.requests == 2

    with pytest.raises(UnknownGitHubRepositoryError) as excinfo:
        await storage.get_repository("lsst-sqre/unknown")
    assert str(excinfo.value) == (
        "Repository lsst-sqre/unknown not found or not public"
    )


@pytest.mark.asyncio
async def test_get_repository_errors(
    factory: Factory, respx_mock: respx.Router
) -> None:
    storage = GitHubStorage(
        http_client=factory._context.http_client, logger=factory._logger
    )
    url = f"{GITHUB_API_URL}/repos/lsst-sqre/sqr-062"

    respx_mock.get(url).mock(return_value=Response(500))
    with pytest.raises(GitHubWebError):
        await storage.get_repository("lsst-sqre/sqr-062")

    respx_mock.get(url).mock(return_value=Response(200, json={"id": 1}))
    with pytest.raises(GitHubError):
        await storage.get_repository("lsst-sqre/sqr-062")

    respx_mock.get(url).mock(return_value=Response(200, text="not json"))
    with pytest.raises(GitHubError):
        await storage.get_repository("lsst-sqre/sqr-062")


@pytest.mark.asyncio
async def test_get_owner(factory: Factory, respx_mock: respx.Router) -> None:
    storage = GitHubStorage(
        http_client=factory._context.http_client, logger=factory._logger
    )
    expected = GitHubOwner(name="lsst-sqre", id=654321)
    mock = mock_github_owners(respx_mock, [expected])

    # The login as GitHub reports it is returned regardless of the case in
    # the request.
    assert await storage.get_owner("lsst-sqre") == expected
    assert await storage.get_owner("LSST-SQRE") == expected
    assert mock.requests == 2

    with pytest.raises(UnknownGitHubOwnerError) as excinfo:
        await storage.get_owner("lsst-unknown")
    assert str(excinfo.value) == "GitHub owner lsst-unknown not found"


@pytest.mark.asyncio
async def test_get_owner_errors(
    factory: Factory, respx_mock: respx.Router
) -> None:
    storage = GitHubStorage(
        http_client=factory._context.http_client, logger=factory._logger
    )
    url = f"{GITHUB_API_URL}/users/lsst-sqre"

    respx_mock.get(url).mock(return_value=Response(500))
    with pytest.raises(GitHubWebError):
        await storage.get_owner("lsst-sqre")

    respx_mock.get(url).mock(return_value=Response(200, json={"id": 1}))
    with pytest.raises(GitHubError):
        await storage.get_owner("lsst-sqre")

    respx_mock.get(url).mock(return_value=Response(200, text="not json"))
    with pytest.raises(GitHubError):
        await storage.get_owner("lsst-sqre")
