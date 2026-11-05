"""Tests for the GitHub Actions token exchange."""

from datetime import timedelta
from typing import Any
from unittest.mock import ANY

import pytest
import respx
from httpx import AsyncClient
from safir.metrics import MockEventPublisher
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.constants import (
    GITHUB_ACTIONS_ISSUER,
    OAUTH_ACCESS_TOKEN_TYPE,
    OAUTH_ID_TOKEN_TYPE,
    OAUTH_TOKEN_EXCHANGE_GRANT_TYPE,
)
from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.enums import TokenChange, TokenType
from gafaelfawr.models.github import GitHubRepository
from gafaelfawr.models.github_project import GitHubProject, GitHubProjectCreate
from gafaelfawr.models.token import Token
from gafaelfawr.models.userinfo import Group
from gafaelfawr.storage.github_project import GitHubProjectStore

from ..support.github import mock_github_repositories
from ..support.github_actions import (
    GITHUB_ACTIONS_CONFIG_URL,
    GITHUB_ACTIONS_JWKS_URL,
    create_github_actions_jwt,
    mock_github_actions_oidc,
)
from ..support.tokens import create_session_token

URL = "/auth/api/v1/github/token"

# The repository, IDs, and owner match the defaults of
# create_github_actions_jwt, so a default token comes from this repository.
OOK = GitHubRepository(full_name="lsst-sqre/ook", id=123456, owner_id=654321)
SQR_062 = GitHubRepository(
    full_name="lsst-sqre/sqr-062", id=234567, owner_id=654321
)
DOCS = GitHubRepository(full_name="lsst-sqre/docs", id=345678, owner_id=654321)


def exchange_request(
    token: str, *, scope: str | None = None, **extra: str
) -> dict[str, str]:
    """Build the form body of a token exchange request."""
    data = {
        "grant_type": OAUTH_TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": token,
        "subject_token_type": OAUTH_ID_TOKEN_TYPE,
    }
    if scope is not None:
        data["scope"] = scope
    data.update(extra)
    return data


async def register_project(
    factory: Factory, repository: GitHubRepository, **fields: Any
) -> GitHubProject:
    """Register a GitHub project through the registry service."""
    admin = await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )
    service = factory.create_github_project_service()
    fields.setdefault("scopes", {"read:all"})
    create = GitHubProjectCreate(repository=repository.full_name, **fields)
    return await service.create_project(create, admin, ip_address="127.0.0.1")


def published_exchanges() -> MockEventPublisher:
    """Return the mock publisher of token exchange events."""
    events = context_dependency._events
    assert events
    assert isinstance(events.github_token_exchange, MockEventPublisher)
    return events.github_token_exchange


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_exchange(
    client: AsyncClient, factory: Factory, respx_mock: respx.Router
) -> None:
    mock_github_repositories(respx_mock, [OOK])
    mock = mock_github_actions_oidc(respx_mock)
    project = await register_project(
        factory,
        OOK,
        workflow=".github/workflows/ci.yaml",
        ref="refs/heads/main",
        scopes={"read:all", "exec:test"},
        max_lifetime=timedelta(minutes=15),
        uid=2000,
        gid=3000,
        groups=[Group(name="bots", id=4000)],
    )

    # Exchange a token without requesting scopes, which grants every scope
    # of the project.
    id_token = create_github_actions_jwt()
    r = await client.post(URL, data=exchange_request(id_token))
    assert r.status_code == 200
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["Pragma"] == "no-cache"
    reply = r.json()
    assert reply == {
        "access_token": ANY,
        "issued_token_type": OAUTH_ACCESS_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": ANY,
        "scope": "exec:test read:all",
    }
    assert 15 * 60 - 5 <= reply["expires_in"] <= 15 * 60
    token = Token.from_str(reply["access_token"])
    assert mock.jwks_requests == 1

    # The minted token is a github token for the project's bot user,
    # carries the project's identity attributes, and records the project.
    headers = {"Authorization": f"Bearer {token}"}
    r = await client.get("/auth/api/v1/token-info", headers=headers)
    assert r.status_code == 200
    info = r.json()
    assert info == {
        "token": token.key,
        "username": "bot-gh-lsst-sqre-ook",
        "token_type": "github",
        "scopes": ["exec:test", "read:all"],
        "created": ANY,
        "expires": ANY,
        "github_project_id": project.id,
    }
    assert info["expires"] - info["created"] == 15 * 60
    r = await client.get("/auth/api/v1/user-info", headers=headers)
    assert r.status_code == 200
    assert r.json() == {
        "username": "bot-gh-lsst-sqre-ook",
        "uid": 2000,
        "gid": 3000,
        "groups": [{"name": "bots", "id": 4000}],
    }

    # The creation is recorded in the token change history with the bot
    # user as the actor, the runner's address, and the project.
    admin = await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )
    token_service = factory.create_token_service()
    history = await token_service.get_change_history(
        admin, token_type=TokenType.github
    )
    assert len(history.entries) == 1
    assert history.entries[0].model_dump(mode="json") == {
        "token": token.key,
        "username": "bot-gh-lsst-sqre-ook",
        "token_type": "github",
        "token_name": None,
        "parent": None,
        "scopes": ["exec:test", "read:all"],
        "service": None,
        "expires": ANY,
        "actor": "bot-gh-lsst-sqre-ook",
        "action": TokenChange.create.value,
        "old_token_name": None,
        "old_scopes": None,
        "old_expires": None,
        "ip_address": "127.0.0.1",
        "event_time": ANY,
        "github_project_id": project.id,
    }

    # The exchange is recorded as a metrics event tying the token to the
    # workflow run.
    published_exchanges().published.assert_published_all(
        [
            {
                "username": "bot-gh-lsst-sqre-ook",
                "github_project_id": project.id,
                "token": token.key,
                "repository": "lsst-sqre/ook",
                "job_workflow_ref": (
                    "lsst-sqre/ook/.github/workflows/ci.yaml@refs/heads/main"
                ),
                "ref": "refs/heads/main",
                "environment": None,
                "event_name": "push",
                "actor": "someuser",
                "run_id": "9876543210",
                "run_attempt": "1",
                "jti": "0e3b4a6e-1c6f-4a8e-9c4a-7f1b5f2a3d4c",
            }
        ]
    )

    # Requesting a subset of the project's scopes narrows the token. The
    # cached keys are reused, and the repository name is matched
    # case-insensitively.
    id_token = create_github_actions_jwt(repository="LSST-SQRE/Ook")
    r = await client.post(
        URL, data=exchange_request(id_token, scope="read:all")
    )
    assert r.status_code == 200
    assert r.json()["scope"] == "read:all"
    token = Token.from_str(r.json()["access_token"])
    headers = {"Authorization": f"Bearer {token}"}
    r = await client.get("/auth/api/v1/token-info", headers=headers)
    assert r.status_code == 200
    assert r.json()["scopes"] == ["read:all"]
    assert mock.jwks_requests == 1


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_scope_errors(
    client: AsyncClient, factory: Factory, respx_mock: respx.Router
) -> None:
    mock_github_repositories(respx_mock, [OOK])
    mock_github_actions_oidc(respx_mock)
    await register_project(factory, OOK, scopes={"read:all", "exec:test"})
    id_token = create_github_actions_jwt()

    # Scopes outside the project's scopes are refused rather than silently
    # narrowed. Only the refused scopes are named, not the project's.
    for scope in ("read:some", "read:all read:some", "exec:admin unknown"):
        r = await client.post(
            URL, data=exchange_request(id_token, scope=scope)
        )
        assert r.status_code == 400
        refused = " ".join(sorted(set(scope.split()) - {"read:all"}))
        assert r.json() == {
            "error": "invalid_scope",
            "error_description": (
                f"Requested scopes not allowed for this workflow: {refused}"
            ),
        }

    # A scope with no scope tokens is a malformed request rather than a
    # request for the full scope list. An empty scope parameter cannot be
    # told apart from an omitted one, since FastAPI treats empty form
    # fields as absent, and so grants the full scope list.
    r = await client.post(URL, data=exchange_request(id_token, scope="  "))
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_request",
        "error_description": "Empty scope parameter",
    }
    published_exchanges().published.assert_published_all([])
    r = await client.post(URL, data=exchange_request(id_token, scope=""))
    assert r.status_code == 200
    assert r.json()["scope"] == "exec:test read:all"


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_request_errors(
    client: AsyncClient, factory: Factory, respx_mock: respx.Router
) -> None:
    mock_github_repositories(respx_mock, [OOK])
    mock = mock_github_actions_oidc(respx_mock)
    await register_project(factory, OOK)
    id_token = create_github_actions_jwt()

    # An empty request, and a JSON body rather than a form.
    r = await client.post(URL)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_request",
        "error_description": "Missing grant_type parameter",
    }
    r = await client.post(URL, json=exchange_request(id_token))
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"

    # Exactly one grant type and subject token type are supported.
    data = exchange_request(id_token, grant_type="authorization_code")
    r = await client.post(URL, data=data)
    assert r.status_code == 400
    assert r.json() == {
        "error": "unsupported_grant_type",
        "error_description": (
            "Unsupported grant type authorization_code, must be"
            f" {OAUTH_TOKEN_EXCHANGE_GRANT_TYPE}"
        ),
    }
    data = exchange_request(
        id_token, subject_token_type=OAUTH_ACCESS_TOKEN_TYPE
    )
    r = await client.post(URL, data=data)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_request",
        "error_description": (
            f"Unsupported subject token type {OAUTH_ACCESS_TOKEN_TYPE}, must"
            f" be {OAUTH_ID_TOKEN_TYPE}"
        ),
    }

    # Each required parameter is checked.
    for missing in ("grant_type", "subject_token_type", "subject_token"):
        data = exchange_request(id_token)
        del data[missing]
        r = await client.post(URL, data=data)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_request",
            "error_description": f"Missing {missing} parameter",
        }
        data[missing] = ""
        r = await client.post(URL, data=data)
        assert r.status_code == 400
        assert r.json()["error_description"] == f"Missing {missing} parameter"

    # RFC 8693 parameters that the endpoint does not support are rejected
    # rather than ignored.
    for param in (
        "resource",
        "audience",
        "requested_token_type",
        "actor_token",
        "actor_token_type",
    ):
        data = exchange_request(id_token, **{param: "something"})
        r = await client.post(URL, data=data)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_request",
            "error_description": f"Unsupported parameters: {param}",
        }
    data = exchange_request(id_token, actor_token="x", actor_token_type="y")
    r = await client.post(URL, data=data)
    assert r.status_code == 400
    assert r.json()["error_description"] == (
        "Unsupported parameters: actor_token, actor_token_type"
    )

    # Unrecognized parameters are ignored, as OAuth 2.0 requires.
    r = await client.post(URL, data=exchange_request(id_token, foo="bar"))
    assert r.status_code == 200

    # None of the rejected requests went as far as verifying the token.
    assert mock.jwks_requests == 1
    assert len(published_exchanges().published) == 1


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_verification_errors(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    respx_mock: respx.Router,
) -> None:
    assert config.github_token_exchange
    audience = config.github_token_exchange.audience
    mock_github_repositories(respx_mock, [OOK])
    mock_github_actions_oidc(respx_mock)
    await register_project(factory, OOK)

    async def assert_rejected(id_token: str, description: str) -> None:
        r = await client.post(URL, data=exchange_request(id_token))
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": description,
        }

    # The audience and issuer errors report the value the token carried,
    # since a wrong audience is the most likely mistake of a workflow
    # author and the value is theirs to read.
    await assert_rejected(
        create_github_actions_jwt(audience="https://other.example.com"),
        "Token audience https://other.example.com does not match the"
        f" expected audience {audience}",
    )
    await assert_rejected(
        create_github_actions_jwt(issuer="https://issuer.example.com"),
        "Token issuer https://issuer.example.com is not the GitHub Actions"
        f" issuer {GITHUB_ACTIONS_ISSUER}",
    )

    # Validity window.
    await assert_rejected(
        create_github_actions_jwt(lifetime=timedelta(minutes=-1)),
        "Token has expired",
    )
    await assert_rejected(
        create_github_actions_jwt(not_before=timedelta(minutes=5)),
        "Token is not yet valid",
    )

    # Signature, key, and algorithm problems.
    await assert_rejected(
        create_github_actions_jwt(keypair=RSAKeyPair.generate()),
        "Token failed verification: Signature verification failed",
    )
    await assert_rejected(
        create_github_actions_jwt(kid="other-kid"),
        "GitHub Actions has no kid other-kid",
    )
    await assert_rejected(
        create_github_actions_jwt(kid=None), "No kid in token header"
    )
    await assert_rejected(
        create_github_actions_jwt(algorithm="RS512"),
        "Token algorithm RS512 not RS256",
    )

    # Missing or malformed claims, and a subject token that is not a JWT.
    await assert_rejected(
        create_github_actions_jwt(omit={"repository_id"}),
        "Invalid or missing claims in token: repository_id",
    )
    await assert_rejected(
        create_github_actions_jwt(extra={"repository_owner_id": "abc"}),
        "Invalid or missing claims in token: repository_owner_id",
    )
    await assert_rejected(
        "not-a-jwt", "Token failed verification: Not enough segments"
    )

    published_exchanges().published.assert_published_all([])


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_matching(
    client: AsyncClient, factory: Factory, respx_mock: respx.Router
) -> None:
    mock_github_repositories(respx_mock, [OOK, SQR_062, DOCS])
    mock_github_actions_oidc(respx_mock)

    # Disjoint projects for one repository: the CI workflow on the default
    # branch, any workflow on a tag, and a reusable workflow from another
    # repository on a release branch. A second repository is constrained
    # only by environment, and a third is registered but disabled.
    main = await register_project(
        factory,
        OOK,
        workflow=".github/workflows/ci.yaml",
        ref="refs/heads/main",
        scopes={"read:all"},
    )
    tags = await register_project(
        factory, OOK, ref="refs/tags/", scopes={"read:some"}
    )
    reusable = await register_project(
        factory,
        OOK,
        workflow="lsst/sqre-docs/.github/workflows/build.yaml",
        ref="refs/heads/release/",
        scopes={"exec:test"},
    )
    production = await register_project(
        factory, SQR_062, environment="production", scopes={"read:all"}
    )
    await register_project(factory, DOCS, scopes={"read:all"}, enabled=False)

    async def assert_matches(id_token: str, project: GitHubProject) -> None:
        r = await client.post(URL, data=exchange_request(id_token))
        assert r.status_code == 200
        assert r.json()["scope"] == " ".join(sorted(project.scopes))
        token = Token.from_str(r.json()["access_token"])
        headers = {"Authorization": f"Bearer {token}"}
        r = await client.get("/auth/api/v1/token-info", headers=headers)
        assert r.status_code == 200
        assert r.json()["github_project_id"] == project.id
        assert r.json()["username"] == project.username

    async def assert_no_match(id_token: str, claims: str) -> None:
        r = await client.post(URL, data=exchange_request(id_token))
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": (
                f"No enabled GitHub project matches {claims}"
            ),
        }

    # Exact workflow and ref.
    await assert_matches(create_github_actions_jwt(), main)
    await assert_no_match(
        create_github_actions_jwt(workflow=".github/workflows/docs.yaml"),
        "repository lsst-sqre/ook (ID 123456, owner ID 654321), workflow"
        " lsst-sqre/ook/.github/workflows/docs.yaml@refs/heads/main, ref"
        " refs/heads/main, environment (none)",
    )
    await assert_no_match(
        create_github_actions_jwt(ref="refs/pull/42/merge"),
        "repository lsst-sqre/ook (ID 123456, owner ID 654321), workflow"
        " lsst-sqre/ook/.github/workflows/ci.yaml@refs/pull/42/merge, ref"
        " refs/pull/42/merge, environment (none)",
    )

    # Ref prefix, with any workflow.
    await assert_matches(
        create_github_actions_jwt(
            workflow=".github/workflows/release.yaml", ref="refs/tags/v1.0.0"
        ),
        tags,
    )
    await assert_no_match(
        create_github_actions_jwt(ref="refs/tags"),
        "repository lsst-sqre/ook (ID 123456, owner ID 654321), workflow"
        " lsst-sqre/ook/.github/workflows/ci.yaml@refs/tags, ref refs/tags,"
        " environment (none)",
    )

    # A reusable workflow in another repository, named by the
    # job_workflow_ref claim while the repository claim is the caller's.
    # The repository part of the workflow is matched case-insensitively.
    job_workflow_ref = (
        "LSST/SQRE-Docs/.github/workflows/build.yaml@refs/heads/main"
    )
    await assert_matches(
        create_github_actions_jwt(
            ref="refs/heads/release/1.0",
            extra={"job_workflow_ref": job_workflow_ref},
        ),
        reusable,
    )

    # Pinned repository IDs: the same name with a different repository or
    # owner ID is not the same repository.
    await assert_no_match(
        create_github_actions_jwt(repository_id=999999),
        "repository lsst-sqre/ook (ID 999999, owner ID 654321), workflow"
        " lsst-sqre/ook/.github/workflows/ci.yaml@refs/heads/main, ref"
        " refs/heads/main, environment (none)",
    )
    await assert_no_match(
        create_github_actions_jwt(repository_owner_id=999999),
        "repository lsst-sqre/ook (ID 123456, owner ID 999999), workflow"
        " lsst-sqre/ook/.github/workflows/ci.yaml@refs/heads/main, ref"
        " refs/heads/main, environment (none)",
    )

    # Environment.
    sqr_062: dict[str, Any] = {
        "repository": SQR_062.full_name,
        "repository_id": SQR_062.id,
        "repository_owner_id": SQR_062.owner_id,
    }
    await assert_matches(
        create_github_actions_jwt(environment="production", **sqr_062),
        production,
    )
    await assert_no_match(
        create_github_actions_jwt(environment="staging", **sqr_062),
        "repository lsst-sqre/sqr-062 (ID 234567, owner ID 654321),"
        " workflow lsst-sqre/sqr-062/.github/workflows/ci.yaml@refs/heads/"
        "main, ref refs/heads/main, environment staging",
    )
    await assert_no_match(
        create_github_actions_jwt(**sqr_062),
        "repository lsst-sqre/sqr-062 (ID 234567, owner ID 654321),"
        " workflow lsst-sqre/sqr-062/.github/workflows/ci.yaml@refs/heads/"
        "main, ref refs/heads/main, environment (none)",
    )

    # A disabled project and an unregistered repository never match.
    await assert_no_match(
        create_github_actions_jwt(
            repository=DOCS.full_name,
            repository_id=DOCS.id,
            repository_owner_id=DOCS.owner_id,
        ),
        "repository lsst-sqre/docs (ID 345678, owner ID 654321), workflow"
        " lsst-sqre/docs/.github/workflows/ci.yaml@refs/heads/main, ref"
        " refs/heads/main, environment (none)",
    )
    await assert_no_match(
        create_github_actions_jwt(
            repository="lsst-sqre/other", repository_id=456789
        ),
        "repository lsst-sqre/other (ID 456789, owner ID 654321), workflow"
        " lsst-sqre/other/.github/workflows/ci.yaml@refs/heads/main, ref"
        " refs/heads/main, environment (none)",
    )


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_multiple_matches(
    client: AsyncClient, factory: Factory, respx_mock: respx.Router
) -> None:
    """Overlapping enabled projects are refused rather than picked from.

    The registry service refuses to create or enable overlapping projects,
    so the second project is created disabled and then enabled beneath the
    service.
    """
    mock_github_repositories(respx_mock, [OOK])
    mock_github_actions_oidc(respx_mock)
    await register_project(factory, OOK, ref="refs/heads/main")
    broad = await register_project(factory, OOK, enabled=False)
    store = GitHubProjectStore(factory.session)
    async with factory.session.begin():
        await store.update(broad.model_copy(update={"enabled": True}))

    r = await client.post(
        URL, data=exchange_request(create_github_actions_jwt())
    )
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": (
            "Multiple GitHub projects match this token, which is a registry"
            " misconfiguration; contact an administrator"
        ),
    }
    published_exchanges().published.assert_published_all([])


@pytest.mark.parametrize(
    "config", ["github-token-exchange-short-lifetime"], indirect=True
)
@pytest.mark.asyncio
async def test_lifetime_cap(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    respx_mock: respx.Router,
) -> None:
    """The configured maximum lifetime caps the project's lifetime.

    The registry service refuses a project lifetime above the configured
    maximum, so this simulates the configuration having been lowered after
    registration by changing the stored project beneath the service.
    """
    assert config.github_token_exchange
    assert config.github_token_exchange.max_lifetime == timedelta(minutes=30)
    mock_github_repositories(respx_mock, [OOK])
    mock_github_actions_oidc(respx_mock)
    project = await register_project(factory, OOK)
    store = GitHubProjectStore(factory.session)
    async with factory.session.begin():
        await store.update(
            project.model_copy(update={"max_lifetime": timedelta(hours=2)})
        )

    r = await client.post(
        URL, data=exchange_request(create_github_actions_jwt())
    )
    assert r.status_code == 200
    assert 30 * 60 - 5 <= r.json()["expires_in"] <= 30 * 60


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_keys_unavailable(
    client: AsyncClient,
    factory: Factory,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    mock_github_repositories(respx_mock, [OOK])
    await register_project(factory, OOK)
    id_token = create_github_actions_jwt()
    expected = {
        "error": "temporarily_unavailable",
        "error_description": (
            "Unable to retrieve GitHub Actions signing keys, retry later"
        ),
    }

    # GitHub's OpenID Connect configuration cannot be retrieved.
    respx_mock.get(GITHUB_ACTIONS_CONFIG_URL).respond(500)
    r = await client.post(URL, data=exchange_request(id_token))
    assert r.status_code == 502
    assert r.json() == expected
    assert len(mock_slack.messages) == 1

    # The key set is malformed.
    respx_mock.get(GITHUB_ACTIONS_CONFIG_URL).respond(
        json={"jwks_uri": GITHUB_ACTIONS_JWKS_URL}
    )
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).respond(json={"keys": []})
    r = await client.post(URL, data=exchange_request(id_token))
    assert r.status_code == 502
    assert r.json() == expected
    assert len(mock_slack.messages) == 2

    published_exchanges().published.assert_published_all([])


@pytest.mark.asyncio
async def test_not_configured(client: AsyncClient, config: Config) -> None:
    assert not config.github_token_exchange
    id_token = create_github_actions_jwt(audience="https://example.com")
    r = await client.post(URL, data=exchange_request(id_token))
    assert r.status_code == 404
    assert r.json()["detail"][0]["type"] == "not_supported"
