"""GitHub Actions ID token and OpenID Connect provider mocks for testing."""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import respx
from httpx import Request, Response

from gafaelfawr.constants import ALGORITHM, GITHUB_ACTIONS_ISSUER
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.keypair import RSAKeyPair

from .constants import TEST_KEYPAIR

__all__ = [
    "GITHUB_ACTIONS_CONFIG_URL",
    "GITHUB_ACTIONS_JWKS_URL",
    "MockGitHubActionsOIDC",
    "create_github_actions_jwt",
    "mock_github_actions_oidc",
]

GITHUB_ACTIONS_CONFIG_URL = (
    GITHUB_ACTIONS_ISSUER + "/.well-known/openid-configuration"
)
"""URL of the mocked GitHub Actions OpenID Connect configuration."""

GITHUB_ACTIONS_JWKS_URL = GITHUB_ACTIONS_ISSUER + "/.well-known/jwks"
"""URL of the mocked GitHub Actions JWKS (matches GitHub's real URL)."""


class MockGitHubActionsOIDC:
    """Mock of the GitHub Actions OpenID Connect provider metadata.

    The methods of this object should be installed as respx mock side effects
    using `mock_github_actions_oidc`. The key set can be changed between
    requests to simulate key rotation, and the number of requests to each
    endpoint is counted so that tests can check caching.

    Parameters
    ----------
    kid
        The key ID to return for the test key pair.
    """

    def __init__(self, kid: str) -> None:
        self.keypairs: dict[str, RSAKeyPair] = {kid: TEST_KEYPAIR}
        self.config_requests = 0
        self.jwks_requests = 0

    def get_config(self, request: Request) -> Response:
        self.config_requests += 1
        return Response(
            200,
            json={
                "issuer": GITHUB_ACTIONS_ISSUER,
                "jwks_uri": GITHUB_ACTIONS_JWKS_URL,
                "response_types_supported": ["id_token"],
                "id_token_signing_alg_values_supported": [ALGORITHM],
            },
        )

    def get_jwks(self, request: Request) -> Response:
        self.jwks_requests += 1
        keys: list[dict[str, Any]] = []
        for kid, keypair in self.keypairs.items():
            jwk = keypair.public_key_as_jwks(kid).keys[0].model_dump()
            keys.append({**jwk, "x5t": "ignored", "x5c": ["ignored"]})
        return Response(200, json={"keys": keys})


def mock_github_actions_oidc(
    respx_mock: respx.Router, kid: str = "github-kid"
) -> MockGitHubActionsOIDC:
    """Mock out the GitHub Actions OpenID Connect provider metadata.

    Parameters
    ----------
    respx_mock
        The mock router.
    kid
        The key ID to return for the test key pair.

    Returns
    -------
    MockGitHubActionsOIDC
        The mock, so that tests can adjust its key set and inspect request
        counts.
    """
    mock = MockGitHubActionsOIDC(kid)
    respx_mock.get(GITHUB_ACTIONS_CONFIG_URL).mock(side_effect=mock.get_config)
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).mock(side_effect=mock.get_jwks)
    return mock


def create_github_actions_jwt(
    *,
    repository: str = "lsst-sqre/ook",
    repository_id: int = 123456,
    repository_owner: str = "lsst-sqre",
    repository_owner_id: int = 654321,
    workflow: str = ".github/workflows/ci.yaml",
    ref: str = "refs/heads/main",
    environment: str | None = None,
    audience: str | None = None,
    issuer: str = GITHUB_ACTIONS_ISSUER,
    kid: str | None = "github-kid",
    keypair: RSAKeyPair = TEST_KEYPAIR,
    algorithm: str = ALGORITHM,
    lifetime: timedelta = timedelta(minutes=5),
    not_before: timedelta = timedelta(0),
    omit: set[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Create a signed ID token shaped like one from GitHub Actions.

    By default, the token matches the issuer and configured audience of the
    GitHub Actions token exchange and carries every claim that GitHub
    includes, with the numeric ID claims encoded as strings as GitHub does.

    Parameters
    ----------
    repository
        Full name of the repository.
    repository_id
        Numeric ID of the repository.
    repository_owner
        Login of the repository owner.
    repository_owner_id
        Numeric ID of the repository owner.
    workflow
        Path of the workflow file relative to the repository root, used to
        build the ``workflow_ref`` and ``job_workflow_ref`` claims.
    ref
        Git ref that triggered the run.
    environment
        GitHub Actions environment, if any.
    audience
        Audience claim. If not given, use the configured audience.
    issuer
        Issuer claim.
    kid
        Key ID for the token header, or `None` to omit it.
    keypair
        Key pair to sign the token with.
    algorithm
        Algorithm to sign the token with.
    lifetime
        How long after now the token expires.
    not_before
        How long after now the token becomes valid.
    omit
        Claims to leave out of the token.
    extra
        Additional claims to add, overriding any default claims.

    Returns
    -------
    str
        The encoded token.
    """
    if audience is None:
        config = config_dependency.config()
        assert config.github_token_exchange
        audience = config.github_token_exchange.audience

    now = datetime.now(tz=UTC).replace(microsecond=0)
    workflow_ref = f"{repository}/{workflow}@{ref}"
    if environment:
        sub = f"repo:{repository}:environment:{environment}"
    else:
        sub = f"repo:{repository}:ref:{ref}"
    payload: dict[str, Any] = {
        "jti": "0e3b4a6e-1c6f-4a8e-9c4a-7f1b5f2a3d4c",
        "sub": sub,
        "aud": audience,
        "ref": ref,
        "sha": "0123456789abcdef0123456789abcdef01234567",
        "repository": repository,
        "repository_owner": repository_owner,
        "repository_owner_id": str(repository_owner_id),
        "run_id": "9876543210",
        "run_number": "42",
        "run_attempt": "1",
        "repository_visibility": "public",
        "repository_id": str(repository_id),
        "actor_id": "1234",
        "actor": "someuser",
        "workflow": "CI",
        "head_ref": "",
        "base_ref": "",
        "event_name": "push",
        "ref_protected": "true",
        "ref_type": "branch",
        "workflow_ref": workflow_ref,
        "workflow_sha": "0123456789abcdef0123456789abcdef01234567",
        "job_workflow_ref": workflow_ref,
        "job_workflow_sha": "0123456789abcdef0123456789abcdef01234567",
        "runner_environment": "github-hosted",
        "iss": issuer,
        "nbf": int((now + not_before).timestamp()),
        "exp": int((now + not_before + lifetime).timestamp()),
        "iat": int((now + not_before).timestamp()),
    }
    if environment:
        payload["environment"] = environment
    if extra:
        payload.update(extra)
    for claim in omit or set():
        del payload[claim]

    headers: dict[str, Any] = {}
    if kid:
        headers["kid"] = kid
    return jwt.encode(
        payload,
        keypair.private_key_as_pem().decode(),
        algorithm=algorithm,
        headers=headers,
    )
