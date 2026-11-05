"""Tests for verification of GitHub Actions ID tokens."""

from datetime import timedelta

import pytest
import respx
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    MissingRequiredClaimError,
)

from gafaelfawr.config import Config
from gafaelfawr.exceptions import (
    FetchKeysError,
    GitHubWebError,
    InvalidTokenClaimsError,
    NotConfiguredError,
    UnknownAlgorithmError,
    UnknownKeyIdError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.keypair import RSAKeyPair

from ..support.constants import TEST_KEYPAIR
from ..support.github_actions import (
    GITHUB_ACTIONS_CONFIG_URL,
    GITHUB_ACTIONS_JWKS_URL,
    create_github_actions_jwt,
    mock_github_actions_oidc,
)


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_verify_token(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    assert config.github_token_exchange
    verifier = factory.create_github_actions_token_verifier()
    mock = mock_github_actions_oidc(respx_mock)

    token = create_github_actions_jwt(environment="production")
    claims = await verifier.verify_token(token)
    assert claims.sub == "repo:lsst-sqre/ook:environment:production"
    assert claims.repository == "lsst-sqre/ook"
    assert claims.repository_id == 123456
    assert claims.repository_owner == "lsst-sqre"
    assert claims.repository_owner_id == 654321
    assert claims.job_workflow_ref == (
        "lsst-sqre/ook/.github/workflows/ci.yaml@refs/heads/main"
    )
    assert claims.workflow_ref == claims.job_workflow_ref
    assert claims.ref == "refs/heads/main"
    assert claims.environment == "production"
    assert claims.event_name == "push"
    assert claims.actor == "someuser"
    assert claims.run_id == "9876543210"
    assert claims.run_attempt == "1"
    assert claims.jti
    assert claims.workflow_sha
    assert mock.config_requests == 1
    assert mock.jwks_requests == 1

    # A job that doesn't use an environment has no environment claim.
    token = create_github_actions_jwt()
    claims = await verifier.verify_token(token)
    assert claims.sub == "repo:lsst-sqre/ook:ref:refs/heads/main"
    assert claims.environment is None

    # Missing audit claims are tolerated, but not missing registry claims.
    token = create_github_actions_jwt(omit={"event_name", "actor", "run_id"})
    claims = await verifier.verify_token(token)
    assert claims.event_name is None
    token = create_github_actions_jwt(omit={"repository_id", "ref"})
    with pytest.raises(InvalidTokenClaimsError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == (
        "Invalid or missing claims in token: repository_id, ref"
    )
    token = create_github_actions_jwt(extra={"repository_owner_id": "abc"})
    with pytest.raises(InvalidTokenClaimsError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == (
        "Invalid or missing claims in token: repository_owner_id"
    )

    # The keys were cached across all of those verifications.
    assert mock.config_requests == 1
    assert mock.jwks_requests == 1


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_verify_rejections(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    verifier = factory.create_github_actions_token_verifier()
    mock_github_actions_oidc(respx_mock)
    excinfo: pytest.ExceptionInfo[Exception]

    # Wrong issuer.
    token = create_github_actions_jwt(issuer="https://bogus.example.com")
    with pytest.raises(InvalidIssuerError):
        await verifier.verify_token(token)
    token = create_github_actions_jwt(omit={"iss"})
    with pytest.raises(MissingRequiredClaimError):
        await verifier.verify_token(token)

    # Wrong audience, including the audience for another environment and a
    # trailing slash.
    token = create_github_actions_jwt(audience="https://other.example.com")
    with pytest.raises(InvalidAudienceError):
        await verifier.verify_token(token)
    token = create_github_actions_jwt(audience="https://example.com/")
    with pytest.raises(InvalidAudienceError):
        await verifier.verify_token(token)
    token = create_github_actions_jwt(omit={"aud"})
    with pytest.raises(MissingRequiredClaimError):
        await verifier.verify_token(token)

    # Validity window, with a small amount of clock skew allowed.
    token = create_github_actions_jwt(lifetime=timedelta(seconds=-10))
    assert await verifier.verify_token(token)
    token = create_github_actions_jwt(lifetime=timedelta(minutes=-5))
    with pytest.raises(ExpiredSignatureError):
        await verifier.verify_token(token)
    token = create_github_actions_jwt(not_before=timedelta(seconds=10))
    assert await verifier.verify_token(token)
    token = create_github_actions_jwt(not_before=timedelta(minutes=5))
    with pytest.raises(ImmatureSignatureError):
        await verifier.verify_token(token)
    token = create_github_actions_jwt(omit={"exp"})
    with pytest.raises(MissingRequiredClaimError):
        await verifier.verify_token(token)

    # Wrong signing key.
    token = create_github_actions_jwt(keypair=RSAKeyPair.generate())
    with pytest.raises(InvalidSignatureError):
        await verifier.verify_token(token)

    # Wrong algorithm or missing key ID in the header, both of which are
    # rejected before the key set is consulted.
    token = create_github_actions_jwt(algorithm="RS512")
    with pytest.raises(UnknownAlgorithmError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == "Token algorithm RS512 not RS256"
    token = create_github_actions_jwt(kid=None)
    with pytest.raises(UnknownKeyIdError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == "No kid in token header"


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_key_rotation(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    verifier = factory.create_github_actions_token_verifier()
    mock = mock_github_actions_oidc(respx_mock, "old-kid")

    token = create_github_actions_jwt(kid="old-kid")
    assert await verifier.verify_token(token)
    assert mock.jwks_requests == 1

    # A token with an unknown key ID forces one refresh of the key set and
    # then fails if the key is still not there.
    token = create_github_actions_jwt(kid="new-kid")
    with pytest.raises(UnknownKeyIdError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == "GitHub Actions has no kid new-kid"
    assert mock.jwks_requests == 2

    # Rotate the key at GitHub. The old key is still in the cache, so the
    # new token triggers a refresh and the old token still works until the
    # cache is next refreshed.
    keypair = RSAKeyPair.generate()
    mock.keypairs = {"new-kid": keypair}
    token = create_github_actions_jwt(kid="new-kid", keypair=keypair)
    assert await verifier.verify_token(token)
    assert mock.jwks_requests == 3
    token = create_github_actions_jwt(kid="old-kid")
    with pytest.raises(UnknownKeyIdError):
        await verifier.verify_token(token)
    assert mock.jwks_requests == 4

    # Clearing the cache forces a fetch on the next verification.
    assert factory._context.github_jwks_cache
    await factory._context.github_jwks_cache.clear()
    token = create_github_actions_jwt(kid="new-kid", keypair=keypair)
    assert await verifier.verify_token(token)
    assert mock.jwks_requests == 5


@pytest.mark.parametrize("config", ["github-token-exchange"], indirect=True)
@pytest.mark.asyncio
async def test_key_retrieval_errors(
    config: Config, factory: Factory, respx_mock: respx.Router
) -> None:
    verifier = factory.create_github_actions_token_verifier()
    token = create_github_actions_jwt()

    # GitHub's OpenID Connect configuration is unavailable or malformed.
    respx_mock.get(GITHUB_ACTIONS_CONFIG_URL).respond(500)
    with pytest.raises(GitHubWebError):
        await verifier.verify_token(token)
    respx_mock.get(GITHUB_ACTIONS_CONFIG_URL).respond(json=["foo"])
    with pytest.raises(FetchKeysError):
        await verifier.verify_token(token)

    # The key set is unavailable or malformed.
    respx_mock.get(GITHUB_ACTIONS_CONFIG_URL).respond(
        json={"jwks_uri": GITHUB_ACTIONS_JWKS_URL}
    )
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).respond(404)
    with pytest.raises(GitHubWebError):
        await verifier.verify_token(token)
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).respond(json={"foo": "bar"})
    with pytest.raises(FetchKeysError):
        await verifier.verify_token(token)
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).respond(json={"keys": "foo"})
    with pytest.raises(FetchKeysError):
        await verifier.verify_token(token)

    # The key for the token uses an unsupported algorithm or is unusable.
    # These key sets are cached since they were retrieved successfully, so
    # clear the cache between them.
    jwks_cache = factory._context.github_jwks_cache
    assert jwks_cache
    jwks = TEST_KEYPAIR.public_key_as_jwks("github-kid").model_dump()
    jwks["keys"][0]["alg"] = "ES256"
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).respond(json=jwks)
    with pytest.raises(UnknownAlgorithmError):
        await verifier.verify_token(token)
    await jwks_cache.clear()
    jwks["keys"][0]["alg"] = "RS256"
    jwks["keys"][0]["n"] = "not-a-modulus"
    respx_mock.get(GITHUB_ACTIONS_JWKS_URL).respond(json=jwks)
    with pytest.raises(FetchKeysError):
        await verifier.verify_token(token)
    await jwks_cache.clear()

    # A working key set is picked up on the next verification.
    mock = mock_github_actions_oidc(respx_mock)
    assert await verifier.verify_token(token)
    assert mock.jwks_requests == 1


@pytest.mark.asyncio
async def test_not_configured(config: Config, factory: Factory) -> None:
    assert config.github_token_exchange is None
    assert factory._context.github_jwks_cache is None
    with pytest.raises(NotConfiguredError):
        factory.create_github_actions_token_verifier()
