"""Utility functions for tests."""

from __future__ import annotations

import base64
import os
import sys
from asyncio import Future
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY, Mock

import jwt
import mockaioredis
from aiohttp import ClientResponse, web
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from jwt_authorizer.app import create_app
from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.factory import ComponentFactory
from jwt_authorizer.providers import GitHubProvider
from jwt_authorizer.util import number_to_base64
from jwt_authorizer.verify import KeyClient, TokenVerifier

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from aioredis import Redis
    from jwt_authorizer.config import Config
    from logger import Logger
    from typing import Any, Dict, List, Optional


class FakeGitHubProvider(GitHubProvider):
    """Override GitHubProvider to not make HTTP requests.

    This returns synthesized responses from the GitHub APIs that we use for
    authentication.
    """

    async def http_get(
        self, url: str, *, headers: Dict[str, str], raise_for_status: bool
    ) -> ClientResponse:
        assert headers == {"Authorization": "token some-github-token"}
        assert raise_for_status
        if url == self._USER_URL:
            user_data = {
                "login": "githubuser",
                "id": 123456,
                "email": "githubuser@example.com",
            }
            return self._build_response(user_data)
        elif url == self._TEAMS_URL:
            teams_data = [
                {"name": "A Team", "organization": {"login": "org"}},
                {"name": "Other Team", "organization": {"login": "org"}},
                {"name": "Team 3", "organization": {"login": "other-org"}},
            ]
            return self._build_response(teams_data)
        else:
            assert False, f"Unexpected URL {url}"

    async def http_post(
        self,
        url: str,
        *,
        data: Dict[str, str],
        headers: Dict[str, str],
        raise_for_status: bool,
    ) -> ClientResponse:
        assert headers == {"Accept": "application/json"}
        assert data == {
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": "some-code",
            "state": ANY,
        }
        assert raise_for_status
        assert url == self._TOKEN_URL

        response = {
            "access_token": "some-github-token",
            "scope": ",".join(self._SCOPES),
            "token_type": "bearer",
        }
        return self._build_response(response)

    def _build_response(self, result: Any) -> ClientResponse:
        """Build a successful response."""
        r = Mock(spec=ClientResponse)
        if sys.version_info[0] == 3 and sys.version_info[1] < 8:
            future: Future[Any] = Future()
            future.set_result(result)
            r.json.return_value = future
        else:
            r.json.return_value = result
        r.status = 200
        return r


class FakeKeyClient(KeyClient):
    """Override KeyClient to not make HTTP requests.

    This returns minimal OpenID Connect and JWKS metadata for the two issuers
    used by the test suite.
    """

    def __init__(self, keypair: RSAKeyPair) -> None:
        self.keypair = keypair

    async def get_url(self, url: str) -> ClientResponse:
        if url == "https://test.example.com/.well-known/openid-configuration":
            jwks_uri = "https://test.example.com/.well-known/jwks.json"
            return self._build_response_success({"jwks_uri": jwks_uri})
        elif url == "https://test.example.com/.well-known/jwks.json":
            return self._build_response_success(self._build_keys("some-kid"))
        elif url == "https://orig.example.com/.well-known/jwks.json":
            return self._build_response_success(self._build_keys("orig-kid"))
        else:
            return self._build_response_failure()

    def _build_keys(self, kid: str) -> Dict[str, Any]:
        """Generate the JSON-encoded keys structure for a keypair."""
        public_numbers = self.keypair.public_numbers()
        e = number_to_base64(public_numbers.e).decode()
        n = number_to_base64(public_numbers.n).decode()
        return {"keys": [{"alg": ALGORITHM, "e": e, "n": n, "kid": kid}]}

    def _build_response_failure(self) -> ClientResponse:
        """Build a successful response."""
        r = Mock(spec=ClientResponse)
        r.status = 404
        return r

    def _build_response_success(
        self, result: Dict[str, Any]
    ) -> ClientResponse:
        """Build a successful response."""
        r = Mock(spec=ClientResponse)
        if sys.version_info[0] == 3 and sys.version_info[1] < 8:
            future: Future[Dict[str, Any]] = Future()
            future.set_result(result)
            r.json.return_value = future
        else:
            r.json.return_value = result
        r.status = 200
        return r


class MockComponentFactory(ComponentFactory):
    """Component factory for testing.

    Selectively overrides some factory methods to use mocked objects.

    Parameters
    ----------
    config : `jwt_authorizer.config.Config`
        JWT Authorizer configuration.
    redis : `aioredis.Redis`
        Redis client.
    keypair : `RSAKeyPair`
        RSA key pair used for token signing.
    """

    def __init__(
        self, config: Config, redis: Redis, keypair: RSAKeyPair
    ) -> None:
        super().__init__(config, redis)
        self._keypair = keypair

    def create_github_provider(self, request: web.Request) -> GitHubProvider:
        """Create a GitHubProvider with a mocked HTTP client.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request.

        Returns
        -------
        token_verifier : `jwt_authorizer.providers.GitHubProvider`
            A new GitHubProvider.
        """
        http_session: ClientSession = request.config_dict["safir/http_session"]
        logger: Logger = request["safir/logger"]
        assert self._config.github
        return FakeGitHubProvider(self._config.github, http_session, logger)

    def create_token_verifier(self, request: web.Request) -> TokenVerifier:
        """Create a TokenVerifier with a mocked HTTP client.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The incoming request.

        Returns
        -------
        token_verifier : `jwt_authorizer.verify.TokenVerifier`
            A new TokenVerifier.
        """
        logger: Logger = request["safir/logger"]
        key_client = FakeKeyClient(self._keypair)
        return TokenVerifier(self._config.issuers, key_client, logger)


class RSAKeyPair:
    """An autogenerated public/private key pair."""

    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def private_key_as_pem(self) -> bytes:
        return self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

    def public_key_as_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
        )

    def public_numbers(self) -> rsa.RSAPublicNumbers:
        return self.private_key.public_key().public_numbers()


async def create_test_app(
    keypair: Optional[RSAKeyPair] = None,
    session_secret: Optional[bytes] = None,
    **kwargs: Any,
) -> web.Application:
    """Configured aiohttp Application for testing."""
    if not keypair:
        keypair = RSAKeyPair()
    if not session_secret:
        session_secret = os.urandom(16)

    kwargs["SESSION_SECRET"] = Fernet.generate_key().decode()
    kwargs["OAUTH2_JWT.KEY"] = keypair.private_key_as_pem().decode()
    secret_b64 = base64.urlsafe_b64encode(session_secret).decode()
    kwargs["OAUTH2_STORE_SESSION.OAUTH2_PROXY_SECRET"] = secret_b64
    kwargs["OAUTH2_STORE_SESSION.REDIS_URL"] = "dummy"

    redis_pool = await mockaioredis.create_redis_pool("")
    app = await create_app(
        redis_pool=redis_pool,
        key_client=FakeKeyClient(keypair),
        FORCE_ENV_FOR_DYNACONF="testing",
        **kwargs,
    )

    config = app["jwt_authorizer/config"]
    app["jwt_authorizer/factory"] = MockComponentFactory(
        config, redis_pool, keypair
    )

    return app


def create_test_token(
    keypair: RSAKeyPair,
    groups: Optional[List[str]] = None,
    kid: str = "some-kid",
    **attributes: str,
) -> str:
    """Create a signed token using the configured test issuer.

    This will match the issuer and audience of the default JWT Authorizer
    issuer, so JWT Authorizer will not attempt to reissue it.

    Parameters
    ----------
    keypair : `RSAKeyPair`
        The key pair to use to sign the token.
    groups : List[`str`], optional
        Group memberships the generated token should have.
    kid : `str`
        The key ID to use.
    **attributes : `str`
        Other attributes to set or override in the token.

    Returns
    -------
    token : `str`
        The encoded token.
    """
    payload = create_test_token_payload(groups, **attributes)
    return jwt.encode(
        payload,
        keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers={"kid": kid},
    ).decode()


def create_test_token_payload(
    groups: Optional[List[str]] = None, **attributes: str,
) -> Dict[str, Any]:
    """Create the contents of a token using the configured test issuer.

    This will match the issuer and audience of the default JWT Authorizer
    issuer, so JWT Authorizer will not attempt to reissue it.

    Parameters
    ----------
    groups : List[`str`], optional
        Group memberships the generated token should have.
    **attributes : `str`
        Other attributes to set or override in the token.

    Returns
    -------
    payload : Dict[`str`, Any]
        The contents of the token.
    """
    exp = datetime.now(timezone.utc) + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "exp": int(exp.timestamp()),
        "iss": "https://test.example.com/",
        "jti": "some-unique-id",
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }
    payload.update(attributes)
    if groups:
        payload["isMemberOf"] = [{"name": g} for g in groups]
    return payload
