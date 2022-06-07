"""OpenID Connect provider mocks for testing."""

from __future__ import annotations

from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

import respx
from httpx import AsyncClient, Request, Response

from gafaelfawr.config import OIDCConfig
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.oidc import OIDCToken, OIDCVerifiedToken

from .constants import TEST_KEYPAIR

__all__ = [
    "mock_oidc_provider_config",
    "mock_oidc_provider_token",
    "simulate_oidc_login",
]


class MockOIDCConfig:
    """Mock OpenID Connect upstream provider configuration.

    The methods of this object should be installed as respx mock side effects
    using `mock_oidc_provider_config`.

    Parameters
    ----------
    config : `gafaelfawr.config.OIDCConfig`
        Configuration for the OpenID Connect provider.
    kid : `str`
        The key ID to return.
    """

    def __init__(self, config: OIDCConfig, kid: str) -> None:
        self.config = config
        self.kid = kid

    def get_config(self, request: Request) -> Response:
        jwks_url = urljoin(self.config.issuer, "/jwks.json")
        return Response(200, json={"jwks_uri": jwks_url})

    def get_jwks(self, request: Request) -> Response:
        jwks = TEST_KEYPAIR.public_key_as_jwks(self.kid)
        return Response(200, json=jwks.dict())


class MockOIDCToken:
    """Mock OpenID Connect upstream provider token endpoint.

    The methods of this object should be installed as respx mock side effects
    using `mock_oidc_provider_config`.

    Parameters
    ----------
    config : `gafaelfawr.config.OIDCConfig`
        Configuration for Gafaelfawr.
    code : `str`
        The code that Gafaelfawr must send to redeem for a token.
    token : `gafaelfawr.models.oidc.OIDCToken`
        The token to return after authentication.
    """

    def __init__(
        self, config: OIDCConfig, code: str, token: OIDCToken
    ) -> None:
        self.config = config
        self.code = code
        self.token = token

    def post_token(self, request: Request) -> Response:
        assert request.headers["Accept"] == "application/json"
        assert parse_qs(request.read().decode()) == {
            "grant_type": ["authorization_code"],
            "client_id": [self.config.client_id],
            "client_secret": [self.config.client_secret],
            "code": [self.code],
            "redirect_uri": [self.config.redirect_url],
        }
        return Response(
            200, json={"id_token": self.token.encoded, "token_type": "Bearer"}
        )


async def mock_oidc_provider_config(
    respx_mock: respx.Router, kid: str
) -> None:
    """Mock out the API for the upstream OpenID Connect provider.

    Parameters
    ----------
    respx_mock : `respx.Router`
        The mock router.
    kid : `str`
        The key ID to return.
    """
    config = await config_dependency()
    assert config.oidc
    mock = MockOIDCConfig(config.oidc, kid)
    issuer = config.oidc.issuer
    config_url = urljoin(issuer, "/.well-known/openid-configuration")
    respx_mock.get(config_url).mock(side_effect=mock.get_config)
    jwks_url = urljoin(issuer, "/jwks.json")
    respx_mock.get(jwks_url).mock(side_effect=mock.get_jwks)


async def mock_oidc_provider_token(
    respx_mock: respx.Router, code: str, token: OIDCToken
) -> None:
    """Mock out the API for the upstream OpenID Connect provider.

    Parameters
    ----------
    respx_mock : `respx.Router`
        The mock router.
    code : `str`
        The code that Gafaelfawr must send to redeem for a token.
    token : `gafaelfawr.models.oidc.OIDCToken`
        The token to return after authentication.
    """
    config = await config_dependency()
    assert config.oidc
    mock = MockOIDCToken(config.oidc, code, token)
    respx_mock.post(config.oidc.token_url).mock(side_effect=mock.post_token)


async def simulate_oidc_login(
    client: AsyncClient,
    respx_mock: respx.Router,
    token: OIDCVerifiedToken,
    *,
    return_url: str = "https://example.com/foo",
    use_redirect_header: bool = False,
    callback_route: str = "/login",
    expect_enrollment: bool = False,
) -> Response:
    """Simulate an OpenID Connect login and return the final response.

    Parameters
    ----------
    client : `httpx.AsyncClient`
        Client to use to make calls to the application.
    respx_mock : `respx.Router`
        Mock for httpx calls.
    token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
        Authentication token the upstream OpenID Connect provider should
        return.
    return_url : `str`, optional
        The return URL to pass to the login process.  If not provided, a
        simple one will be used.
    use_redirect_header : `bool`, optional
        If set to `True`, pass the return URL in a header instead of as a
        parameter to the ``/login`` route.
    callback_route : `str`, optional
        Override the callback route to which the upstream OpenID Connect
        provider is expected to send the redirect.
    expect_enrollment : `bool`, optional
        If set to `True`, expect a redirect to the enrollment URL after login
        rather than to the return URL.

    Returns
    -------
    response : ``httpx.Response``
        The response from the return to the ``/login`` handler.
    """
    config = await config_dependency()
    assert config.oidc
    await mock_oidc_provider_config(respx_mock, "orig-kid")
    await mock_oidc_provider_token(respx_mock, "some-code", token)

    # Simulate the redirect to the OpenID Connect provider.
    if use_redirect_header:
        r = await client.get(
            "/login", headers={"X-Auth-Request-Redirect": return_url}
        )
    else:
        r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    assert r.headers["Location"].startswith(config.oidc.login_url)
    url = urlparse(r.headers["Location"])
    assert url.query
    query = parse_qs(url.query)
    login_params = {p: [v] for p, v in config.oidc.login_params.items()}
    assert query == {
        "client_id": [config.oidc.client_id],
        "redirect_uri": [config.oidc.redirect_url],
        "response_type": ["code"],
        "scope": ["openid " + " ".join(config.oidc.scopes)],
        "state": [ANY],
        **login_params,
    }

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        callback_route,
        params={"code": "some-code", "state": query["state"][0]},
    )
    if r.status_code == 307:
        if expect_enrollment:
            assert r.headers["Location"] == config.oidc.enrollment_url
        else:
            assert r.headers["Location"] == return_url

    return r
