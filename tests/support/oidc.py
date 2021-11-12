"""OpenID Connect provider mocks for testing."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urljoin

from httpx import Response

if TYPE_CHECKING:
    from typing import Optional

    import respx
    from httpx import Request

    from gafaelfawr.config import Config
    from gafaelfawr.keypair import RSAKeyPair
    from gafaelfawr.models.oidc import OIDCToken

__all__ = ["mock_oidc_provider_config", "mock_oidc_provider_token"]


class MockOIDCConfig:
    """Mock OpenID Connect upstream provider configuration.

    The methods of this object should be installed as respx mock side effects
    using `mock_oidc_provider_config`.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Configuration for Gafaelfawr.
    keypair : `gafaelfawr.keypair.RSAKeyPair`, optional
        The keypair to use.  Defaults to the configured issuer keypair.
    kid : `str`, optional
        The key ID to return.  Defaults to the first key ID in the
        configuration.
    """

    def __init__(
        self,
        config: Config,
        keypair: Optional[RSAKeyPair] = None,
        kid: Optional[str] = None,
    ) -> None:
        assert config.oidc
        self.config = config
        self.keypair = keypair if keypair else config.issuer.keypair
        self.kid = kid if kid else config.oidc.key_ids[0]

    def get_config(self, request: Request) -> Response:
        assert self.config.oidc
        jwks_url = urljoin(self.config.oidc.issuer, "/jwks.json")
        return Response(200, json={"jwks_uri": jwks_url})

    def get_jwks(self, request: Request) -> Response:
        jwks = self.keypair.public_key_as_jwks(self.kid)
        return Response(200, json=jwks.dict())


class MockOIDCToken:
    """Mock OpenID Connect upstream provider token endpoint.

    The methods of this object should be installed as respx mock side effects
    using `mock_oidc_provider_config`.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Configuration for Gafaelfawr.
    code : `str`
        The code that Gafaelfawr must send to redeem for a token.
    token : `gafaelfawr.models.oidc.OIDCToken`
        The token to return after authentication.
    """

    def __init__(self, config: Config, code: str, token: OIDCToken) -> None:
        assert config.oidc
        self.config = config
        self.code = code
        self.token = token

    def post_token(self, request: Request) -> Response:
        assert self.config.oidc
        assert request.headers["Accept"] == "application/json"
        assert parse_qs(request.read().decode()) == {
            "grant_type": ["authorization_code"],
            "client_id": [self.config.oidc.client_id],
            "client_secret": [self.config.oidc.client_secret],
            "code": [self.code],
            "redirect_uri": [self.config.oidc.redirect_url],
        }
        return Response(
            200, json={"id_token": self.token.encoded, "token_type": "Bearer"}
        )


def mock_oidc_provider_config(
    respx_mock: respx.Router,
    config: Config,
    keypair: Optional[RSAKeyPair] = None,
    kid: Optional[str] = None,
) -> None:
    """Mock out the API for the upstream OpenID Connect provider.

    Parameters
    ----------
    respx_mock : `respx.Router`
        The mock router.
    config : `gafaelfawr.config.Config`
        Configuration for Gafaelfawr.
    keypair : `gafaelfawr.keypair.RSAKeyPair`, optional
        The keypair to use.  Defaults to the configured issuer keypair.
    kid : `str`, optional
        The key ID to return.  Defaults to the first key ID in the
        configuration.
    """
    assert config.oidc
    mock = MockOIDCConfig(config, keypair, kid)
    issuer = config.oidc.issuer
    config_url = urljoin(issuer, "/.well-known/openid-configuration")
    respx_mock.get(config_url).mock(side_effect=mock.get_config)
    jwks_url = urljoin(issuer, "/jwks.json")
    respx_mock.get(jwks_url).mock(side_effect=mock.get_jwks)


def mock_oidc_provider_token(
    respx_mock: respx.Router, config: Config, code: str, token: OIDCToken
) -> None:
    """Mock out the API for the upstream OpenID Connect provider.

    Parameters
    ----------
    respx_mock : `respx.Router`
        The mock router.
    config : `gafaelfawr.config.Config`
        Configuration for Gafaelfawr.
    code : `str`
        The code that Gafaelfawr must send to redeem for a token.
    token : `gafaelfawr.models.oidc.OIDCToken`
        The token to return after authentication.
    """
    assert config.oidc
    mock = MockOIDCToken(config, code, token)
    respx_mock.post(config.oidc.token_url).mock(side_effect=mock.post_token)
