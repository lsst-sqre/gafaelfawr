"""Configuration for tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jwt_authorizer.config import GitHubConfig, OIDCConfig
    from tests.support.keypair import RSAKeyPair
    from typing import Optional

__all__ = ["ConfigForTests"]


@dataclass
class ConfigForTests:
    """Configuration for tests.

    Various tests will make (mocked) HTTP requests for data or will want to
    independently verify the results of internal functions.  This class holds
    keys and other data in use by the test app for easy access by test
    functions, and allows customization of the return values of mocked HTTP
    requests.

    Notes
    -----
    This class is somewhat oddly named to avoid starting or ending the class
    name with Test, which can cause a test framework to think it's a test
    case.
    """

    keypair: RSAKeyPair
    """Key pair used for signing all tokens."""

    session_key: bytes
    """Key used to encrypt the individual members of sessions in Redis."""

    internal_issuer_url: str
    """The URL of the internal issuer."""

    upstream_issuer_url: str
    """The URL of the upstream OpenID Connect issuer."""

    github: Optional[GitHubConfig] = None
    """The configuration for talking to GitHub."""

    oidc: Optional[OIDCConfig] = None
    """The configuration for talking to an OpenID Connect provider."""
