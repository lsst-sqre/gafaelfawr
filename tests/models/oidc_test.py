"""Tests for the OIDC models."""

from __future__ import annotations

from datetime import timedelta

from gafaelfawr.constants import OIDC_AUTHORIZATION_LIFETIME
from gafaelfawr.models.oidc import OIDCAuthorization
from gafaelfawr.models.token import Token
from gafaelfawr.util import current_datetime


def test_authorization_lifetime() -> None:
    authorization = OIDCAuthorization(
        client_id="foo",
        redirect_uri="https://example.com/",
        token=Token(),
    )
    assert OIDC_AUTHORIZATION_LIFETIME >= authorization.lifetime
    assert OIDC_AUTHORIZATION_LIFETIME - 2 <= authorization.lifetime

    lifetime = timedelta(seconds=OIDC_AUTHORIZATION_LIFETIME)
    authorization.created_at = current_datetime() - lifetime
    assert authorization.lifetime == 0

    authorization.created_at = authorization.created_at - timedelta(days=7)
    assert authorization.lifetime == 0
