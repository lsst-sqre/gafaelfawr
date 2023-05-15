"""Tests for the OIDC models."""

from __future__ import annotations

from datetime import timedelta

from safir.datetime import current_datetime

from gafaelfawr.constants import OIDC_AUTHORIZATION_LIFETIME
from gafaelfawr.models.oidc import OIDCAuthorization
from gafaelfawr.models.token import Token


def test_authorization_lifetime() -> None:
    authorization = OIDCAuthorization(
        client_id="foo",
        redirect_uri="https://example.com/",
        token=Token(),
    )
    assert authorization.lifetime <= OIDC_AUTHORIZATION_LIFETIME
    assert OIDC_AUTHORIZATION_LIFETIME - 2 <= authorization.lifetime

    lifetime = timedelta(seconds=OIDC_AUTHORIZATION_LIFETIME)
    authorization.created_at = current_datetime() - lifetime
    assert authorization.lifetime == 0

    authorization.created_at = authorization.created_at - timedelta(days=7)
    assert authorization.lifetime == 0
