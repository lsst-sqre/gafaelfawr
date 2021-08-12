"""Tests for the gafaelfawr.issuer package."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_issue_token(setup: SetupTest) -> None:
    await setup.configure("oidc")
    issuer = setup.factory.create_token_issuer()

    token_data = await setup.create_session_token()
    oidc_token = issuer.issue_token(token_data, jti="new-jti", scope="openid")

    assert oidc_token.claims == {
        "aud": setup.config.issuer.aud,
        "exp": ANY,
        "iat": ANY,
        "iss": setup.config.issuer.iss,
        "jti": "new-jti",
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid",
        "sub": token_data.username,
        setup.config.issuer.username_claim: token_data.username,
        setup.config.issuer.uid_claim: token_data.uid,
    }

    now = time.time()
    assert now - 5 <= oidc_token.claims["iat"] <= now + 5
    expected_exp = now + setup.config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= oidc_token.claims["exp"] <= expected_exp + 5
