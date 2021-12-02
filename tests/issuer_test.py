"""Tests for the gafaelfawr.issuer package."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from tests.support.settings import configure
from tests.support.tokens import create_session_token

if TYPE_CHECKING:
    from pathlib import Path

    from gafaelfawr.factory import ComponentFactory


@pytest.mark.asyncio
async def test_issue_token(tmp_path: Path, factory: ComponentFactory) -> None:
    config = await configure(tmp_path, "oidc")
    factory.reconfigure(config)
    issuer = factory.create_token_issuer()

    token_data = await create_session_token(factory)
    oidc_token = issuer.issue_token(token_data, jti="new-jti", scope="openid")

    assert oidc_token.claims == {
        "aud": config.issuer.aud,
        "exp": ANY,
        "iat": ANY,
        "iss": config.issuer.iss,
        "jti": "new-jti",
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid",
        "sub": token_data.username,
        config.issuer.username_claim: token_data.username,
        config.issuer.uid_claim: token_data.uid,
    }

    now = time.time()
    assert now - 5 <= oidc_token.claims["iat"] <= now + 5
    expected_exp = now + config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= oidc_token.claims["exp"] <= expected_exp + 5
