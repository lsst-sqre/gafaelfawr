"""Tests for the jwt_authorizer.issuer package."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

from tests.support.app import (
    create_test_app,
    get_test_config,
    get_test_factory,
)
from tests.support.tokens import create_test_token, create_upstream_test_token

if TYPE_CHECKING:
    from pathlib import Path


async def test_reissue_token(tmp_path: Path) -> None:
    app = await create_test_app(tmp_path)
    config = get_test_config(app)
    factory = get_test_factory(app)
    issuer = factory.create_token_issuer()

    local_token = create_test_token(config)
    upstream_token = create_upstream_test_token(
        config,
        email="other-user@example.com",
        sub="upstream",
        uid="upstream-user",
        uidNumber="2000",
    )
    reissued_token = issuer.reissue_token(upstream_token, jti="new-jti")

    assert reissued_token.claims == {
        "act": {
            "aud": upstream_token.claims["aud"],
            "iss": upstream_token.claims["iss"],
            "jti": upstream_token.claims["jti"],
        },
        "aud": local_token.claims["aud"],
        "email": "other-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "iss": local_token.claims["iss"],
        "jti": "new-jti",
        "sub": "upstream",
        "uid": "upstream-user",
        "uidNumber": "2000",
    }

    now = time.time()
    exp_minutes = app["jwt_authorizer/config"].issuer.exp_minutes
    expected_exp = now + exp_minutes * 60
    assert expected_exp - 5 <= reissued_token.claims["exp"] <= expected_exp + 5
    assert now - 5 <= reissued_token.claims["iat"] <= now + 5


async def test_reissue_token_scope(tmp_path: Path) -> None:
    app = await create_test_app(tmp_path)
    config = get_test_config(app)
    factory = get_test_factory(app)
    issuer = factory.create_token_issuer()

    upstream_token = create_upstream_test_token(
        config, groups=["user"], scope="read:all"
    )
    reissued_token = issuer.reissue_token(upstream_token, jti="new-jti")
    assert "scope" not in reissued_token.claims

    upstream_token = create_upstream_test_token(
        config, groups=["admin"], scope="other:scope"
    )
    reissued_token = issuer.reissue_token(upstream_token, jti="new-jti")
    assert reissued_token.claims["scope"] == "exec:admin read:all"


async def test_reissue_token_jti(tmp_path: Path) -> None:
    app = await create_test_app(tmp_path)
    config = get_test_config(app)
    factory = get_test_factory(app)
    issuer = factory.create_token_issuer()

    upstream_token = create_upstream_test_token(config)
    reissued_token = issuer.reissue_token(upstream_token, jti="new-jti")
    assert reissued_token.claims["jti"] == "new-jti"
    assert reissued_token.claims["act"]["jti"] == upstream_token.claims["jti"]
