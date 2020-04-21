"""Tests for the gafaelfawr.issuer package."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

from tests.setup import SetupTest

if TYPE_CHECKING:
    from pathlib import Path


async def test_reissue_token(tmp_path: Path) -> None:
    setup = await SetupTest.create(tmp_path)
    issuer = setup.factory.create_token_issuer()

    local_token = setup.create_token()
    claims = {
        "email": "other-user@example.com",
        "sub": "upstream",
        setup.config.username_claim: "upstream-user",
        setup.config.uid_claim: "2000",
    }
    oidc_token = setup.create_oidc_token(groups=[], **claims)
    reissued_token = issuer.reissue_token(oidc_token, jti="new-jti")

    assert reissued_token.claims == {
        "act": {
            "aud": oidc_token.claims["aud"],
            "iss": oidc_token.claims["iss"],
            "jti": oidc_token.claims["jti"],
        },
        "aud": local_token.claims["aud"],
        "email": "other-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "iss": local_token.claims["iss"],
        "jti": "new-jti",
        "sub": "upstream",
        setup.config.username_claim: "upstream-user",
        setup.config.uid_claim: "2000",
    }

    now = time.time()
    expected_exp = now + setup.config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= reissued_token.claims["exp"] <= expected_exp + 5
    assert now - 5 <= reissued_token.claims["iat"] <= now + 5


async def test_reissue_token_scope(tmp_path: Path) -> None:
    setup = await SetupTest.create(tmp_path)
    issuer = setup.factory.create_token_issuer()

    oidc_token = setup.create_oidc_token(groups=["user"], scope="read:all")
    reissued_token = issuer.reissue_token(oidc_token, jti="new-jti")
    assert "scope" not in reissued_token.claims

    oidc_token = setup.create_oidc_token(groups=["admin"], scope="other:scope")
    reissued_token = issuer.reissue_token(oidc_token, jti="new-jti")
    assert reissued_token.claims["scope"] == "exec:admin read:all"


async def test_reissue_token_jti(tmp_path: Path) -> None:
    setup = await SetupTest.create(tmp_path)
    issuer = setup.factory.create_token_issuer()

    oidc_token = setup.create_oidc_token()
    reissued_token = issuer.reissue_token(oidc_token, jti="new-jti")
    assert reissued_token.claims["jti"] == "new-jti"
    assert reissued_token.claims["act"]["jti"] == oidc_token.claims["jti"]
