"""Tests for the jwt_authorizer.authnz package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from jwt_authorizer.authnz import scopes_from_token
from jwt_authorizer.tokens import VerifiedToken
from tests.support.app import create_test_app

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any, Dict


async def test_capabilities_from_groups(tmp_path: Path) -> None:
    app = await create_test_app(tmp_path)
    group_mapping = app["jwt_authorizer/config"].group_mapping
    claims: Dict[str, Any] = {
        "sub": "bvan",
        "email": "bvan@gmail.com",
        "isMemberOf": [{"name": "user"}],
    }
    token = VerifiedToken(encoded="", claims=claims)

    assert scopes_from_token(token, group_mapping) == set()

    claims["scope"] = "other:scope"
    assert scopes_from_token(token, group_mapping) == {"other:scope"}

    claims["isMemberOf"].append({"name": "admin"})
    assert scopes_from_token(token, group_mapping) == {
        "exec:admin",
        "other:scope",
        "read:all",
    }
