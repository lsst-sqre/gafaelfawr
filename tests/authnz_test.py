"""Tests for the jwt_authorizer.authnz package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from jwt_authorizer.authnz import capabilities_from_groups
from jwt_authorizer.tokens import VerifiedToken
from tests.util import create_test_app

if TYPE_CHECKING:
    from typing import Any, Dict


async def test_capabilities_from_groups() -> None:
    app = await create_test_app()
    group_mapping = app["jwt_authorizer/config"].group_mapping
    claims: Dict[str, Any] = {
        "sub": "bvan",
        "email": "bvan@gmail.com",
        "isMemberOf": [{"name": "user"}],
    }
    token = VerifiedToken(encoded="", claims=claims)

    assert capabilities_from_groups(token, group_mapping) == set()

    claims["isMemberOf"].append({"name": "admin"})
    assert capabilities_from_groups(token, group_mapping) == {
        "exec:admin",
        "read:all",
    }
