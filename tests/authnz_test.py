"""Tests for the jwt_authorizer.authnz package."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from jwt_authorizer.authnz import capabilities_from_groups
from tests.util import create_test_app

if TYPE_CHECKING:
    from typing import Any, Dict


async def test_capabilities_from_groups() -> None:
    app = await create_test_app()
    group_mapping = app["jwt_authorizer/config"].group_mapping
    token: Dict[str, Any] = {
        "sub": "bvan",
        "email": "bvan@gmail.com",
        "isMemberOf": [{"name": "user"}],
    }

    assert capabilities_from_groups(token, group_mapping) == set()

    admin_token = copy.deepcopy(token)
    admin_token["isMemberOf"].append({"name": "admin"})
    assert capabilities_from_groups(admin_token, group_mapping) == {
        "exec:admin",
        "read:all",
    }
