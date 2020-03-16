"""Tests for the jwt_authorizer.authnz package."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from jwt_authorizer.authnz import capabilities_from_groups
from tests.util import create_test_app

if TYPE_CHECKING:
    from typing import Any, Dict


def test_capabilities_from_groups() -> None:
    app = create_test_app()
    token: Dict[str, Any] = {
        "sub": "bvan",
        "email": "bvan@gmail.com",
        "isMemberOf": [{"name": "user"}],
    }

    with app.app_context():
        assert capabilities_from_groups(token) == set()

        admin_token = copy.deepcopy(token)
        admin_token["isMemberOf"].append({"name": "admin"})
        assert capabilities_from_groups(admin_token) == {"exec:admin"}
