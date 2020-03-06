from __future__ import annotations

from typing import TYPE_CHECKING
from unittest import TestCase

import flask
from dynaconf.contrib.flask_dynaconf import DynaconfConfig
from dynaconf.utils import DynaconfDict

from authorizer.authnz import capabilities_from_groups

if TYPE_CHECKING:
    from typing import Any, Dict


class TestAuthnz(TestCase):
    def test_capabilities_from_groups(self) -> None:
        app = flask.Flask(__name__)
        mocked_settings = DynaconfDict(
            {"GROUP_MAPPING": {"exec:admin": ["admin"]}}
        )
        mocked_settings.store = {}
        config = DynaconfConfig(
            mocked_settings, app, root_path=".", defaults=app.config
        )
        app.config = config
        token: Dict[str, Any] = {
            "sub": "bvan",
            "email": "bvan@gmail.com",
        }
        is_member_of = [{"name": "user"}]

        with app.app_context():
            user_token = token.copy()
            user_token["isMemberOf"] = is_member_of
            print(capabilities_from_groups(user_token))

            admin_token = token.copy()
            admin_is_member_of = is_member_of.copy()
            admin_is_member_of.append({"name": "admin"})
            admin_token["isMemberOf"] = admin_is_member_of
            print(capabilities_from_groups(admin_token))
