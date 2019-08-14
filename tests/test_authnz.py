from unittest import TestCase

from dynaconf.utils import DynaconfDict
from dynaconf.contrib.flask_dynaconf import DynaconfConfig
import flask

from authorizer.authnz import capabilities_from_groups


class TestAuthnz(TestCase):
    def test_capabilities_from_groups(self):
        app = flask.Flask(__name__)
        mocked_settings = DynaconfDict({'GROUP_MAPPING': {"exec:admin": ["admin"]}})
        mocked_settings.store = {}
        config = DynaconfConfig(root_path=".", defaults=app.config, _settings=mocked_settings)
        app.config = config
        token = {
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
