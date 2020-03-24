import os

from jwt_authorizer.app import app
from jwt_authorizer.config import Config


def configure() -> None:
    """Configure the Flask app on module load."""
    settings_path = os.environ.get(
        "SETTINGS_PATH", "/etc/jwt-authorizer/authorizer.yaml"
    )
    Config.validate(app, settings_path)


configure()
