"""Configuration for JWT Authorizer."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dynaconf import LazySettings, Validator

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["Config", "Configuration"]


logger = logging.getLogger(__name__)

ALGORITHM = "RS256"


@dataclass
class Configuration:
    """Configuration for jwt_authorizer."""

    name: str = os.getenv("SAFIR_NAME", "jwt_authorizer")
    """The application's name, which doubles as the root HTTP endpoint path.

    Set with the ``SAFIR_NAME`` environment variable.
    """

    profile: str = os.getenv("SAFIR_PROFILE", "development")
    """Application run profile: "development" or "production".

    Set with the ``SAFIR_PROFILE`` environment variable.
    """

    logger_name: str = os.getenv("SAFIR_LOGGER", "jwt_authorizer")
    """The root name of the application's logger.

    Set with the ``SAFIR_LOGGER`` environment variable.
    """

    log_level: str = os.getenv("SAFIR_LOG_LEVEL", "INFO")
    """The log level of the application's logger.

    Set with the ``SAFIR_LOG_LEVEL`` environment variable.
    """


class Config:
    @staticmethod
    def validate(user_config: Optional[str]) -> LazySettings:
        """Load and validate the application configuration.

        Parameters
        ----------
        user_config : `str`, optional
            An additional configuration file to load.
        """
        global logger
        defaults_file = os.path.join(
            os.path.dirname(__file__), "defaults.yaml"
        )

        if user_config:
            settings_module = f"{defaults_file},{user_config}"
        else:
            settings_module = defaults_file
        settings = LazySettings(SETTINGS_FILE_FOR_DYNACONF=settings_module)
        settings.validators.register(
            Validator("NO_VERIFY", "NO_AUTHORIZE", is_type_of=bool),
            Validator("GROUP_MAPPING", is_type_of=dict),
        )

        settings.validators.validate()

        if settings.get("OAUTH2_JWT.ISS"):
            iss = settings["OAUTH2_JWT.ISS"]
            kid = settings["OAUTH2_JWT.KEY_ID"]
            logger.info(f"Configuring Token Issuer: {iss} with Key ID {kid}")

            if settings.get("OAUTH2_JWT.AUD.DEFAULT"):
                aud = settings.get("OAUTH2_JWT.AUD.DEFAULT")
                logger.info(f"Configured Default Audience: {aud}")

            if settings.get("OAUTH2_JWT.AUD.INTERNAL"):
                aud = settings.get("OAUTH2_JWT.AUD.DEFAULT")
                logger.info(f"Configured Internal Audience: {aud}")

        if settings.get("OAUTH2_JWT.KEY_FILE"):
            jwt_key_file_path = settings["OAUTH2_JWT.KEY_FILE"]
            with open(jwt_key_file_path, "r") as secret_key_file:
                secret_key = secret_key_file.read().strip()
                settings["OAUTH2_JWT.KEY"] = secret_key

        default_jwt_exp = settings.get("OAUTH2_JWT_EXP")
        logger.info(f"Default JWT Expiration is {default_jwt_exp} minutes")

        if settings.get("LOGLEVEL"):
            level = settings["LOGLEVEL"]
            logger.info(f"Reconfiguring log, level={level}")
            # Reconfigure logging
            for handler in logging.root.handlers[:]:
                logging.root.removeHandler(handler)
            logging.basicConfig(level=level)
            logger = logging.getLogger(__name__)
            if level == "DEBUG":
                logging.getLogger("werkzeug").setLevel(level)

        logger.info(f"Configured realm {settings['REALM']}")
        logger.info(
            f"Configured WWW-Authenticate type: {settings['WWW_AUTHENTICATE']}"
        )

        if settings["NO_VERIFY"]:
            logger.warning("Authentication verification is disabled")

        if settings["NO_AUTHORIZE"]:
            logger.warning("Authorization is disabled")

        if settings.get("GROUP_MAPPING"):
            for key, value in settings["GROUP_MAPPING"].items():
                assert isinstance(key, str) and isinstance(
                    value, list
                ), "Mapping is malformed"
            logger.info(
                f"Configured Group Mapping: {settings['GROUP_MAPPING']}"
            )

        if settings.get("OAUTH2_STORE_SESSION"):
            proxy_config = settings["OAUTH2_STORE_SESSION"]
            ticket_prefix = proxy_config["TICKET_PREFIX"]
            oauth2_proxy_secret_file_path = proxy_config[
                "OAUTH2_PROXY_SECRET_FILE"
            ]
            assert os.path.exists(
                oauth2_proxy_secret_file_path
            ), "OAUTH2_PROXY_SECRET_FILE must exist"
            with open(oauth2_proxy_secret_file_path, "r") as secret_key_file:
                secret = secret_key_file.read().strip()
            assert len(secret), "OAUTH2_PROXY_SECRET_FILE have content"
            proxy_config["OAUTH2_PROXY_SECRET"] = secret
            logger.info(
                f"Configured redis pool from url: {proxy_config['REDIS_URL']} "
                f"with prefix: {ticket_prefix}"
            )

        if settings.get("ISSUERS"):
            # Issuers
            for issuer_url, issuer_info in settings["ISSUERS"].items():
                logger.info(
                    f"Configured token access for {issuer_url}: {issuer_info}"
                )
            logger.info("Configured Issuers")
        else:
            logger.warning("No Issuers Configures")

        return settings
