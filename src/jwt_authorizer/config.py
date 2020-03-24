__all__ = [
    "AuthorizerApp",
    "Config",
]

import logging
import os
from typing import Any, Callable, Mapping, Tuple

import redis
from dynaconf import FlaskDynaconf, Validator
from flask import Flask

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"

AccessT = Callable[[str, Mapping[str, Any]], Tuple[bool, str]]


class AuthorizerApp(Flask):
    ACCESS_CHECK_CALLABLES: Mapping[str, AccessT] = {}


class Config:
    @staticmethod
    def configure_plugins(app: AuthorizerApp) -> None:
        """Configure authorization checking plugins.

        Parameters
        ----------
        app : `AuthorizerApp`
            The Flask application to configure.
        """
        from jwt_authorizer.authnz import (
            scope_check_access,
            group_membership_check_access,
        )

        app.ACCESS_CHECK_CALLABLES = {
            "scope": scope_check_access,
            "group_membership": group_membership_check_access,
        }

    @staticmethod
    def validate(app: AuthorizerApp, user_config: str) -> None:
        """Load and validate the application configuration.

        Parameters
        ----------
        app : `AuthorizerApp`
            The Flask application to configure.
        user_config : `str`
            An additional configuration file to load.
        """
        global logger
        Config.configure_plugins(app)
        defaults_file = os.path.join(
            os.path.dirname(__file__), "defaults.yaml"
        )

        settings_module = f"{defaults_file},{user_config}"
        print(settings_module)
        config = FlaskDynaconf(app, SETTINGS_FILE_FOR_DYNACONF=settings_module)
        settings = config.settings
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

        assert (
            "FLASK_SECRET_KEY_FILE" in settings
        ), "No FLASK_SECRET_KEY_FILE defined"
        secret_key_file_path = settings["FLASK_SECRET_KEY_FILE"]
        with open(secret_key_file_path, "r") as secret_key_file:
            secret_key = secret_key_file.read().strip()
            assert len(
                secret_key
            ), "FLASK_SECRET_KEY_FILE contains no secret data"
            app.secret_key = secret_key

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
            app.redis_pool = redis.ConnectionPool.from_url(
                url=proxy_config["REDIS_URL"]
            )
            logger.info(
                f"Configured redis pool from url: {proxy_config['REDIS_URL']} "
                f"with prefix: {ticket_prefix}"
            )

        # Find Resource Check Callables
        for access_check_name in settings["ACCESS_CHECKS"]:
            if access_check_name not in app.ACCESS_CHECK_CALLABLES:
                raise Exception(
                    f"No access checker for id {access_check_name}"
                )
            logger.info(
                f"Configured default access checks: {access_check_name}"
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
