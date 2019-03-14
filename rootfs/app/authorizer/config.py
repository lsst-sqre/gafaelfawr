# This file is part of jwt_authorizer.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (https://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import logging
import os
from typing import Callable, Dict, Tuple

import redis  # type: ignore
from dynaconf import FlaskDynaconf, Validator  # type: ignore

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"


class Config:
    @staticmethod
    def configure_plugins(app):
        from .authorizers import scp_check_access, group_membership_check_access
        from .lsst import lsst_group_membership_check_access, lsst_users_membership_check_access

        app.ACCESS_CHECK_CALLABLES: Dict[str, Callable[[str, Dict], Tuple[bool, str]]] = {
            "scp": scp_check_access,
            "group_membership": group_membership_check_access,
            "lsst_group_membership": lsst_group_membership_check_access,
            "lsst_users_membership": lsst_users_membership_check_access,
        }

    @staticmethod
    def validate(app, user_config):
        global logger
        Config.configure_plugins(app)
        defaults_file = os.path.join(os.path.dirname(__file__), "defaults.yaml")

        settings_module = f"{defaults_file},{user_config}"
        print(settings_module)
        dynaconf = FlaskDynaconf(app, SETTINGS_MODULE_FOR_DYNACONF=settings_module)
        settings = dynaconf.settings
        settings.validators.register(
            Validator("NO_VERIFY", "NO_AUTHORIZE", is_type_of=bool),
            Validator("GROUP_MAPPING", is_type_of=dict),
            Validator("ISSUERS", is_type_of=dict, must_exist=True),
        )

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
        logger.info(f"Configured WWW-Authenticate type: {settings['WWW_AUTHENTICATE']}")

        if settings["NO_VERIFY"]:
            logger.warning("Authentication verification is disabled")

        if settings["NO_AUTHORIZE"]:
            logger.warning("Authorization is disabled")

        if settings.get("GROUP_DEPLOYMENT_PREFIX"):
            logger.info(
                f"Configured LSST Group Deployment Prefix: "
                f"{settings['GROUP_DEPLOYMENT_PREFIX']}"
            )

        if settings.get("GROUP_MAPPING"):
            for key, value in settings["GROUP_MAPPING"].items():
                assert isinstance(key, str) and isinstance(value, str), "Mapping is malformed"
            logger.info(f"Configured Group Mapping: {settings['GROUP_MAPPING']}")

        if settings.get("OAUTH2_STORE_SESSION"):
            proxy_config = settings["OAUTH2_STORE_SESSION"]
            key_prefix = proxy_config["KEY_PREFIX"]
            secret = proxy_config["OAUTH2_PROXY_SECRET"]
            app.redis_pool = redis.ConnectionPool.from_url(url=proxy_config["REDIS_URL"])
            logger.info(
                f"Configured redis pool from url: {proxy_config['REDIS_URL']} "
                f"with prefix: {key_prefix}"
            )

        # Find Resource Check Callables
        for access_check_name in settings["ACCESS_CHECKS"]:
            if access_check_name not in app.ACCESS_CHECK_CALLABLES:
                raise Exception(f"No access checker for id {access_check_name}")
            logger.info(f"Configured default access checks: {access_check_name}")

        # Sections
        for issuer_url, issuer_info in settings["ISSUERS"].items():
            # if 'map_subject' in cp.options(section):
            #     issuer_info['map_subject'] = cp.getboolean(section, 'map_subject')
            logger.info(f"Configured token access for {issuer_url}: {issuer_info}")
        logger.info("Configured Issuers")
