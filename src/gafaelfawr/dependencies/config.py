"""Config dependency for FastAPI."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from gafaelfawr.config import Config
from gafaelfawr.constants import SETTINGS_PATH

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["ConfigDependency", "config_dependency"]


class ConfigDependency:
    """Provides the configuration as a dependency.

    We want a production deployment to default to one configuration path, but
    allow that path to be overridden by the test suite and, if the path
    changes, to reload the configuration (which allows sharing the same set of
    global singletons across multiple tests).  Do this by loading the config
    dynamically when it's first requested and reloading it whenever the
    configuration path is changed.
    """

    def __init__(self) -> None:
        self._settings_path = os.getenv(
            "GAFAELFAWR_SETTINGS_PATH", SETTINGS_PATH
        )
        self._config: Optional[Config] = None

    def __call__(self) -> Config:
        """Load the configuration if necessary and return it."""
        if not self._config:
            self._load_config()
        assert self._config
        return self._config

    def set_settings_path(self, path: str) -> None:
        """Change the settings path and reload the config.

        Parameters
        ----------
        path : `str`
            The new configuration path.
        """
        self._settings_path = path
        self._load_config()

    def _load_config(self) -> None:
        """Load the configuration from the currently-configured path."""
        self._config = Config.from_file(self._settings_path)


config_dependency = ConfigDependency()
"""The dependency that will return the current configuration."""
