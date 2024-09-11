"""Config dependency for FastAPI."""

from __future__ import annotations

import os
from pathlib import Path

from ..config import Config
from ..constants import CONFIG_PATH

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
        config_path = os.getenv("GAFAELFAWR_CONFIG_PATH", CONFIG_PATH)
        self._config_path = Path(config_path)
        self._config: Config | None = None

    async def __call__(self) -> Config:
        """Load the configuration if necessary and return it."""
        return self.config()

    @property
    def config_path(self) -> Path:
        """Path to the configuration file."""
        return self._config_path

    def config(self) -> Config:
        """Load the configuration if necessary and return it.

        This is equivalent to using the dependency as a callable except that
        it's not async and can therefore be used from non-async functions.
        """
        if not self._config:
            self._config = Config.from_file(self._config_path)
            self._config.configure_logging()
        return self._config

    def set_config_path(self, path: Path) -> None:
        """Change the configuration path and reload the config.

        Parameters
        ----------
        path
            The new configuration path.
        """
        self._config_path = path
        self._config = Config.from_file(path)
        self._config.configure_logging()


config_dependency = ConfigDependency()
"""The dependency that will return the current configuration."""
