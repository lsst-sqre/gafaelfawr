"""Config dependency for FastAPI."""

from typing import TYPE_CHECKING

from gafaelfawr.config import Config
from gafaelfawr.constants import CONFIG_PATH

if TYPE_CHECKING:
    from typing import Optional


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
        self.config_path = CONFIG_PATH
        self.config: Optional[Config] = None

    def __call__(self) -> Config:
        """Load the configuration if necessary and return it."""
        if not self.config:
            self._load_config()
        assert self.config
        return self.config

    def set_config_path(self, path: str) -> None:
        """Change the configuration path and reload the config.

        Parameters
        ----------
        path : `str`
            The new configuration path.
        """
        self.config_path = path
        self._load_config()

    def _load_config(self) -> None:
        """Load the configuration from the currently-configured path."""
        self.config = Config.from_file(self.config_path)


config_dependency = ConfigDependency()
