"""Config dependency for FastAPI."""

from safir.dependencies.config import ConfigDependency

from ..config import Config
from ..constants import CONFIG_PATH

__all__ = ["config_dependency"]

config_dependency = ConfigDependency(
    Config, CONFIG_PATH, "GAFAELFAWR_CONFIG_PATH"
)
"""The dependency that will return the current configuration."""
