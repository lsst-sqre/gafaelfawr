"""Redis dependency for FastAPI."""

from typing import Optional

from aioredis import Redis
from fastapi import Depends

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency

__all__ = ["RedisDependency", "redis_dependency"]


class RedisDependency:
    """Provides an aioredis pool as a dependency.

    Notes
    -----
    Creation of the Redis pool has to be deferred until the configuration has
    been loaded, which in turn is deferred for the first request.
    """

    def __init__(self) -> None:
        self.redis: Optional[Redis] = None

    async def __call__(
        self, config: Config = Depends(config_dependency)
    ) -> Redis:
        """Creates the Redis pool if necessary and returns it."""
        if not self.redis:
            password = config.redis_password
            self.redis = Redis.from_url(config.redis_url, password=password)
        assert self.redis
        return self.redis

    async def aclose(self) -> None:
        """Close the open Redis pool.

        Should be called from a shutdown hook to ensure that the Redis clients
        are cleanly shut down and any pending writes are complete.
        """
        if self.redis:
            await self.redis.close()
            await self.redis.connection_pool.disconnect()
            self.redis = None


redis_dependency = RedisDependency()
"""The dependency that will return the Redis pool."""
