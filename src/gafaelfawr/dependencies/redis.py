"""Redis dependency for FastAPI."""

from typing import TYPE_CHECKING

from aioredis import Redis, create_redis_pool
from fastapi import Depends

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["RedisDependency", "redis_dependency"]


class RedisDependency:
    """Provides an aioredis pool as a dependency.

    Notes
    -----
    Creation of the Redis pool has to be deferred until the configuration has
    been loaded, which in turn is deferred for the first request.  We also
    want to provide an opportunity for the test suite to tell it to use a
    mockaioredis pool instead.  Do this by deferring creation of the pool
    until the first time the dependency is called.
    """

    def __init__(self) -> None:
        self.redis: Optional[Redis] = None
        self.is_mocked = False

    async def __call__(
        self, config: Config = Depends(config_dependency)
    ) -> Redis:
        """Creates the Redis pool if necessary and returns it."""
        if not self.redis:
            await self._create_pool(config)
        assert self.redis
        return self.redis

    async def close(self) -> None:
        """Close the open Redis pool.

        Should be called from a shutdown hook to ensure that the Redis clients
        are cleanly shut down and any pending writes are complete.
        """
        if self.redis:
            self.redis.close()
            await self.redis.wait_closed()
            self.redis = None

    async def _create_pool(self, config: Config) -> None:
        """Creates the Redis pool, honoring ``is_mocked``."""
        if self.is_mocked:
            import mockaioredis

            self.redis = await mockaioredis.create_redis_pool("")
        else:
            self.redis = await create_redis_pool(
                config.redis_url, password=config.redis_password
            )


redis_dependency = RedisDependency()
"""The dependency that will return the Redis pool."""
