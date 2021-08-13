"""Redis dependency for FastAPI."""

from typing import TYPE_CHECKING

from aioredis import Redis
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
            self.redis = Redis.from_url(
                config.redis_url, password=config.redis_password
            )
        assert self.redis
        return self.redis

    async def close(self) -> None:
        """Close the open Redis pool.

        Should be called from a shutdown hook to ensure that the Redis clients
        are cleanly shut down and any pending writes are complete.
        """
        if self.redis and not self.is_mocked:
            await self.redis.close()
            await self.redis.connection_pool.disconnect()
            self.redis = None

    def set_redis(self, redis: Redis) -> None:
        """Set the Redis object returned by ``__call__``.

        Used to inject a mock.
        """
        self.redis = redis
        self.is_mocked = True


redis_dependency = RedisDependency()
"""The dependency that will return the Redis pool."""
