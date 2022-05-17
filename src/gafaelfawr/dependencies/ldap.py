"""LDAP connection pool dependency for FastAPI."""

from typing import Optional

from bonsai import LDAPClient
from bonsai.asyncio import AIOConnectionPool
from fastapi import Depends

from ..config import Config
from .config import config_dependency

__all__ = ["LDAPPoolDependency", "ldap_pool_dependency"]


class LDAPPoolDependency:
    """Provides a bonsai LDAP connection pool as a dependency.

    Notes
    -----
    Creation of the Redis pool has to be deferred until the configuration has
    been loaded, which in turn is deferred for the first request.  This is
    done on the first request instead of from the startup hook since, when
    testing, the startup hook runs before Gafaelfawr has been reconfigured by
    the test to use an LDAP configuration.
    """

    def __init__(self) -> None:
        self._pool: Optional[AIOConnectionPool] = None

    async def __call__(
        self, config: Config = Depends(config_dependency)
    ) -> Optional[AIOConnectionPool]:
        """Creates the LDAP connection pool if necessary and returns it."""
        if not self._pool and config.ldap:
            client = LDAPClient(config.ldap.url)
            if config.ldap.user_dn and config.ldap.password:
                client.set_credentials(
                    "SIMPLE",
                    user=config.ldap.user_dn,
                    password=config.ldap.password,
                )
            self._pool = AIOConnectionPool(client)
        return self._pool

    async def aclose(self) -> None:
        """Close the LDAP connection pool.

        Should be called from a shutdown hook to ensure that the connection
        pool is cleanly shut down.
        """
        if self._pool:
            await self._pool.close()
            self._pool = None


ldap_pool_dependency = LDAPPoolDependency()
"""The dependency that will return the LDAP connection pool."""
