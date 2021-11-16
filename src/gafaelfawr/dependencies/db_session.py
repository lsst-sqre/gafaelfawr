"""Manage an async database session."""

from typing import AsyncIterator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker

__all__ = ["DatabaseSessionDependency", "db_session_dependency"]


class DatabaseSessionDependency:
    """Manages an async per-request SQLAlchemy session.

    Notes
    -----
    Creation of the database session factory has to be deferred until the
    configuration has been loaded, which in turn is deferred until app
    startup.  An app that uses this dependency must call:

    .. code-block:: python

       await db_session_dependency.initialize(database_url)

    from its startup hook and:

    .. code-block:: python

       await db_session_dependency.aclose()

    from its shutdown hook.
    """

    def __init__(self) -> None:
        self._engine: Optional[AsyncEngine] = None
        self._factory: Optional[sessionmaker] = None

    async def __call__(self) -> AsyncIterator[AsyncSession]:
        """Create a database session and open a transaction.

        This implements a policy of one request equals one transaction, which
        is closed when that request returns.

        Returns
        -------
        session : `sqlalchemy.ext.asyncio.AsyncSession`
            The newly-created session.

        Notes
        -----
        This creates a new session for every request rather than using
        `~sqlalchemy.ext.asyncio.async_scoped_session`.  Experiments with the
        latter showed that it added unwanted complexity around cleanup during
        shutdown (it was hard to find all of the sessions to close them
        cleanly, so test shutdown produced asyncpg warnings), and (at least as
        of SQLAlchemy 1.4.27) the ``close_all`` method on an
        `~sqlalchemy.ext.asyncio.AsyncSession` does not work.

        This can be revisited if creating a session each time causes
        performance issues, but the session shares an underlying engine and
        thus connection pool so hopefully this won't be an issue.
        """
        assert self._factory, "db_session_dependency not initialized"
        async with self._factory() as session:
            async with session.begin():
                yield session

    async def aclose(self) -> None:
        """Shut down the database engine."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None

    async def initialize(self, url: str) -> None:
        """Initialize the session dependency.

        Parameters
        ----------
        url : `str`
            The URL for the database.  Must include any required password.
        """
        self._engine = create_async_engine(url, future=True)
        self._factory = sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )


db_session_dependency = DatabaseSessionDependency()
"""The dependency that will return the async session proxy."""
