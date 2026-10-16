"""Manage an async database session."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

__all__ = ["DatabaseSessionDependency", "db_session_dependency"]


class DatabaseSessionDependency:
    """Manages an async per-request SQLAlchemy session."""

    def __init__(self) -> None:
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

    async def __call__(self) -> AsyncGenerator[AsyncSession]:
        """Return the database session manager.

        Returns
        -------
        sqlalchemy.ext.asyncio.AsyncSession
            The newly-created session.
        """
        if not self._sessionmaker:
            raise RuntimeError("db_session_dependency not initialized")
        async with self._sessionmaker() as session:
            yield session

    def initialize(self, engine: AsyncEngine) -> None:
        """Initialize the session dependency.

        Parameters
        ----------
        engine
            Database engine to use.
        """
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)


db_session_dependency = DatabaseSessionDependency()
"""The dependency that will return the async session proxy."""
