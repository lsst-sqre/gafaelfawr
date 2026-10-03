"""Database utility functions for Gafaelfawr."""

import asyncio
from abc import ABCMeta, abstractmethod
from types import TracebackType
from typing import Any, Literal, override

from alembic import context
from google.cloud.sql.connector import Connector, create_async_connector
from safir.database import initialize_database
from sqlalchemy import MetaData, create_mock_engine, select
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from structlog.stdlib import BoundLogger

from .config import Config
from .factory import Factory
from .models.database import CloudSqlSettings, DatabaseSettings
from .schema import SchemaBase, Token

__all__ = [
    "CloudSqlEngineManager",
    "DatabaseEngineManager",
    "EngineManager",
    "engine_manager",
    "generate_schema_sql",
    "initialize_gafaelfawr_database",
    "is_database_initialized",
    "run_migrations_online",
]


class EngineManager(metaclass=ABCMeta):
    """Base class for database engine management.

    Parameters
    ----------
    connect_args
        Additional connection arguments to pass directly to the underlying
        database driver.
    """

    def __init__(self, connect_args: dict[str, Any] | None) -> None:
        self._connect_args = connect_args
        self._engine: AsyncEngine | None = None

    async def __aenter__(self) -> AsyncEngine:
        return await self.create_engine()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        await self.aclose()
        return False

    async def aclose(self) -> None:
        """Close the engine and all associated resources."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None

    @abstractmethod
    async def create_engine(self) -> AsyncEngine:
        """Create a new database engine.

        Prefer using this class as a context manager instead where possible.
        If this method is used, the caller must call `aclose` on this object
        when the engine is no longer needed rather than calling the
        `~AsyncEngine.dispose` method directly.

        Returns
        -------
        AsyncEngine
            Newly-created database engine.
        """


class CloudSqlEngineManager(EngineManager):
    """Manages a Cloud SQL database engine and its associated resources.

    This class should be created via `DatabaseManager.engine_manager`, not
    directly.

    Parameters
    ----------
    config
        Connection configuration for the Cloud SQL database.
    connect_args
        Additional connection arguments to pass directly to the underlying
        database driver.
    """

    def __init__(
        self, config: CloudSqlSettings, connect_args: dict[str, Any] | None
    ) -> None:
        super().__init__(connect_args)
        self._config = config
        self._connector: Connector | None = None

    @override
    async def aclose(self) -> None:
        if self._connector:
            await self._connector.close_async()
            self._connector = None
        await super().aclose()

    @override
    async def create_engine(self) -> AsyncEngine:
        if self._engine:
            raise RuntimeError("Call aclose before creating another engine")
        connector = await create_async_connector(enable_iam_auth=True)
        kwargs = self._config.engine_kwargs(self._connect_args)
        async_creator = connector.connect_async(
            self._config.instance_connection_name,
            "asyncpg",
            user=self._config.user,
            db=self._config.database,
            **kwargs,
        )
        url = "postgres+asyncpg://"
        try:
            engine = create_async_engine(url, async_creator=async_creator)
        except Exception:
            await connector.close_async()
            raise
        self._connector = connector
        self._engine = engine
        return engine


class DatabaseEngineManager(EngineManager):
    """Manages a database engine and its associated resources.

    This class should be created via `DatabaseManager.engine_manager`, not
    directly.

    Parameters
    ----------
    config
        Connection configuration for the database.
    connect_args
        Additional connection arguments to pass directly to the underlying
        database driver.
    """

    def __init__(
        self, config: DatabaseSettings, connect_args: dict[str, Any] | None
    ) -> None:
        super().__init__(connect_args)
        self._config = config

    @override
    async def create_engine(self) -> AsyncEngine:
        if self._engine:
            raise RuntimeError("Call aclose before creating another engine")
        kwargs = self._config.engine_kwargs(self._connect_args)
        self._engine = create_async_engine(self._config.build_url(), **kwargs)
        return self._engine


def engine_manager(
    config: CloudSqlSettings | DatabaseSettings,
    connect_args: dict[str, Any] | None = None,
) -> EngineManager:
    """Create a database engine manager.

    config
        Database connection configuration.
    connect_args
        Additional connection arguments to pass directly to the underlying
        database driver.

    Returns
    -------
    EngineManager
        Engine manager that can be used to create an engine and clean up its
        associated resources when the caller is finished with the engine.
    """
    match config:
        case CloudSqlSettings():
            return CloudSqlEngineManager(config, connect_args)
        case DatabaseSettings():
            return DatabaseEngineManager(config, connect_args)


def generate_schema_sql(config: Config) -> str:
    """Generate SQL for the Gafaelfawr databsae schema.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    """
    result = ""

    def dump(sql: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal result
        result += str(sql.compile(dialect=engine.dialect)) + ";\n"

    engine = create_mock_engine(config.database.mock_url, dump)
    SchemaBase.metadata.create_all(engine, checkfirst=False)
    return result


async def initialize_gafaelfawr_database(
    config: Config,
    logger: BoundLogger,
    engine: AsyncEngine | None = None,
    *,
    reset: bool = False,
) -> None:
    """Initialize the database.

    This is the internal async implementation details of the ``init`` command,
    except for the Alembic parts. Alembic has to run outside of a running
    asyncio loop, hence this separation. Always stamp the database with
    Alembic after calling this function.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    logger
        Logger to use for status reporting.
    engine
        If given, database engine to use, which avoids the need to create
        another one.
    reset
        Whether to reset the database.
    """
    schema = SchemaBase.metadata

    async def initialize(engine: AsyncEngine) -> None:
        await initialize_database(engine, logger, schema=schema, reset=reset)
        if config.firestore:
            async with Factory.standalone(config, engine) as factory:
                firestore = factory.create_firestore_storage()
                logger.debug("Initializing Firestore")
                await firestore.initialize()

    if not engine:
        async with engine_manager(config.database) as tmp_engine:
            await initialize(tmp_engine)
    else:
        await initialize(engine)


async def is_database_initialized(
    config: Config, logger: BoundLogger, engine: AsyncEngine | None = None
) -> bool:
    """Check whether the database has been initialized.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    logger
        Logger to use for status reporting.
    engine
        If given, database engine to use, which avoids the need to create
        another one.

    Returns
    -------
    bool
        `True` if some Gafaelfawr schema (possibly out of date) appears to
        exist, `False` otherwise. This may misdetect partial schemas that
        contain some tables and not others or that are missing indices.
    """
    statement = select(Token).limit(1)

    async def check(engine: AsyncEngine) -> bool:
        try:
            for _ in range(5):
                try:
                    async with engine.begin() as connection:
                        await connection.execute(statement)
                        return True
                except ConnectionRefusedError, OperationalError, OSError:
                    logger.info("database not ready, waiting two seconds")
                    await asyncio.sleep(2)
                    continue

            # If we got here, we failed five times. Try one more time to
            # generate a proper exception.
            async with engine.begin() as connection:
                await connection.execute(statement)
                return True
        except ProgrammingError:
            logger.info("Database appears not to be initialized")
            return False

    if not engine:
        async with engine_manager(config.database) as tmp_engine:
            return await check(tmp_engine)
    else:
        return await check(engine)


def run_migrations_online(
    metadata: MetaData, config: CloudSqlSettings | DatabaseSettings
) -> None:
    """Run Alembic migrations online using an async backend.

    This function may only be called from the Alembic :file:`env.py` file.

    Parameters
    ----------
    metadata
        Schema metadata object for the current schema.
    config
        Database connection configuration.

    Examples
    --------
    Normally this is called from :file:`alembic/env.py` with code similar to
    the following:

    .. code-block:: python

       from alembic import context
       from safir.database import run_migrations_offline

       from example.config import config
       from example.schema import SchemaBase

       if not context.is_offline_mode():
           run_migrations_online(SchemaBase.metadata, config)
    """

    def do_migrations(connection: Connection) -> None:
        context.configure(connection=connection, target_metadata=metadata)
        with context.begin_transaction():
            context.run_migrations()

    async def run_async_migrations() -> None:
        async with engine_manager(config) as engine:
            async with engine.connect() as connection:
                await connection.run_sync(do_migrations)

    asyncio.run(run_async_migrations())
