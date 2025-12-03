"""Storage for token administrators."""

from __future__ import annotations

from typing import cast

from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import async_scoped_session

from ..models.admin import Admin
from ..schema import Admin as SQLAdmin

__all__ = ["AdminStore"]


class AdminStore:
    """Stores and retrieves token administrators.

    Parameters
    ----------
    session
        The database session proxy.
    """

    def __init__(self, session: async_scoped_session) -> None:
        self._session = session

    async def add(self, admin: Admin) -> None:
        """Add a new token administrator.

        Parameters
        ----------
        admin
            The administrator to add.
        """
        new = SQLAdmin(username=admin.username)
        self._session.add(new)

    async def delete(self, admin: Admin) -> bool:
        """Delete an administrator.

        Parameters
        ----------
        admin
            The administrator to delete.

        Returns
        -------
        bool
            `True` if the administrator was found and deleted, `False`
            otherwise.
        """
        stmt = delete(SQLAdmin).where(SQLAdmin.username == admin.username)

        # See https://github.com/sqlalchemy/sqlalchemy/issues/9185
        # and https://github.com/sqlalchemy/sqlalchemy/issues/12813
        result = cast("CursorResult", await self._session.execute(stmt))
        return result.rowcount > 0

    async def list(self) -> list[Admin]:
        """Return a list of current administrators.

        Returns
        -------
        list of Admin
            Current administrators.
        """
        stmt = select(SQLAdmin).order_by(SQLAdmin.username)
        result = await self._session.scalars(stmt)
        return [
            Admin.model_validate(a, from_attributes=True) for a in result.all()
        ]
