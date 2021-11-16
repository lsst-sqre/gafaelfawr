"""Storage for token administrators."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from sqlalchemy import delete
from sqlalchemy.engine import CursorResult
from sqlalchemy.future import select

from gafaelfawr.models.admin import Admin
from gafaelfawr.schema import Admin as SQLAdmin

if TYPE_CHECKING:
    from typing import List

    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["AdminStore"]


class AdminStore:
    """Stores and retrieves token administrators.

    Parameters
    ----------
    session : `sqlalchemy.ext.asyncio.AsyncSession`
        The database session proxy.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, admin: Admin) -> None:
        """Add a new token administrator."""
        new = SQLAdmin(username=admin.username)
        self._session.add(new)

    async def delete(self, admin: Admin) -> bool:
        """Delete an administrator.

        Parameters
        ----------
        admin : `gafaelfawr.models.admin.Admin`
            The administrator to delete.

        Returns
        -------
        result : `bool`
            `True` if the administrator was found and deleted, `False`
            otherwise.
        """
        stmt = delete(SQLAdmin).where(SQLAdmin.username == admin.username)
        result = cast(CursorResult, await self._session.execute(stmt))
        return result.rowcount > 0

    async def list(self) -> List[Admin]:
        """Return a list of current administrators."""
        stmt = select(SQLAdmin).order_by(SQLAdmin.username)
        result = await self._session.scalars(stmt)
        return [Admin.from_orm(a) for a in result.all()]
