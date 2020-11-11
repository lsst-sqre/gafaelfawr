"""Storage for token administrators."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.models.admin import Admin
from gafaelfawr.schema import Admin as SQLAdmin

if TYPE_CHECKING:
    from typing import List

    from sqlalchemy.orm import Session

__all__ = ["AdminStore"]


class AdminStore:
    """Stores and retrieves token administrators.

    Parameters
    ----------
    session : `sqlalchemy.orm.Session`
        The underlying database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, admin: Admin) -> None:
        """Add a new token administrator."""
        new = SQLAdmin(username=admin.username)
        self._session.add(new)

    def list(self) -> List[Admin]:
        """Return a list of current administrators."""
        return [
            Admin.from_orm(a)
            for a in self._session.query(SQLAdmin)
            .order_by(SQLAdmin.username)
            .all()
        ]
