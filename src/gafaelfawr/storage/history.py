"""Storage for change and authentication history."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.schema import AdminHistory

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from gafaelfawr.models.history import AdminHistoryEntry

__all__ = ["AdminHistoryStore"]


class AdminHistoryStore:
    """Stores and retrieves the history of changes to token administrators.

    Parameters
    ----------
    session : `sqlalchemy.orm.Session`
        The underlying database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, entry: AdminHistoryEntry) -> None:
        """Record a change to the token administrators."""
        new = AdminHistory(**entry.dict())
        self._session.add(new)
