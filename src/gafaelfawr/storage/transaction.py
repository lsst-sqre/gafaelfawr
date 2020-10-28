"""Manage database transactions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Literal, Optional

    from sqlalchemy.orm import Session

__all__ = ["Transaction"]


class Transaction:
    """Returned by a TransactionManager as a context manager.

    This will automatically commit the transaction at the end of the context
    block and automatically roll back if there was an exception.

    Parameters
    ----------
    session : `sqlalchemy.orm.Session`
        The database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def __enter__(self) -> None:
        pass

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Optional[TracebackType],
    ) -> Literal[False]:
        if exc_type:
            self._session.rollback()
        else:
            self._session.commit()
        return False


class TransactionManager:
    """Manage SQL database transactions.

    Parameters
    ----------
    session : `sqlalchemy.orm.Session`
        The database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def transaction(self) -> Transaction:
        """Start a new transaction."""
        return Transaction(self._session)
