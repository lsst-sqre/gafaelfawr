"""Manage the configured token administrators."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.history import AdminChange, AdminHistoryEntry

if TYPE_CHECKING:
    from typing import List

    from gafaelfawr.storage.admin import AdminStore
    from gafaelfawr.storage.history import AdminHistoryStore
    from gafaelfawr.storage.transaction import TransactionManager

__all__ = ["AdminService"]


class AdminService:
    """Manage the token administrators.

    Parameters
    ----------
    admin_store : `gafaelfawr.storage.admin.AdminStore`
        The backing store for token administrators.
    admin_history_store : `gafaelfawr.storage.history.AdminHistoryStore`
        The backing store for history of changes to token administrators.
    transaction_manager : `gafaelfawr.storage.transaction.TransactionManager`
        Database transaction manager.
    """

    def __init__(
        self,
        admin_store: AdminStore,
        admin_history_store: AdminHistoryStore,
        transaction_manager: TransactionManager,
    ) -> None:
        self._admin_store = admin_store
        self._admin_history_store = admin_history_store
        self._transaction_manager = transaction_manager

    def add_admin(self, username: str, *, actor: str, ip_address: str) -> None:
        """Add a new administrator."""
        if not self.is_admin(actor):
            raise PermissionDeniedError(f"{actor} is not an admin")
        admin = Admin(username=username)
        history_entry = AdminHistoryEntry(
            username=username,
            action=AdminChange.add,
            actor=actor,
            ip_address=ip_address,
            event_time=datetime.now(timezone.utc),
        )
        with self._transaction_manager.transaction():
            self._admin_store.add(admin)
            self._admin_history_store.add(history_entry)

    def get_admins(self) -> List[Admin]:
        """Get the current administrators."""
        return self._admin_store.list()

    def is_admin(self, username: str) -> bool:
        """Returns whether the given user is a token administrator."""
        return any((username == a.username for a in self.get_admins()))
