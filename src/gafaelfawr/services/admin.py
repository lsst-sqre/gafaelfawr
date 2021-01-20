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
        """Add a new administrator.

        Parameters
        ----------
        username : `str`
            The administrator to delete.
        actor : `str`
            The person doing the deleting.
        ip_address : `str`
            The IP address from which the request came.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            If the actor is not an admin.
        """
        if not self.is_admin(actor) and actor != "<bootstrap>":
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

    def delete_admin(
        self, username: str, *, actor: str, ip_address: str
    ) -> bool:
        """Delete an administrator.

        Parameters
        ----------
        username : `str`
            The administrator to delete.
        actor : `str`
            The person doing the deleting.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        success : `bool`
            `True` if the administrator was found and deleted, `False` if they
            were not found.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            If the actor is not an admin.
        """
        if not self.is_admin(actor) and actor != "<bootstrap>":
            raise PermissionDeniedError(f"{actor} is not an admin")
        admin = Admin(username=username)
        history_entry = AdminHistoryEntry(
            username=username,
            action=AdminChange.remove,
            actor=actor,
            ip_address=ip_address,
            event_time=datetime.now(timezone.utc),
        )
        with self._transaction_manager.transaction():
            if self.get_admins() == [admin]:
                raise PermissionDeniedError("Cannot delete the last admin")
            result = self._admin_store.delete(admin)
            if result:
                self._admin_history_store.add(history_entry)
        return result

    def get_admins(self) -> List[Admin]:
        """Get the current administrators."""
        return self._admin_store.list()

    def is_admin(self, username: str) -> bool:
        """Returns whether the given user is a token administrator."""
        return any((username == a.username for a in self.get_admins()))
