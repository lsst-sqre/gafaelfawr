"""Manage the configured token administrators."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.history import AdminChange, AdminHistoryEntry
from gafaelfawr.storage.admin import AdminStore
from gafaelfawr.storage.history import AdminHistoryStore

__all__ = ["AdminService"]


class AdminService:
    """Manage the token administrators.

    Parameters
    ----------
    admin_store : `gafaelfawr.storage.admin.AdminStore`
        The backing store for token administrators.
    admin_history_store : `gafaelfawr.storage.history.AdminHistoryStore`
        The backing store for history of changes to token administrators.
    """

    def __init__(
        self, admin_store: AdminStore, admin_history_store: AdminHistoryStore
    ) -> None:
        self._admin_store = admin_store
        self._admin_history_store = admin_history_store

    async def add_admin(
        self, username: str, *, actor: str, ip_address: str
    ) -> None:
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
        if not await self.is_admin(actor) and actor != "<bootstrap>":
            raise PermissionDeniedError(f"{actor} is not an admin")
        admin = Admin(username=username)
        history_entry = AdminHistoryEntry(
            username=username,
            action=AdminChange.add,
            actor=actor,
            ip_address=ip_address,
            event_time=datetime.now(timezone.utc),
        )
        await self._admin_store.add(admin)
        await self._admin_history_store.add(history_entry)

    async def delete_admin(
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
        if not await self.is_admin(actor) and actor != "<bootstrap>":
            raise PermissionDeniedError(f"{actor} is not an admin")
        admin = Admin(username=username)
        history_entry = AdminHistoryEntry(
            username=username,
            action=AdminChange.remove,
            actor=actor,
            ip_address=ip_address,
            event_time=datetime.now(timezone.utc),
        )
        if await self.get_admins() == [admin]:
            raise PermissionDeniedError("Cannot delete the last admin")
        result = await self._admin_store.delete(admin)
        if result:
            await self._admin_history_store.add(history_entry)
        return result

    async def get_admins(self) -> List[Admin]:
        """Get the current administrators."""
        return await self._admin_store.list()

    async def is_admin(self, username: str) -> bool:
        """Returns whether the given user is a token administrator."""
        return any((username == a.username for a in await self.get_admins()))
