"""Manage the configured token administrators."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from structlog.stdlib import BoundLogger

from ..exceptions import PermissionDeniedError
from ..models.admin import Admin
from ..models.history import AdminChange, AdminHistoryEntry
from ..storage.admin import AdminStore
from ..storage.history import AdminHistoryStore

__all__ = ["AdminService"]


class AdminService:
    """Manage the token administrators.

    Parameters
    ----------
    admin_store
        The backing store for token administrators.
    admin_history_store
        The backing store for history of changes to token administrators.
    logger
        Logger to use for messages.
    """

    def __init__(
        self,
        admin_store: AdminStore,
        admin_history_store: AdminHistoryStore,
        logger: BoundLogger,
    ) -> None:
        self._admin_store = admin_store
        self._admin_history_store = admin_history_store
        self._logger = logger

    async def add_admin(
        self, username: str, *, actor: str, ip_address: str
    ) -> None:
        """Add a new administrator.

        Parameters
        ----------
        username
            The administrator to delete.
        actor
            The person doing the deleting.
        ip_address
            The IP address from which the request came.

        Raises
        ------
        PermissionDeniedError
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
        self._logger.info(f"Added admin {admin.username}")

    async def add_initial_admins(self, admins: Iterable[str]) -> None:
        """Add the initial admins if the database is not initialized.

        This should be called after database initialization to add the
        configured initial admins.  The admin list will only be changed if it
        is currently empty.

        Parameters
        ----------
        admins
            Usernames of initial admins.
        """
        if not await self._admin_store.list():
            for admin in admins:
                self._logger.info(f"Adding initial admin {admin}")
                await self._admin_store.add(Admin(username=admin))

    async def delete_admin(
        self, username: str, *, actor: str, ip_address: str
    ) -> bool:
        """Delete an administrator.

        Parameters
        ----------
        username
            The administrator to delete.
        actor
            The person doing the deleting.
        ip_address
            The IP address from which the request came.

        Returns
        -------
        bool
            `True` if the administrator was found and deleted, `False` if they
            were not found.

        Raises
        ------
        PermissionDeniedError
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
            self._logger.info(f"Deleted admin {username}")
        return result

    async def get_admins(self) -> list[Admin]:
        """Get the current administrators."""
        return await self._admin_store.list()

    async def is_admin(self, username: str) -> bool:
        """Returns whether the given user is a token administrator.

        Parameters
        ----------
        username
            Username to check.
        """
        return any((username == a.username for a in await self.get_admins()))
