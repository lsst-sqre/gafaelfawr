"""Storage for change and authentication history."""

from __future__ import annotations

from datetime import datetime

from safir.database import (
    CountedPaginatedList,
    CountedPaginatedQueryRunner,
    datetime_to_db,
)
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import async_scoped_session
from sqlalchemy.sql import Select, text

from ..models.enums import TokenType
from ..models.history import (
    AdminHistoryEntry,
    TokenChangeHistoryCursor,
    TokenChangeHistoryEntry,
    TokenChangeHistoryRecord,
)
from ..schema import AdminHistory, TokenChangeHistory

__all__ = ["AdminHistoryStore", "TokenChangeHistoryStore"]


class AdminHistoryStore:
    """Stores and retrieves the history of changes to token administrators.

    Parameters
    ----------
    session
        The database session proxy.
    """

    def __init__(self, session: async_scoped_session) -> None:
        self._session = session

    async def add(self, entry: AdminHistoryEntry) -> None:
        """Record a change to the token administrators.

        Parameters
        ----------
        entry
            The change to record.
        """
        new = AdminHistory(**entry.model_dump())
        new.event_time = datetime_to_db(entry.event_time)
        self._session.add(new)


class TokenChangeHistoryStore:
    """Stores and retrieves the history of changes to tokens.

    Parameters
    ----------
    session
        The database session proxy.
    """

    def __init__(self, session: async_scoped_session) -> None:
        self._session = session
        self._paginated_runner = CountedPaginatedQueryRunner(
            TokenChangeHistoryRecord, TokenChangeHistoryCursor
        )

    async def add(self, entry: TokenChangeHistoryEntry) -> None:
        """Record a change to a token.

        Parameters
        ----------
        entry
            New entry to add to the database.
        """
        entry_dict = entry.model_dump()

        # Convert the lists of scopes to the empty string for an empty list
        # and a comma-separated string otherwise.
        entry_dict["scopes"] = ",".join(sorted(entry.scopes))
        if entry.old_scopes is not None:
            entry_dict["old_scopes"] = ",".join(sorted(entry.old_scopes))

        new = TokenChangeHistory(**entry_dict)
        new.expires = datetime_to_db(entry.expires)
        new.old_expires = datetime_to_db(entry.old_expires)
        new.event_time = datetime_to_db(entry.event_time)
        self._session.add(new)

    async def delete(self, *, older_than: datetime) -> None:
        """Delete older entries.

        Parameters
        ----------
        older_than
            Delete entries created prior to this date.
        """
        stmt = delete(TokenChangeHistory).where(
            TokenChangeHistory.event_time < datetime_to_db(older_than)
        )
        await self._session.execute(stmt)

    async def list(
        self,
        *,
        cursor: TokenChangeHistoryCursor | None = None,
        limit: int | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        username: str | None = None,
        actor: str | None = None,
        key: str | None = None,
        token: str | None = None,
        token_type: TokenType | None = None,
        ip_or_cidr: str | None = None,
    ) -> CountedPaginatedList[
        TokenChangeHistoryRecord, TokenChangeHistoryCursor
    ]:
        """Return all changes to a specific token.

        Parameters
        ----------
        cursor
            A pagination cursor specifying where to start in the results.
        limit
            Limit the number of returned results.
        since
            Limit the results to events at or after this time.
        until
            Limit the results to events before or at this time.
        username
            Limit the results to tokens owned by this user.
        actor
            Limit the results to actions performed by this user.
        key
            Limit the results to this token and any subtokens of this token.
            Note that this will currently pick up direct subtokens but not
            subtokens of subtokens.
        token
            Limit the results to only this token.
        token_type
            Limit the results to tokens of this type.
        ip_or_cidr
            Limit the results to changes made from this IPv4 or IPv6 address
            or CIDR block.  Unless the underlying database is PostgreSQL, the
            CIDR block must be on an octet boundary.

        Returns
        -------
        safir.database.CountedPaginatedList of TokenChangeHistoryEntry
            List of change history entries, which may be empty.
        """
        stmt = select(TokenChangeHistory)
        if since:
            since = datetime_to_db(since)
            stmt = stmt.where(TokenChangeHistory.event_time >= since)
        if until:
            until = datetime_to_db(until)
            stmt = stmt.where(TokenChangeHistory.event_time <= until)
        if username:
            stmt = stmt.where(TokenChangeHistory.username == username)
        if actor:
            stmt = stmt.where(TokenChangeHistory.actor == actor)
        if key:
            stmt = stmt.where(
                or_(
                    TokenChangeHistory.token == key,
                    TokenChangeHistory.parent == key,
                )
            )
        if token:
            stmt = stmt.where(TokenChangeHistory.token == token)
        if token_type:
            stmt = stmt.where(TokenChangeHistory.token_type == token_type)
        if ip_or_cidr:
            stmt = self._apply_ip_or_cidr_filter(stmt, ip_or_cidr)

        # Perform the paginated query.
        return await self._paginated_runner.query_object(
            self._session, stmt, cursor=cursor, limit=limit
        )

    def _apply_ip_or_cidr_filter(
        self, stmt: Select, ip_or_cidr: str
    ) -> Select:
        """Apply an appropriate filter for an IP or CIDR block.

        Notes
        -----
        If there is ever a need to support a database that does not have
        native CIDR membership queries, fallback code (probably using a LIKE
        expression) will need to be added here.
        """
        if "/" in ip_or_cidr:
            return stmt.where(text(":c >> ip_address")).params(c=ip_or_cidr)
        else:
            return stmt.where(TokenChangeHistory.ip_address == str(ip_or_cidr))
