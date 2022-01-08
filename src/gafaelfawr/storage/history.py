"""Storage for change and authentication history."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import Select, text

from gafaelfawr.models.history import (
    AdminHistoryEntry,
    HistoryCursor,
    PaginatedHistory,
    TokenChangeHistoryEntry,
)
from gafaelfawr.models.token import TokenType
from gafaelfawr.schema import AdminHistory, TokenChangeHistory
from gafaelfawr.util import datetime_to_db, normalize_datetime

__all__ = ["AdminHistoryStore", "TokenChangeHistoryStore"]


class AdminHistoryStore:
    """Stores and retrieves the history of changes to token administrators.

    Parameters
    ----------
    session : `sqlalchemy.ext.asyncio.AsyncSession`
        The database session proxy.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entry: AdminHistoryEntry) -> None:
        """Record a change to the token administrators."""
        new = AdminHistory(**entry.dict())
        new.event_time = datetime_to_db(entry.event_time)
        self._session.add(new)


class TokenChangeHistoryStore:
    """Stores and retrieves the history of changes to tokens.

    Parameters
    ----------
    session : `sqlalchemy.ext.asyncio.AsyncSession`
        The database session proxy.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entry: TokenChangeHistoryEntry) -> None:
        """Record a change to a token."""
        entry_dict = entry.dict()

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

    async def list(
        self,
        *,
        cursor: Optional[HistoryCursor] = None,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        username: Optional[str] = None,
        actor: Optional[str] = None,
        key: Optional[str] = None,
        token: Optional[str] = None,
        token_type: Optional[TokenType] = None,
        ip_or_cidr: Optional[str] = None,
    ) -> PaginatedHistory[TokenChangeHistoryEntry]:
        """Return all changes to a specific token.

        Parameters
        ----------
        cursor : `gafaelfawr.models.history.HistoryCursor`, optional
            A pagination cursor specifying where to start in the results.
        limit : `int`, optional
            Limit the number of returned results.
        since : `datetime.datetime`, optional
            Limit the results to events at or after this time.
        until : `datetime.datetime`, optional
            Limit the results to events before or at this time.
        username : `str`, optional
            Limit the results to tokens owned by this user.
        actor : `str`, optional
            Limit the results to actions performed by this user.
        key : `str`, optional
            Limit the results to this token and any subtokens of this token.
            Note that this will currently pick up direct subtokens but not
            subtokens of subtokens.
        token : `str`, optional
            Limit the results to only this token.
        token_type : `gafaelfawr.models.token.TokenType`, optional
            Limit the results to tokens of this type.
        ip_or_cidr : `str`, optional
            Limit the results to changes made from this IPv4 or IPv6 address
            or CIDR block.  Unless the underlying database is PostgreSQL, the
            CIDR block must be on an octet boundary.

        Returns
        -------
        entries : List[`gafaelfawr.models.history.TokenChangeHistoryEntry`]
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

        # Shunt the complicated case of a paginated query to a separate
        # function to keep the logic more transparent.
        if cursor or limit:
            return await self._paginated_query(stmt, cursor, limit)

        # Perform the query and return the results.
        stmt = stmt.order_by(
            TokenChangeHistory.event_time.desc(), TokenChangeHistory.id.desc()
        )
        result = await self._session.scalars(stmt)
        entries = result.all()
        history = PaginatedHistory[TokenChangeHistoryEntry](
            entries=[TokenChangeHistoryEntry.from_orm(e) for e in entries],
            count=len(entries),
            prev_cursor=None,
            next_cursor=None,
        )
        return history

    async def _paginated_query(
        self,
        stmt: Select,
        cursor: Optional[HistoryCursor],
        limit: Optional[int],
    ) -> PaginatedHistory[TokenChangeHistoryEntry]:
        """Run a paginated query (one with a limit or a cursor)."""
        limited_stmt = stmt

        # Apply the cursor, if there is one.
        if cursor:
            limited_stmt = self._apply_cursor(limited_stmt, cursor)

        # When retrieving a previous set of results using a previous
        # cursor, we have to reverse the sort algorithm so that the cursor
        # boundary can be applied correctly.  We'll then later reverse the
        # result set to return it in proper forward-sorted order.
        if cursor and cursor.previous:
            limited_stmt = limited_stmt.order_by(
                TokenChangeHistory.event_time, TokenChangeHistory.id
            )
        else:
            limited_stmt = limited_stmt.order_by(
                TokenChangeHistory.event_time.desc(),
                TokenChangeHistory.id.desc(),
            )

        # Grab one more element than the query limit so that we know whether
        # to create a cursor (because there are more elements) and what the
        # cursor value should be (for forward cursors).
        if limit:
            limited_stmt = limited_stmt.limit(limit + 1)

        # Execute the query twice, once to get the next bach of results and
        # once to get the count of all entries without pagination.
        result = await self._session.scalars(limited_stmt)
        entries = result.all()
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count = await self._session.scalar(count_stmt)

        # Calculate the cursors, remove the extra element we asked for, and
        # reverse the results again if we did a reverse sort because we were
        # using a previous cursor.
        prev_cursor = None
        next_cursor = None
        if cursor and cursor.previous:
            if limit:
                next_cursor = HistoryCursor.invert(cursor)
                if len(entries) > limit:
                    prev_cursor = self._build_prev_cursor(entries[limit - 1])
                    entries = entries[:limit]
            entries.reverse()
        elif limit:
            if cursor:
                prev_cursor = HistoryCursor.invert(cursor)
            if len(entries) > limit:
                next_cursor = self._build_next_cursor(entries[limit])
                entries = entries[:limit]

        # Return the results.
        return PaginatedHistory[TokenChangeHistoryEntry](
            entries=[TokenChangeHistoryEntry.from_orm(e) for e in entries],
            count=count,
            prev_cursor=prev_cursor,
            next_cursor=next_cursor,
        )

    @staticmethod
    def _apply_cursor(stmt: Select, cursor: HistoryCursor) -> Select:
        """Apply a cursor to a query."""
        time = datetime_to_db(cursor.time)
        if cursor.previous:
            return stmt.where(
                or_(
                    TokenChangeHistory.event_time > time,
                    and_(
                        TokenChangeHistory.event_time == time,
                        TokenChangeHistory.id > cursor.id,
                    ),
                )
            )
        else:
            return stmt.where(
                or_(
                    TokenChangeHistory.event_time < time,
                    and_(
                        TokenChangeHistory.event_time == time,
                        TokenChangeHistory.id <= cursor.id,
                    ),
                )
            )

    @staticmethod
    def _build_next_cursor(entry: TokenChangeHistory) -> HistoryCursor:
        """Construct a next cursor for entries >= the given entry."""
        next_time = normalize_datetime(entry.event_time)
        assert next_time
        return HistoryCursor(time=next_time, id=entry.id)

    @staticmethod
    def _build_prev_cursor(entry: TokenChangeHistory) -> HistoryCursor:
        """Construct a prev cursor for entries before the given entry."""
        prev_time = normalize_datetime(entry.event_time)
        assert prev_time
        return HistoryCursor(time=prev_time, id=entry.id, previous=True)

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
