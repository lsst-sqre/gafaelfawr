"""Storage for authentication sessions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from jwt.exceptions import InvalidTokenError

from gafaelfawr.exceptions import DeserializeException
from gafaelfawr.session import Session
from gafaelfawr.storage.base import Serializable
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from typing import Optional

    from aioredis.commands import Pipeline
    from structlog import BoundLogger

    from gafaelfawr.session import SessionHandle
    from gafaelfawr.storage.base import RedisStorage
    from gafaelfawr.verify import TokenVerifier

__all__ = ["SerializedSession", "SessionStore"]


@dataclass
class SerializedSession(Serializable):
    """A session suitable for storage in Redis.

    This is a lower-level class from `~gafaelfawr.session.Session` that just
    represents the data in a session without the verification logic.  It
    contains an encoded token and has not verified the secret of the
    `~gafaelfawr.session.SessionHandle` against the stored secret.
    """

    secret: str
    """The secret for the session, verified against the `SessionHandle`."""

    token: Token
    """The authentication token stored in the session."""

    email: str
    """The email address of the user (taken from the token claims)."""

    created_at: datetime
    """When the session was created."""

    expires_on: datetime
    """When the session will expire."""

    @classmethod
    def from_json(cls, data: str) -> SerializedSession:
        """Deserialize from JSON.

        Parameters
        ----------
        data : `str`
            JSON-serialized representation.

        Returns
        -------
        serialized : `SerializedSession`
            The serialized session object.  This will then need to be verified
            and converted into a full `~gafaelfawr.session.Session` object.
        """
        session = json.loads(data)
        return cls(
            secret=session["secret"],
            token=Token(encoded=session["token"]),
            email=session["email"],
            created_at=datetime.fromtimestamp(
                session["created_at"], tz=timezone.utc
            ),
            expires_on=datetime.fromtimestamp(
                session["expires_on"], tz=timezone.utc
            ),
        )

    @classmethod
    def from_session(cls, session: Session) -> SerializedSession:
        """Convert a `~gafaelfawr.session.Session` for storage.

        Parameters
        ----------
        session : `gafaelfawr.session.Session`
            A session to be stored in Redis.

        Returns
        -------
        serialized : `SerializedSession`
            Session suitable for storage.
        """
        return cls(
            secret=session.handle.secret,
            token=Token(encoded=session.token.encoded),
            email=session.email,
            created_at=session.created_at,
            expires_on=session.expires_on,
        )

    @property
    def lifetime(self) -> int:
        now = datetime.now(timezone.utc)
        return int((self.expires_on - now).total_seconds())

    def to_json(self) -> str:
        data = {
            "secret": self.secret,
            "token": self.token.encoded,
            "email": self.email,
            "created_at": int(self.created_at.timestamp()),
            "expires_on": int(self.expires_on.timestamp()),
        }
        return json.dumps(data)


class SessionStore:
    """Stores and retrieves sessions.

    Parameters
    ----------
    storage : `gafaelfawr.storage.base.RedisStorage`
        The underlying storage for `SerializedSession`.
    verifier : `gafaelfawr.verify.TokenVerifier`
        A token verifier to check the retrieved token.
    logger : `structlog.BoundLogger`
        Logger for diagnostics.
    """

    def __init__(
        self,
        storage: RedisStorage[SerializedSession],
        verifier: TokenVerifier,
        logger: BoundLogger,
    ) -> None:
        self._storage = storage
        self._verifier = verifier
        self._logger = logger

    async def delete_session(self, key: str, pipeline: Pipeline) -> None:
        """Delete a session.

        To allow the caller to batch this with other Redis modifications, the
        deletion is done using the provided pipeline.  The caller is
        responsible for executing the pipeline.

        Parameters
        ----------
        key : `str`
            The key of the session.
        pipeline : `aioredis.commands.Pipeline`
            The pipeline to use to delete the sesion.
        """
        await self._storage.delete(f"session:{key}", pipeline)

    async def get_session(self, handle: SessionHandle) -> Optional[Session]:
        """Retrieve the session for a handle.

        Parameters
        ----------
        handle : `gafaelfawr.session.SessionHandle`
            The handle corresponding to the session.

        Returns
        -------
        session : `gafaelfawr.session.Session` or `None`
            The corresponding session, or `None` if no session exists for this
            session handle or if the stored session is invalid for whatever
            reason.
        """
        try:
            serialized = await self._storage.get(f"session:{handle.key}")
        except DeserializeException as e:
            self._logger.error("Cannot retrieve session", error=str(e))
            return None
        if not serialized:
            return None

        if serialized.secret != handle.secret:
            error = f"Secret mismatch for {handle.key}"
            self._logger.error("Cannot retrieve session", error=error)
            return None

        try:
            token = self._verifier.verify_internal_token(serialized.token)
        except InvalidTokenError as e:
            error = f"Token for {handle.key} does not verify: {str(e)}"
            self._logger.error("Cannot retrieve session", error=error)
            return None

        return Session(
            handle=handle,
            token=token,
            email=serialized.email,
            created_at=serialized.created_at,
            expires_on=serialized.expires_on,
        )

    async def store_session(
        self, session: Session, pipeline: Optional[Pipeline] = None
    ) -> None:
        """Store a session.

        To allow the caller to batch this with other Redis modifications, if a
        pipeline is provided, the session will be stored but the pipeline will
        not be executed.  In this case, the caller is responsible for
        executing the pipeline.

        Parameters
        ----------
        session : `gafaelfawr.session.Session`
            The session to store.
        pipeline : `aioredis.commands.Pipeline`, optional
            The pipeline in which to store the session.
        """
        serialized = SerializedSession.from_session(session)
        key = f"session:{session.handle.key}"
        await self._storage.store(key, serialized, pipeline)
