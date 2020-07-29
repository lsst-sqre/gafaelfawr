"""Session storage for JWT Authorizer."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet, InvalidToken
from jwt.exceptions import InvalidTokenError

from gafaelfawr.exceptions import InvalidSessionHandleException
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from typing import Any, Dict, Optional

    from aioredis import Redis
    from aioredis.commands import Pipeline
    from structlog import BoundLogger

    from gafaelfawr.tokens import VerifiedToken
    from gafaelfawr.verify import TokenVerifier

__all__ = [
    "Session",
    "SessionHandle",
    "SessionStore",
]


def _random_128_bits() -> str:
    """Generate random 128 bits encoded in base64 without padding."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")


@dataclass
class SessionHandle:
    """A handle for a session, usable instead of a JWT.

    Notes
    -----
    A session handle consists of two parts, a semi-public key that is used as
    the token jti claim and as the Redis key, and a secret that is only
    present in the token returned to the user and the encrypted session in
    Redis.

    The serialized form of a session handle always starts with ``gsh-``, short
    for Gafaelfawr session handle, to make it easier to identify these handles
    in logs.

    The serialized form encodes the secret in URL-safe base64 with the padding
    stripped off (because equal signs can be parsed oddly in cookies).
    """

    key: str = field(default_factory=_random_128_bits)
    secret: str = field(default_factory=_random_128_bits)

    @classmethod
    def from_str(cls, handle: str) -> SessionHandle:
        """Parse a serialized handle into a `SessionHandle`.

        Parameters
        ----------
        handle : `str`
            The serialized handle.

        Returns
        -------
        decoded_handle : `SessionHandle`
            The decoded SessionHandle.

        Raises
        ------
        gafaelfawr.exceptions.InvalidSessionHandleException
            The provided string is not a valid session handle.
        """
        if not handle.startswith("gsh-"):
            msg = "Session handle does not start with gsh-"
            raise InvalidSessionHandleException(msg)
        trimmed_handle = handle[len("gsh-") :]

        if "." not in trimmed_handle:
            raise InvalidSessionHandleException("Ticket is malformed")
        key, secret = trimmed_handle.split(".", 1)
        if len(key) != 22 or len(secret) != 22:
            raise InvalidSessionHandleException("Ticket is malformed")

        return cls(key=key, secret=secret)

    def encode(self) -> str:
        """Return the encoded session handle."""
        return f"gsh-{self.key}.{self.secret}"


@dataclass
class Session:
    """An authentication session.

    Notes
    -----
    The JWT is the user's authentication credentials and could be used alone.
    However JWTs tend to be long, which causes various problems in practice.
    Therefore, JWTs are stored in authentication sessions, and the session
    handle can be used instead of the JWT.

    The session handle is represented by the `SessionHandle` class.  It
    consists of a key and a secret.  The key corresponds to the Redis key
    under which the session is stored.  The secret must match the
    corresponding secret inside the encrypted Redis session value.  This
    approach prevents someone with access to list the Redis keys from using a
    Redis key directly as a session handle.
    """

    handle: SessionHandle
    """The handle for this session."""

    token: VerifiedToken
    """The authentication token stored in the session."""

    email: str
    """The email address of the user (taken from the token claims)."""

    created_at: datetime
    """When the session was created."""

    expires_on: datetime
    """When the session will expire."""

    @classmethod
    def create(cls, handle: SessionHandle, token: VerifiedToken) -> Session:
        """Create a new session.

        Parameters
        ----------
        handle : `SessionHandle`
            The handle for this session.
        token : `gafaelfawr.tokens.VerifiedToken`
            The token to store in this session.

        Returns
        -------
        session : `Session`
            The newly-created session.
        """
        email: str = token.claims["email"]
        iat: int = token.claims["iat"]
        exp: int = token.claims["exp"]

        return cls(
            handle=handle,
            token=token,
            email=email,
            created_at=datetime.fromtimestamp(iat, tz=timezone.utc),
            expires_on=datetime.fromtimestamp(exp, tz=timezone.utc),
        )


class SessionStore:
    """Stores and retrieves sessions.

    Parameters
    ----------
    key : `str`
        Encryption key for the session store.  Must be a
        `cryptography.fernet.Fernet` key.
    verifier : `gafaelfawr.verify.TokenVerifier`
        A token verifier to check the retrieved token.
    redis : `aioredis.Redis`
        A Redis client configured to talk to the backend store that holds the
        (encrypted) tokens.
    logger : `structlog.BoundLogger`
        Logger for diagnostics.
    """

    def __init__(
        self,
        key: str,
        verifier: TokenVerifier,
        redis: Redis,
        logger: BoundLogger,
    ) -> None:
        self._fernet = Fernet(key.encode())
        self._verifier = verifier
        self._redis = redis
        self._logger = logger

    async def analyze_handle(self, handle: SessionHandle) -> Dict[str, Any]:
        """Analyze a session handle and return its expanded information.

        Parameters
        ----------
        handle : `gafaelfawr.session.SessionHandle`
            The session handle to analyze.

        Returns
        -------
        output : Dict[`str`, Any]
            The contents of the session handle and its underlying session.
            This will include the session key and secret, the session it
            references, and the token that session contains.
        """
        output: Dict[str, Any] = {
            "handle": {"key": handle.key, "secret": handle.secret}
        }

        session = await self.get_session(handle)
        if not session:
            output["errors"] = [f"No session found for {handle.encode()}"]
            return output

        created_at = session.created_at.strftime("%Y-%m-%d %H:%M:%S -0000")
        expires_on = session.expires_on.strftime("%Y-%m-%d %H:%M:%S -0000")
        output["session"] = {
            "email": session.email,
            "created_at": created_at,
            "expires_on": expires_on,
        }

        output["token"] = self._verifier.analyze_token(session.token)

        return output

    def delete_session(self, key: str, pipeline: Pipeline) -> None:
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
        pipeline.delete(f"session:{key}")

    async def get_session(self, handle: SessionHandle) -> Optional[Session]:
        """Retrieve and decrypt the session for a handle.

        Parameters
        ----------
        handle : `SessionHandle`
            The handle corresponding to the session.

        Returns
        -------
        session : `Session` or `None`
            The corresponding session, or `None` if no session exists for this
            session handle.
        """
        redis_key = self._redis_key_for_handle(handle)
        encrypted_session = await self._redis.get(redis_key)
        if not encrypted_session:
            return None
        return await self._decrypt_session(handle, encrypted_session)

    async def store_session(
        self, session: Session, pipeline: Optional[Pipeline] = None,
    ) -> None:
        """Store a session.

        To allow the caller to batch this with other Redis modifications, if a
        pipeline is provided, the session will be stored but the pipeline will
        not be executed.  In this case, the caller is responsible for
        executing the pipeline.

        Parameters
        ----------
        session : `Session`
            The session to store.
        pipeline : `aioredis.commands.Pipeline`, optional
            The pipeline in which to store the session.
        """
        encrypted_session = self._encrypt_session(session)
        now = datetime.now(timezone.utc)
        expires = int((session.expires_on - now).total_seconds())
        redis_key = self._redis_key_for_handle(session.handle)
        if pipeline:
            pipeline.set(redis_key, encrypted_session, expire=expires)
        else:
            await self._redis.set(redis_key, encrypted_session, expire=expires)

    async def _decrypt_session(
        self, handle: SessionHandle, encrypted_session: bytes
    ) -> Optional[Session]:
        """Decrypt a session and validate the secret.

        If the key exists but the secret doesn't match, we return None exactly
        as if no key exists to not leak information to an attacker, but we log
        a loud error message.  If the Redis session cannot be decrypted, treat
        it as if it were missing (chances are the key was changed).

        Parameters
        ----------
        handle : `SessionHandle`
            The handle for the session.
        encrypted_session : `bytes`
            The encrypted session.

        Returns
        -------
        session : `Sesssion` or None
            The decrypted sesssion or None if it could not be decrypted.
        """
        try:
            session = json.loads(self._fernet.decrypt(encrypted_session))
        except InvalidToken:
            self._logger.exception(
                "Cannot decrypt session data for %s", handle.key
            )
            return None
        except json.JSONDecodeError:
            self._logger.exception("Invalid session data for %s", handle.key)
            return None

        if session["secret"] != handle.secret:
            self._logger.error("Secret mismatch for %s", handle.key)
            return None

        unverified_token = Token(encoded=session["token"])
        try:
            token = self._verifier.verify_internal_token(unverified_token)
        except InvalidTokenError:
            self._logger.exception(
                "Token in session %s does not verify", handle.key
            )
            return None

        try:
            return Session(
                handle=handle,
                token=token,
                email=session["email"],
                created_at=datetime.fromtimestamp(
                    session["created_at"], tz=timezone.utc
                ),
                expires_on=datetime.fromtimestamp(
                    session["expires_on"], tz=timezone.utc
                ),
            )
        except Exception:
            self._logger.exception("Invalid session data for %s", handle.key)
            return None

    def _encrypt_session(self, session: Session) -> bytes:
        """Serialize and encrypt a session.

        Parameters
        ----------
        session : `Session`
            The session to serialize and encrypt.

        Returns
        -------
        session : `bytes`
            The encrypted session information.
        """
        data = {
            "secret": session.handle.secret,
            "token": session.token.encoded,
            "email": session.email,
            "created_at": int(session.created_at.timestamp()),
            "expires_on": int(session.expires_on.timestamp()),
        }
        return self._fernet.encrypt(json.dumps(data).encode())

    def _redis_key_for_handle(self, handle: SessionHandle) -> str:
        """Determine the Redis key for a session handle.

        Parameters
        ----------
        handle : `SessionHandle`
            The session handle.

        Returns
        -------
        redis_key : `str`
            The key to use in Redis.
        """
        return f"session:{handle.key}"
