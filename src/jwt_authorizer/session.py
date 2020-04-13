"""Session storage for JWT Authorizer.

Stores an oauth2_proxy session suitable for retrieval with a ticket using our
patched version of oauth2_proxy.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from jwt_authorizer.util import add_padding

if TYPE_CHECKING:
    import aioredis
    from aiohttp import web
    from aioredis.commands import Pipeline
    from jwt_authorizer.config import Config
    from typing import Optional

__all__ = [
    "InvalidCookieException",
    "InvalidTicketException",
    "Session",
    "SessionStore",
    "Ticket",
]


class InvalidCookieException(Exception):
    """Session cookie is not in expected format."""


class InvalidTicketException(Exception):
    """Ticket is not in expected format."""


def _new_ticket_id() -> str:
    """Generate a new ticket ID."""
    return os.urandom(20).hex()


def _new_ticket_secret() -> bytes:
    """Generate a new ticket encryption secret."""
    return os.urandom(16)


@dataclass
class Ticket:
    """A class represeting an oauth2_proxy ticket."""

    ticket_id: str = field(default_factory=_new_ticket_id)
    secret: bytes = field(default_factory=_new_ticket_secret)

    @classmethod
    def from_cookie(cls, prefix: str, cookie: str) -> Ticket:
        """Parse an oauth2_proxy session cookie value into a Ticket.

        Parameters
        ----------
        prefix : `str`
            The expected prefix for the ticket.
        cookie : `str`
            The value of the oauth2_proxy cookie.

        Returns
        -------
        ticket : `Ticket`
            The decoded ticket.

        Raises
        ------
        InvalidCookieException
            The syntax of the cookie is not valid.
        InvalidTicketException
            The ticket contained in the cookie is not valid.
        """
        try:
            encoded_ticket, _ = cookie.split("|", 1)
            ticket = base64.urlsafe_b64decode(encoded_ticket).decode()
        except Exception as e:
            msg = f"Error decoding cookie: {str(e)}"
            raise InvalidCookieException(msg)

        return cls.from_str(prefix, ticket)

    @classmethod
    def from_str(cls, prefix: str, ticket: str) -> Ticket:
        """Parse an oauth2_proxy ticket string into a Ticket.

        Parameters
        ----------
        prefix : `str`
            The expected prefix for the ticket.
        ticket : `str`
            The encoded ticket string.

        Returns
        -------
        decoded_ticket : `Ticket`
            The decoded Ticket.

        Raises
        ------
        InvalidTicketException
            The provided string is not a valid ticket.
        """
        full_prefix = f"{prefix}-"
        if not ticket.startswith(full_prefix):
            msg = f"Ticket does not start with {full_prefix}"
            raise InvalidTicketException(msg)

        trimmed_ticket = ticket[len(full_prefix) :]
        if "." not in trimmed_ticket:
            raise InvalidTicketException("Ticket is malformed")

        try:
            ticket_id, secret_b64 = trimmed_ticket.split(".", 1)
            int(ticket_id, 16)  # Check that the ticket ID is valid hex.
            secret = cls._base64_decode(secret_b64)
            if secret == b"":
                raise InvalidTicketException("Ticket secret is empty")
        except Exception as e:
            msg = f"Error decoding ticket: {str(e)}"
            raise InvalidTicketException(msg)

        return cls(ticket_id=ticket_id, secret=secret)

    def as_handle(self, prefix: str) -> str:
        """Return the handle for this ticket.

        Parameters
        ----------
        prefix : `str`
            Prefix to prepend to the ticket ID.
        """
        return f"{prefix}-{self.ticket_id}"

    def encode(self, prefix: str) -> str:
        """Return the encoded ticket, suitable for putting in a cookie.

        Parameters
        ----------
        prefix : `str`
            Prefix to prepend to the ticket ID.
        """
        secret_b64 = base64.urlsafe_b64encode(self.secret).decode().rstrip("=")
        return f"{prefix}-{self.ticket_id}.{secret_b64}"

    @staticmethod
    def _base64_decode(data: str) -> bytes:
        """Helper function to do base64 decoding.

        Undoes URL-safe base64 encoding, allowing for stripped padding and
        enabling validation so that an exception is thrown for invalid data.

        Notes
        -----
        Used instead of urlsafe_b64decode because that standard function
        doesn't have support for enabling validation.
        """
        return base64.b64decode(
            add_padding(data), altchars=b"-_", validate=True
        )


@dataclass
class Session:
    """An oauth2_proxy session.

    Tokens are currently stored in Redis as a JSON dump of a dictionary.  This
    class represents the deserialized form of a session.  created_at and
    expires_on must be UTC timestamps.
    """

    token: str
    email: str
    user: str
    created_at: datetime
    expires_on: datetime


class SessionStore:
    """Stores oauth2_proxy sessions and retrieves them by ticket.

    Parameters
    ----------
    prefix : `str`
        Prefix used for storing oauth2_proxy session state.
    key : `bytes`
        Encryption key for the individual components of the stored session.
    redis : `aioredis.Redis`
        A Redis client configured to talk to the backend store that holds the
        (encrypted) tokens.
    """

    def __init__(self, prefix: str, key: bytes, redis: aioredis.Redis) -> None:
        self.prefix = prefix
        self.key = key
        self.redis = redis

    async def get_session(self, ticket: Ticket) -> Optional[Session]:
        """Retrieve and decrypt the session for a ticket.

        Parameters
        ----------
        ticket : `Ticket`
            The ticket corresponding to the token.

        Returns
        -------
        session : `Session` or `None`
            The corresponding session, or `None` if no session exists for this
            ticket.
        """
        handle = ticket.as_handle(self.prefix)
        encrypted_session = await self.redis.get(handle)
        if not encrypted_session:
            return None

        return self._decrypt_session(ticket.secret, encrypted_session)

    def store_session(
        self, ticket: Ticket, session: Session, pipeline: Pipeline
    ) -> None:
        """Store an oauth2_proxy session in the provided pipeline.

        To allow the caller to batch this with other Redis modifications, the
        session will be stored but the pipeline will not be executed.  The
        caller is responsible for executing the pipeline.

        Parameters
        ----------
        ticket : `Ticket`
            The ticket under which to store the session.
        session : `Session`
            The session to store.
        pipeline : `aioredis.commands.Pipeline`
            The pipeline in which to store the session.
        """
        handle = ticket.as_handle(self.prefix)
        encrypted_session = self._encrypt_session(ticket.secret, session)
        expires_delta = (
            session.expires_on - datetime.now(timezone.utc)
        ).total_seconds()
        pipeline.set(handle, encrypted_session, expire=int(expires_delta))

    def _decrypt_session(
        self, secret: bytes, encrypted_session: bytes
    ) -> Session:
        """Decrypt an oauth2_proxy session.

        Parameters
        ----------
        secret : `bytes`
            Decryption key.
        encrypted_session : `bytes`
            The encrypted session.

        Returns
        -------
        session : `Sesssion`
            The decrypted sesssion.
        """
        cipher = Cipher(
            algorithms.AES(secret), modes.CFB(secret), default_backend()
        )
        decryptor = cipher.decryptor()
        session_dict = json.loads(
            decryptor.update(encrypted_session) + decryptor.finalize()
        )
        return Session(
            token=self._decrypt_session_component(session_dict["IDToken"]),
            email=self._decrypt_session_component(session_dict["Email"]),
            user=self._decrypt_session_component(session_dict["User"]),
            created_at=self._parse_session_date(session_dict["CreatedAt"]),
            expires_on=self._parse_session_date(session_dict["ExpiresOn"]),
        )

    def _decrypt_session_component(self, encrypted_str: str) -> str:
        """Decrypt a component of an encrypted oauth2_proxy session.

        Parameters
        ----------
        encrypted_str : `str`
            The encrypted field with its IV prepended.

        Returns
        -------
        component : `str`
            The decrypted value.
        """
        encrypted_bytes = base64.b64decode(encrypted_str)
        iv = encrypted_bytes[:16]
        cipher = Cipher(
            algorithms.AES(self.key), modes.CFB(iv), default_backend()
        )
        decryptor = cipher.decryptor()
        field = decryptor.update(encrypted_bytes[16:]) + decryptor.finalize()
        return field.decode()

    def _encrypt_session(self, secret: bytes, session: Session) -> bytes:
        """Generate an encrypted oauth2_proxy session.

        Parameters
        ----------
        secret : `bytes`
            Encryption key.
        session : `Session`
            The oauth2_proxy session to encrypt.

        Returns
        -------
        session : `bytes`
            The encrypted session information.
        """
        data = {
            "IDToken": self._encrypt_session_component(session.token),
            "Email": self._encrypt_session_component(session.email),
            "User": self._encrypt_session_component(session.user),
            "CreatedAt": session.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ExpiresOn": session.expires_on.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        data_as_json = json.dumps(data)
        cipher = Cipher(
            algorithms.AES(secret),
            modes.CFB(secret),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        encrypted_session = (
            encryptor.update(data_as_json.encode()) + encryptor.finalize()
        )
        return encrypted_session

    def _encrypt_session_component(self, component: str) -> str:
        """Encrypt a single oauth2_proxy session field.

        The initialization vector is randomly generated and stored with the
        field.  The component is encrypted with the SessionStore key, which
        is separate from the encryption secret used for the overall session.

        Parameters
        ----------
        component : `str`
            The field value to encrypt.

        Returns
        -------
        encrypted_str : `str`
            The IV and encrypted field, encoded in base64 and converted to a
            str for ease of json encoding.
        """
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_component = (
            encryptor.update(component.encode()) + encryptor.finalize()
        )
        return base64.b64encode(iv + encrypted_component).decode()

    @staticmethod
    def _parse_session_date(date_str: str) -> datetime:
        """Parse a date from a session record.

        Parameters
        ----------
        date_str : `str`
            The date in string format.

        Returns
        -------
        date : `datetime`
            The parsed date.

        Notes
        -----
        This date may be written by oauth2_proxy instead of us, in which case
        it will use a Go date format that includes fractional seconds down to
        the nanosecond.  Python doesn't have a date format that parses this,
        so the fractional seconds portion will be dropped, leading to an
        inaccuracy of up to a second.
        """
        date_str = re.sub("[.][0-9]+Z$", "Z", date_str)
        date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        return date.replace(tzinfo=timezone.utc)


def create_session_store(request: web.Request) -> SessionStore:
    """Create a TokenStore from an app configuration.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    session_store : `SessionStore`
        A TokenStore created from that Flask application configuration.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis_client = request.config_dict["jwt_authorizer/redis"]

    prefix = config.session_store.ticket_prefix
    secret = config.session_store.oauth2_proxy_secret
    return SessionStore(prefix, secret, redis_client)
