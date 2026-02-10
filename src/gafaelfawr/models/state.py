"""Representation of Gafaelfawr state stored in a cookie.

This is the Gafaelfawr version of `~gafaelfawr.middleware.state.BaseState`,
used by the `~gafaelfawr.middleware.state.StateMiddleware` middleware.  It
holds the data that Gafaelfawr stores in a session cookie.
"""

from typing import Annotated, Self, override

from cryptography.fernet import Fernet
from fastapi import Request
from pydantic import BaseModel, BeforeValidator, Field, PlainSerializer
from safir.dependencies.logger import logger_dependency
from safir.pydantic import UtcDatetime

from ..dependencies.config import config_dependency
from ..middleware.state import BaseState
from .token import Token

__all__ = ["State"]


class State(BaseState, BaseModel):
    """State information stored in a cookie."""

    csrf: Annotated[
        str | None,
        Field(
            title="CSRF token", description="CSRF token for form submissions"
        ),
    ] = None

    token: Annotated[
        Token | None,
        BeforeValidator(
            lambda t: Token.from_str(t) if isinstance(t, str) else t
        ),
        PlainSerializer(str),
        Field(title="Token", description="Token if the user is authenticated"),
    ] = None

    github: Annotated[
        str | None,
        Field(
            title="GitHub OAuth token",
            description="GitHub OAuth token if user authenticated via GitHub",
        ),
    ] = None

    return_url: Annotated[
        str | None,
        Field(
            title="Destination after login",
            description="Destination URL after completion of login",
        ),
    ] = None

    state: Annotated[
        str | None,
        Field(
            title="Login state",
            description="State token for OAuth 2.0 and OpenID Connect logins",
        ),
    ] = None

    login_start: Annotated[
        UtcDatetime | None,
        Field(
            title="Login start time",
            description="Start time of login process if one is in progress",
        ),
    ] = None

    @override
    @classmethod
    async def from_cookie(
        cls, cookie: str, request: Request | None = None
    ) -> Self:
        """Reconstruct state from an encrypted cookie.

        Parameters
        ----------
        cookie
            The encrypted cookie value.
        key
            The `~cryptography.fernet.Fernet` key used to decrypt it.
        request
            The request, used for logging.  If not provided (primarily for the
            test suite), invalid state cookies will not be logged.

        Returns
        -------
        State
            The state represented by the cookie.
        """
        config = await config_dependency()
        fernet = Fernet(config.session_secret.get_secret_value().encode())
        try:
            data = fernet.decrypt(cookie.encode()).decode()
            return cls.model_validate_json(data)
        except Exception as e:
            if request:
                logger = await logger_dependency(request)
                error = type(e).__name__
                if str(e):
                    error += f": {e!s}"
                logger.warning("Discarding invalid state cookie", error=error)
            return cls()

    @override
    def to_cookie(self) -> str:
        """Build an encrypted cookie representation of the state.

        Returns
        -------
        str
            The encrypted cookie value.
        """
        config = config_dependency.config()
        fernet = Fernet(config.session_secret.get_secret_value().encode())
        json_data = self.model_dump_json(exclude_none=True)
        return fernet.encrypt(json_data.encode()).decode()
