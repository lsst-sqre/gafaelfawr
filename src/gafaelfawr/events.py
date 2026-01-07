"""Metrics implementation for Gafaelfawr."""

from typing import override

from pydantic import Field
from safir.dependencies.metrics import EventMaker
from safir.metrics import EventManager, EventPayload

__all__ = [
    "ActiveUserSessionsEvent",
    "ActiveUserTokensEvent",
    "AuthBotEvent",
    "AuthUserEvent",
    "BaseAuthEvent",
    "FrontendEvents",
    "LoginAttemptEvent",
    "LoginEnrollmentEvent",
    "LoginFailureEvent",
    "LoginSuccessEvent",
    "RateLimitEvent",
    "StateEvents",
]


class ActiveUserSessionsEvent(EventPayload):
    """Current count of the number of active user sessions.

    These correspond to unexpired ``session`` tokens, which in turn correspond
    to unexpired user browser session cookies.

    Notes
    -----
    This is really a proper metric that is measured periodically, not an
    event. For now, Gafaelfawr uses the event system to log this metric since
    that's the system we have in place. If we later have a proper metrics
    system for storing measurements, this should move to that.
    """

    count: int = Field(
        ...,
        title="Active user sessions",
        description="Number of unexpired user session tokens",
    )


class ActiveUserTokensEvent(EventPayload):
    """Current count of the number of active ``user`` tokens.

    Notes
    -----
    This is really a proper metric that is measured periodically, not an
    event. For now, Gafaelfawr uses the event system to log this metric since
    that's the system we have in place. If we later have a proper metrics
    system for storing measurements, this should move to that.
    """

    count: int = Field(
        ...,
        title="Active user tokens",
        description="Number of unexpired user tokens",
    )


class StateEvents(EventMaker):
    """Event publishers for metrics about the current Gafaelfawr state.

    Attributes
    ----------
    active_user_sessions
        Event publisher for the count of active user sessions.
    active_user_tokens
        Event publisher for the count of active user tokens.
    """

    @override
    async def initialize(self, manager: EventManager) -> None:
        self.active_user_sessions = await manager.create_publisher(
            "active_user_sessions", ActiveUserSessionsEvent
        )
        self.active_user_tokens = await manager.create_publisher(
            "active_user_tokens", ActiveUserTokensEvent
        )


class BaseAuthEvent(EventPayload):
    """Base class for authentication events."""

    username: str = Field(
        ..., title="Username", description="Username of authenticated user"
    )

    service: str | None = Field(
        None,
        title="Service",
        description="Service to which the user was authenticated",
    )

    quota: int | None = Field(
        None,
        title="Quota",
        description="API quota for this service, if one is imposed",
    )

    quota_used: int | None = Field(
        None,
        title="Quota used",
        description="Amount of API quota used as of this request",
    )


class AuthBotEvent(BaseAuthEvent):
    """An authentication to a service by a bot user."""


class AuthUserEvent(BaseAuthEvent):
    """An authentication to a service by a user.

    Bot users are not included in this metric.
    """


class LoginAttemptEvent(EventPayload):
    """User attempted to log in and was directed to the identity provider.

    Records instances where Gafaelfawr sends the user to the identity provider
    for authentication. This does not include duplicate redirects when the
    given user already has an authentication in progress.
    """


class LoginEnrollmentEvent(EventPayload):
    """Authenticated but unknown user redirected to the enrollment flow."""


class LoginFailureEvent(EventPayload):
    """User authentication failed.

    A login fails at the Gafaelfawr end, meaning that either something went
    wrong in Gafaelfawr itself, with the request to the remote authentication
    service, or via an error reported by the remote authentication service.
    This does not count cases where the authentication service never returns
    the user to us.
    """


class LoginSuccessEvent(EventPayload):
    """User successfully authenticated.

    A user returned successfully from the identity provider after
    authenticating.
    """

    username: str = Field(
        ..., title="Username", description="Username of authenticated user"
    )

    elapsed: float | None = Field(
        None,
        title="Duration of login process (seconds)",
        description=(
            "How long it took the user to complete the login process in"
            " seconds"
        ),
    )


class RateLimitEvent(EventPayload):
    """Authentication request rejected by API rate limits."""

    username: str = Field(
        ..., title="Username", description="Username of authenticated user"
    )

    is_bot: bool = Field(
        ...,
        title="Whether user is a bot",
        description="Whether this user is a bot user",
    )

    service: str = Field(
        ...,
        title="Service",
        description="Service to which the user was authenticated",
    )

    quota: int = Field(
        ...,
        title="Quota",
        description="API quota amount that was exceeded",
    )


class FrontendEvents(EventMaker):
    """Event publishers for Gafaelfawr frontend events.

    Attributes
    ----------
    auth
        Event publisher for each user authentication to a service.
        Authentications from mobu bot users are not logged as events.
    login_attempt
        Event publisher for when an unauthenticated user is redirected to the
        authentication provider.
    login_enrollment
        Event publisher for when an authenticated but unknown user is
        redirected to the enrollment flow.
    login_failure
        Event publisher for authentications that fail in Gafaelfawr.
    login_success
        Event publisher for login successes.
    rate_limit
        Event publisher for rate limit rejections.
    """

    @override
    async def initialize(self, manager: EventManager) -> None:
        self.auth_bot = await manager.create_publisher(
            "auth_bot", AuthBotEvent
        )
        self.auth_user = await manager.create_publisher(
            "auth_user", AuthUserEvent
        )
        self.login_attempt = await manager.create_publisher(
            "login_attempt", LoginAttemptEvent
        )
        self.login_enrollment = await manager.create_publisher(
            "login_enrollment", LoginEnrollmentEvent
        )
        self.login_failure = await manager.create_publisher(
            "login_failure", LoginFailureEvent
        )
        self.login_success = await manager.create_publisher(
            "login_success", LoginSuccessEvent
        )
        self.rate_limit = await manager.create_publisher(
            "rate_limit", RateLimitEvent
        )
